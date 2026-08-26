//! The I10 key-derivation isolation layer.
//!
//! Every function takes and returns raw byte arrays; no Monero library type
//! crosses this boundary. The derivations implemented are the pre-FCMP++
//! (CryptoNote/CLSAG-era) rules; the CARROT replacements will land here and
//! nowhere else.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE, edwards::CompressedEdwardsY, edwards::EdwardsPoint,
    scalar::Scalar as DalekScalar, traits::Identity,
};
use zeroize::Zeroizing;

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ed25519};
use monero_wallet::address::Network;
use monero_wallet::ed25519::{Commitment, CompressedPoint, Point, Scalar as MScalar};
use monero_wallet::primitives::keccak256;
use monero_wallet::ViewPair;

/// A 32-byte key/scalar/hash.
pub type Bytes32 = [u8; 32];

fn decompress(bytes: &Bytes32) -> Option<EdwardsPoint> {
    let p = CompressedEdwardsY(*bytes).decompress()?;
    // Reject the identity and torsioned points at the boundary.
    if p == EdwardsPoint::identity() || !p.is_torsion_free() {
        return None;
    }
    Some(p)
}

fn scalar(bytes: &Bytes32) -> Option<DalekScalar> {
    Option::<DalekScalar>::from(DalekScalar::from_canonical_bytes(*bytes))
}

/// Monero's `hash_to_scalar`: `keccak256(data) mod ℓ` (narrow reduction).
fn hash_to_scalar(data: &[u8]) -> DalekScalar {
    DalekScalar::from_bytes_mod_order(keccak256(data))
}

fn varint(mut n: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            return out;
        }
    }
}

/// `derivation_to_scalar`: `Hs(8·r·V ‖ varint(index))`, the per-output shared
/// secret of the CryptoNote one-time address scheme.
fn derivation_scalar(derivation: &EdwardsPoint, index: u64) -> DalekScalar {
    let mut buf = derivation.compress().to_bytes().to_vec();
    buf.extend(varint(index));
    hash_to_scalar(&buf)
}

/// MuSig-aggregate the parties' spend-key contributions into the joint spend
/// key (rogue-key-safe binding, so neither party can choose their key to
/// cancel the other's). `context` domain-separates the swap session. The key
/// list must be sorted/agreed identically by both parties.
pub fn aggregate_spend(context: Bytes32, spend_pubs: &[Bytes32]) -> Option<Bytes32> {
    let mut keys = Vec::with_capacity(spend_pubs.len());
    for pk in spend_pubs {
        let mut repr = <<Ed25519 as Ciphersuite>::G as GroupEncoding>::Repr::default();
        repr.as_mut().copy_from_slice(pk);
        let p = Option::from(<<Ed25519 as Ciphersuite>::G as GroupEncoding>::from_bytes(&repr))?;
        keys.push(p);
    }
    let joint = dkg_musig::musig_key::<Ed25519>(context, &keys).ok()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(joint.to_bytes().as_ref());
    Some(out)
}

/// Derive the shared private view key from both parties' view contributions
/// (each a 32-byte secret both sides exchange at session setup). Order
/// independent, so both parties compute the identical key. The view key is
/// deliberately shared in full: the channel *wants* both parties to see every
/// output; only spends need 2-of-2.
pub fn shared_view_key(context: Bytes32, a: &Bytes32, b: &Bytes32) -> Bytes32 {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut buf = b"XNOXMR-shared-view-v1".to_vec();
    buf.extend_from_slice(&context);
    buf.extend_from_slice(lo);
    buf.extend_from_slice(hi);
    hash_to_scalar(&buf).to_bytes()
}

/// The Monero network flavor for address encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Net {
    Mainnet,
    Stagenet,
    Testnet,
}

impl From<Net> for Network {
    fn from(n: Net) -> Network {
        match n {
            Net::Mainnet => Network::Mainnet,
            Net::Stagenet => Network::Stagenet,
            Net::Testnet => Network::Testnet,
        }
    }
}

/// The joint account's primary address for (joint spend pub, shared view key).
pub fn joint_address(spend_pub: &Bytes32, view_key: &Bytes32, net: Net) -> Option<String> {
    // Audit #20: reject identity/torsioned spend keys, matching the hardened
    // validation used by the one-time-key derivations.
    let _ = decompress(spend_pub)?;
    let spend = CompressedPoint::from(*spend_pub).decompress()?;
    let view = scalar(view_key)?;
    let pair = ViewPair::new(spend, Zeroizing::new(MScalar::from(view))).ok()?;
    Some(pair.legacy_address(net.into()).to_string())
}

/// Sender side: derive the transaction public key `R = r·G` and the one-time
/// output key `P = Hs(8·r·V ‖ varint(i))·G + S` paying the account
/// `(S = spend_pub, V = view_pub)` at output index `i`.
pub fn sender_one_time_key(
    tx_secret: &Bytes32,
    view_pub: &Bytes32,
    spend_pub: &Bytes32,
    index: u64,
) -> Option<(Bytes32, Bytes32)> {
    let r = scalar(tx_secret)?;
    let v = decompress(view_pub)?;
    let s = decompress(spend_pub)?;
    let tx_pub = (&r * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    let derivation = v * r * DalekScalar::from(8u8);
    let shared = derivation_scalar(&derivation, index);
    let one_time = (&shared * ED25519_BASEPOINT_TABLE) + s;
    Some((tx_pub, one_time.compress().to_bytes()))
}

/// Receiver side: recompute the key offset for an output. Returns the shared
/// scalar `Hs(8·v·R ‖ varint(i))` iff `offset·G + S` equals the output key —
/// i.e. iff the output actually pays this account. The full private spend key
/// of the output is `offset + joint_spend_secret`, which no single party
/// holds; the offset feeds [`crate::cosign`] as the `ThresholdKeys` offset.
pub fn receiver_key_offset(
    view_key: &Bytes32,
    tx_pub: &Bytes32,
    spend_pub: &Bytes32,
    index: u64,
    output_key: &Bytes32,
) -> Option<Bytes32> {
    let v = scalar(view_key)?;
    let r_pub = decompress(tx_pub)?;
    let s = decompress(spend_pub)?;
    let derivation = r_pub * v * DalekScalar::from(8u8);
    let shared = derivation_scalar(&derivation, index);
    let candidate = (&shared * ED25519_BASEPOINT_TABLE) + s;
    if candidate.compress().to_bytes() != *output_key {
        return None;
    }
    Some(shared.to_bytes())
}

/// `Hp(P)` — the key-image generator for an output key. The joint key image
/// is `(offset + joint_secret)·Hp(P)`, assembled from per-party shares inside
/// the co-signing ceremony; no single party can compute it alone.
pub fn key_image_generator(output_key: &Bytes32) -> Bytes32 {
    Point::biased_hash(*output_key).compress().to_bytes()
}

/// Pedersen commitment `x·G + amount·H` for the given mask — needed to open
/// ring-member commitments when co-signing.
pub fn commitment(mask: &Bytes32, amount: u64) -> Option<Bytes32> {
    let m = scalar(mask)?;
    let c = Commitment::new(MScalar::from(m), amount).commit();
    Some(c.compress().to_bytes())
}
