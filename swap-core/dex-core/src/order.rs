//! I7: signed orders.
//!
//! An order is a maker's signed commitment to trade. The signature is
//! ed25519-blake2b over the canonical encoding, so the same key material and
//! verifier as Nano blocks apply (one audited signing stack, everywhere).
//! Orders carry expiry and a proof-of-funds reference; freshness re-proofs
//! and reserve-proof validation plug in at the gossip edge.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

pub type Bytes32 = [u8; 32];

/// Sentinel `proof-of-funds` hash carried by orders that have NO PoF attached
/// (P0 gap: real reserve/account proofs are not yet produced or verified).
/// Such orders are structurally valid but are flagged `pof_verified=false` at
/// the relay/book layer (B1: shown thinner, never hidden). The PoF pipeline is
/// a pre-launch blocker, not something this sentinel papers over.
pub const NO_POF: Bytes32 = [0xEE; 32];

/// Maximum lifetime of an order, in seconds. Makers post short-lived orders and
/// re-gossip them (M3 freshness); a bound here stops a captured or malicious
/// order with a far-future expiry from squatting in the book forever (which,
/// combined with the relay's book cap, would be a cheap DoS that crowd out
/// honest depth).
pub const MAX_ORDER_TTL_SECS: u64 = 7 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// Maker sells XNO for XMR.
    SellXno,
    /// Maker sells XMR for XNO.
    SellXmr,
}

/// The unsigned order body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderBody {
    pub maker: Bytes32,
    pub side: Side,
    /// Amount of the sold asset, raw units.
    pub amount: u128,
    /// Rate in XMR-per-XNO, scaled by 1e12 (integer, no float in consensus
    /// surfaces).
    pub rate_pico: u128,
    /// Unix seconds after which the order is dead.
    pub expiry: u64,
    /// Anti-replay nonce, unique per (maker, order).
    pub nonce: u64,
    /// Hash of the attached proof-of-funds (reserve proof for XMR, account
    /// for XNO); the PoF itself travels beside the order.
    pub pof_hash: Bytes32,
}

impl OrderBody {
    /// Canonical encoding — the byte string that is hashed and signed.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 16 + 16 + 8 + 8 + 32 + 8);
        out.extend_from_slice(b"XNOXMR-ORDER-v1\0");
        out.extend_from_slice(&self.maker);
        out.push(match self.side {
            Side::SellXno => 0,
            Side::SellXmr => 1,
        });
        out.extend_from_slice(&self.amount.to_be_bytes());
        out.extend_from_slice(&self.rate_pico.to_be_bytes());
        out.extend_from_slice(&self.expiry.to_be_bytes());
        out.extend_from_slice(&self.nonce.to_be_bytes());
        out.extend_from_slice(&self.pof_hash);
        out
    }

    /// The canonical order hash — the identity used for tie-breaking,
    /// Merkle anchoring, and tickets.
    pub fn hash(&self) -> Bytes32 {
        let mut h = Blake2b::<U32>::new();
        h.update(self.encode());
        h.finalize().into()
    }
}

/// A signed order as gossiped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedOrder {
    pub body: OrderBody,
    pub signature: [u8; 64],
}

impl SignedOrder {
    /// Verify the maker's signature (ed25519-blake2b over the canonical
    /// encoding) and basic sanity, including a bounded lifetime.
    pub fn verify(&self, now: u64) -> bool {
        self.body.amount > 0
            && self.body.rate_pico > 0
            && self.body.expiry > now
            && self.body.expiry.saturating_sub(now) <= MAX_ORDER_TTL_SECS
            && signing::nano_verify::verify(&self.body.maker, &self.body.encode(), &self.signature)
    }

    /// Deterministic total order for identical (rate, amount) levels —
    /// every client sorts identically (B8/I7): by hash, ascending.
    pub fn tie_break_key(&self) -> Bytes32 {
        self.body.hash()
    }
}

impl SignedOrder {
    /// Wire encoding: canonical body ‖ 64-byte signature. Self-delimiting
    /// because the body encoding is fixed-length.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = self.body.encode();
        out.extend_from_slice(&self.signature);
        out
    }

    /// Decode from wire bytes. Verifies structure only; call `verify` for
    /// signature/expiry checks.
    pub fn from_wire(bytes: &[u8]) -> Option<SignedOrder> {
        // Body is a fixed 16+32+1+16+16+8+8+32 = 129 byte prefix.
        const BODY_LEN: usize = 16 + 32 + 1 + 16 + 16 + 8 + 8 + 32;
        if bytes.len() != BODY_LEN + 64 {
            return None;
        }
        let b = bytes;
        if &b[..16] != b"XNOXMR-ORDER-v1\0" {
            return None;
        }
        let maker: Bytes32 = b[16..48].try_into().ok()?;
        let side = match b[48] {
            0 => Side::SellXno,
            1 => Side::SellXmr,
            _ => return None,
        };
        let amount = u128::from_be_bytes(b[49..65].try_into().ok()?);
        let rate_pico = u128::from_be_bytes(b[65..81].try_into().ok()?);
        let expiry = u64::from_be_bytes(b[81..89].try_into().ok()?);
        let nonce = u64::from_be_bytes(b[89..97].try_into().ok()?);
        let pof_hash: Bytes32 = b[97..129].try_into().ok()?;
        let signature: [u8; 64] = b[129..193].try_into().ok()?;
        let order = SignedOrder {
            body: OrderBody { maker, side, amount, rate_pico, expiry, nonce, pof_hash },
            signature,
        };
        // Round-trip guard: the decoded body must re-encode to the same prefix.
        if order.body.encode() != b[..BODY_LEN] {
            return None;
        }
        Some(order)
    }
}
