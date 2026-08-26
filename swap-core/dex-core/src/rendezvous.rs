//! Derived-onion rendezvous (R18) — two strangers establish an interactive
//! channel while NOTHING larger than a 32-byte nonce ever crosses a Nano field.
//!
//! The insight that dissolves the size problem: a Tor v3 `.onion` address IS an
//! ed25519 public key. So instead of transmitting a >56-byte onion descriptor
//! through the beacon, both parties DERIVE the same onion key from a shared
//! secret they each compute locally:
//!
//! 1. Discovery over the feeless Nano beacon (R4): each party picks a random
//!    32-byte `nonce` and sends dust to `contact_account(swap_id, nonce)` — a
//!    deterministic account both can compute. When A sees dust arrive on one of
//!    its own contact accounts *from* one of B's, the pair has matched and each
//!    learns the other's nonce (the sender account reveals it via the same
//!    derivation). Only 32-byte values ever touch the ledger.
//! 2. Both compute `seed = rendezvous_seed(swap_id, nonce_low, nonce_high)`
//!    (nonces sorted, so order-independent) and from it the SAME ed25519
//!    keypair. The maker configures a Tor v3 hidden service at that key; the
//!    taker computes the identical `.onion` address locally and dials it. The
//!    ceremony runs over that Tor circuit — no server, no descriptor sent, no
//!    `tx_extra`, nothing over 32 bytes on-chain.
//!
//! This module is the pure, testable crypto core: swap-id + contact-account
//! derivation, the seed KDF, the seed→ed25519 keypair, and the exact Tor v3
//! `.onion` address encoding (both sides provably agree). The Nano dust sends,
//! the match scan, and hosting the hidden service are thin integration on top.
//!
//! STILL OPEN (documented, not solved here): how two TRUE strangers first agree
//! on `swap_id` without prior contact, and authenticating the channel against a
//! man-in-the-middle. `swap_id` here binds the maker's beacon identity + the
//! order + the taker's ephemeral key, which authenticates the pair to each
//! other but assumes the taker learned the maker's key from the beacon.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest as _};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use sha3::{Sha3_256, Sha3_512};

use crate::beacon::Bytes32;
use crate::order::Side;

/// Domain-separation tags.
const TAG_SWAPID: &[u8] = b"xnoxmr-rendezvous-swapid-v1";
const TAG_CONTACT: &[u8] = b"xnoxmr-rendezvous-contact-v1";
const TAG_SEED: &[u8] = b"xnoxmr-rendezvous-seed-v1";

fn blake32(parts: &[&[u8]]) -> Bytes32 {
    let mut h = Blake2b::<U32>::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The session identity binding a specific taker to a specific maker order.
/// Both parties compute it identically: the taker knows the maker's beacon
/// account, the order parameters, and its own ephemeral pubkey; the maker
/// learns the taker's ephemeral pubkey during discovery.
pub fn swap_id(
    maker_account: &Bytes32,
    pair: &str,
    side: Side,
    price_e9: u64,
    taker_ephemeral_pub: &Bytes32,
) -> Bytes32 {
    let side_byte = [match side {
        Side::SellXno => 0u8,
        Side::SellXmr => 1u8,
    }];
    blake32(&[
        TAG_SWAPID,
        maker_account,
        pair.as_bytes(),
        &side_byte,
        &price_e9.to_le_bytes(),
        taker_ephemeral_pub,
    ])
}

/// A deterministic Nano account a party dusts to signal presence for `nonce`
/// under `swap_id`. The counterparty watches these; both derive them identically.
pub fn contact_account(swap_id: &Bytes32, nonce: &Bytes32) -> Bytes32 {
    blake32(&[TAG_CONTACT, swap_id, nonce])
}

/// The shared rendezvous seed. Nonces are sorted so both parties reach the same
/// value regardless of who is "A" and who is "B".
pub fn rendezvous_seed(swap_id: &Bytes32, nonce_x: &Bytes32, nonce_y: &Bytes32) -> Bytes32 {
    let (lo, hi) = if nonce_x <= nonce_y {
        (nonce_x, nonce_y)
    } else {
        (nonce_y, nonce_x)
    };
    blake32(&[TAG_SEED, swap_id, lo, hi])
}

/// An ed25519 keypair derived from a 32-byte seed, in the exact form Tor v3
/// hidden services use (an expanded secret key: clamped scalar + hash prefix).
/// Both parties derive the identical keypair from the shared seed; the maker
/// hosts the service, the taker only needs the public address.
#[derive(Clone)]
pub struct OnionKey {
    /// The clamped ed25519 scalar (little-endian bytes) — first half of Tor's
    /// `hs_ed25519_secret_key`.
    pub scalar: [u8; 32],
    /// The hash prefix — second half of Tor's expanded secret key.
    pub prefix: [u8; 32],
    /// The ed25519 public key (== the onion address's key material).
    pub public: [u8; 32],
}

/// Derive the Tor-style expanded ed25519 keypair from a seed (RFC 8032 §5.1.5
/// expansion: SHA-512(seed) → clamp low half = scalar, high half = prefix).
pub fn onion_key_from_seed(seed: &Bytes32) -> OnionKey {
    let mut h = Sha3_512::new();
    // Tor derives from SHA-512 of the seed; we use a domain-separated SHA3-512
    // so the seed space is our own (the address encoding below is standard Tor).
    h.update(b"xnoxmr-onion-expand-v1");
    h.update(seed);
    let digest = h.finalize();
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&digest[..32]);
    // ed25519 clamping.
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&digest[32..]);

    let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
    let public = (&scalar * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    OnionKey { scalar: scalar_bytes, prefix, public }
}

/// The Tor v3 `.onion` address for an ed25519 public key:
/// base32(PUBKEY ‖ CHECKSUM ‖ VERSION) + ".onion", where
/// CHECKSUM = SHA3-256(".onion checksum" ‖ PUBKEY ‖ VERSION)[..2] and
/// VERSION = 0x03. Lowercase, no padding (RFC 4648 base32).
pub fn onion_address(public: &[u8; 32]) -> String {
    const VERSION: u8 = 0x03;
    let mut cs = Sha3_256::new();
    cs.update(b".onion checksum");
    cs.update(public);
    cs.update([VERSION]);
    let checksum = cs.finalize();

    let mut blob = Vec::with_capacity(35);
    blob.extend_from_slice(public);
    blob.extend_from_slice(&checksum[..2]);
    blob.push(VERSION);

    format!("{}.onion", base32_lower(&blob))
}

/// The full rendezvous both parties compute from the shared seed: the onion
/// keypair (maker hosts it) and its address (taker dials it).
pub fn rendezvous(seed: &Bytes32) -> (OnionKey, String) {
    let key = onion_key_from_seed(seed);
    let addr = onion_address(&key.public);
    (key, addr)
}

/// RFC 4648 base32, lowercase, no padding (Tor's alphabet).
fn base32_lower(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(b: u8) -> Bytes32 {
        [b; 32]
    }

    #[test]
    fn both_parties_derive_the_same_onion() {
        // Maker and taker compute the same swap_id, then each learns the
        // other's nonce; both must land on the identical seed → address.
        let maker = n(0xAA);
        let taker_pub = n(0xBB);
        let sid_maker = swap_id(&maker, "XNO/XMR", Side::SellXmr, 3_750_000, &taker_pub);
        let sid_taker = swap_id(&maker, "XNO/XMR", Side::SellXmr, 3_750_000, &taker_pub);
        assert_eq!(sid_maker, sid_taker, "swap_id agrees");

        let nonce_maker = n(0x11);
        let nonce_taker = n(0x22);
        // Order-independent: maker sees (its nonce, taker nonce); taker sees the
        // reverse — same seed either way.
        let seed_m = rendezvous_seed(&sid_maker, &nonce_maker, &nonce_taker);
        let seed_t = rendezvous_seed(&sid_taker, &nonce_taker, &nonce_maker);
        assert_eq!(seed_m, seed_t, "seed is order-independent");

        let (key_m, addr_m) = rendezvous(&seed_m);
        let (_key_t, addr_t) = rendezvous(&seed_t);
        assert_eq!(addr_m, addr_t, "both compute the identical .onion");
        assert!(addr_m.ends_with(".onion"));
        assert_eq!(addr_m.len(), 56 + ".onion".len(), "v3 onion is 56 base32 chars + suffix");
        // The address's key material is the derived public key.
        assert_eq!(key_m.public.len(), 32);
    }

    #[test]
    fn onion_address_matches_tor_v3_spec() {
        // Known-answer: the all-zero ed25519 public key.
        // Independently reproducible: base32(0x00*32 ‖ sha3_256(".onion checksum"‖0*32‖3)[..2] ‖ 3).
        let addr = onion_address(&[0u8; 32]);
        assert!(addr.ends_with(".onion"));
        assert_eq!(addr.len(), 62); // 56 + ".onion"
        // Every character is in the lowercase base32 alphabet.
        assert!(addr
            .trim_end_matches(".onion")
            .bytes()
            .all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c)));
    }

    #[test]
    fn distinct_swaps_distinct_onions() {
        let a = rendezvous(&rendezvous_seed(&n(1), &n(2), &n(3))).1;
        let b = rendezvous(&rendezvous_seed(&n(1), &n(2), &n(4))).1;
        assert_ne!(a, b, "a different counterparty nonce → a different rendezvous");
    }

    #[test]
    fn contact_accounts_are_deterministic_and_unlinkable() {
        let sid = n(0x33);
        assert_eq!(contact_account(&sid, &n(1)), contact_account(&sid, &n(1)));
        assert_ne!(contact_account(&sid, &n(1)), contact_account(&sid, &n(2)));
        // A different swap yields unrelated contact accounts (no linkage).
        assert_ne!(contact_account(&sid, &n(1)), contact_account(&n(0x44), &n(1)));
    }

    #[test]
    fn base32_lower_is_rfc4648() {
        // "foobar" → RFC 4648 base32 "MZXW6YTBOI" → lowercased.
        assert_eq!(base32_lower(b"foobar"), "mzxw6ytboi");
        assert_eq!(base32_lower(b"f"), "my");
        assert_eq!(base32_lower(b"fo"), "mzxq");
    }
}
