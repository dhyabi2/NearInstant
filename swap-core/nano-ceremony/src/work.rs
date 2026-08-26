//! Nano proof-of-work: `Blake2b-64(nonce_le ‖ root)` interpreted little-endian
//! must meet the network threshold. The root of block *i+1* is block *i*'s
//! hash — known at signing time — so work pipelines fully ahead of a chunk
//! stream (N4).

use blake2::digest::consts::U8;
use blake2::{Blake2b, Digest};

use crate::Bytes32;

/// Mainnet threshold for send/change blocks (epoch v2).
pub const THRESHOLD_SEND: u64 = 0xFFFF_FFF8_0000_0000;
/// Mainnet threshold before epoch v2 (still what pre-2020 blocks carry).
pub const THRESHOLD_EPOCH_V1: u64 = 0xFFFF_FFC0_0000_0000;
/// Mainnet threshold for receive/open blocks (epoch v2).
pub const THRESHOLD_RECEIVE: u64 = 0xFFFF_FE00_0000_0000;

/// The work value for a nonce over a root.
pub fn value(root: &Bytes32, nonce: u64) -> u64 {
    let mut h = Blake2b::<U8>::new();
    h.update(nonce.to_le_bytes());
    h.update(root);
    let mut out = [0u8; 8];
    out.copy_from_slice(&h.finalize());
    u64::from_le_bytes(out)
}

/// Validate a nonce against a threshold.
pub fn validate(root: &Bytes32, nonce: u64, threshold: u64) -> bool {
    value(root, nonce) >= threshold
}

/// Brute-force a valid nonce starting from `seed`. Untrusted-provider
/// friendly: any nonce from anywhere is accepted iff [`validate`] passes.
pub fn generate(root: &Bytes32, threshold: u64, seed: u64) -> u64 {
    let mut nonce = seed;
    loop {
        if validate(root, nonce, threshold) {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}
