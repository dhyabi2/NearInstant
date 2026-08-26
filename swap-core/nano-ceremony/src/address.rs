//! Nano account address encoding: `nano_` + 52-char base32 of the public key
//! (260 bits, 4-bit zero pad) + 8-char base32 of the reversed 5-byte Blake2b
//! checksum.

use blake2::digest::{consts::U5, Digest};
use blake2::Blake2b;

use crate::Bytes32;

const ALPHABET: &[u8; 32] = b"13456789abcdefghijkmnopqrstuwxyz";

fn char_value(c: u8) -> Option<u8> {
    ALPHABET.iter().position(|&a| a == c).map(|i| i as u8)
}

fn checksum(public_key: &Bytes32) -> [u8; 5] {
    let mut h = Blake2b::<U5>::new();
    h.update(public_key);
    let mut out = [0u8; 5];
    out.copy_from_slice(&h.finalize());
    out.reverse();
    out
}

/// Encode a bit string (MSB first) into the Nano base32 alphabet.
fn encode_bits(bits: &[bool]) -> String {
    debug_assert_eq!(bits.len() % 5, 0);
    bits.chunks(5)
        .map(|c| {
            let mut v = 0u8;
            for &b in c {
                v = (v << 1) | b as u8;
            }
            ALPHABET[v as usize] as char
        })
        .collect()
}

fn bytes_to_bits(bytes: &[u8], pad: usize) -> Vec<bool> {
    let mut bits = vec![false; pad];
    for byte in bytes {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    bits
}

/// Encode a public key as a `nano_…` address.
pub fn encode(public_key: &Bytes32) -> String {
    let body = encode_bits(&bytes_to_bits(public_key, 4));
    let check = encode_bits(&bytes_to_bits(&checksum(public_key), 0));
    format!("nano_{body}{check}")
}

/// Decode a `nano_…` (or legacy `xrb_…`) address back to the public key,
/// verifying length, alphabet, zero padding, and checksum.
pub fn decode(address: &str) -> Option<Bytes32> {
    let rest = address
        .strip_prefix("nano_")
        .or_else(|| address.strip_prefix("xrb_"))?;
    if rest.len() != 60 {
        return None;
    }
    let mut bits = Vec::with_capacity(300);
    for c in rest.bytes() {
        let v = char_value(c)?;
        for i in (0..5).rev() {
            bits.push((v >> i) & 1 == 1);
        }
    }
    // 4 pad bits + 256 key bits + 40 checksum bits.
    if bits[..4].iter().any(|&b| b) {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, chunk) in bits[4..260].chunks(8).enumerate() {
        let mut v = 0u8;
        for &b in chunk {
            v = (v << 1) | b as u8;
        }
        key[i] = v;
    }
    let mut check = [0u8; 5];
    for (i, chunk) in bits[260..].chunks(8).enumerate() {
        let mut v = 0u8;
        for &b in chunk {
            v = (v << 1) | b as u8;
        }
        check[i] = v;
    }
    if check != checksum(&key) {
        return None;
    }
    Some(key)
}
