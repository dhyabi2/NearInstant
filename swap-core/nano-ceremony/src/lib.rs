//! Block 2 of the build order: the Nano side of the swap.
//!
//! - [`address`]: Nano account encoding of the FROST joint public key.
//! - [`block`]: state-block construction and Blake2b-256 hashing.
//! - [`work`]: proof-of-work validation and (pipelined) generation (N4).
//! - [`ceremony`]: joint 2-of-2 and adaptor signing of block hashes over the
//!   `signing` crate.
//! - [`guard`]: the I3 guard ladder — pre-signed representative-change blocks
//!   that advance the frontier before any secret-revealing broadcast,
//!   invalidating every stale-frontier signature.
//! - [`broadcast`]: node abstraction and saturation broadcast.

#![forbid(unsafe_code)]

pub mod address;
pub mod block;
pub mod broadcast;
pub mod ceremony;
pub mod guard;
pub mod work;

/// A 32-byte hash / key, the universal Nano field width.
pub type Bytes32 = [u8; 32];
