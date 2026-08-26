//! Block 3 of the build order: the Monero side of the swap.
//!
//! - [`isolation`]: the I10 key-derivation isolation layer — a pure-function,
//!   raw-bytes-in/raw-bytes-out boundary holding *every* CLSAG/CARROT-coupled
//!   derivation. When FCMP++/CARROT changes Monero's key derivation, this
//!   module is the only file that changes; the swap engine above it never
//!   sees a Monero type.
//! - [`cosign`]: 2-of-2 CLSAG co-signing of channel state transactions over
//!   `monero-clsag`'s multisig implementation (`modular-frost`), with the
//!   joint key built by MuSig aggregation (rogue-key safe) and offset by the
//!   output's key offset — the exact shape of an I5 channel-state spend.
//! - [`rpc`]: a live daemon client over a public (or local) node — no local
//!   `monerod` install required; the URL selects the network.

#![forbid(unsafe_code)]

pub mod cosign;
pub mod eclipse;
pub mod selftest;
pub mod fee;
pub mod isolation;
#[cfg(feature = "rpc")]
pub mod rpc;
