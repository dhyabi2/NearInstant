//! Block 4 of the build order: the chunked swap engine.
//!
//! - [`schedule`]: I1 chunk schedules — value-at-risk per abort is capped at
//!   one chunk by construction.
//! - [`premium`]: I4/N6 pricing — exponential-decay VWAP and volatility from
//!   settled trades only, and the explicit time-decaying option premium.
//! - [`machine`]: the deterministic, transport-agnostic swap state machine —
//!   events in, actions out, illegal transitions rejected, loss accounting
//!   maintained at every step.
//!
//! The integration test drives one real atomic chunk end to end across the
//! `signing`, `nano-ceremony`, and `monero-side` crates: Bob's only path to
//! the XNO chunk reveals the exact secret Alice needs to sweep the XMR.

#![forbid(unsafe_code)]

pub mod machine;
pub mod premium;
pub mod schedule;
