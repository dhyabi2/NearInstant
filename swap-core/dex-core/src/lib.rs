//! Block 7 of the build order: the DEX layers, as a transport-agnostic core.
//!
//! Everything here is deterministic and network-free: gossip transports and
//! RPC feeds plug in at the edges. Modules map to the settled register:
//!
//! - [`order`] — I7: signed orders (ed25519-blake2b), canonical hashing,
//!   deterministic tie-breaking, expiry and proof-of-funds hooks.
//! - [`book`] — B1/I7: the client-side consolidated book — staleness-aware,
//!   PoF-weighted, identical on every client, Merkle-rooted for Nano `link`
//!   anchoring with inclusion proofs.
//! - [`market`] — B2/N6: candles, ticker, and volume computed only from the
//!   settled-trade journal; decay VWAP/volatility re-exported from
//!   `swap-engine`.
//! - [`matching`] — B8: taker-choice best-execution selection, commit-reveal
//!   quote taking with single-use tickets, maker-side FCFS signed receipts.
//! - [`triggers`] — B3: client-side stop / stop-limit / OCO / trailing
//!   evaluation against the settled-trade VWAP; no delegation, no oracle.
//! - [`earn`] — G1: the quoting engine behind the Earn toggle — VWAP-anchored
//!   quotes, inventory skew, volatility widening, drawdown circuit breaker,
//!   realized-yield band from the journal only.
//! - [`ledger`] — G2: the deterministic earnings ledger — a pure function
//!   from the signed event log to income-statement lines.
//! - [`privacy`] — I9: the swap-chaining planner — XNO→XMR→XNO round trips
//!   through distinct counterparties, fixed denominations, batch windows.

#![forbid(unsafe_code)]

pub mod beacon;
pub mod book;
pub mod rendezvous;
pub mod reputation;
pub mod earn;
pub mod ledger;
pub mod market;
pub mod matching;
pub mod order;
pub mod pof;
pub mod privacy;
pub mod triggers;
