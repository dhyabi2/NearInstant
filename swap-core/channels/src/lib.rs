//! Block 6 of the build order: one-way swap channels (I5).
//!
//! The maker locks XMR once into the 2-of-2 joint account. Every trade after
//! that is instant: the taker pays an XNO chunk on Nano (sub-second, final),
//! and the maker co-signs a new unbroadcast Monero state transaction giving
//! the taker a cumulatively larger slice. **Only the taker holds completed
//! states**, each strictly better for them than the last — so no revocation
//! and no timelocks: the taker always broadcasts the latest, and the maker
//! holds nothing broadcastable. Every state spends the same funding output,
//! so all states share one key image and at most one can ever confirm.
//!
//! - [`channel`]: the monotone channel state machine (maker and taker views),
//!   lifetime caps (client-enforced auto-close before the maker's puzzle
//!   horizon T2 and before any announced fork height, per I5/N2), and the
//!   no-cross-channel-credit rule.
//! - [`journal`]: N1 anchoring — each accepted state's hash is written to the
//!   Nano chain as a 1-raw send whose destination *is* the state hash, making
//!   the chain a free trustless journal; recovery reads the anchors back and
//!   convicts a counterparty serving a stale state.

#![forbid(unsafe_code)]

pub mod channel;
pub mod journal;
