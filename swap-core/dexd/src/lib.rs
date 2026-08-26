//! Block 10: the `dexd` relay library — a de-duplicating gossip node holding
//! the deterministic consolidated book (B4). The `dexd` binary wraps this in
//! a TCP listener + peer connections; tests drive the relay in-process.

pub mod relay;
