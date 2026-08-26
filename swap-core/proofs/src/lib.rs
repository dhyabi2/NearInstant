//! Adversarial security proofs for the XNO⇄XMR protocol.
//!
//! Each security-critical property is stated, then backed by an *adversarial*
//! test in `tests/` — an attacker attempt that MUST fail (plus the honest path
//! that must succeed). Run: `cargo test -p proofs`.
//!
//! This is machine-checked self-verification. It is not a substitute for an
//! independent audit: an author shares the code's blind spots. It IS a precise,
//! reproducible statement of what the protocol claims and evidence each claim
//! holds against concrete attacks.
