//! Block 5 of the build order: the I1 refund backstop.
//!
//! Each party escrows *their own* key share in RSW time-lock puzzles over RSA
//! moduli *they generate themselves* — a weak modulus only speeds up the
//! counterparty's solve, hurting the generator alone, so setup is
//! incentive-aligned without any trusted party.
//!
//! Verifiability is cut-and-choose with algebraic binding (the construction
//! validated by `verify_core.py` S10):
//!
//! - The escrower produces `m` instances; instance `i` holds a random scalar
//!   `r_i` inside a puzzle, plus public `R_i = r_i·G` and `d_i = r_i + k mod ℓ`
//!   (where `k` is the escrowed share, `K = k·G` its public key).
//! - The verifier opens a random half: the escrower reveals `r_i` *and the
//!   modulus factors* for those instances (per-instance moduli, so opening
//!   audited puzzles never weakens kept ones), letting the verifier confirm
//!   in milliseconds that each audited puzzle honestly hides its `r_i`.
//! - Kept instances are checked purely algebraically: `d_i·G == R_i + K`.
//!   A cheating escrower must guess the audit subset exactly — probability
//!   `1 / C(m, m/2)`.
//! - To recover after a disappearance, the counterparty solves ONE kept
//!   puzzle by sequential squaring (`T` steps, inherently serial) and gets
//!   `k = d_i − r_i`, verified against `K`.
//!
//! Invariants enforced from the design record:
//! - **S10**: every modulus must exceed the curve order, or the escrowed
//!   share silently truncates — rejected at verification, asserted at
//!   creation.
//! - **N3**: the horizon rule `deadline < T_target / (2·S_max)` holds
//!   *strictly*; boundary equality fails.

#![forbid(unsafe_code)]

pub mod escrow;
pub mod horizon;
pub mod puzzle;
