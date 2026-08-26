//! The Pledge mechanic (H-series): bilateral commitment bonds.
//!
//! Two parties lock XNO into a 2-of-2 FROST joint account for a fixed term.
//! At setup — before funds move — they jointly pre-sign each party's
//! **early-exit chain**: two chained sends that (1) pay the *staying*
//! counterparty their principal **plus the leaver's penalty**, then (2)
//! return the remainder to the leaver. Leaving early needs no cooperation —
//! you broadcast your own chain and eat your penalty, compensating the
//! specific person your broken commitment harmed. Nothing pays a pool;
//! nothing needs a custodian.
//!
//! The **clean maturity split is deliberately NOT pre-signed**: before
//! maturity the only broadcastable paths are the penalty chains, so there is
//! no penalty-free early door. At maturity the parties co-sign the clean
//! split; if the counterparty has vanished, each party holds the other's
//! FROST share inside an RSW **puzzle escrow** sized (N3 margins) to become
//! solvable around maturity — solve it, reconstruct the joint key, and
//! execute the clean split unilaterally. Nano's one-block-per-frontier rule
//! makes all paths mutually exclusive: whichever chain lands first is the
//! outcome.
//!
//! Ledger honesty (H2): a received penalty is booked as
//! "counterparty early-exit compensation", never blended into yield.

#![forbid(unsafe_code)]

/// Errors from the audit-#5 safe maturity recovery path.
#[derive(Debug, PartialEq, Eq)]
pub enum MaturityError {
    Presign,
    Escrow,
    Complete,
}

pub mod bond;
pub mod selftest;
pub mod stream;
pub mod terms;
