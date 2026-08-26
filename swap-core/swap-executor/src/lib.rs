//! `swap-executor` — the settlement driver (P0 items #13/#14/#15/#17).
//!
//! The cryptographic primitives (joint FROST key, adaptor pre-signature, the
//! I3 guard ladder, CLSAG sweep) are proven in `signing`/`nano-ceremony`/
//! `monero-side`; the multi-node confirmation gates (C1/C2/H3) are proven in
//! `nano-ceremony::broadcast`. This crate is the missing glue: the *driver*
//! that sequences a real chunk settlement through those gates in the correct,
//! race-safe order for each role, over a [`NanoNode`] set and a [`XmrSide`]
//! hook.
//!
//! - [`bob_settle_chunk`]: confirm the guard rung on ≥`quorum` independent
//!   nodes FIRST, and only then complete (revealing the swap secret) and
//!   broadcast the claim via the guarded [`broadcast_secret_claim`] send.
//! - [`alice_settle_chunk`]: extract the secret from Bob's broadcast claim and
//!   sweep the locked XMR.
//!
//! The driver is transport/chain-agnostic: pass real `RpcNode`s + a real
//! `monero_side::rpc::Node` for mainnet, or mocks for tests. It moves real
//! value only when the caller hands it a live node set and funded material —
//! the driver itself never fabricates or gates funds.

pub mod checkpoint;
pub mod driver;
pub mod monero;
pub mod session;
pub mod transcript;
pub mod xmr;
pub mod bridge;

pub use checkpoint::{resume_alice, resume_bob, AliceCheckpoint, BobCheckpoint, CheckpointError};
pub use driver::{alice_settle_chunk, bob_settle_chunk, DriverError, XmrError, XmrSide};
pub use monero::{JointError, JointXmr, MoneroNet};
pub use session::{run_alice, run_alice_with_reserve, run_bob, ReserveProof, SessionError, XmrParty};
pub use transcript::{SwapManifest, Transcript, TranscriptError};
pub use xmr::DryRun;

#[cfg(feature = "monero")]
pub use xmr::MoneroLeg;

pub use bridge::handle_rpc;
