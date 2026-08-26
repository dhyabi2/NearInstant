//! `XmrSide` implementations.
//!
//! - [`DryRun`]: the safe default — logs every action, moves nothing. Used by
//!   the `swapper` binary until the operator points it at a funded wallet.
//! - The real Monero implementation (lock a chunk to the joint account via
//!   `SignableTransaction`, then sweep it with the extracted secret — the
//!   `sweep_joint` example path) is the one remaining fund-dependent piece; it
//!   requires a funded mainnet/stagenet wallet and must be exercised under
//!   supervision, so it is NOT shipped as an auto-run path.

use nano_ceremony::Bytes32;

use crate::driver::{XmrError, XmrSide};
use crate::monero::JointXmr;

#[cfg(feature = "monero")]
pub mod monero_leg;

#[cfg(feature = "monero")]
pub use monero_leg::MoneroLeg;

/// A Monero leg that logs instead of moving funds. Always matured, never
/// sweeps real value. The `--live` gate refuses to substitute this out.
pub struct DryRun;

impl XmrSide for DryRun {
    fn lock(&self, joint: &JointXmr, chunk_raw: u128) -> Result<(), XmrError> {
        eprintln!(
            "[xmr:dry-run] lock {chunk_raw} raw → joint {} (no value moved)",
            joint.address
        );
        Ok(())
    }

    fn lock_matured(&self, _joint: &JointXmr) -> Result<bool, XmrError> {
        Ok(true)
    }

    fn sweep(&self, joint: &JointXmr, secret: &Bytes32) -> Result<(), XmrError> {
        eprintln!(
            "[xmr:dry-run] sweep {} with secret {} (no value moved)",
            joint.address,
            hex::encode(secret)
        );
        Ok(())
    }
}
