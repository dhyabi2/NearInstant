//! The settlement driver: the correct, race-safe ordering of a chunk settle.

use nano_ceremony::block::{SignedBlock, StateBlock};
use nano_ceremony::broadcast::{self, NanoNode};
use nano_ceremony::Bytes32;
use signing::adaptor::{complete_presignature, extract_secret, PreSignature};

use crate::monero::JointXmr;

/// The Monero leg of a chunk. Abstracted behind a trait so the driver runs
/// identically against a real public node / wallet (`MoneroLeg`) or an
/// in-process double. All methods move real value only when the concrete
/// implementation points at a live chain.
pub trait XmrSide {
    /// Bob locks the XMR chunk to the joint account (the driver waits for it to
    /// reach the 10-block maturity before Alice may pre-sign).
    fn lock(&self, joint: &JointXmr, chunk_raw: u128) -> Result<(), XmrError>;
    /// Whether the lock is now mature (≥ 10 confirmations).
    fn lock_matured(&self, joint: &JointXmr) -> Result<bool, XmrError>;
    /// Alice sweeps the joint output using the reconstructed joint spend secret.
    fn sweep(&self, joint: &JointXmr, joint_spend_secret: &Bytes32) -> Result<(), XmrError>;

    /// Authoritatively verify a maker's Monero reserve proof
    /// (`check_reserve_proof`) against this side's wallet-rpc.
    ///
    /// Returns `Ok(None)` when this side has no wallet to check with (dry-run,
    /// mock, or a taker without a wallet-rpc) — the caller must then treat the
    /// reserve as *unverified*, not pass it. `Ok(Some(status))` is the
    /// authoritative result; the caller gates on `good && available() >= amount`.
    ///
    /// This is the take-time XMR proof-of-funds gate. It is a pre-screening /
    /// reputation check, NOT a safety boundary: even a lying maker cannot take
    /// Alice's XNO without the on-chain lock, which is enforced by `lock`.
    fn check_reserve(
        &self,
        _address: &str,
        _message: &str,
        _signature: &str,
    ) -> Result<Option<ReserveStatus>, XmrError> {
        Ok(None)
    }

    /// The wallet's primary receive address, if this side has a wallet attached
    /// (via wallet-rpc). The browser shows this so the user can fund it: the
    /// coins still come from OUTSIDE — an exchange or another wallet — never
    /// from the helper itself.
    fn xmr_address(&self) -> Result<Option<String>, XmrError> {
        Ok(None)
    }

    /// The wallet's total unlocked balance in piconero, if a wallet is attached.
    fn xmr_balance(&self) -> Result<Option<u128>, XmrError> {
        Ok(None)
    }

    /// The Monero block height of the matured lock, if this side knows it (the
    /// maker learns it from its own lock tx). The maker sends this to the taker
    /// so the taker's sweep scans a tight window. `None` if unknown.
    fn lock_height(&self) -> Option<usize> {
        None
    }

    /// Tell this side the lock's block height (the taker receives it from the
    /// maker over the wire). No-op for sides that don't scan (mock/dry-run).
    fn set_lock_height(&self, _height: usize) {}
}

/// The outcome of `check_reserve_proof` — the authoritative "does the maker
/// actually hold ≥ amount of XMR" signal, run by the taker at take time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReserveStatus {
    /// `check_reserve_proof` returned `good == true`.
    pub good: bool,
    /// Amount (piconero) of the proven reserve that has been spent.
    pub spent: u128,
    /// Total reserve amount (piconero) the proof attests.
    pub total: u128,
}

impl ReserveStatus {
    /// The unspent reserve the maker still holds — compare against the order's
    /// amount (and worst-case one-chunk loss) before settling.
    pub fn available(&self) -> u128 {
        self.total.saturating_sub(self.spent)
    }
}

/// Errors from the Monero leg.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum XmrError {
    Lock(String),
    Maturity(String),
    Sweep(String),
}

/// Errors from the settlement driver.
#[derive(Debug, PartialEq, Eq)]
pub enum DriverError {
    /// The guard rung could not be CONFIRMED on the quorum — the driver refuses
    /// to reveal the secret (fail-closed, audit #1 / C1 / H3).
    Confirm(&'static str),
    /// The adaptor claim could not be completed with the secret.
    Complete,
    /// The completed claim was not accepted by any node.
    ClaimRejected,
    /// The secret could not be extracted from the broadcast signature.
    Extract,
    /// The Monero sweep failed.
    Sweep,
}

/// Bob settles one chunk: confirm the guard rung, then reveal-and-broadcast.
///
/// Safety property (the whole point of the driver): the swap secret `x` is
/// released ONLY after the guard rung is cemented on at least `quorum`
/// independent nodes. The rung's frontier advance invalidates every
/// stale-frontier signature, so once it is confirmed, Bob's claim is the sole
/// path — and completing it reveals `x` to Alice, which is exactly the hinge
/// the atomic swap relies on. If the rung cannot be confirmed within `attempts`
/// polls, this returns an error WITHOUT revealing the secret.
///
/// `rung` and `claim` carry their own work (computed ahead per N4); the claim's
/// signature is produced here from `presig` + `secret`. `poll` is a no-op sleep
/// callback the caller supplies so confirmation polling yields.
#[allow(clippy::too_many_arguments)]
pub fn bob_settle_chunk(
    nodes: &[&dyn NanoNode],
    rung: &SignedBlock,
    presig: &PreSignature,
    secret: &Bytes32,
    claim: &StateBlock,
    claim_work: u64,
    quorum: usize,
    attempts: usize,
    poll: &mut dyn FnMut(),
) -> Result<[u8; 64], DriverError> {
    // 1. CONFIRM BEFORE REVEAL: cement the guard rung first. This also
    //    broadcasts it (saturation) and waits for `quorum` of the ACCEPTING
    //    nodes to report it confirmed — never one lying node, never mere
    //    acceptance (C1/H3). On failure we return without ever completing the
    //    claim, so the secret stays private.
    broadcast::broadcast_and_confirm(nodes, rung, quorum, attempts, poll).map_err(DriverError::Confirm)?;

    // 2. Complete the claim — this is the secret-revealing step — and broadcast
    //    it with the guarded send (withheld from any node whose frontier has
    //    already moved, C2).
    let signature = complete_presignature(presig, secret).map_err(|_| DriverError::Complete)?;
    let claim_signed = SignedBlock {
        block: claim.clone(),
        signature,
        work: claim_work,
    };
    let results = broadcast::broadcast_secret_claim(nodes, &claim_signed);
    if !broadcast::any_accepted(&results) {
        return Err(DriverError::ClaimRejected);
    }
    Ok(signature)
}

/// Alice settles one chunk: extract the secret from Bob's broadcast claim,
/// reconstruct the joint Monero spend secret, and sweep. Returns the secret
/// Bob revealed on-chain (his XMR spend secret).
pub fn alice_settle_chunk(
    xmr: &dyn XmrSide,
    joint: &JointXmr,
    alice_spend_secret: &Bytes32,
    presig: &PreSignature,
    claim_signature: &[u8; 64],
) -> Result<Bytes32, DriverError> {
    let x = extract_secret(presig, claim_signature).map_err(|_| DriverError::Extract)?;
    // x = Bob's XMR spend secret; combine with Alice's share via the MuSig
    // bindings to recover the joint spend secret, then sweep with it.
    let joint_secret = monero_side::cosign::reconstruct_joint_secret(
        joint.context,
        alice_spend_secret,
        &x,
        &joint.spend_pubs,
    )
    .map_err(|_| DriverError::Sweep)?;
    xmr.sweep(joint, &joint_secret).map_err(|_| DriverError::Sweep)?;
    Ok(x)
}
