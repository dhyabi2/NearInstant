//! The full two-party swap session: Alice (XNO seller) and Bob (XMR seller)
//! run one atomic chunk end-to-end over a byte wire, real nodes, and a real
//! Monero leg — the "real client swap execution" (P0 #13) and the maker-side
//! completion (P0 #14) in one place.
//!
//! Flow (both parties in lockstep, one chunk):
//! 1. Distributed 2-of-2 keygen over the wire (no trusted dealer) — the Nano
//!    joint account.
//! 2. Exchange Monero spend-pub + view contributions; derive the joint Monero
//!    account (MuSig spend key + shared view key).
//! 3. The Nano claim's adaptor point IS Bob's Monero spend public key
//!    (`T = x·G`, `x` = Bob's spend secret): Bob settles the Nano leg → reveals
//!    `x` → Alice reconstructs the joint Monero spend secret and sweeps.
//! 4. Bob locks XMR to the joint address and waits for maturity.
//! 5. Alice funds the joint Nano account (joint-signed open) and broadcasts it.
//! 6. Guard rung (joint-signed) + claim (adaptor-pre-signed against `T`).
//! 7. Bob confirms the rung on a multi-node quorum, then completes + broadcasts
//!    the claim — revealing `x` on-chain.
//! 8. Alice reads the claim off-chain, extracts `x`, reconstructs the joint
//!    Monero spend secret, and sweeps the locked XMR.

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};

use nano_ceremony::block::{SignedBlock, StateBlock, Subtype};
use nano_ceremony::broadcast::{any_accepted, saturation_broadcast, NanoNode};
use nano_ceremony::{work, Bytes32};
use signing::{keys, Identifier};
use transport::ceremonies::{adaptor_presign_over_wire, keygen_over_wire, sign_block_over_wire};
use transport::{recv_frame, send_frame, tag, Wire};

use crate::driver::{alice_settle_chunk, bob_settle_chunk, XmrSide};
use crate::monero::{JointXmr, MoneroNet};

/// Role identifiers for the 2-of-2 DKG.
pub const ALICE_ID: u16 = 1;
pub const BOB_ID: u16 = 2;

/// One party's Monero key material for the joint account.
#[derive(Clone, Debug)]
pub struct XmrParty {
    /// Session context (domain separation).
    pub context: Bytes32,
    /// This party's XMR spend secret.
    pub spend_secret: Bytes32,
    /// This party's view-key contribution.
    pub view_contribution: Bytes32,
    /// Network (address encoding).
    pub net: MoneroNet,
}

impl XmrParty {
    /// This party's XMR spend public key (`spend_secret·G`).
    pub fn spend_pub(&self) -> Bytes32 {
        (&Scalar::from_bytes_mod_order(self.spend_secret) * ED25519_BASEPOINT_TABLE)
            .compress()
            .to_bytes()
    }
}

/// The maker's Monero reserve proof the taker verifies at take time — the
/// XMR-leg proof-of-funds gate. `message` is the exact string the maker's
/// wallet signed in `get_reserve_proof` (the order hash); `amount` is the
/// claimed reserve in piconero; `proof` is the opaque reserve-proof signature.
#[derive(Clone, Debug)]
pub struct ReserveProof {
    pub address: String,
    pub amount: u128,
    pub message: String,
    pub proof: String,
}

/// Errors from the session.
#[derive(Debug)]
pub enum SessionError {
    /// Wire/ceremony failure.
    Wire(transport::WireError),
    /// A joint-key/ceremony step failed.
    Ceremony,
    /// A block failed to be accepted by any node.
    NotAccepted,
    /// The settlement driver failed.
    Driver(crate::driver::DriverError),
    /// The maker's reserve proof failed the take-time check (not `good`, or the
    /// unspent reserve is below the claimed amount).
    InsufficientReserve,
    /// The taker configured a reserve check but it could not be completed.
    ReserveCheck(crate::driver::XmrError),
}

impl From<transport::WireError> for SessionError {
    fn from(e: transport::WireError) -> Self {
        SessionError::Wire(e)
    }
}

/// The joint account public key (verifying key) as Nano account bytes.
fn account_of(pubkeys: &keys::PublicKeyPackage) -> Bytes32 {
    pubkeys
        .verifying_key()
        .serialize()
        .expect("serialize vk")
        .try_into()
        .expect("32 bytes")
}

/// The claim block: after the guard rung, send the whole balance to `bob_dest`.
fn claim_block(account: Bytes32, rung_hash: Bytes32, bob_dest: Bytes32) -> StateBlock {
    StateBlock {
        account,
        previous: rung_hash,
        representative: account,
        balance: 0,
        link: bob_dest,
        subtype: Subtype::Send,
    }
}

/// Symmetric exchange: send this party's (spend_pub, view_contribution),
/// receive the counterparty's. Both parties call this; each ends with the
/// other's two 32-byte contributions.
fn exchange_xmr_contrib(
    wire: &impl Wire,
    me: &XmrParty,
) -> Result<(Bytes32, Bytes32), SessionError> {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&me.spend_pub());
    payload.extend_from_slice(&me.view_contribution);
    send_frame(wire, tag::XMR_CONTRIB, &payload)?;
    let theirs = recv_frame(wire, tag::XMR_CONTRIB)?;
    let their_spend_pub: Bytes32 = theirs[..32].try_into().map_err(|_| SessionError::Ceremony)?;
    let their_view: Bytes32 = theirs[32..64].try_into().map_err(|_| SessionError::Ceremony)?;
    Ok((their_spend_pub, their_view))
}

/// Alice's side. `open_link` is the pending-send hash the funding transaction
/// created (the operator's send into the joint account). After Bob settles,
/// Alice polls the nodes for the claim and sweeps the locked XMR.
#[allow(clippy::too_many_arguments)]
pub fn run_alice(
    wire: &impl Wire,
    nodes: &[&dyn NanoNode],
    xmr: &dyn XmrSide,
    chunk: u128,
    open_link: Bytes32,
    work_threshold: u64,
    me: &XmrParty,
) -> Result<Bytes32, SessionError> {
    run_alice_with_reserve(wire, nodes, xmr, chunk, open_link, work_threshold, me, None, None, None, None, &mut |_| {})
}

/// Alice's side with an optional maker reserve proof. When `reserve` is provided,
/// it is verified against the XMR side's wallet BEFORE any funds move: `good`
/// must hold and `available() >= amount`, else the swap aborts as
/// [`SessionError::InsufficientReserve`]. When this side cannot check (dry-run,
/// mock, no wallet), the reserve is treated as *unverified* — a no-op — never a
/// false pass.
#[allow(clippy::too_many_arguments)]
pub fn run_alice_with_reserve(
    wire: &impl Wire,
    nodes: &[&dyn NanoNode],
    xmr: &dyn XmrSide,
    chunk: u128,
    open_link: Bytes32,
    work_threshold: u64,
    me: &XmrParty,
    reserve: Option<&ReserveProof>,
    checkpoint: Option<&std::path::Path>,
    transcript: Option<&std::path::Path>,
    funder: Option<&mut dyn FnMut(&Bytes32) -> Option<Bytes32>>,
    progress: &mut dyn FnMut(&str),
) -> Result<Bytes32, SessionError> {
    // 0. Take-time XMR reserve check (reputation/pre-screen; the on-chain lock
    //    is the real safety boundary). Runs before any funds move.
    progress("Checking the maker's funds…");
    if let Some(rp) = reserve {
        verify_reserve(xmr, rp)?;
    }

    // 1. Nano keygen.
    progress("Setting up the joint account…");
    let (kp, pubkeys) = keygen_over_wire(
        wire,
        Identifier::try_from(ALICE_ID).unwrap(),
        Identifier::try_from(BOB_ID).unwrap(),
    )?;
    let account = account_of(&pubkeys);

    // 2. Exchange Monero contributions + derive the joint Monero account.
    let (bob_spend_pub, bob_view) = exchange_xmr_contrib(wire, me)?;
    let joint = JointXmr::derive(
        me.context,
        vec![me.spend_pub(), bob_spend_pub],
        &me.view_contribution,
        &bob_view,
        me.net,
    )
    .map_err(|_| SessionError::Ceremony)?;

    // 3. Receive Bob's Nano destination (where the XNO leg pays).
    let bob_dest = recv_frame(wire, tag::BOB_DEST)?;
    let bob_dest: Bytes32 = bob_dest[..32].try_into().map_err(|_| SessionError::Ceremony)?;

    // 3b. The joint account only exists NOW (post-DKG), so this is the first
    // moment Alice can fund it. A funder callback sends the chunk into the
    // account and returns the pending-send hash; without one, the operator
    // pre-funded and passed --open-link. Either way Bob learns the hash over
    // the wire — he cannot know it in advance.
    let open_link = match funder {
        Some(f) => {
            progress("Funding the joint account…");
            f(&account).ok_or(SessionError::Ceremony)?
        }
        None => open_link,
    };
    send_frame(wire, tag::OPEN_LINK, &open_link)?;

    // 4. Fund the joint Nano account.
    progress("Sending your XNO into the swap…");
    let open = StateBlock {
        account,
        previous: [0u8; 32],
        representative: account,
        balance: chunk,
        link: open_link,
        subtype: Subtype::Open,
    };
    let open_sig = sign_block_over_wire(wire, &open, &kp, &pubkeys)?;
    let open_signed = SignedBlock {
        block: open.clone(),
        signature: open_sig,
        work: work::generate(&open.work_root(), work_threshold, 0),
    };
    if !any_accepted(&saturation_broadcast(nodes, &open_signed)) {
        return Err(SessionError::NotAccepted);
    }

    // 5. Guard rung + claim (adaptor point = Bob's Monero spend pub).
    progress("Securing the swap…");
    let rung = StateBlock::change(account, open.hash(), account, chunk);
    let rung_sig = sign_block_over_wire(wire, &rung, &kp, &pubkeys)?;
    let _ = SignedBlock {
        block: rung.clone(),
        signature: rung_sig,
        work: work::generate(&rung.work_root(), work_threshold, 0),
    };
    let claim = claim_block(account, rung.hash(), bob_dest);
    let presig = adaptor_presign_over_wire(wire, &claim, &bob_spend_pub, &kp, &pubkeys)?;
    let claim_hash = claim.hash();

    // R2: the manifest + hash-chained transcript (public evidence; a failed
    // write never aborts a live settlement).
    let mut log = transcript.and_then(|p| {
        let m = crate::transcript::SwapManifest {
            version: 1,
            nano_account: account,
            xmr_address: joint.address.clone(),
            chunk,
            adaptor_point: bob_spend_pub,
            bob_dest,
            open_link,
            rung_hash: rung.hash(),
            claim_hash,
        };
        crate::transcript::Transcript::start(p, &m).ok()
    });
    if let Some(t) = log.as_mut() {
        let _ = t.record("funded", serde_json::json!({ "open_hash": hex::encode(open.hash()) }));
        let _ = t.record("presigned", serde_json::json!({
            "r_adapted": hex::encode(presig.r_adapted),
            "adaptor_point": hex::encode(presig.adaptor_point),
        }));
    }

    // From here Alice needs no counterparty: persist everything her tail
    // needs, so a crash resumes via `checkpoint::resume_alice` (no deadline —
    // the claim signature is permanent on-chain).
    if let Some(path) = checkpoint {
        let cp = crate::checkpoint::AliceCheckpoint {
            joint: joint.clone(),
            presig,
            claim_hash,
            chunk,
        };
        if cp.save(path).is_err() {
            progress("Warning: could not write the recovery checkpoint");
        }
    }

    // 5b. Receive the lock's block height from Bob (sent once his XMR matured),
    // so the sweep scans a tight window rather than hundreds of blocks.
    if let Ok(frame) = recv_frame(wire, tag::LOCK_HEIGHT) {
        if let Ok(bytes) = <[u8; 8]>::try_from(&frame[..8.min(frame.len())]) {
            let h = u64::from_le_bytes(bytes) as usize;
            if h > 0 {
                xmr.set_lock_height(h);
            }
        }
    }

    // 6. Read the revealed secret off the settled claim, reconstruct the joint
    //    Monero spend secret, and sweep.
    progress("Waiting for the maker to settle…");
    let claim_sig = wait_for_claim(nodes, &claim_hash)
        .ok_or(SessionError::Driver(crate::driver::DriverError::ClaimRejected))?;
    if let Some(t) = log.as_mut() {
        let _ = t.record("claim-observed", serde_json::json!({
            "claim_hash": hex::encode(claim_hash),
            "signature": hex::encode(claim_sig),
        }));
    }
    progress("Receiving your XMR…");
    let secret = alice_settle_chunk(xmr, &joint, &me.spend_secret, &presig, &claim_sig)
        .map_err(SessionError::Driver)?;
    if let Some(t) = log.as_mut() {
        // `x` is public knowledge the moment the claim broadcast — recording
        // it here is evidence, not a leak.
        let _ = t.record("secret-extracted", serde_json::json!({ "x": hex::encode(secret) }));
        let _ = t.record("swept", serde_json::json!({ "xmr_address": joint.address }));
    }
    if let Some(path) = checkpoint {
        let _ = std::fs::remove_file(path);
    }
    Ok(secret)
}

/// Bob's side. `bob` is his Monero key material (his spend secret IS the swap
/// secret `x`); `bob_dest` is the Nano account he receives the XNO into.
#[allow(clippy::too_many_arguments)]
pub fn run_bob(
    wire: &impl Wire,
    nodes: &[&dyn NanoNode],
    xmr: &dyn XmrSide,
    chunk: u128,
    bob: &XmrParty,
    bob_dest: Bytes32,
    _open_link: Bytes32,
    work_threshold: u64,
    quorum: usize,
    attempts: usize,
    checkpoint: Option<&std::path::Path>,
    transcript: Option<&std::path::Path>,
    progress: &mut dyn FnMut(&str),
) -> Result<(), SessionError> {
    // 1. Nano keygen.
    progress("Setting up the joint account…");
    let (kp, pubkeys) = keygen_over_wire(
        wire,
        Identifier::try_from(BOB_ID).unwrap(),
        Identifier::try_from(ALICE_ID).unwrap(),
    )?;
    let account = account_of(&pubkeys);

    // 2. Exchange Monero contributions + derive the joint Monero account.
    let (alice_spend_pub, alice_view) = exchange_xmr_contrib(wire, bob)?;
    let joint = JointXmr::derive(
        bob.context,
        vec![alice_spend_pub, bob.spend_pub()],
        &alice_view,
        &bob.view_contribution,
        bob.net,
    )
    .map_err(|_| SessionError::Ceremony)?;

    // 3. Send Bob's Nano destination to Alice.
    send_frame(wire, tag::BOB_DEST, &bob_dest)?;

    // 3b. Receive the funding hash — Alice funds the joint account only after
    // the DKG creates it, so the authoritative open_link arrives on the wire
    // (any pre-agreed CLI value is superseded).
    let open_link_frame = recv_frame(wire, tag::OPEN_LINK)?;
    let open_link: Bytes32 =
        open_link_frame[..32].try_into().map_err(|_| SessionError::Ceremony)?;

    // 4. Lock the XMR chunk to the joint account and wait for maturity.
    progress("Locking your XMR…");
    xmr.lock(&joint, chunk).map_err(|_| SessionError::Ceremony)?;
    loop {
        if xmr.lock_matured(&joint).map_err(|_| SessionError::Ceremony)? {
            break;
        }
        // Monero maturity is 10 blocks (~20 min); poll at a sane cadence.
        std::thread::sleep(std::time::Duration::from_secs(5));
    }

    // 5. Co-sign Alice's funding open block.
    let open = StateBlock {
        account,
        previous: [0u8; 32],
        representative: account,
        balance: chunk,
        link: open_link,
        subtype: Subtype::Open,
    };
    let _ = sign_block_over_wire(wire, &open, &kp, &pubkeys)?;

    // 6. Guard rung + claim (adaptor point = Bob's spend pub = x·G).
    progress("Securing the swap…");
    let rung = StateBlock::change(account, open.hash(), account, chunk);
    let rung_sig = sign_block_over_wire(wire, &rung, &kp, &pubkeys)?;
    let rung_signed = SignedBlock {
        block: rung.clone(),
        signature: rung_sig,
        work: work::generate(&rung.work_root(), work_threshold, 0),
    };
    let claim = claim_block(account, rung.hash(), bob_dest);
    let presig = adaptor_presign_over_wire(wire, &claim, &bob.spend_pub(), &kp, &pubkeys)?;

    // 6b. Tell Alice the lock's block height (known since maturity in step 4)
    // so her sweep scans a tight window. Sent here — after the pre-sign — so it
    // lands in the wire stream exactly where Alice reads it (step 5b).
    let lock_h = xmr.lock_height().unwrap_or(0) as u64;
    send_frame(wire, tag::LOCK_HEIGHT, &lock_h.to_le_bytes())?;

    // 7. Confirm rung, then complete + broadcast the claim (reveals x).
    progress("Confirming and settling…");
    let claim_work = work::generate(&claim.work_root(), work_threshold, 0);
    let claim_hash = claim.hash();

    // R2: manifest + transcript (Bob's mirror — a third party can check the
    // two sides' manifest hashes are IDENTICAL).
    let mut log = transcript.and_then(|p| {
        let m = crate::transcript::SwapManifest {
            version: 1,
            nano_account: account,
            xmr_address: joint.address.clone(),
            chunk,
            adaptor_point: bob.spend_pub(),
            bob_dest,
            open_link,
            rung_hash: rung.hash(),
            claim_hash,
        };
        crate::transcript::Transcript::start(p, &m).ok()
    });
    if let Some(t) = log.as_mut() {
        let _ = t.record("locked", serde_json::json!({ "xmr_address": joint.address, "chunk": chunk.to_string() }));
        let _ = t.record("cosigned-open", serde_json::json!({ "open_hash": hex::encode(open.hash()) }));
    }

    // From here Bob needs no counterparty: persist everything the settle
    // needs, so a crash resumes via `checkpoint::resume_bob` (idempotent —
    // a claim already on-chain resumes as a no-op success).
    if let Some(path) = checkpoint {
        let cp = crate::checkpoint::BobCheckpoint {
            joint: joint.clone(),
            rung: rung_signed.clone(),
            claim: claim.clone(),
            claim_work,
            presig,
            chunk,
        };
        if cp.save(path).is_err() {
            progress("Warning: could not write the recovery checkpoint");
        }
    }

    bob_settle_chunk(
        nodes,
        &rung_signed,
        &presig,
        &bob.spend_secret,
        &claim,
        claim_work,
        quorum,
        attempts,
        &mut || std::thread::sleep(std::time::Duration::from_secs(1)),
    )
    .map_err(SessionError::Driver)?;
    if let Some(t) = log.as_mut() {
        let _ = t.record("rung-confirmed", serde_json::json!({ "rung_hash": hex::encode(rung_signed.block.hash()) }));
        let _ = t.record("claim-broadcast", serde_json::json!({ "claim_hash": hex::encode(claim_hash) }));
    }
    if let Some(path) = checkpoint {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

/// The take-time XMR reserve gate. `Ok(())` = the maker is verified, or this
/// side cannot check (dry-run/mock/no wallet → treated as unverified, a no-op,
/// never a false pass). `Err` = insufficient reserve or a failed check.
fn verify_reserve(xmr: &dyn XmrSide, rp: &ReserveProof) -> Result<(), SessionError> {
    match xmr
        .check_reserve(&rp.address, &rp.message, &rp.proof)
        .map_err(SessionError::ReserveCheck)?
    {
        Some(status) if !status.good || status.available() < rp.amount => {
            Err(SessionError::InsufficientReserve)
        }
        _ => Ok(()),
    }
}

/// Poll the nodes for the claim block until one returns its signature. Waits
/// long enough for the counterparty's XMR lock to mature (~20 min) plus the
/// Nano settlement, then gives up.
pub(crate) fn wait_for_claim(nodes: &[&dyn NanoNode], claim_hash: &Bytes32) -> Option<[u8; 64]> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45 * 60);
    while std::time::Instant::now() < deadline {
        for node in nodes {
            if let Some(blk) = node.block(claim_hash) {
                return Some(blk.signature);
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{ReserveStatus, XmrError};

    /// A mock XMR side whose `check_reserve` returns a fixed, configurable result.
    struct ReserveMock(Option<Result<Option<ReserveStatus>, XmrError>>);

    impl XmrSide for ReserveMock {
        fn lock(&self, _: &JointXmr, _: u128) -> Result<(), XmrError> {
            Ok(())
        }
        fn lock_matured(&self, _: &JointXmr) -> Result<bool, XmrError> {
            Ok(true)
        }
        fn sweep(&self, _: &JointXmr, _: &Bytes32) -> Result<(), XmrError> {
            Ok(())
        }
        fn check_reserve(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<Option<ReserveStatus>, XmrError> {
            self.0.clone().unwrap_or(Ok(None))
        }
    }

    fn rp(amount: u128) -> ReserveProof {
        ReserveProof {
            address: "4addr".into(),
            amount,
            message: "order-hash".into(),
            proof: "ReserveProofV1...".into(),
        }
    }

    #[test]
    fn reserve_gate_passes_when_good_and_sufficient() {
        let funded = ReserveMock(Some(Ok(Some(ReserveStatus {
            good: true,
            spent: 0,
            total: 1_000,
        }))));
        assert!(verify_reserve(&funded, &rp(1_000)).is_ok());
    }

    #[test]
    fn reserve_gate_rejects_insufficient() {
        let broke = ReserveMock(Some(Ok(Some(ReserveStatus {
            good: true,
            spent: 0,
            total: 999,
        }))));
        assert!(matches!(
            verify_reserve(&broke, &rp(1_000)),
            Err(SessionError::InsufficientReserve)
        ));

        // good=false is also rejected even with a huge total.
        let not_good = ReserveMock(Some(Ok(Some(ReserveStatus {
            good: false,
            spent: 0,
            total: 9_999_999,
        }))));
        assert!(matches!(
            verify_reserve(&not_good, &rp(1_000)),
            Err(SessionError::InsufficientReserve)
        ));
    }

    #[test]
    fn reserve_gate_spent_amount_reduces_available() {
        // spent 900 of 1_000 leaves 100 < 1_000 → rejected.
        let spent = ReserveMock(Some(Ok(Some(ReserveStatus {
            good: true,
            spent: 900,
            total: 1_000,
        }))));
        assert!(matches!(
            verify_reserve(&spent, &rp(1_000)),
            Err(SessionError::InsufficientReserve)
        ));
    }

    #[test]
    fn reserve_gate_no_wallet_is_a_noop_not_a_fail() {
        let no_wallet = ReserveMock(Some(Ok(None)));
        assert!(verify_reserve(&no_wallet, &rp(1_000)).is_ok());
    }

    #[test]
    fn reserve_gate_check_failure_is_fail_closed() {
        let broken = ReserveMock(Some(Err(XmrError::Lock("wallet down".into()))));
        assert!(matches!(
            verify_reserve(&broken, &rp(1_000)),
            Err(SessionError::ReserveCheck(XmrError::Lock(_)))
        ));
    }
}
