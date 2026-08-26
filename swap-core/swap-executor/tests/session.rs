//! Full-session integration test: Alice and Bob run one atomic chunk over a
//! loopback wire + two independent mock Nano nodes + a shared mock XMR leg, and
//! both legs settle — the secret flows only through Bob's on-chain claim.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rand::rngs::OsRng;
use rand::RngCore;

use nano_ceremony::block::SignedBlock;
use nano_ceremony::broadcast::{NanoNode, ProcessResult};
use nano_ceremony::{work, Bytes32};
use swap_executor::{run_alice_with_reserve, run_bob, JointXmr, MoneroNet, XmrError, XmrParty, XmrSide};
use transport::loopback;

const TEST_THRESHOLD: u64 = 0xFF00_0000_0000_0000;
const CHUNK: u128 = 1_000;

// ---------------------------------------------------------------------------
// Shared mock XMR leg (thread-safe).
// ---------------------------------------------------------------------------

struct MockXmr {
    locked: Mutex<bool>,
    swept: Mutex<Option<Bytes32>>,
    /// Number of upcoming `sweep` calls that fail (simulates a crash mid-tail).
    fail_sweeps: Mutex<usize>,
}

impl MockXmr {
    fn new() -> Self {
        Self {
            locked: Mutex::new(false),
            swept: Mutex::new(None),
            fail_sweeps: Mutex::new(0),
        }
    }

    fn failing_sweeps(n: usize) -> Self {
        let m = Self::new();
        *m.fail_sweeps.lock().unwrap() = n;
        m
    }
}

impl XmrSide for MockXmr {
    fn lock(&self, _joint: &JointXmr, _chunk_raw: u128) -> Result<(), XmrError> {
        *self.locked.lock().unwrap() = true;
        Ok(())
    }
    fn lock_matured(&self, _joint: &JointXmr) -> Result<bool, XmrError> {
        Ok(*self.locked.lock().unwrap())
    }
    fn sweep(&self, _joint: &JointXmr, secret: &Bytes32) -> Result<(), XmrError> {
        let mut fails = self.fail_sweeps.lock().unwrap();
        if *fails > 0 {
            *fails -= 1;
            return Err(XmrError::Sweep("simulated crash".into()));
        }
        *self.swept.lock().unwrap() = Some(*secret);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Mock Nano ledger (thread-safe, one per independent node).
// ---------------------------------------------------------------------------

#[derive(Default)]
struct LedgerState {
    accounts: HashMap<Bytes32, (Bytes32, u128)>,
    blocks: HashMap<Bytes32, SignedBlock>,
}

struct MockLedger {
    state: Mutex<LedgerState>,
}

impl MockLedger {
    fn new() -> Self {
        Self {
            state: Mutex::new(LedgerState::default()),
        }
    }
}

impl NanoNode for MockLedger {
    fn process(&self, sb: &SignedBlock) -> ProcessResult {
        let hash = sb.block.hash();
        if !work::validate(&sb.block.work_root(), sb.work, TEST_THRESHOLD) {
            return ProcessResult::Rejected("insufficient work".into());
        }
        if !sb.verify_signature() {
            return ProcessResult::Rejected("bad signature".into());
        }
        let mut st = self.state.lock().unwrap();
        match st.accounts.get(&sb.block.account) {
            None => {
                if sb.block.previous != [0u8; 32] {
                    return ProcessResult::Rejected("gap".into());
                }
            }
            Some((frontier, _)) => {
                if sb.block.previous != *frontier {
                    return ProcessResult::Rejected("stale frontier".into());
                }
            }
        }
        st.accounts.insert(sb.block.account, (hash, sb.block.balance));
        st.blocks.insert(hash, sb.clone());
        ProcessResult::Accepted(hash)
    }
    fn confirmed(&self, hash: &Bytes32) -> bool {
        self.state.lock().unwrap().blocks.contains_key(hash)
    }
    fn frontier(&self, account: &Bytes32) -> Option<Bytes32> {
        self.state.lock().unwrap().accounts.get(account).map(|(f, _)| *f)
    }
    fn frontier_balance(&self, account: &Bytes32) -> Option<u128> {
        self.state.lock().unwrap().accounts.get(account).map(|(_, b)| *b)
    }
    fn block(&self, hash: &Bytes32) -> Option<SignedBlock> {
        self.state.lock().unwrap().blocks.get(hash).cloned()
    }
}

#[test]
fn alice_and_bob_complete_one_swap() {
    let node_a = Arc::new(MockLedger::new());
    let node_b = Arc::new(MockLedger::new());
    let xmr = Arc::new(MockXmr::new());

    let mut wide = [0u8; 64];
    OsRng.fill_bytes(&mut wide);
    let x = curve25519_dalek::Scalar::from_bytes_mod_order_wide(&wide).to_bytes();

    let mut ctx = [0u8; 32];
    OsRng.fill_bytes(&mut ctx);
    let mut view_a = [0u8; 32];
    let mut view_b = [0u8; 32];
    OsRng.fill_bytes(&mut view_a);
    OsRng.fill_bytes(&mut view_b);

    let alice_party = XmrParty {
        context: ctx,
        spend_secret: {
            let mut w = [0u8; 64];
            OsRng.fill_bytes(&mut w);
            curve25519_dalek::Scalar::from_bytes_mod_order_wide(&w).to_bytes()
        },
        view_contribution: view_a,
        net: MoneroNet::Stagenet,
    };
    let bob_party = XmrParty {
        context: ctx,
        spend_secret: x,
        view_contribution: view_b,
        net: MoneroNet::Stagenet,
    };

    // Expected joint spend secret (for the sweep assertion).
    let expected_joint = {
        let ap = alice_party.spend_pub();
        let bp = bob_party.spend_pub();
        let mut pubs = vec![ap, bp];
        pubs.sort();
        monero_side::cosign::reconstruct_joint_secret(
            ctx,
            &alice_party.spend_secret,
            &bob_party.spend_secret,
            &pubs,
        )
        .unwrap()
    };

    let mut bob_dest = [0u8; 32];
    OsRng.fill_bytes(&mut bob_dest);
    let open_link = [0xAA; 32];

    let (wa, wb) = loopback();

    // Checkpoint files: written at the point-of-no-return, deleted on success.
    let cp_dir = std::env::temp_dir().join(format!("xnoxmr-session-test-{}", std::process::id()));
    let bob_cp = cp_dir.join("bob.chkpt.json");
    let alice_cp = cp_dir.join("alice.chkpt.json");
    let (bob_cp_t, alice_cp_t) = (bob_cp.clone(), alice_cp.clone());
    let bob_tr = cp_dir.join("bob.transcript.jsonl");
    let alice_tr = cp_dir.join("alice.transcript.jsonl");
    let (bob_tr_t, alice_tr_t) = (bob_tr.clone(), alice_tr.clone());

    // Capture the plain-English progress both sides emit, to assert the
    // driver streams milestones (the bridge surfaces these to the browser).
    let progress: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    // Bob's thread.
    let b = {
        let node_a = node_a.clone();
        let node_b = node_b.clone();
        let xmr = xmr.clone();
        let bob_party = bob_party.clone();
        let progress = progress.clone();
        std::thread::spawn(move || {
            let nodes: Vec<&dyn NanoNode> = vec![&*node_a, &*node_b];
            run_bob(
                &wb,
                &nodes,
                &*xmr,
                CHUNK,
                &bob_party,
                bob_dest,
                open_link,
                TEST_THRESHOLD,
                2,
                5,
                Some(bob_cp_t.as_path()),
                Some(bob_tr_t.as_path()),
                &mut |m| progress.lock().unwrap().push(m.into()),
            )
            .expect("bob settles");
        })
    };

    // Alice's thread.
    let a = {
        let node_a = node_a.clone();
        let node_b = node_b.clone();
        let xmr = xmr.clone();
        let alice_party = alice_party.clone();
        let progress = progress.clone();
        std::thread::spawn(move || {
            let nodes: Vec<&dyn NanoNode> = vec![&*node_a, &*node_b];
            run_alice_with_reserve(
                &wa,
                &nodes,
                &*xmr,
                CHUNK,
                open_link,
                TEST_THRESHOLD,
                &alice_party,
                None,
                Some(alice_cp_t.as_path()),
                Some(alice_tr_t.as_path()),
                None,
                &mut |m| progress.lock().unwrap().push(m.into()),
            )
            .expect("alice settles")
        })
    };

    b.join().unwrap();
    let secret = a.join().unwrap();

    assert_eq!(secret, x, "Alice extracts exactly Bob's XMR spend secret");
    assert_eq!(
        *xmr.swept.lock().unwrap(),
        Some(expected_joint),
        "XMR swept with the reconstructed joint secret"
    );
    assert!(*xmr.locked.lock().unwrap(), "Bob locked the XMR chunk");

    // Both sides finished cleanly → their checkpoints must be gone.
    assert!(!bob_cp.exists(), "bob checkpoint removed on clean finish");
    assert!(!alice_cp.exists(), "alice checkpoint removed on clean finish");

    // R2: both transcripts chain-verify, and — the whole point — the two
    // independently computed manifests are IDENTICAL, so a third party can
    // check the parties agreed before funds moved.
    let a_events = swap_executor::transcript::verify(
        &std::fs::read_to_string(&alice_tr).expect("alice transcript written"),
    )
    .expect("alice transcript chain-verifies");
    let b_events = swap_executor::transcript::verify(
        &std::fs::read_to_string(&bob_tr).expect("bob transcript written"),
    )
    .expect("bob transcript chain-verifies");
    assert_eq!(
        a_events[0].data.get("manifest_hash"),
        b_events[0].data.get("manifest_hash"),
        "both sides computed the SAME manifest"
    );
    let a_steps: Vec<&str> = a_events.iter().map(|e| e.step.as_str()).collect();
    assert_eq!(
        a_steps,
        ["manifest", "funded", "presigned", "claim-observed", "secret-extracted", "swept"],
    );
    let b_steps: Vec<&str> = b_events.iter().map(|e| e.step.as_str()).collect();
    assert_eq!(
        b_steps,
        ["manifest", "locked", "cosigned-open", "rung-confirmed", "claim-broadcast"],
    );
    let _ = std::fs::remove_file(&alice_tr);
    let _ = std::fs::remove_file(&bob_tr);

    let msgs = progress.lock().unwrap();
    let join = msgs.join(" | ");
    assert!(join.contains("Setting up the joint account"), "progress: {join}");
    assert!(join.contains("Securing the swap"), "progress: {join}");
    assert!(join.contains("Receiving your XMR"), "progress: {join}");
}

/// A crash after the point-of-no-return resumes from the checkpoint file:
/// Alice's sweep dies mid-tail, her checkpoint survives, and `resume_alice`
/// finishes her side with NO wire and NO counterparty. Bob's resume of an
/// already-settled claim is a no-op success.
#[test]
fn crashed_tail_resumes_from_checkpoint() {
    let node_a = Arc::new(MockLedger::new());
    let node_b = Arc::new(MockLedger::new());
    // The first sweep call "crashes"; the resume's sweep succeeds.
    let xmr = Arc::new(MockXmr::failing_sweeps(1));

    let mut wide = [0u8; 64];
    OsRng.fill_bytes(&mut wide);
    let x = curve25519_dalek::Scalar::from_bytes_mod_order_wide(&wide).to_bytes();

    let mut ctx = [0u8; 32];
    OsRng.fill_bytes(&mut ctx);
    let mut view_a = [0u8; 32];
    let mut view_b = [0u8; 32];
    OsRng.fill_bytes(&mut view_a);
    OsRng.fill_bytes(&mut view_b);

    let alice_party = XmrParty {
        context: ctx,
        spend_secret: {
            let mut w = [0u8; 64];
            OsRng.fill_bytes(&mut w);
            curve25519_dalek::Scalar::from_bytes_mod_order_wide(&w).to_bytes()
        },
        view_contribution: view_a,
        net: MoneroNet::Stagenet,
    };
    let bob_party = XmrParty {
        context: ctx,
        spend_secret: x,
        view_contribution: view_b,
        net: MoneroNet::Stagenet,
    };
    let expected_joint = {
        let ap = alice_party.spend_pub();
        let bp = bob_party.spend_pub();
        let mut pubs = vec![ap, bp];
        pubs.sort();
        monero_side::cosign::reconstruct_joint_secret(
            ctx,
            &alice_party.spend_secret,
            &bob_party.spend_secret,
            &pubs,
        )
        .unwrap()
    };

    let mut bob_dest = [0u8; 32];
    OsRng.fill_bytes(&mut bob_dest);
    let open_link = [0xAA; 32];
    let (wa, wb) = loopback();

    let cp_dir = std::env::temp_dir().join(format!("xnoxmr-resume-test-{}", std::process::id()));
    let alice_cp = cp_dir.join("alice.chkpt.json");
    let alice_cp_t = alice_cp.clone();

    let b = {
        let (node_a, node_b) = (node_a.clone(), node_b.clone());
        let (xmr, bob_party) = (xmr.clone(), bob_party.clone());
        std::thread::spawn(move || {
            let nodes: Vec<&dyn NanoNode> = vec![&*node_a, &*node_b];
            run_bob(
                &wb, &nodes, &*xmr, CHUNK, &bob_party, bob_dest, open_link,
                TEST_THRESHOLD, 2, 5, None, None, &mut |_| {},
            )
            .expect("bob settles");
        })
    };
    let a = {
        let (node_a, node_b) = (node_a.clone(), node_b.clone());
        let (xmr, alice_party) = (xmr.clone(), alice_party.clone());
        std::thread::spawn(move || {
            let nodes: Vec<&dyn NanoNode> = vec![&*node_a, &*node_b];
            run_alice_with_reserve(
                &wa, &nodes, &*xmr, CHUNK, open_link, TEST_THRESHOLD, &alice_party,
                None, Some(alice_cp_t.as_path()), None, None, &mut |_| {},
            )
        })
    };

    b.join().unwrap();
    let crash = a.join().unwrap();
    assert!(crash.is_err(), "the simulated sweep crash surfaces as an error");
    assert!(alice_cp.exists(), "the checkpoint survives the crash");
    assert!(xmr.swept.lock().unwrap().is_none(), "nothing swept yet");

    // JSON round-trip is exact.
    let cp = swap_executor::AliceCheckpoint::load(&alice_cp).expect("load checkpoint");
    assert_eq!(
        swap_executor::AliceCheckpoint::from_json(&cp.to_json()).unwrap(),
        cp,
        "checkpoint JSON round-trips"
    );

    // Resume: no wire, no counterparty — just nodes + the checkpoint + her key.
    let nodes: Vec<&dyn NanoNode> = vec![&*node_a, &*node_b];
    let secret = swap_executor::resume_alice(
        &nodes, &*xmr, &alice_party.spend_secret, &cp, &mut |_| {},
    )
    .expect("alice resumes and settles");
    assert_eq!(secret, x, "resume extracts exactly Bob's revealed secret");
    assert_eq!(
        *xmr.swept.lock().unwrap(),
        Some(expected_joint),
        "resume sweeps with the reconstructed joint secret"
    );

    // Bob resuming an already-settled claim is a no-op success: his claim
    // block is on-chain, so resume returns before touching the rung/presig.
    let claim_hash = cp.claim_hash;
    let claim_signed = node_a.block(&claim_hash).expect("claim is on-chain");
    let bob_cp = swap_executor::BobCheckpoint {
        joint: cp.joint.clone(),
        rung: claim_signed.clone(), // dummies: the no-op path never reads them
        claim: claim_signed.block.clone(),
        claim_work: claim_signed.work,
        presig: cp.presig,
        chunk: CHUNK,
    };
    assert_eq!(
        swap_executor::BobCheckpoint::from_json(&bob_cp.to_json()).unwrap(),
        bob_cp,
        "bob checkpoint JSON round-trips"
    );
    swap_executor::resume_bob(&nodes, &x, &bob_cp, 2, 5, &mut |_| {})
        .expect("bob's resume of a settled claim is a no-op success");

    let _ = std::fs::remove_file(&alice_cp);
}
