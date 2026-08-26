//! Settlement-driver integration test: a full chunk settled by Bob (guard rung
//! confirmed on 2 independent nodes, then secret-revealing claim) and by Alice
//! (secret extraction + XMR sweep) — the P0 items #13/#15/#17 exercised over
//! real cryptography and a frontier-enforcing mock ledger.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

use rand::rngs::OsRng;
use rand::RngCore;

use nano_ceremony::block::{SignedBlock, StateBlock, Subtype};
use nano_ceremony::broadcast::{saturation_broadcast, NanoNode, ProcessResult};
use nano_ceremony::{ceremony, work, Bytes32};
use signing::adaptor::{complete_presignature, extract_secret};
use signing::{keys, round1, Identifier};
use swap_executor::{alice_settle_chunk, bob_settle_chunk, JointXmr, MoneroNet, XmrError, XmrSide};

const TEST_THRESHOLD: u64 = 0xFF00_0000_0000_0000;
const CHUNK: u128 = 1_000;

// ---------------------------------------------------------------------------
// Mock Monero leg (records the sweep).
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockXmr {
    locked: RefCell<bool>,
    swept: RefCell<Option<Bytes32>>,
}

impl XmrSide for MockXmr {
    fn lock(&self, _joint: &JointXmr, _chunk_raw: u128) -> Result<(), XmrError> {
        *self.locked.borrow_mut() = true;
        Ok(())
    }
    fn lock_matured(&self, _joint: &JointXmr) -> Result<bool, XmrError> {
        Ok(*self.locked.borrow())
    }
    fn sweep(&self, _joint: &JointXmr, secret: &Bytes32) -> Result<(), XmrError> {
        *self.swept.borrow_mut() = Some(*secret);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Mock Nano ledger (one per independent node).
// ---------------------------------------------------------------------------

#[derive(Default)]
struct LedgerState {
    accounts: HashMap<Bytes32, (Bytes32, u128)>,
    blocks: HashMap<Bytes32, SignedBlock>,
}

struct MockLedger {
    state: RefCell<LedgerState>,
}

impl MockLedger {
    fn new() -> Self {
        Self {
            state: RefCell::new(LedgerState::default()),
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
        let mut st = self.state.borrow_mut();
        match st.accounts.get(&sb.block.account) {
            None => {
                if sb.block.previous != [0u8; 32] {
                    return ProcessResult::Rejected("gap: unknown account".into());
                }
            }
            Some((frontier, _)) => {
                if sb.block.previous != *frontier {
                    return ProcessResult::Rejected("fork: stale frontier".into());
                }
            }
        }
        st.accounts.insert(sb.block.account, (hash, sb.block.balance));
        st.blocks.insert(hash, sb.clone());
        ProcessResult::Accepted(hash)
    }

    fn confirmed(&self, hash: &Bytes32) -> bool {
        self.state.borrow().blocks.contains_key(hash)
    }

    fn frontier(&self, account: &Bytes32) -> Option<Bytes32> {
        self.state.borrow().accounts.get(account).map(|(f, _)| *f)
    }

    fn frontier_balance(&self, account: &Bytes32) -> Option<u128> {
        self.state.borrow().accounts.get(account).map(|(_, b)| *b)
    }
}

// ---------------------------------------------------------------------------
// FROST fixture + joint helpers.
// ---------------------------------------------------------------------------

struct Joint {
    key_packages: BTreeMap<Identifier, keys::KeyPackage>,
    pubkeys: keys::PublicKeyPackage,
    account: Bytes32,
}

fn joint_account() -> Joint {
    let (shares, pubkeys) =
        keys::generate_with_dealer(2, 2, keys::IdentifierList::Default, &mut OsRng).unwrap();
    let key_packages: BTreeMap<_, _> = shares
        .into_iter()
        .map(|(id, s)| (id, keys::KeyPackage::try_from(s).unwrap()))
        .collect();
    let account: Bytes32 = pubkeys
        .verifying_key()
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();
    Joint {
        key_packages,
        pubkeys,
        account,
    }
}

fn commit_all(
    j: &Joint,
) -> (
    BTreeMap<Identifier, round1::SigningNonces>,
    BTreeMap<Identifier, round1::SigningCommitments>,
) {
    let mut nonces = BTreeMap::new();
    let mut comms = BTreeMap::new();
    for (id, kp) in &j.key_packages {
        let (n, c) = round1::commit(kp.signing_share(), &mut OsRng);
        nonces.insert(*id, n);
        comms.insert(*id, c);
    }
    (nonces, comms)
}

fn jointly_sign(j: &Joint, block: &StateBlock) -> [u8; 64] {
    let (nonces, comms) = commit_all(j);
    ceremony::sign_block(block, comms, &nonces, &j.key_packages, &j.pubkeys).unwrap()
}

fn signed(block: StateBlock, signature: [u8; 64]) -> SignedBlock {
    let wk = work::generate(&block.work_root(), TEST_THRESHOLD, 0);
    SignedBlock {
        block,
        signature,
        work: wk,
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[test]
fn bob_and_alice_settle_one_chunk_over_two_nodes() {
    let j = joint_account();

    // Fund the joint account: open block broadcast to both independent nodes.
    let open = StateBlock {
        account: j.account,
        previous: [0u8; 32],
        representative: j.account,
        balance: CHUNK,
        link: [0xAA; 32],
        subtype: Subtype::Open,
    };
    let open_signed = signed(open.clone(), jointly_sign(&j, &open));

    let node_a = MockLedger::new();
    let node_b = MockLedger::new();
    let nodes: Vec<&dyn NanoNode> = vec![&node_a, &node_b];
    for r in saturation_broadcast(&nodes, &open_signed) {
        assert!(matches!(r, ProcessResult::Accepted(_)), "open accepted: {r:?}");
    }

    // Guard rung (change) and the adaptor-pre-signed claim.
    let rung = StateBlock::change(j.account, open.hash(), j.account, CHUNK);
    let rung_signed = signed(rung.clone(), jointly_sign(&j, &rung));

    let claim = StateBlock {
        account: j.account,
        previous: rung.hash(),
        representative: j.account,
        balance: 0,
        link: [0xB0; 32],
        subtype: Subtype::Send,
    };

    let mut wide = [0u8; 64];
    OsRng.fill_bytes(&mut wide);
    let x = curve25519_dalek::Scalar::from_bytes_mod_order_wide(&wide);
    let x_bytes = x.to_bytes();
    let t_point = (&x * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE)
        .compress()
        .to_bytes();
    let (nonces, comms) = commit_all(&j);
    let presig = ceremony::adaptor_presign_block(
        &claim, &t_point, comms, &nonces, &j.key_packages, &j.pubkeys,
    )
    .expect("adaptor presign");

    // The Monero joint account: Alice's secret + Bob's secret (= x), with the
    // adaptor point T = Bob's spend pub — so the claim reveals exactly x.
    let alice = curve25519_dalek::Scalar::from_bytes_mod_order_wide(&{
        let mut w = [0u8; 64];
        OsRng.fill_bytes(&mut w);
        w
    });
    let alice_bytes = alice.to_bytes();
    let alice_pub = (&alice * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE)
        .compress()
        .to_bytes();
    let mut ctx = [0u8; 32];
    OsRng.fill_bytes(&mut ctx);
    let mut view_a = [0u8; 32];
    let mut view_b = [0u8; 32];
    OsRng.fill_bytes(&mut view_a);
    OsRng.fill_bytes(&mut view_b);
    let joint = JointXmr::derive(ctx, vec![alice_pub, t_point], &view_a, &view_b, MoneroNet::Stagenet)
        .expect("joint derive");

    // Bob settles: confirm rung on quorum=2, then reveal-and-broadcast claim.
    let mut polled = 0u32;
    let claim_sig = bob_settle_chunk(
        &nodes,
        &rung_signed,
        &presig,
        &x_bytes,
        &claim,
        work::generate(&claim.work_root(), TEST_THRESHOLD, 0),
        2,
        5,
        &mut || polled += 1,
    )
    .expect("bob settles");

    // Both nodes settled the claim (frontier advanced past rung → claim).
    for n in [&node_a, &node_b] {
        assert_eq!(n.frontier(&j.account), Some(claim.hash()), "claim is the tip");
    }
    assert_eq!(
        claim_sig,
        complete_presignature(&presig, &x_bytes).expect("completed sig"),
        "the broadcast signature completes the pre-signature"
    );

    // Alice extracts x, reconstructs the joint Monero spend secret, and sweeps.
    let xmr = MockXmr::default();
    let secret = alice_settle_chunk(&xmr, &joint, &alice_bytes, &presig, &claim_sig)
        .expect("alice settles");
    assert_eq!(secret, x_bytes, "returned secret equals Bob's x");
    assert_eq!(extract_secret(&presig, &claim_sig).unwrap(), x_bytes);
    // The sweep used the RECONSTRUCTED joint secret (opens the joint spend key).
    let swept = *xmr.swept.borrow();
    let joint_secret = monero_side::cosign::reconstruct_joint_secret(
        ctx,
        &alice_bytes,
        &x_bytes,
        &joint.spend_pubs,
    )
    .unwrap();
    assert_eq!(swept, Some(joint_secret), "sweep used the reconstructed joint secret");
}

#[test]
fn bob_does_not_reveal_the_secret_without_confirmation() {
    let j = joint_account();
    let open = StateBlock {
        account: j.account,
        previous: [0u8; 32],
        representative: j.account,
        balance: CHUNK,
        link: [0xAA; 32],
        subtype: Subtype::Open,
    };
    let open_signed = signed(open.clone(), jointly_sign(&j, &open));

    // One node accepts but NEVER confirms (a lying/censoring node).
    struct NeverConfirms(MockLedger);
    impl NanoNode for NeverConfirms {
        fn process(&self, sb: &SignedBlock) -> ProcessResult {
            NanoNode::process(&self.0, sb)
        }
        fn confirmed(&self, _h: &Bytes32) -> bool {
            false
        }
        fn frontier(&self, a: &Bytes32) -> Option<Bytes32> {
            NanoNode::frontier(&self.0, a)
        }
        fn frontier_balance(&self, a: &Bytes32) -> Option<u128> {
            NanoNode::frontier_balance(&self.0, a)
        }
    }

    let node_a = NeverConfirms(MockLedger::new());
    let node_b = MockLedger::new();
    let nodes: Vec<&dyn NanoNode> = vec![&node_a, &node_b];
    let _ = saturation_broadcast(&nodes, &open_signed);

    let rung = StateBlock::change(j.account, open.hash(), j.account, CHUNK);
    let rung_signed = signed(rung.clone(), jointly_sign(&j, &rung));

    let claim = StateBlock {
        account: j.account,
        previous: rung.hash(),
        representative: j.account,
        balance: 0,
        link: [0xB0; 32],
        subtype: Subtype::Send,
    };

    let mut wide = [0u8; 64];
    OsRng.fill_bytes(&mut wide);
    let x = curve25519_dalek::Scalar::from_bytes_mod_order_wide(&wide);
    let t_point = (&x * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE)
        .compress()
        .to_bytes();
    let (nonces, comms) = commit_all(&j);
    let presig = ceremony::adaptor_presign_block(
        &claim, &t_point, comms, &nonces, &j.key_packages, &j.pubkeys,
    )
    .expect("adaptor presign");

    // quorum=2 but only node_b confirms → the gate fails and NO claim is
    // completed: the secret is never revealed (fail-closed).
    let res = bob_settle_chunk(
        &nodes,
        &rung_signed,
        &presig,
        &x.to_bytes(),
        &claim,
        work::generate(&claim.work_root(), TEST_THRESHOLD, 0),
        2,
        3,
        &mut || {},
    );
    assert!(res.is_err(), "no reveal without 2-of-2 confirmation");
    // The claim never reached either node.
    for n in [&node_a.0, &node_b] {
        assert_ne!(n.frontier(&j.account), Some(claim.hash()));
    }
}
