//! Block 2 verification battery: address encoding against a known mainnet
//! vector, block hashing, PoW pipelining, joint block signing, and the I3
//! guard ladder exercised against a ledger model that enforces Nano's
//! one-block-per-frontier and signature rules (the Rust re-run of
//! verify_core.py scenarios S05/S05b with real block structures).

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

use rand::rngs::OsRng;

use nano_ceremony::block::{SignedBlock, StateBlock, Subtype};
use nano_ceremony::broadcast::{
    any_accepted, frontier_balance_quorum, saturation_broadcast, NanoNode, ProcessResult,
};
use nano_ceremony::guard::{build_rungs, GuardLadder, Rung};
use nano_ceremony::{address, ceremony, work, Bytes32};
use signing::adaptor::{complete_presignature, extract_secret, verify_presignature};
use signing::{keys, round1, Identifier};

/// Low threshold so test work generation is instant; the validation code path
/// is identical to mainnet's.
const TEST_THRESHOLD: u64 = 0xFF00_0000_0000_0000;

// ---------------------------------------------------------------------------
// Ledger model: one block per frontier, signature and work enforced.
// ---------------------------------------------------------------------------

struct MockLedger {
    state: RefCell<LedgerState>,
}

#[derive(Default)]
struct LedgerState {
    /// account → (frontier hash, balance)
    accounts: HashMap<Bytes32, (Bytes32, u128)>,
    /// block hash → block
    blocks: HashMap<Bytes32, SignedBlock>,
}

impl MockLedger {
    fn new() -> Self {
        Self {
            state: RefCell::new(LedgerState::default()),
        }
    }

    fn block(&self, hash: &Bytes32) -> Option<SignedBlock> {
        self.state.borrow().blocks.get(hash).cloned()
    }

    fn balance(&self, account: &Bytes32) -> Option<u128> {
        self.state.borrow().accounts.get(account).map(|(_, b)| *b)
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
                // Open block: previous must be zero.
                if sb.block.previous != [0u8; 32] {
                    return ProcessResult::Rejected("gap: unknown account".into());
                }
            }
            Some((frontier, _)) => {
                // THE rule the guard ladder leans on: only the current
                // frontier may be extended; any stale-frontier signature is
                // dead the moment the frontier moves.
                if sb.block.previous != *frontier {
                    return ProcessResult::Rejected("fork: stale frontier".into());
                }
            }
        }
        st.accounts
            .insert(sb.block.account, (hash, sb.block.balance));
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

/// A node that reports a fixed balance (or `None`) for any account — used to
/// exercise the proof-of-funds quorum resolver without a full ledger.
struct FixedBalance(Option<u128>);

impl NanoNode for FixedBalance {
    fn process(&self, _: &SignedBlock) -> ProcessResult {
        ProcessResult::Rejected("not a ledger".into())
    }
    fn confirmed(&self, _: &Bytes32) -> bool {
        false
    }
    fn frontier(&self, _: &Bytes32) -> Option<Bytes32> {
        None
    }
    fn frontier_balance(&self, _: &Bytes32) -> Option<u128> {
        self.0
    }
}

#[test]
fn proof_of_funds_quorum_takes_the_minimum_balance() {
    let acct = [7u8; 32];

    // Fewer than two nodes is refused outright (a single node must never
    // decide a funds gate).
    let one = FixedBalance(Some(100));
    let refs: Vec<&dyn NanoNode> = vec![&one];
    assert_eq!(frontier_balance_quorum(&refs, &acct, 2), None);

    // A quorum of three returns the MINIMUM — a lying-high node cannot push
    // the result up.
    let a = FixedBalance(Some(1_000));
    let b = FixedBalance(Some(1_000));
    let lying = FixedBalance(Some(9_999_999));
    let refs: Vec<&dyn NanoNode> = vec![&a, &b, &lying];
    assert_eq!(frontier_balance_quorum(&refs, &acct, 2), Some(1_000));

    // A node that cannot answer is simply skipped; the quorum still needs to
    // be met by the rest.
    let silent = FixedBalance(None);
    let refs: Vec<&dyn NanoNode> = vec![&a, &silent, &lying];
    assert_eq!(frontier_balance_quorum(&refs, &acct, 2), Some(1_000));

    // If too few nodes answer, nothing can be concluded.
    let refs: Vec<&dyn NanoNode> = vec![&a, &silent];
    assert_eq!(frontier_balance_quorum(&refs, &acct, 2), None);
}

// ---------------------------------------------------------------------------
// FROST fixture
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

fn jointly_sign(j: &Joint, block: &StateBlock) -> SignedBlock {
    let (nonces, comms) = commit_all(j);
    let sig =
        ceremony::sign_block(block, comms, &nonces, &j.key_packages, &j.pubkeys).expect("sign");
    let w = work::generate(&block.work_root(), TEST_THRESHOLD, 0);
    ceremony::assemble(block.clone(), sig, w)
}

/// Open the joint account on the ledger with `balance` and return the frontier.
fn open_joint(ledger: &MockLedger, j: &Joint, balance: u128) -> Bytes32 {
    let open = StateBlock {
        account: j.account,
        previous: [0u8; 32],
        representative: j.account,
        balance,
        link: [0xAA; 32], // stand-in pending-send hash
        subtype: Subtype::Open,
    };
    let sb = jointly_sign(j, &open);
    match ledger.process(&sb) {
        ProcessResult::Accepted(h) => h,
        other => panic!("open rejected: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn address_known_vector_and_round_trip() {
    // Nano genesis account.
    let pk: Bytes32 = hex::decode("E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA")
        .unwrap()
        .try_into()
        .unwrap();
    let addr = address::encode(&pk);
    assert_eq!(
        addr,
        "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3"
    );
    assert_eq!(address::decode(&addr), Some(pk));
    // Legacy prefix decodes too.
    assert_eq!(
        address::decode("xrb_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3"),
        Some(pk)
    );
    // A flipped checksum char fails.
    let mut bad = addr.clone();
    bad.pop();
    bad.push('1');
    assert_eq!(address::decode(&bad), None);

    // Random round trips.
    for i in 0u8..8 {
        let k = [i.wrapping_mul(37); 32];
        assert_eq!(address::decode(&address::encode(&k)), Some(k));
    }
}

#[test]
fn work_pipelines_ahead_of_the_chunk_stream() {
    let root = [0x42; 32];
    let nonce = work::generate(&root, TEST_THRESHOLD, 7);
    assert!(work::validate(&root, nonce, TEST_THRESHOLD));
    assert!(!work::validate(&root, nonce.wrapping_add(1), u64::MAX));

    // N4: the next block's work root is the current block's hash — known at
    // signing time, before broadcast.
    let b = StateBlock::change([1; 32], [2; 32], [3; 32], 10);
    let next = StateBlock::change([1; 32], b.hash(), [3; 32], 10);
    assert_eq!(next.work_root(), b.hash());
    // And an open block's root is the account key, known even earlier.
    let open = StateBlock {
        previous: [0u8; 32],
        ..b.clone()
    };
    assert_eq!(open.work_root(), b.account);
}

#[test]
fn joint_signature_is_valid_on_ledger_and_stale_frontier_is_rejected() {
    let ledger = MockLedger::new();
    let j = joint_account();
    let f0 = open_joint(&ledger, &j, 1_000);

    let b1 = StateBlock::change(j.account, f0, j.account, 1_000);
    let sb1 = jointly_sign(&j, &b1);
    assert!(sb1.verify_signature());
    assert!(matches!(ledger.process(&sb1), ProcessResult::Accepted(_)));

    // Re-signing against the now-stale frontier f0 must be rejected.
    let stale = StateBlock::change(j.account, f0, [7; 32], 1_000);
    let sb_stale = jointly_sign(&j, &stale);
    assert!(matches!(
        ledger.process(&sb_stale),
        ProcessResult::Rejected(r) if r.contains("stale")
    ));

    // Tampered signature rejected.
    let mut tampered = jointly_sign(&j, &StateBlock::change(j.account, b1.hash(), [8; 32], 1_000));
    tampered.signature[10] ^= 1;
    assert!(matches!(
        ledger.process(&tampered),
        ProcessResult::Rejected(r) if r.contains("signature")
    ));
}

#[test]
fn guard_ladder_builds_verifies_and_walks() {
    let j = joint_account();
    let frontier = [0x11; 32];
    let rep = [0x22; 32];
    let blocks = build_rungs(j.account, frontier, rep, 500, 3);
    assert_eq!(blocks.len(), 3);
    assert_eq!(blocks[1].previous, blocks[0].hash());
    assert_eq!(blocks[2].previous, blocks[1].hash());

    let rungs: Vec<Rung> = blocks
        .iter()
        .map(|b| {
            let sb = jointly_sign(&j, b);
            Rung {
                block: b.clone(),
                signature: sb.signature,
            }
        })
        .collect();
    let ladder = GuardLadder::new(j.account, 500, rungs.clone()).expect("ladder verifies");
    assert_eq!(ladder.remaining(&frontier), 3);
    assert_eq!(
        ladder.next_rung(&frontier).unwrap().block.hash(),
        blocks[0].hash()
    );
    assert_eq!(ladder.remaining(&blocks[0].hash()), 2);
    assert_eq!(ladder.remaining(&[0x99; 32]), 0);
    assert!(ladder.next_rung(&[0x99; 32]).is_none());

    // A broken chain is refused.
    let mut broken = rungs.clone();
    broken.swap(0, 1);
    assert!(GuardLadder::new(j.account, 500, broken).is_none());
    // A tampered rung signature is refused.
    let mut forged = rungs;
    forged[1].signature[3] ^= 1;
    assert!(GuardLadder::new(j.account, 500, forged).is_none());
}

/// Audit #10: `from_confirmed` sources the balance from the node, so a burn
/// ladder — rungs built against a balance BELOW the account's true confirmed
/// frontier — is rejected. Broadcasting such a rung would send the difference
/// to the zero account; the enforced constructor makes that unbuildable.
#[test]
fn from_confirmed_rejects_a_burn_ladder() {
    let ledger = MockLedger::new();
    let j = joint_account();
    let true_balance = 1_000u128;
    let f0 = open_joint(&ledger, &j, true_balance);

    // Honest ladder: rungs carry the true confirmed balance → accepted, and it
    // matches the node's reported balance.
    let honest_block = StateBlock::change(j.account, f0, j.account, true_balance);
    let honest = Rung {
        block: honest_block.clone(),
        signature: jointly_sign(&j, &honest_block).signature,
    };
    let ladder = GuardLadder::from_confirmed(j.account, &ledger, vec![honest])
        .expect("honest ladder verifies against the confirmed balance");
    assert!(ladder.matches_frontier_balance(true_balance));

    // Burn ladder: a rung built with balance 400 (< 1000). Even though it is a
    // validly jointly-signed change block, from_confirmed uses the node's 1000
    // and Rung::verify rejects the 400-balance rung.
    let burn_block = StateBlock::change(j.account, f0, j.account, 400);
    let burn = Rung {
        block: burn_block.clone(),
        signature: jointly_sign(&j, &burn_block).signature,
    };
    assert!(
        GuardLadder::from_confirmed(j.account, &ledger, vec![burn]).is_none(),
        "a ladder below the confirmed frontier balance must not build"
    );
    // The naive constructor would have accepted it (the exact hole #10 closes).
    assert!(GuardLadder::new(j.account, 400, vec![Rung {
        block: burn_block.clone(),
        signature: jointly_sign(&j, &burn_block).signature,
    }])
    .is_some());
}

/// S05: the guard block kills a stale co-signed refund, then the
/// adaptor-completed claim — pre-signed against the *post-guard* frontier,
/// which is computable at setup because rung hashes are deterministic —
/// settles and reveals the secret.
#[test]
fn guard_kills_stale_refund_then_claim_reveals_secret() {
    use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};

    let ledger = MockLedger::new();
    let j = joint_account();
    let balance = 1_000u128;
    let f0 = open_joint(&ledger, &j, balance);
    let alice_refund_key = [0xA1; 32];
    let bob_claim_key = [0xB0; 32];

    // Setup (before any secret matters): one guard rung at f0, and the claim
    // adaptor-pre-signed against the rung's hash — the frontier that will
    // exist after the guard confirms.
    let rung_block = StateBlock::change(j.account, f0, j.account, balance);
    let rung = Rung {
        block: rung_block.clone(),
        signature: jointly_sign(&j, &rung_block).signature,
    };
    let ladder = GuardLadder::new(j.account, balance, vec![rung]).unwrap();

    let x = Scalar::from_bytes_mod_order_wide(&[13u8; 64]);
    let t = EdwardsPoint::mul_base(&x).compress().to_bytes();
    let claim_block = StateBlock {
        account: j.account,
        previous: rung_block.hash(),
        representative: j.account,
        balance: 0,
        link: bob_claim_key,
        subtype: Subtype::Send,
    };
    let (nonces, comms) = commit_all(&j);
    let presig = ceremony::adaptor_presign_block(
        &claim_block,
        &t,
        comms,
        &nonces,
        &j.key_packages,
        &j.pubkeys,
    )
    .expect("presign claim");
    verify_presignature(&presig, &j.account, &claim_block.hash()).expect("presig valid");

    // A co-signed refund against f0 exists (the state I3's invariant forbids,
    // simulated here to show the guard kills it anyway).
    let refund_block = StateBlock {
        account: j.account,
        previous: f0,
        representative: j.account,
        balance: 0,
        link: alice_refund_key,
        subtype: Subtype::Send,
    };
    let refund = jointly_sign(&j, &refund_block);

    // Claim discipline: broadcast the guard first…
    let rung_signed = ceremony::assemble(
        rung_block.clone(),
        ladder.next_rung(&f0).unwrap().signature,
        work::generate(&rung_block.work_root(), TEST_THRESHOLD, 0),
    );
    let results = saturation_broadcast(&[&ledger], &rung_signed);
    assert!(any_accepted(&results));

    // …the stale refund is now dead…
    assert!(matches!(
        ledger.process(&refund),
        ProcessResult::Rejected(r) if r.contains("stale")
    ));

    // …complete the claim with x and settle it on the fresh frontier.
    let claim_sig = complete_presignature(&presig, &x.to_bytes()).expect("complete");
    let claim_signed = ceremony::assemble(
        claim_block.clone(),
        claim_sig,
        work::generate(&claim_block.work_root(), TEST_THRESHOLD, 0),
    );
    let hash = match ledger.process(&claim_signed) {
        ProcessResult::Accepted(h) => h,
        other => panic!("claim rejected: {other:?}"),
    };
    assert_eq!(ledger.balance(&j.account), Some(0));

    // Alice reads the broadcast signature off the ledger and extracts x.
    let on_chain = ledger.block(&hash).unwrap();
    let extracted = extract_secret(&presig, &on_chain.signature).expect("extract");
    assert_eq!(extracted, x.to_bytes());
}

/// S05b: losing the guard race is a clean abort — the refund lands first, the
/// rung is rejected, and nothing secret was ever put on the wire.
#[test]
fn losing_the_guard_race_is_a_clean_abort() {
    let ledger = MockLedger::new();
    let j = joint_account();
    let balance = 700u128;
    let f0 = open_joint(&ledger, &j, balance);

    let rung_block = StateBlock::change(j.account, f0, j.account, balance);
    let rung_signed = jointly_sign(&j, &rung_block);

    // Adversary's co-signed refund reaches the network first.
    let refund_block = StateBlock {
        account: j.account,
        previous: f0,
        representative: j.account,
        balance: 0,
        link: [0xA1; 32],
        subtype: Subtype::Send,
    };
    let refund = jointly_sign(&j, &refund_block);
    assert!(matches!(ledger.process(&refund), ProcessResult::Accepted(_)));

    // The guard now loses: stale frontier.
    assert!(matches!(
        ledger.process(&rung_signed),
        ProcessResult::Rejected(r) if r.contains("stale")
    ));

    // Clean abort: the claimant never completed the pre-signature, so no
    // secret exists anywhere — the guard block itself moved nothing and
    // revealed nothing (it is a value-free change block).
    assert_eq!(rung_block.balance, balance);
    assert_eq!(rung_block.link, [0u8; 32]);
}

/// Audit #1: broadcast_and_confirm must NOT return Ok on mere acceptance —
/// it waits for a confirmation quorum. Nodes that accept but never confirm
/// yield an error, so the caller aborts instead of revealing the secret.
#[test]
fn broadcast_and_confirm_requires_confirmation_not_just_acceptance() {
    use nano_ceremony::broadcast::{broadcast_and_confirm, NanoNode, ProcessResult};

    // Ledgers that ACCEPT but never CONFIRM.
    struct AcceptOnly;
    impl NanoNode for AcceptOnly {
        fn process(&self, sb: &SignedBlock) -> ProcessResult {
            ProcessResult::Accepted(sb.block.hash())
        }
        fn confirmed(&self, _h: &Bytes32) -> bool { false }
        fn frontier(&self, _a: &Bytes32) -> Option<Bytes32> { None }
    }
    let (n0, n1) = (AcceptOnly, AcceptOnly);
    let nodes: [&dyn NanoNode; 2] = [&n0, &n1];
    let block = jointly_sign_standalone();
    let mut polls = 0;
    let mut poll = || polls += 1;
    let r = broadcast_and_confirm(&nodes, &block, 2, 3, &mut poll);
    assert!(r.is_err(), "must not proceed on acceptance alone (audit #1)");
    assert!(polls >= 1);
}

/// Race C1: a single lying node cannot forge cementing. With a quorum of 2, one
/// node that lies (`confirmed → true`) is not enough — the honest node never
/// confirms, so the gate refuses and the secret is never revealed. Also: a
/// single-node set (or quorum < 2) is rejected outright — no one node may
/// decide a secret-reveal gate.
#[test]
fn confirm_gate_rejects_single_node_forge() {
    use nano_ceremony::broadcast::{broadcast_and_confirm, NanoNode, ProcessResult};

    struct Node { lies: bool }
    impl NanoNode for Node {
        fn process(&self, sb: &SignedBlock) -> ProcessResult {
            ProcessResult::Accepted(sb.block.hash())
        }
        fn confirmed(&self, _h: &Bytes32) -> bool { self.lies }
        fn frontier(&self, _a: &Bytes32) -> Option<Bytes32> { None }
    }
    let liar = Node { lies: true };
    let honest = Node { lies: false };
    let block = jointly_sign_standalone();
    let mut poll = || {};

    // One liar + one honest, quorum 2: only 1 confirms → refused.
    let nodes: [&dyn NanoNode; 2] = [&liar, &honest];
    assert!(
        broadcast_and_confirm(&nodes, &block, 2, 3, &mut poll).is_err(),
        "a single lying node must not satisfy a quorum-2 gate"
    );
    // A lone node (even lying) can't meet the >=2-node / >=2-quorum floor.
    let solo: [&dyn NanoNode; 1] = [&liar];
    assert!(broadcast_and_confirm(&solo, &block, 1, 3, &mut poll).is_err());
    assert!(broadcast_and_confirm(&solo, &block, 2, 3, &mut poll).is_err());
}

/// Race C2: broadcast_secret_claim must WITHHOLD the secret-bearing claim from
/// any node whose frontier has already moved past the claim's target — the
/// secret must never hit the socket of a node that would only reject it.
#[test]
fn secret_claim_is_withheld_from_moved_frontier_nodes() {
    use nano_ceremony::broadcast::{broadcast_secret_claim, NanoNode, ProcessResult};
    use std::cell::Cell;

    // Records whether the secret-bearing block was ever handed to `process`.
    struct Watcher { frontier: Bytes32, saw_secret: Cell<bool> }
    impl NanoNode for Watcher {
        fn process(&self, _sb: &SignedBlock) -> ProcessResult {
            self.saw_secret.set(true);
            ProcessResult::Accepted([0u8; 32])
        }
        fn confirmed(&self, _h: &Bytes32) -> bool { false }
        fn frontier(&self, _a: &Bytes32) -> Option<Bytes32> { Some(self.frontier) }
    }

    let block = jointly_sign_standalone();
    let target_prev = block.block.previous; // the frontier the claim extends
    // Node A still holds the target frontier → safe to send.
    let good = Watcher { frontier: target_prev, saw_secret: Cell::new(false) };
    // Node B's frontier has moved → must NOT receive the secret.
    let moved = Watcher { frontier: [0x99; 32], saw_secret: Cell::new(false) };
    let nodes: [&dyn NanoNode; 2] = [&good, &moved];
    let _ = broadcast_secret_claim(&nodes, &block);
    assert!(good.saw_secret.get(), "node holding the target frontier receives the claim");
    assert!(!moved.saw_secret.get(), "moved-frontier node must NOT receive the secret (race C2)");
}

// Minimal standalone-signed block for the confirm test (reuses the joint sign path).
fn jointly_sign_standalone() -> SignedBlock {
    use std::collections::BTreeMap as BM;
    use signing::{keys, round1, Identifier};
    let (shares, pubkeys) =
        keys::generate_with_dealer(2, 2, keys::IdentifierList::Default, &mut OsRng).unwrap();
    let kps: BM<Identifier, keys::KeyPackage> = shares
        .into_iter().map(|(id, s)| (id, keys::KeyPackage::try_from(s).unwrap())).collect();
    let account: Bytes32 = pubkeys.verifying_key().serialize().unwrap().try_into().unwrap();
    let block = StateBlock::change(account, [1u8; 32], account, 10);
    let mut nonces = BTreeMap::new();
    let mut comms = BTreeMap::new();
    for (id, kp) in &kps {
        let (n, c) = round1::commit(kp.signing_share(), &mut OsRng);
        nonces.insert(*id, n); comms.insert(*id, c);
    }
    let sig = ceremony::sign_block(&block, comms, &nonces, &kps, &pubkeys).unwrap();
    ceremony::assemble(block.clone(), sig, work::generate(&block.work_root(), TEST_THRESHOLD, 0))
}
