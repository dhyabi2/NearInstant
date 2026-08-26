//! Provable-drip battery: the full streamed-exit lifecycle on the ledger —
//! exit leaves the penalty behind, sealed installments unseal strictly in
//! order and settle on-chain in order, the audit catches dishonest sealing,
//! kept-bundle tamper is caught at use, and the sequencing is structural
//! (no public starting point exists for any link but the first).

use std::collections::{BTreeMap, HashMap};

use rand::rngs::OsRng;

use nano_ceremony::block::{SignedBlock, StateBlock, Subtype};
use nano_ceremony::{ceremony, work, Bytes32};
use pledge::bond::{exit_chain_with_drip, sign_chain, Party};
use pledge::stream::{
    choose_audit, drip_chain, make_bundles, verify_audit, DripSolver, StreamError,
};
use pledge::terms::Terms;
use signing::{keys, round1, Identifier};

const TEST_THRESHOLD: u64 = 0xFF00_0000_0000_0000;
const T_UNIT: u64 = 400; // squarings per "hour" (test-sized)
const PRIME_BITS: usize = 130;

#[derive(Default)]
struct Ledger {
    accounts: HashMap<Bytes32, (Bytes32, u128)>,
    credited: HashMap<Bytes32, u128>,
}

impl Ledger {
    fn process(&mut self, sb: &SignedBlock) -> Result<Bytes32, &'static str> {
        let hash = sb.block.hash();
        if !work::validate(&sb.block.work_root(), sb.work, TEST_THRESHOLD) {
            return Err("work");
        }
        if !sb.verify_signature() {
            return Err("signature");
        }
        let prev = match self.accounts.get(&sb.block.account) {
            None => {
                if sb.block.previous != [0u8; 32] {
                    return Err("gap");
                }
                0
            }
            Some((f, b)) => {
                if sb.block.previous != *f {
                    return Err("stale frontier");
                }
                *b
            }
        };
        if sb.block.subtype == Subtype::Send {
            let sent = prev.checked_sub(sb.block.balance).ok_or("bad send")?;
            *self.credited.entry(sb.block.link).or_default() += sent;
        }
        self.accounts.insert(sb.block.account, (hash, sb.block.balance));
        Ok(hash)
    }
}

struct Fixture {
    terms: Terms,
    account: Bytes32,
    frontier: Bytes32,
    key_packages: BTreeMap<Identifier, keys::KeyPackage>,
    pubkeys: keys::PublicKeyPackage,
}

fn setup(ledger: &mut Ledger) -> Fixture {
    let terms = Terms {
        principal_a: 1_000,
        principal_b: 500,
        penalty_bps: 1_000,
        start: 0,
        maturity: 1_000,
    };
    let (shares, pubkeys) =
        keys::generate_with_dealer(2, 2, keys::IdentifierList::Default, &mut OsRng).unwrap();
    let key_packages: BTreeMap<Identifier, keys::KeyPackage> = shares
        .into_iter()
        .map(|(id, s)| (id, keys::KeyPackage::try_from(s).unwrap()))
        .collect();
    let account: Bytes32 = pubkeys
        .verifying_key()
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();
    let open = StateBlock {
        account,
        previous: [0u8; 32],
        representative: account,
        balance: terms.total(),
        link: [0xAA; 32],
        subtype: Subtype::Open,
    };
    let mut nonces = BTreeMap::new();
    let mut comms = BTreeMap::new();
    for (id, kp) in &key_packages {
        let (n, c) = round1::commit(kp.signing_share(), &mut OsRng);
        nonces.insert(*id, n);
        comms.insert(*id, c);
    }
    let sig = ceremony::sign_block(&open, comms, &nonces, &key_packages, &pubkeys).unwrap();
    let frontier = ledger
        .process(&ceremony::assemble(
            open.clone(),
            sig,
            work::generate(&open.work_root(), TEST_THRESHOLD, 0),
        ))
        .unwrap();
    Fixture {
        terms,
        account,
        frontier,
        key_packages,
        pubkeys,
    }
}

/// Jointly sign every drip block (setup-time; the LEAVER aggregates and
/// seals — the stayer only ever receives ciphertexts).
fn sign_drip(
    f: &Fixture,
    blocks: &[StateBlock],
) -> Vec<[u8; 64]> {
    blocks
        .iter()
        .map(|b| {
            let mut nonces = BTreeMap::new();
            let mut comms = BTreeMap::new();
            for (id, kp) in &f.key_packages {
                let (n, c) = round1::commit(kp.signing_share(), &mut OsRng);
                nonces.insert(*id, n);
                comms.insert(*id, c);
            }
            ceremony::sign_block(b, comms, &nonces, &f.key_packages, &f.pubkeys).unwrap()
        })
        .collect()
}

#[test]
fn streamed_exit_end_to_end() {
    let mut ledger = Ledger::default();
    let f = setup(&mut ledger);
    let (dest_a, dest_b) = ([0xA1; 32], [0xB1; 32]);
    let n_installments = 4;
    let penalty = f.terms.full_penalty(f.terms.principal_a); // A leaves: 100

    // --- Setup: exit chain (drip variant) + drip blocks all pre-signed.
    let exit = exit_chain_with_drip(&f.terms, f.account, f.frontier, f.account, Party::A, dest_a, dest_b);
    let exit_signed = sign_chain(&exit, &f.key_packages, &f.pubkeys, &mut OsRng).unwrap();
    let drips = drip_chain(f.account, exit[1].hash(), f.account, penalty, dest_b, n_installments);
    let drip_sigs = sign_drip(&f, &drips);

    // Leaver seals; stayer audits (cut-and-choose m=6, open 3).
    let (bundles, trapdoors) = make_bundles(&mut OsRng, &drip_sigs, 6, PRIME_BITS, T_UNIT);
    let audit = choose_audit(&mut OsRng, 6);
    let opened: Vec<_> = audit.iter().map(|&i| trapdoors[i].clone()).collect();
    let kept = verify_audit(&f.account, &drips, &bundles, &audit, &opened).expect("audit passes");
    assert_eq!(kept.len(), 3);

    // --- A exits: principal to B now, remainder to A, penalty stays.
    for blk in exit_signed.assemble(TEST_THRESHOLD) {
        ledger.process(&blk).unwrap();
    }
    assert_eq!(ledger.credited[&dest_b], 500, "stayer principal paid at once");
    assert_eq!(ledger.credited[&dest_a], 900, "leaver keeps 90%");
    assert_eq!(ledger.accounts[&f.account].1, penalty, "penalty stays behind");

    // --- Stayer grinds the kept bundle: installments unseal IN ORDER and
    // settle on-chain in order (frontier rule); third parties see the pace.
    let mut solver = DripSolver::new(&bundles[kept[0]]);
    for (k, drip) in drips.iter().enumerate() {
        assert_eq!(solver.unlocked(), k);
        let sig = solver.solve_next(&f.account, &drips).expect("unseal");
        let sb = ceremony::assemble(
            drip.clone(),
            sig,
            work::generate(&drip.work_root(), TEST_THRESHOLD, 0),
        );
        ledger.process(&sb).unwrap();
    }
    assert_eq!(ledger.credited[&dest_b], 500 + penalty, "full penalty streamed");
    assert_eq!(ledger.accounts[&f.account].1, 0);
}

#[test]
fn dishonest_sealing_is_caught_in_audit() {
    let mut ledger = Ledger::default();
    let f = setup(&mut ledger);
    let penalty = 100u128;
    let drips = drip_chain(f.account, [0x77; 32], f.account, penalty, [0xB1; 32], 3);
    let drip_sigs = sign_drip(&f, &drips);

    let (mut bundles, trapdoors) = make_bundles(&mut OsRng, &drip_sigs, 4, PRIME_BITS, T_UNIT);
    // The leaver corrupts one ciphertext in bundle 1.
    bundles[1].sealed[2][5] ^= 1;
    let audit = vec![0usize, 1];
    let opened: Vec<_> = audit.iter().map(|&i| trapdoors[i].clone()).collect();
    assert_eq!(
        verify_audit(&f.account, &drips, &bundles, &audit, &opened),
        Err(StreamError::AuditFailed(1))
    );
}

#[test]
fn kept_bundle_tamper_is_caught_at_use_and_sequencing_is_structural() {
    let mut ledger = Ledger::default();
    let f = setup(&mut ledger);
    let drips = drip_chain(f.account, [0x66; 32], f.account, 90, [0xB1; 32], 3);
    let drip_sigs = sign_drip(&f, &drips);
    let (mut bundles, _tds) = make_bundles(&mut OsRng, &drip_sigs, 2, PRIME_BITS, T_UNIT);

    // Tampered kept bundle: unsealing yields an invalid signature — caught
    // before anything is broadcast.
    bundles[0].sealed[0][0] ^= 1;
    let mut bad = DripSolver::new(&bundles[0]);
    assert_eq!(
        bad.solve_next(&f.account, &drips),
        Err(StreamError::BadSignature)
    );

    // Structural sequencing: the public bundle carries exactly ONE starting
    // point; later links' starts exist nowhere in public data, so link k+1
    // cannot be ground before link k's solution exists.
    let good = &bundles[1];
    assert_eq!(good.c.len(), 3);
    // (One x0 field total — this is the whole point; asserting the type
    // shape documents it.)
    let _single_start: &num_bigint_dig::BigUint = &good.x0;

    // Honest solve still works on the untampered bundle, strictly in order.
    let mut solver = DripSolver::new(good);
    for k in 0..3 {
        assert_eq!(solver.unlocked(), k);
        solver.solve_next(&f.account, &drips).expect("in-order unseal");
    }
}

#[test]
fn drip_chain_arithmetic_folds_remainder() {
    let blocks = drip_chain([1; 32], [2; 32], [3; 32], 103, [4; 32], 4);
    assert_eq!(blocks.len(), 4);
    // 25 + 25 + 25 + 28 (remainder folded into the last).
    let mut prev_balance = 103u128;
    let mut amounts = Vec::new();
    for b in &blocks {
        amounts.push(prev_balance - b.balance);
        prev_balance = b.balance;
    }
    assert_eq!(amounts, vec![25, 25, 25, 28]);
    assert_eq!(blocks.last().unwrap().balance, 0);
    // Chained: each block's previous is the prior hash.
    for w in blocks.windows(2) {
        assert_eq!(w[1].previous, w[0].hash());
    }
}
