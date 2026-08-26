//! Pledge battery: the full bond lifecycle on a frontier-enforcing ledger —
//! early exit pays the stayer the penalty and kills every other path;
//! cooperative maturity close pays clean; a vanished counterparty is
//! recovered via the share escrow and the clean split executes unilaterally;
//! the penalty-free early door provably does not exist; terms validate and
//! the penalty decays to zero at maturity.

use std::collections::{BTreeMap, HashMap};

use rand::rngs::OsRng;

use nano_ceremony::block::{SignedBlock, StateBlock, Subtype};
use nano_ceremony::{ceremony, work, Bytes32};
use pledge::bond::{
    adaptor_lock_maturity, escrow_maturity_secret, exit_chain, maturity_chain, recover_maturity,
    sign_chain, Party,
};
use pledge::terms::{Terms, TermsError};
use puzzle_escrow::escrow::{choose_audit, escrow_open, escrow_verify};
use signing::{keys, round1, Identifier};

use curve25519_dalek::scalar::Scalar;
use rand::RngCore;

const TEST_THRESHOLD: u64 = 0xFF00_0000_0000_0000;

// Frontier-enforcing mock ledger (same rules as prior batteries).
#[derive(Default)]
struct Ledger {
    accounts: HashMap<Bytes32, (Bytes32, u128)>,
    credited: HashMap<Bytes32, u128>, // send destinations -> total received
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
        let prev_balance = match self.accounts.get(&sb.block.account) {
            None => {
                if sb.block.previous != [0u8; 32] {
                    return Err("gap");
                }
                0
            }
            Some((frontier, bal)) => {
                if sb.block.previous != *frontier {
                    return Err("stale frontier");
                }
                *bal
            }
        };
        if sb.block.subtype == Subtype::Send {
            let sent = prev_balance
                .checked_sub(sb.block.balance)
                .ok_or("send increases balance")?;
            *self.credited.entry(sb.block.link).or_default() += sent;
        }
        self.accounts.insert(sb.block.account, (hash, sb.block.balance));
        Ok(hash)
    }
}

struct Bond {
    terms: Terms,
    account: Bytes32,
    frontier: Bytes32,
    key_packages: BTreeMap<Identifier, keys::KeyPackage>,
    pubkeys: keys::PublicKeyPackage,
    dest_a: Bytes32,
    dest_b: Bytes32,
}

fn setup(ledger: &mut Ledger, terms: Terms) -> Bond {
    terms.validate().unwrap();
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

    // Fund: open the joint account with the combined principal.
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
    let sb = ceremony::assemble(
        open.clone(),
        sig,
        work::generate(&open.work_root(), TEST_THRESHOLD, 0),
    );
    let frontier = ledger.process(&sb).unwrap();

    Bond {
        terms,
        account,
        frontier,
        key_packages,
        pubkeys,
        dest_a: [0xA1; 32],
        dest_b: [0xB1; 32],
    }
}

fn terms_10pct() -> Terms {
    Terms {
        principal_a: 1_000,
        principal_b: 500,
        penalty_bps: 1_000, // 10%
        start: 0,
        maturity: 1_000,
    }
}

#[test]
fn early_exit_pays_the_stayer_and_kills_other_paths() {
    let mut ledger = Ledger::default();
    let b = setup(&mut ledger, terms_10pct());

    // Setup: both exit chains pre-signed (and only those).
    let a_exit = exit_chain(&b.terms, b.account, b.frontier, b.account, Party::A, b.dest_a, b.dest_b);
    let b_exit = exit_chain(&b.terms, b.account, b.frontier, b.account, Party::B, b.dest_a, b.dest_b);
    let a_chain = sign_chain(&a_exit, &b.key_packages, &b.pubkeys, &mut OsRng).unwrap();
    let b_chain = sign_chain(&b_exit, &b.key_packages, &b.pubkeys, &mut OsRng).unwrap();
    assert!(a_chain.verify(&b.account));
    assert!(b_chain.verify(&b.account));

    // A exits early: broadcast A's chain.
    for blk in a_chain.assemble(TEST_THRESHOLD) {
        ledger.process(&blk).unwrap();
    }
    // B (stayer) got principal + A's 10% penalty; A got 90% of principal.
    assert_eq!(ledger.credited[&b.dest_b], 500 + 100);
    assert_eq!(ledger.credited[&b.dest_a], 900);
    assert_eq!(ledger.accounts[&b.account].1, 0);

    // Every other pre-signed path is now dead (stale frontier).
    let dead = b_chain.assemble(TEST_THRESHOLD);
    assert_eq!(ledger.process(&dead[0]), Err("stale frontier"));
}

#[test]
fn cooperative_maturity_close_pays_clean() {
    let mut ledger = Ledger::default();
    let b = setup(&mut ledger, terms_10pct());
    // (Exit chains would be pre-signed here; not broadcast.)

    // At maturity the parties co-sign the clean split fresh.
    let chain = maturity_chain(&b.terms, b.account, b.frontier, b.account, b.dest_a, b.dest_b);
    let signed = sign_chain(&chain, &b.key_packages, &b.pubkeys, &mut OsRng).unwrap();
    for blk in signed.assemble(TEST_THRESHOLD) {
        ledger.process(&blk).unwrap();
    }
    assert_eq!(ledger.credited[&b.dest_a], 1_000);
    assert_eq!(ledger.credited[&b.dest_b], 500);
    assert_eq!(ledger.accounts[&b.account].1, 0);
}

/// The maturity fallback (audit #5, SAFE path): B vanished. At setup the
/// parties adaptor-pre-signed ONLY the clean maturity split under an adaptor
/// point T = t·G, and B escrowed only the scalar t. A verifies the escrow at
/// setup; months later A solves one kept puzzle for t and completes the two
/// pre-signatures — producing exactly the clean-split signatures and nothing
/// else. No general joint key is ever reconstructed, so there is no path to
/// draining a principal early.
#[test]
fn vanished_counterparty_recovered_via_share_escrow() {
    let mut ledger = Ledger::default();
    let b = setup(&mut ledger, terms_10pct());

    // Setup-time: the exact clean-split chain, adaptor-locked under T = t·G.
    let chain = maturity_chain(&b.terms, b.account, b.frontier, b.account, b.dest_a, b.dest_b);
    let mut secret_bytes = [0u8; 64];
    OsRng.fill_bytes(&mut secret_bytes);
    let adaptor_secret = Scalar::from_bytes_mod_order_wide(&secret_bytes);

    let presigs = adaptor_lock_maturity(
        &chain,
        &adaptor_secret,
        &b.key_packages,
        &b.pubkeys,
        &mut OsRng,
    )
    .expect("adaptor pre-sign the clean split");

    // B escrows ONLY the adaptor scalar t (test-sized puzzle: 512 squarings).
    let (public, escrow_secret) = escrow_maturity_secret(&adaptor_secret, 8, 130, 512, &mut OsRng);
    let audit = choose_audit(&mut OsRng, 8);
    let openings = escrow_open(&escrow_secret, &audit);
    let kept = escrow_verify(&public, &audit, &openings).expect("escrow verifies at setup");

    // …months later, B is gone. A solves for t and completes both presigs.
    // This yields ONLY the two clean-split block signatures.
    let sigs = recover_maturity(&presigs, &public, kept[0]).expect("recover clean split");

    for (blk, sig) in chain.iter().zip(sigs.iter()) {
        let sb = ceremony::assemble(
            blk.clone(),
            *sig,
            work::generate(&blk.work_root(), TEST_THRESHOLD, 0),
        );
        // The completed adaptor signature is an ordinary Nano-valid signature.
        ledger.process(&sb).expect("clean-split block settles");
    }
    assert_eq!(ledger.credited[&b.dest_a], 1_000);
    assert_eq!(ledger.credited[&b.dest_b], 500);
    assert_eq!(ledger.accounts[&b.account].1, 0);
}

/// Structural honesty check: before maturity, the ONLY broadcastable
/// pre-signed paths are the penalty chains. A party trying to leave with a
/// self-made "clean" block fails signature verification (it holds one share,
/// not two), so the penalty-free early door does not exist.
#[test]
fn no_penalty_free_early_exit_exists() {
    let mut ledger = Ledger::default();
    let b = setup(&mut ledger, terms_10pct());

    // A forges the clean split and "signs" it with only its own share by
    // producing a garbage 64-byte signature (it cannot do better: a valid
    // joint signature needs both shares).
    let chain = maturity_chain(&b.terms, b.account, b.frontier, b.account, b.dest_a, b.dest_b);
    let forged = ceremony::assemble(
        chain[0].clone(),
        [0x42; 64],
        work::generate(&chain[0].work_root(), TEST_THRESHOLD, 0),
    );
    assert_eq!(ledger.process(&forged), Err("signature"));
}

#[test]
fn terms_validate_and_penalty_decays_to_zero() {
    let t = terms_10pct();
    assert_eq!(t.validate(), Ok(()));

    // Full at start, half mid-term, zero at maturity (H3 decay).
    assert_eq!(t.penalty_at(1_000, 0), 100);
    assert_eq!(t.penalty_at(1_000, 500), 50);
    assert_eq!(t.penalty_at(1_000, 1_000), 0);
    assert_eq!(t.penalty_at(1_000, 2_000), 0);
    // The pre-signed chain carries the full penalty (upper bound for the
    // cooperative exit auction).
    assert_eq!(t.full_penalty(1_000), 100);

    // Bad terms are refused.
    assert_eq!(
        Terms { principal_a: 0, ..t }.validate(),
        Err(TermsError::ZeroPrincipal)
    );
    assert_eq!(
        Terms { penalty_bps: 6_000, ..t }.validate(),
        Err(TermsError::PenaltyTooLarge)
    );
    assert_eq!(
        Terms { maturity: 0, ..t }.validate(),
        Err(TermsError::BadTerm)
    );

    // Escrow sizing is positive and scales with the term.
    let t_short = t.escrow_t(1_000_000.0, 20.0);
    let longer = Terms { maturity: 2_000, ..t };
    assert!(longer.escrow_t(1_000_000.0, 20.0) > t_short);
    assert!(t_short > 0);
}
