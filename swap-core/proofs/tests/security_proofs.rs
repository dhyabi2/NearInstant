//! Adversarial security proofs. Each test names a protocol claim and then
//! *attacks* it: the attacker attempt must fail, the honest path must succeed.
//! Every primitive here is the real one the swap uses — no mocks.

use std::collections::BTreeMap;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use rand_core::{OsRng, RngCore};

use nano_ceremony::block::{StateBlock, Subtype};
use nano_ceremony::ceremony;
use signing::adaptor::{complete_presignature, extract_secret, verify_presignature, PreSignature};
use signing::{keys, round1, Identifier};

// ---------------------------------------------------------------------------
// helpers — a real 2-of-2 distributed keygen (no trusted dealer) and joint sign
// ---------------------------------------------------------------------------

fn dkg_2of2() -> (BTreeMap<Identifier, keys::KeyPackage>, keys::PublicKeyPackage) {
    let alice = Identifier::try_from(1u16).unwrap();
    let bob = Identifier::try_from(2u16).unwrap();
    let (a1s, a1p) = keys::dkg::part1(alice, OsRng).unwrap();
    let (b1s, b1p) = keys::dkg::part1(bob, OsRng).unwrap();
    let mut a1 = BTreeMap::new();
    a1.insert(bob, b1p.clone());
    let mut b1 = BTreeMap::new();
    b1.insert(alice, a1p.clone());
    let (a2s, a2) = keys::dkg::part2(a1s, &a1).unwrap();
    let (b2s, b2) = keys::dkg::part2(b1s, &b1).unwrap();
    let mut arecv = BTreeMap::new();
    arecv.insert(bob, b2.get(&alice).unwrap().clone());
    let mut brecv = BTreeMap::new();
    brecv.insert(alice, a2.get(&bob).unwrap().clone());
    let (akp, apub) = keys::dkg::part3(&a2s, &a1, &arecv).unwrap();
    let (bkp, _bpub) = keys::dkg::part3(&b2s, &b1, &brecv).unwrap();
    let mut kps = BTreeMap::new();
    kps.insert(alice, akp);
    kps.insert(bob, bkp);
    (kps, apub)
}

fn commit_all(
    kps: &BTreeMap<Identifier, keys::KeyPackage>,
) -> (
    BTreeMap<Identifier, round1::SigningNonces>,
    BTreeMap<Identifier, round1::SigningCommitments>,
) {
    let mut nonces = BTreeMap::new();
    let mut comms = BTreeMap::new();
    for (id, kp) in kps {
        let (n, c) = round1::commit(kp.signing_share(), &mut OsRng);
        nonces.insert(*id, n);
        comms.insert(*id, c);
    }
    (nonces, comms)
}

fn account_of(pubkeys: &keys::PublicKeyPackage) -> [u8; 32] {
    pubkeys.verifying_key().serialize().unwrap().try_into().unwrap()
}

fn rand_scalar() -> Scalar {
    let mut wide = [0u8; 64];
    OsRng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn spend_pub(s: &Scalar) -> [u8; 32] {
    (s * ED25519_BASEPOINT_TABLE).compress().to_bytes()
}

fn claim_block(account: [u8; 32]) -> StateBlock {
    StateBlock {
        account,
        previous: [0x11; 32],
        representative: account,
        balance: 0,
        link: [0xB0; 32],
        subtype: Subtype::Send,
    }
}

fn presign(
    block: &StateBlock,
    t: &[u8; 32],
    kps: &BTreeMap<Identifier, keys::KeyPackage>,
    pubkeys: &keys::PublicKeyPackage,
) -> PreSignature {
    let (nonces, comms) = commit_all(kps);
    ceremony::adaptor_presign_block(block, t, comms, &nonces, kps, pubkeys).expect("presign")
}

// ===========================================================================
// P1 — ADAPTOR ATOMICITY
// The claim can only be completed by revealing exactly the adaptor secret x,
// and that revelation is inevitable once the claim is broadcast.
// ===========================================================================

/// CLAIM: the honest swap completes, and completing reveals *exactly* x.
#[test]
fn p1_honest_swap_completes_and_reveals_exactly_x() {
    let (kps, pubkeys) = dkg_2of2();
    let account = account_of(&pubkeys);
    let x = rand_scalar();
    let t = spend_pub(&x);
    let claim = claim_block(account);
    let hash = claim.hash();

    let presig = presign(&claim, &t, &kps, &pubkeys);
    assert!(verify_presignature(&presig, &account, &hash).is_ok(), "pre-sig must verify");

    let sig = complete_presignature(&presig, &x.to_bytes()).expect("complete with x");
    assert!(signing::nano_verify::verify(&account, &hash, &sig), "completed claim must be valid");

    let extracted = extract_secret(&presig, &sig).expect("extract");
    assert_eq!(extracted, x.to_bytes(), "the ONLY secret the claim can reveal is x");
}

/// ATTACK: broadcast the pre-signature as if it were a finished signature
/// (take the XNO without revealing x). Must be rejected by Nano verification.
#[test]
fn p1_presignature_alone_is_not_a_valid_signature() {
    let (kps, pubkeys) = dkg_2of2();
    let account = account_of(&pubkeys);
    let x = rand_scalar();
    let claim = claim_block(account);
    let presig = presign(&claim, &spend_pub(&x), &kps, &pubkeys);

    let mut forged = [0u8; 64];
    forged[..32].copy_from_slice(&presig.r_adapted);
    forged[32..].copy_from_slice(&presig.s_hat); // ŝ opens R'−T, not R'
    assert!(
        !signing::nano_verify::verify(&account, &claim.hash(), &forged),
        "pre-signature must NOT verify on its own — otherwise x would never be revealed"
    );
}

/// ATTACK: complete the claim with a guessed / wrong secret. Must be rejected
/// (the secret must satisfy x·G = T).
#[test]
fn p1_completing_with_the_wrong_secret_is_rejected() {
    let (kps, pubkeys) = dkg_2of2();
    let account = account_of(&pubkeys);
    let x = rand_scalar();
    let claim = claim_block(account);
    let presig = presign(&claim, &spend_pub(&x), &kps, &pubkeys);

    let wrong = (x + Scalar::ONE).to_bytes();
    assert!(
        complete_presignature(&presig, &wrong).is_err(),
        "completing with a wrong secret must fail"
    );
}

/// ATTACK: reuse a pre-signature bound to one claim on a *different* claim
/// block (e.g. one draining a different amount). Must fail the adaptor relation.
#[test]
fn p1_presignature_is_bound_to_its_exact_message() {
    let (kps, pubkeys) = dkg_2of2();
    let account = account_of(&pubkeys);
    let x = rand_scalar();
    let claim = claim_block(account);
    let presig = presign(&claim, &spend_pub(&x), &kps, &pubkeys);

    let mut other = claim_block(account);
    other.link = [0xC1; 32]; // a different block ⇒ different hash
    assert_ne!(other.hash(), claim.hash());
    assert!(
        verify_presignature(&presig, &account, &other.hash()).is_err(),
        "a pre-signature must not be valid for any block other than the one signed"
    );
}

/// ATTACK: swap the adaptor point T for one whose secret the attacker knows,
/// hoping the pre-signature still verifies (which would let them complete it).
/// Must break verification.
#[test]
fn p1_tampering_the_adaptor_point_breaks_verification() {
    let (kps, pubkeys) = dkg_2of2();
    let account = account_of(&pubkeys);
    let x = rand_scalar();
    let claim = claim_block(account);
    let mut presig = presign(&claim, &spend_pub(&x), &kps, &pubkeys);

    let evil = rand_scalar(); // attacker knows `evil`
    presig.adaptor_point = spend_pub(&evil);
    assert!(
        verify_presignature(&presig, &account, &claim.hash()).is_err(),
        "re-pointing T must invalidate the pre-signature"
    );
}

// ===========================================================================
// P2 — CROSS-CHAIN BINDING
// The secret that unlocks the XMR-seller's Nano claim is EXACTLY the Monero
// share the XNO-seller is missing from the 2-of-2 joint spend key.
// ===========================================================================

use monero_wallet::address::Network;

/// CLAIM: one secret unlocks both legs. The x revealed by the Nano claim,
/// combined with the XNO-seller's own Monero share, opens the joint Monero
/// spend key — so the sweep is guaranteed the instant the claim is public.
#[test]
fn p2_one_secret_unlocks_both_legs() {
    let ctx = [0x42u8; 32];
    let alice_xmr = rand_scalar(); // XNO-seller's Monero share
    let bob_xmr = rand_scalar(); // XMR-seller's Monero share == the adaptor secret x
    let a_pub = spend_pub(&alice_xmr);
    let b_pub = spend_pub(&bob_xmr);

    let joint = wasm_monero::joint_info(ctx, a_pub, b_pub, [0x01; 32], [0x02; 32], Network::Stagenet)
        .expect("joint info");

    // The adaptor point is the XMR-seller's Monero spend pubkey.
    let x = bob_xmr;
    let t = spend_pub(&x);
    assert_eq!(t, b_pub, "adaptor point == XMR-seller's Monero spend key");

    // Nano leg: pre-sign the claim bound to T, complete with x, extract x back.
    let (kps, pubkeys) = dkg_2of2();
    let account = account_of(&pubkeys);
    let claim = claim_block(account);
    let presig = presign(&claim, &t, &kps, &pubkeys);
    let sig = complete_presignature(&presig, &x.to_bytes()).expect("complete");
    let revealed = extract_secret(&presig, &sig).expect("extract");
    assert_eq!(revealed, x.to_bytes());

    // Monero leg: XNO-seller reconstructs the joint secret with its own share +
    // the revealed x, and it opens the joint address.
    let joint_secret = wasm_monero::joint_secret(ctx, alice_xmr.to_bytes(), revealed)
        .expect("reconstruct joint secret");
    let opens = spend_pub(
        &Option::<Scalar>::from(Scalar::from_canonical_bytes(joint_secret)).expect("canonical"),
    );
    assert_eq!(opens, joint.spend_pub, "revealed x opens the joint Monero spend key");
}

/// ATTACK: the XNO-seller tries to sweep the joint Monero BEFORE the claim is
/// broadcast — i.e. with only its own share. Must be impossible.
#[test]
fn p2_xno_seller_cannot_open_the_joint_before_the_reveal() {
    let ctx = [0x42u8; 32];
    let alice_xmr = rand_scalar();
    let bob_xmr = rand_scalar();
    let joint = wasm_monero::joint_info(
        ctx,
        spend_pub(&alice_xmr),
        spend_pub(&bob_xmr),
        [0x01; 32],
        [0x02; 32],
        Network::Stagenet,
    )
    .expect("joint info");

    // Its own share alone is not the joint key.
    assert_ne!(spend_pub(&alice_xmr), joint.spend_pub);

    // And it cannot fabricate the joint by pretending its own share is also the
    // counterparty's: the MuSig keygen refuses a duplicated participant, so no
    // joint secret is produced at all.
    assert!(
        wasm_monero::joint_secret(ctx, alice_xmr.to_bytes(), alice_xmr.to_bytes()).is_err(),
        "reconstructing the joint from one share (used twice) must be refused"
    );

    // Even the honest reconstruction needs BOTH true shares — with only one, the
    // XNO-seller is stuck until x is revealed on Nano.
    let real = wasm_monero::joint_secret(ctx, alice_xmr.to_bytes(), bob_xmr.to_bytes())
        .expect("both shares reconstruct");
    let opens = spend_pub(
        &Option::<Scalar>::from(Scalar::from_canonical_bytes(real)).expect("canonical"),
    );
    assert_eq!(opens, joint.spend_pub, "only the true 2-of-2 pair opens the joint key");
}

// ===========================================================================
// P3 — 2-of-2 REQUIRES BOTH PARTIES
// Neither the joint Nano account nor the joint Monero key can be used by one
// party alone.
// ===========================================================================

/// ATTACK: one party signs the claim block with only its own share and
/// broadcasts. Must not verify for the joint account.
#[test]
fn p3_a_single_party_cannot_sign_for_the_joint_account() {
    let (kps, pubkeys) = dkg_2of2();
    let account = account_of(&pubkeys);
    let alice = Identifier::try_from(1u16).unwrap();

    // Only Alice commits and signs.
    let (n_all, c_all) = commit_all(&kps);
    let mut one_comm = BTreeMap::new();
    one_comm.insert(alice, c_all[&alice].clone());
    let mut one_nonce = BTreeMap::new();
    one_nonce.insert(alice, n_all[&alice].clone());
    let mut one_kp = BTreeMap::new();
    one_kp.insert(alice, kps[&alice].clone());

    let block = claim_block(account);
    // Whether this errors or produces a signature, it must NOT be a valid
    // signature for the joint account.
    match ceremony::sign_block(&block, one_comm, &one_nonce, &one_kp, &pubkeys) {
        Ok(sig) => assert!(
            !signing::nano_verify::verify(&account, &block.hash(), &sig),
            "a one-party signature must not verify for the 2-of-2 joint account"
        ),
        Err(_) => { /* refusing to produce one is also a valid outcome */ }
    }
}

// ===========================================================================
// P4 — SETTLEMENT READS ARE FAIL-CLOSED (anti-lying-node / anti-eclipse)
// A confirmation read across nodes accepts only on unanimous, sized agreement;
// any disagreement is a stop, never a majority vote.
// ===========================================================================

use monero_side::eclipse::quorum_agrees;

/// ATTACK: a lying (or eclipsing) node reports a different block at the target
/// height to force a false confirmation. Must be refused.
#[test]
fn p4_confirmation_quorum_is_fail_closed() {
    let good = [0x07u8; 32];
    let lie = [0x08u8; 32];

    // Honest: enough independent views, all agreeing.
    assert!(quorum_agrees(&[good, good, good], 3), "unanimous, sized ⇒ accept");

    // Attack: one node disagrees ⇒ refuse (NOT a 2/3 majority accept).
    assert!(!quorum_agrees(&[good, good, lie], 3), "any disagreement ⇒ refuse");

    // Attack: too few independent views (can't rule out eclipse) ⇒ refuse.
    assert!(!quorum_agrees(&[good, good], 3), "under-quorum ⇒ refuse");

    // Degenerate: no views ⇒ refuse.
    assert!(!quorum_agrees(&[], 1), "no views ⇒ refuse");
}
