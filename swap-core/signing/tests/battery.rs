//! Block 1 verification battery (issue I2): plain FROST signing verified as a
//! Nano signature, the full adaptor lifecycle, tamper rejection, and
//! edge-scalar adaptor secrets.

use std::collections::BTreeMap;

use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use rand::rngs::OsRng;

use signing::adaptor::{
    adaptor_sign, aggregate_presignature, complete_presignature, extract_secret,
    verify_adaptor_share, verify_presignature, AdaptorError, AdaptorSession, PreSignature,
};
use signing::{keys, nano_verify, round1, round2, Identifier};

struct Party {
    id: Identifier,
    key_package: keys::KeyPackage,
}

fn setup_2of2() -> (Vec<Party>, keys::PublicKeyPackage) {
    let (shares, pubkeys) =
        keys::generate_with_dealer(2, 2, keys::IdentifierList::Default, &mut OsRng)
            .expect("dealer keygen");
    let mut parties = Vec::new();
    for (id, share) in shares {
        let key_package = keys::KeyPackage::try_from(share).expect("share verifies");
        parties.push(Party { id, key_package });
    }
    (parties, pubkeys)
}

fn commit_round(
    parties: &[Party],
) -> (
    BTreeMap<Identifier, round1::SigningNonces>,
    BTreeMap<Identifier, round1::SigningCommitments>,
) {
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for p in parties {
        let (n, c) = round1::commit(p.key_package.signing_share(), &mut OsRng);
        nonces.insert(p.id, n);
        commitments.insert(p.id, c);
    }
    (nonces, commitments)
}

fn group_pubkey_bytes(pubkeys: &keys::PublicKeyPackage) -> [u8; 32] {
    pubkeys
        .verifying_key()
        .serialize()
        .expect("serialize vk")
        .as_slice()
        .try_into()
        .expect("32 bytes")
}

/// Run the full adaptor ceremony for an adaptor secret x, returning
/// (presignature, group public key bytes, message).
fn run_adaptor_ceremony(x: Scalar, message: &[u8]) -> (PreSignature, [u8; 32]) {
    let (parties, pubkeys) = setup_2of2();
    let (nonces, commitments) = commit_round(&parties);
    let t_bytes = EdwardsPoint::mul_base(&x).compress().to_bytes();

    let session = AdaptorSession::new(commitments, message, &t_bytes).expect("session");

    let mut shares = BTreeMap::new();
    for p in &parties {
        let share = adaptor_sign(&session, &nonces[&p.id], &p.key_package).expect("adaptor sign");
        // Cross-verify each share as the counterparty would.
        verify_adaptor_share(
            &session,
            p.id,
            &share,
            pubkeys.verifying_shares().get(&p.id).unwrap(),
            pubkeys.verifying_key(),
        )
        .expect("share verifies");
        shares.insert(p.id, share);
    }

    let presig = aggregate_presignature(&session, &shares, &pubkeys).expect("aggregate");
    (presig, group_pubkey_bytes(&pubkeys))
}

#[test]
fn two_party_dkg_yields_matching_key_and_signs() {
    // No trusted dealer: Alice (id 1) and Bob (id 2) run the three DKG parts.
    let alice_id = Identifier::try_from(1u16).unwrap();
    let bob_id = Identifier::try_from(2u16).unwrap();

    let (a_r1_secret, a_r1_pkg) = keys::dkg::part1(alice_id, OsRng).expect("a part1");
    let (b_r1_secret, b_r1_pkg) = keys::dkg::part1(bob_id, OsRng).expect("b part1");

    let mut a_r1_map = BTreeMap::new();
    a_r1_map.insert(bob_id, b_r1_pkg.clone());
    let mut b_r1_map = BTreeMap::new();
    b_r1_map.insert(alice_id, a_r1_pkg.clone());

    let (a_r2_secret, a_r2_map) = keys::dkg::part2(a_r1_secret, &a_r1_map).expect("a part2");
    let (b_r2_secret, b_r2_map) = keys::dkg::part2(b_r1_secret, &b_r1_map).expect("b part2");

    // Each sends the round-2 package addressed to the other.
    let a_to_b = a_r2_map.get(&bob_id).unwrap().clone();
    let b_to_a = b_r2_map.get(&alice_id).unwrap().clone();

    let mut a_recv = BTreeMap::new();
    a_recv.insert(bob_id, b_to_a);
    let mut b_recv = BTreeMap::new();
    b_recv.insert(alice_id, a_to_b);

    let (a_kp, a_pubkeys) = keys::dkg::part3(&a_r2_secret, &a_r1_map, &a_recv).expect("a part3");
    let (b_kp, b_pubkeys) = keys::dkg::part3(&b_r2_secret, &b_r1_map, &b_recv).expect("b part3");

    // Both parties derive the IDENTICAL joint verifying key.
    assert_eq!(
        group_pubkey_bytes(&a_pubkeys),
        group_pubkey_bytes(&b_pubkeys),
        "DKG parties agree on the joint key"
    );

    // And they can jointly sign under it (Nano-valid).
    let message = b"nano block hash stand-in: 32 bytes long msg";
    let parties = vec![
        Party { id: alice_id, key_package: a_kp },
        Party { id: bob_id, key_package: b_kp },
    ];
    let (nonces, commitments) = commit_round(&parties);
    let package = signing::SigningPackage::new(commitments, message);
    let mut shares = BTreeMap::new();
    for p in &parties {
        shares.insert(
            p.id,
            round2::sign(&package, &nonces[&p.id], &p.key_package).expect("sign"),
        );
    }
    let sig = signing::aggregate(&package, &shares, &a_pubkeys).expect("aggregate");
    let sig_bytes: [u8; 64] = sig.serialize().unwrap().try_into().unwrap();
    assert!(nano_verify::verify(&group_pubkey_bytes(&a_pubkeys), message, &sig_bytes));
}

#[test]
fn plain_frost_signature_is_a_valid_nano_signature() {
    let (parties, pubkeys) = setup_2of2();
    let (nonces, commitments) = commit_round(&parties);
    let message = b"nano block hash stand-in: 32 bytes long msg";
    let package = signing::SigningPackage::new(commitments, message);

    let mut shares = BTreeMap::new();
    for p in &parties {
        shares.insert(
            p.id,
            round2::sign(&package, &nonces[&p.id], &p.key_package).expect("sign"),
        );
    }
    let sig = signing::aggregate(&package, &shares, &pubkeys).expect("aggregate");

    // frost-core's own verifier accepts it…
    pubkeys
        .verifying_key()
        .verify(message, &sig)
        .expect("frost verify");

    // …and the independent ed25519-blake2b verifier (Nano semantics) does too.
    let sig_bytes: [u8; 64] = sig
        .serialize()
        .expect("serialize sig")
        .as_slice()
        .try_into()
        .expect("64 bytes");
    let pk = group_pubkey_bytes(&pubkeys);
    assert!(nano_verify::verify(&pk, message, &sig_bytes));

    // Tampered message must fail.
    assert!(!nano_verify::verify(&pk, b"different message", &sig_bytes));
}

#[test]
fn adaptor_lifecycle_complete_and_extract() {
    let x = Scalar::from_bytes_mod_order_wide(&[7u8; 64]);
    let message = b"chunk 17: pay 0.5 XNO to joint account";
    let (presig, pk) = run_adaptor_ceremony(x, message);

    // The pre-signature satisfies the adaptor relation…
    verify_presignature(&presig, &pk, message).expect("presig verifies");

    // …but is NOT a valid Nano signature by itself.
    let mut fake_sig = [0u8; 64];
    fake_sig[..32].copy_from_slice(&presig.r_adapted);
    fake_sig[32..].copy_from_slice(&presig.s_hat);
    assert!(
        !nano_verify::verify(&pk, message, &fake_sig),
        "pre-signature must be invalid alone"
    );

    // Completion with x yields a valid Nano signature.
    let sig = complete_presignature(&presig, &x.to_bytes()).expect("complete");
    assert!(nano_verify::verify(&pk, message, &sig));

    // Anyone holding the pre-signature extracts exactly x from the broadcast.
    let extracted = extract_secret(&presig, &sig).expect("extract");
    assert_eq!(extracted, x.to_bytes());
}

#[test]
fn adaptor_rejects_wrong_secret_and_foreign_signature() {
    let x = Scalar::from_bytes_mod_order_wide(&[9u8; 64]);
    let message = b"swap session 42";
    let (presig, pk) = run_adaptor_ceremony(x, message);

    // Completing with the wrong secret is refused (x·G ≠ T).
    let wrong = Scalar::from_bytes_mod_order_wide(&[10u8; 64]);
    assert!(matches!(
        complete_presignature(&presig, &wrong.to_bytes()),
        Err(AdaptorError::ExtractedSecretMismatch)
    ));

    // Extraction from a signature of a different ceremony is refused.
    let (other_presig, _) = run_adaptor_ceremony(x, message);
    let other_sig = complete_presignature(&other_presig, &x.to_bytes()).expect("complete other");
    assert!(extract_secret(&presig, &other_sig).is_err());

    // A tampered pre-signature fails public verification.
    let mut bad = presig;
    bad.s_hat[0] ^= 1;
    assert!(verify_presignature(&bad, &pk, message).is_err());
}

#[test]
fn adaptor_share_from_wrong_transcript_is_rejected() {
    let (parties, pubkeys) = setup_2of2();
    let (nonces, commitments) = commit_round(&parties);
    let x = Scalar::from_bytes_mod_order_wide(&[3u8; 64]);
    let t_bytes = EdwardsPoint::mul_base(&x).compress().to_bytes();

    let session =
        AdaptorSession::new(commitments.clone(), b"message A", &t_bytes).expect("session A");
    let other_session =
        AdaptorSession::new(commitments, b"message B", &t_bytes).expect("session B");

    let p = &parties[0];
    let share = adaptor_sign(&session, &nonces[&p.id], &p.key_package).expect("sign");

    // Valid against its own session, invalid against a different message's.
    verify_adaptor_share(
        &session,
        p.id,
        &share,
        pubkeys.verifying_shares().get(&p.id).unwrap(),
        pubkeys.verifying_key(),
    )
    .expect("verifies in own session");
    assert!(verify_adaptor_share(
        &other_session,
        p.id,
        &share,
        pubkeys.verifying_shares().get(&p.id).unwrap(),
        pubkeys.verifying_key(),
    )
    .is_err());
}

#[test]
fn adaptor_rejects_identity_and_noncanonical_points() {
    let (parties, _pubkeys) = setup_2of2();
    let (_nonces, commitments) = commit_round(&parties);

    // x = 0 ⇒ T = identity: refused outright (a zero secret would make the
    // pre-signature immediately valid — the I2 "rejected en route" failure).
    use curve25519_dalek::traits::Identity;
    let identity = curve25519_dalek::edwards::CompressedEdwardsY::identity().to_bytes();
    assert!(matches!(
        AdaptorSession::new(commitments.clone(), b"m", &identity),
        Err(AdaptorError::InvalidAdaptorPoint)
    ));

    // A small-order point is refused.
    let small_order: [u8; 32] = curve25519_dalek::constants::EIGHT_TORSION[1]
        .compress()
        .to_bytes();
    assert!(matches!(
        AdaptorSession::new(commitments, b"m", &small_order),
        Err(AdaptorError::InvalidAdaptorPoint)
    ));
}

#[test]
fn adaptor_edge_scalars_one_and_order_minus_one() {
    for x in [Scalar::ONE, -Scalar::ONE] {
        let message = b"edge scalar ceremony";
        let (presig, pk) = run_adaptor_ceremony(x, message);
        verify_presignature(&presig, &pk, message).expect("presig verifies");
        let sig = complete_presignature(&presig, &x.to_bytes()).expect("complete");
        assert!(nano_verify::verify(&pk, message, &sig));
        assert_eq!(extract_secret(&presig, &sig).expect("extract"), x.to_bytes());
    }
}

#[test]
fn frost_ed25519_sha512_signature_does_not_verify_as_nano() {
    // Sanity check that the blake2b challenge is actually load-bearing: a
    // standard FROST(Ed25519, SHA-512) signature over the same message must
    // NOT pass the Nano verifier.
    use frost_ed25519 as sha_frost;
    let (shares, pubkeys) = sha_frost::keys::generate_with_dealer(
        2,
        2,
        sha_frost::keys::IdentifierList::Default,
        OsRng,
    )
    .expect("keygen");
    let message = b"same message";
    let mut nonces_map = BTreeMap::new();
    let mut comms_map = BTreeMap::new();
    let mut kps = BTreeMap::new();
    for (id, share) in shares {
        let kp = sha_frost::keys::KeyPackage::try_from(share).expect("kp");
        let (n, c) = sha_frost::round1::commit(kp.signing_share(), &mut OsRng);
        nonces_map.insert(id, n);
        comms_map.insert(id, c);
        kps.insert(id, kp);
    }
    let package = sha_frost::SigningPackage::new(comms_map, message);
    let mut sig_shares = BTreeMap::new();
    for (id, kp) in &kps {
        sig_shares.insert(
            *id,
            sha_frost::round2::sign(&package, &nonces_map[id], kp).expect("sign"),
        );
    }
    let sig = sha_frost::aggregate(&package, &sig_shares, &pubkeys).expect("aggregate");

    let pk: [u8; 32] = pubkeys
        .verifying_key()
        .serialize()
        .expect("ser")
        .as_slice()
        .try_into()
        .expect("32");
    let sig_bytes: [u8; 64] = sig
        .serialize()
        .expect("ser")
        .as_slice()
        .try_into()
        .expect("64");
    assert!(!nano_verify::verify(&pk, message, &sig_bytes));
}
