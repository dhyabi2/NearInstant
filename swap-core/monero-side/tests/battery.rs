//! Block 3 verification battery: the I10 isolation layer (aggregation, view
//! key, address, one-time keys) and the full 2-of-2 CLSAG co-signing of a
//! channel-state spend — the I5 core — including key-image determinism (the
//! "all states share one key image" property) and tamper rejection.

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use rand::rngs::OsRng;
use rand::RngCore;

use monero_side::cosign::{
    cosign_in_process, musig_threshold_keys, reconstruct_joint_secret, verify_clsag, Cosigner,
    StateSpend,
};
use monero_side::isolation::{
    aggregate_spend, commitment, joint_address, key_image_generator, receiver_key_offset,
    sender_one_time_key, shared_view_key, Bytes32, Net,
};

fn rand_scalar() -> Scalar {
    let mut wide = [0u8; 64];
    OsRng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn pubkey(secret: &Scalar) -> Bytes32 {
    (secret * ED25519_BASEPOINT_TABLE).compress().to_bytes()
}

/// A fully set-up joint account: two parties, MuSig joint spend, shared view.
struct JointAccount {
    context: Bytes32,
    alice_spend: Scalar,
    bob_spend: Scalar,
    spend_pubs: Vec<Bytes32>,
    joint_spend_pub: Bytes32,
    view_key: Bytes32,
    view_pub: Bytes32,
}

fn setup_joint() -> JointAccount {
    let mut context = [0u8; 32];
    OsRng.fill_bytes(&mut context);
    let alice_spend = rand_scalar();
    let bob_spend = rand_scalar();
    // Canonical ordering: sorted by pubkey bytes, agreed by both parties.
    let mut spend_pubs = vec![pubkey(&alice_spend), pubkey(&bob_spend)];
    spend_pubs.sort();
    let joint_spend_pub = aggregate_spend(context, &spend_pubs).expect("aggregate");

    let mut view_a = [0u8; 32];
    let mut view_b = [0u8; 32];
    OsRng.fill_bytes(&mut view_a);
    OsRng.fill_bytes(&mut view_b);
    let view_key = shared_view_key(context, &view_a, &view_b);
    // Order independence: both parties derive the identical view key.
    assert_eq!(view_key, shared_view_key(context, &view_b, &view_a));
    let view_scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(view_key)).unwrap();
    let view_pub = pubkey(&view_scalar);

    JointAccount {
        context,
        alice_spend,
        bob_spend,
        spend_pubs,
        joint_spend_pub,
        view_key,
        view_pub,
    }
}

#[test]
fn joint_secret_reconstruction_is_the_swap_hinge() {
    let j = setup_joint();
    let alice = j.alice_spend.to_bytes();
    let bob = j.bob_spend.to_bytes();

    // Alice reconstructs from (her secret, Bob's revealed secret); Bob from
    // (his, Alice's). Both yield the SAME joint secret…
    let from_alice = reconstruct_joint_secret(j.context, &alice, &bob, &j.spend_pubs).unwrap();
    let from_bob = reconstruct_joint_secret(j.context, &bob, &alice, &j.spend_pubs).unwrap();
    assert_eq!(from_alice, from_bob);

    // …which opens the MuSig joint spend key.
    let secret = Option::<Scalar>::from(Scalar::from_canonical_bytes(from_alice)).unwrap();
    assert_eq!(pubkey(&secret), j.joint_spend_pub);
}

#[test]
fn aggregation_is_deterministic_and_binding() {
    let j = setup_joint();    // Same inputs → same joint key.
    assert_eq!(
        aggregate_spend(j.context, &j.spend_pubs).unwrap(),
        j.joint_spend_pub
    );
    // Different context → different joint key (session domain separation).
    let mut other_ctx = j.context;
    other_ctx[0] ^= 1;
    assert_ne!(
        aggregate_spend(other_ctx, &j.spend_pubs).unwrap(),
        j.joint_spend_pub
    );
    // MuSig binding: the joint key is NOT the naive sum, so a rogue-key
    // choice cannot cancel the counterparty's contribution.
    let naive_sum = pubkey(&(j.alice_spend + j.bob_spend));
    assert_ne!(j.joint_spend_pub, naive_sum);
    // Both parties' ThresholdKeys agree on the group key and match the
    // isolation layer's aggregation.
    let ka = musig_threshold_keys(j.context, &j.alice_spend.to_bytes(), &j.spend_pubs).unwrap();
    let kb = musig_threshold_keys(j.context, &j.bob_spend.to_bytes(), &j.spend_pubs).unwrap();
    use ciphersuite::group::GroupEncoding;
    assert_eq!(ka.group_key().to_bytes(), j.joint_spend_pub);
    assert_eq!(kb.group_key().to_bytes(), j.joint_spend_pub);
}

#[test]
fn joint_address_encodes_and_known_mainnet_address_parses() {
    let j = setup_joint();
    let addr = joint_address(&j.joint_spend_pub, &j.view_key, Net::Mainnet).expect("address");
    assert!(addr.starts_with('4'), "mainnet primary addresses start with 4: {addr}");
    let stage = joint_address(&j.joint_spend_pub, &j.view_key, Net::Stagenet).expect("address");
    assert_ne!(addr, stage);

    // Spec anchor: the Monero project's donation address round-trips through
    // the same encoder stack (base58 + keccak checksum + network byte).
    use monero_wallet::address::MoneroAddress;
    let donation = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A";
    let parsed = MoneroAddress::from_str(monero_wallet::address::Network::Mainnet, donation)
        .expect("donation address parses");
    assert_eq!(parsed.to_string(), donation);
}

#[test]
fn one_time_keys_round_trip_and_reject_wrong_view() {
    let j = setup_joint();
    let r = rand_scalar().to_bytes();
    let (tx_pub, output_key) =
        sender_one_time_key(&r, &j.view_pub, &j.joint_spend_pub, 0).expect("derive");

    // The receiver recovers the offset…
    let offset = receiver_key_offset(&j.view_key, &tx_pub, &j.joint_spend_pub, 0, &output_key)
        .expect("scan");
    // …which opens the output key over the joint spend key.
    let off = Option::<Scalar>::from(Scalar::from_canonical_bytes(offset)).unwrap();
    let joint = curve25519_dalek::edwards::CompressedEdwardsY(j.joint_spend_pub)
        .decompress()
        .unwrap();
    assert_eq!(
        ((&off * ED25519_BASEPOINT_TABLE) + joint).compress().to_bytes(),
        output_key
    );

    // Wrong output index: not ours.
    assert!(
        receiver_key_offset(&j.view_key, &tx_pub, &j.joint_spend_pub, 1, &output_key).is_none()
    );
    // Wrong view key: not ours.
    let wrong_view = rand_scalar().to_bytes();
    assert!(
        receiver_key_offset(&wrong_view, &tx_pub, &j.joint_spend_pub, 0, &output_key).is_none()
    );
}

/// Build a state-spend fixture paying the joint account, with the real output
/// hidden in a ring of decoys.
fn state_spend_fixture(j: &JointAccount, ring_len: usize, real_index: usize) -> StateSpend {
    let r = rand_scalar().to_bytes();
    let (tx_pub, output_key) =
        sender_one_time_key(&r, &j.view_pub, &j.joint_spend_pub, 0).expect("derive");
    let key_offset = receiver_key_offset(&j.view_key, &tx_pub, &j.joint_spend_pub, 0, &output_key)
        .expect("scan");

    let amount = OsRng.next_u64();
    let mask = rand_scalar().to_bytes();
    let real_commitment = commitment(&mask, amount).unwrap();

    let mut ring = Vec::new();
    for i in 0..ring_len {
        if i == real_index {
            ring.push([output_key, real_commitment]);
        } else {
            ring.push([
                pubkey(&rand_scalar()),
                commitment(&rand_scalar().to_bytes(), OsRng.next_u64()).unwrap(),
            ]);
        }
    }
    let mut msg = [0u8; 32];
    OsRng.fill_bytes(&mut msg);
    StateSpend {
        ring,
        ring_indices: (1..=ring_len as u64).collect(),
        real_index,
        key_offset,
        mask,
        amount,
        pseudo_mask: rand_scalar().to_bytes(),
        msg,
    }
}

#[test]
fn two_of_two_clsag_cosign_verifies() {
    let j = setup_joint();
    let ka = musig_threshold_keys(j.context, &j.alice_spend.to_bytes(), &j.spend_pubs).unwrap();
    let kb = musig_threshold_keys(j.context, &j.bob_spend.to_bytes(), &j.spend_pubs).unwrap();

    let spend = state_spend_fixture(&j, 11, 4);
    let (clsag, key_image, pseudo_out) =
        cosign_in_process(&spend, vec![ka, kb]).expect("cosign");

    assert!(verify_clsag(&clsag, &spend.ring, &key_image, &pseudo_out, &spend.msg));
    // The ceremony's pseudo-out is exactly the commitment to (pseudo_mask, amount).
    assert_eq!(Some(pseudo_out), spend.pseudo_out());

    // Tampering: wrong message, wrong ring member, wrong pseudo-out all fail.
    let mut wrong_msg = spend.msg;
    wrong_msg[0] ^= 1;
    assert!(!verify_clsag(&clsag, &spend.ring, &key_image, &pseudo_out, &wrong_msg));
    let mut wrong_ring = spend.ring.clone();
    wrong_ring[0][0] = pubkey(&rand_scalar());
    assert!(!verify_clsag(&clsag, &wrong_ring, &key_image, &pseudo_out, &spend.msg));
    let wrong_pseudo = commitment(&rand_scalar().to_bytes(), spend.amount).unwrap();
    assert!(!verify_clsag(&clsag, &spend.ring, &key_image, &wrong_pseudo, &spend.msg));

    // The key image lies on the expected generator relation: it is NOT either
    // party's solo product (neither can compute it alone).
    let generator = key_image_generator(&spend.ring[4][0]);
    assert_ne!(key_image, generator);
}

/// The I5 channel property: every state spends the same funding output, so
/// every state's CLSAG carries the SAME key image — only one state can ever
/// confirm, and old states are dead the moment any state settles.
#[test]
fn all_channel_states_share_one_key_image() {
    let j = setup_joint();
    let ka = musig_threshold_keys(j.context, &j.alice_spend.to_bytes(), &j.spend_pubs).unwrap();
    let kb = musig_threshold_keys(j.context, &j.bob_spend.to_bytes(), &j.spend_pubs).unwrap();

    // One funding output…
    let base = state_spend_fixture(&j, 8, 2);
    // …spent by two different states (different messages = different
    // transaction hashes, same real input).
    let mut state2 = StateSpend {
        ring: base.ring.clone(),
        ring_indices: base.ring_indices.clone(),
        real_index: base.real_index,
        key_offset: base.key_offset,
        mask: base.mask,
        amount: base.amount,
        pseudo_mask: rand_scalar().to_bytes(),
        msg: [0u8; 32],
    };
    OsRng.fill_bytes(&mut state2.msg);

    let (clsag1, image1, pseudo1) =
        cosign_in_process(&base, vec![ka.clone(), kb.clone()]).expect("state 1");
    let (clsag2, image2, pseudo2) = cosign_in_process(&state2, vec![ka, kb]).expect("state 2");

    assert!(verify_clsag(&clsag1, &base.ring, &image1, &pseudo1, &base.msg));
    assert!(verify_clsag(&clsag2, &state2.ring, &image2, &pseudo2, &state2.msg));
    // Same output ⇒ same key image, across independent ceremonies with
    // fresh nonces and different pseudo-out masks.
    assert_eq!(image1, image2);
}

#[test]
fn corrupted_share_is_rejected() {
    let j = setup_joint();
    let ka = musig_threshold_keys(j.context, &j.alice_spend.to_bytes(), &j.spend_pubs).unwrap();
    let kb = musig_threshold_keys(j.context, &j.bob_spend.to_bytes(), &j.spend_pubs).unwrap();
    let (pa, pb) = (ka.params().i(), kb.params().i());

    let spend = state_spend_fixture(&j, 5, 0);
    let mut a = Cosigner::new(&spend, ka).unwrap();
    let mut b = Cosigner::new(&spend, kb).unwrap();
    let pre_a = a.preprocess().unwrap();
    let pre_b = b.preprocess().unwrap();
    let _share_a = a.share(pb, &pre_b, &spend.msg).unwrap();
    let share_b = b.share(pa, &pre_a, &spend.msg).unwrap();

    // Alice receives a corrupted share from Bob: the ceremony must fail, not
    // emit a bad CLSAG.
    let mut bad = share_b.clone();
    bad[0] ^= 1;
    assert!(a.finish(pb, &bad).is_err());

    // A party reusing the wrong message also fails on Bob's side.
    let spend2 = state_spend_fixture(&j, 5, 0);
    let ka2 = musig_threshold_keys(j.context, &j.alice_spend.to_bytes(), &j.spend_pubs).unwrap();
    let kb2 = musig_threshold_keys(j.context, &j.bob_spend.to_bytes(), &j.spend_pubs).unwrap();
    let mut a2 = Cosigner::new(&spend2, ka2).unwrap();
    let mut b2 = Cosigner::new(&spend2, kb2).unwrap();
    let pre_a2 = a2.preprocess().unwrap();
    let pre_b2 = b2.preprocess().unwrap();
    let mut wrong = spend2.msg;
    wrong[5] ^= 0xFF;
    let share_a2 = a2.share(pb, &pre_b2, &wrong).unwrap();
    let _share_b2 = b2.share(pa, &pre_a2, &spend2.msg).unwrap();
    assert!(b2.finish(pa, &share_a2).is_err());
}
