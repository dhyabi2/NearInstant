//! The atomic-chunk integration test: one full swap chunk driven across all
//! three crates with real cryptography on both legs.
//!
//! Alice sells XNO, Bob sells XMR. The atomic link: the XNO claim block is
//! adaptor-pre-signed with the adaptor point committed to Bob's XMR key
//! contribution, so Bob's ONLY path to the XNO chunk publishes a signature
//! from which Alice extracts exactly the scalar she needs to reconstruct the
//! joint XMR key and sweep the XMR chunk alone. (verify_core S03 — now with
//! real Nano blocks, a frontier-enforcing ledger, real FROST ed25519-blake2b,
//! real MuSig aggregation, and a real CLSAG sweep.)

use std::collections::{BTreeMap, HashMap};
use std::ops::Deref;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use nano_ceremony::block::{SignedBlock, StateBlock, Subtype};
use nano_ceremony::{ceremony, guard::Rung, work, Bytes32};
use signing::adaptor::{complete_presignature, extract_secret, verify_presignature};
use signing::{keys as xno_keys, round1, Identifier};

use modular_frost::dkg::Interpolation;
use monero_clsag::{Clsag, ClsagContext, Decoys};
use monero_side::cosign::musig_threshold_keys;
use monero_side::isolation::{
    aggregate_spend, commitment, receiver_key_offset, sender_one_time_key, shared_view_key,
};
use monero_wallet::ed25519::{
    Commitment as MCommitment, CompressedPoint, Scalar as MScalar,
};

const TEST_THRESHOLD: u64 = 0xFF00_0000_0000_0000;

// Minimal frontier-enforcing Nano ledger (same rules as the Block 2 battery).
#[derive(Default)]
struct Ledger {
    accounts: HashMap<Bytes32, (Bytes32, u128)>,
    blocks: HashMap<Bytes32, SignedBlock>,
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
        match self.accounts.get(&sb.block.account) {
            None if sb.block.previous != [0u8; 32] => return Err("gap"),
            Some((frontier, _)) if sb.block.previous != *frontier => return Err("stale frontier"),
            _ => {}
        }
        self.accounts.insert(sb.block.account, (hash, sb.block.balance));
        self.blocks.insert(hash, sb.clone());
        Ok(hash)
    }
}

fn rand_scalar() -> Scalar {
    let mut wide = [0u8; 64];
    OsRng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

#[test]
fn one_atomic_chunk_end_to_end() {
    let mut ledger = Ledger::default();
    let chunk_xno: u128 = 500;
    let chunk_xmr: u64 = 700_000;

    // ---------------------------------------------------------------
    // Setup: the XMR joint account. Bob's contribution x IS the adaptor
    // secret; its public point is committed as the adaptor point T.
    // ---------------------------------------------------------------
    let alice_xmr = rand_scalar();
    let bob_x = rand_scalar(); // the atomic secret
    let t_point = (&bob_x * ED25519_BASEPOINT_TABLE).compress().to_bytes();

    let mut xmr_ctx = [0u8; 32];
    OsRng.fill_bytes(&mut xmr_ctx);
    let mut spend_pubs = vec![
        (&alice_xmr * ED25519_BASEPOINT_TABLE).compress().to_bytes(),
        t_point,
    ];
    spend_pubs.sort();
    let joint_xmr_pub = aggregate_spend(xmr_ctx, &spend_pubs).expect("aggregate");

    let mut view_a = [0u8; 32];
    let mut view_b = [0u8; 32];
    OsRng.fill_bytes(&mut view_a);
    OsRng.fill_bytes(&mut view_b);
    let view_key = shared_view_key(xmr_ctx, &view_a, &view_b);
    let view_pub = {
        let v = Option::<Scalar>::from(Scalar::from_canonical_bytes(view_key)).unwrap();
        (&v * ED25519_BASEPOINT_TABLE).compress().to_bytes()
    };

    // Bob funds the XMR chunk: an output paying the joint account.
    let r = rand_scalar().to_bytes();
    let (tx_pub, output_key) =
        sender_one_time_key(&r, &view_pub, &joint_xmr_pub, 0).expect("derive");
    let key_offset =
        receiver_key_offset(&view_key, &tx_pub, &joint_xmr_pub, 0, &output_key).expect("scan");
    let mask = rand_scalar().to_bytes();
    let out_commitment = commitment(&mask, chunk_xmr).unwrap();

    // ---------------------------------------------------------------
    // Setup: the XNO joint account (FROST ed25519-blake2b 2-of-2), funded
    // with the chunk, plus one guard rung and the adaptor-pre-signed claim.
    // ---------------------------------------------------------------
    let (shares, xno_pub) =
        xno_keys::generate_with_dealer(2, 2, xno_keys::IdentifierList::Default, &mut OsRng)
            .unwrap();
    let key_packages: BTreeMap<Identifier, xno_keys::KeyPackage> = shares
        .into_iter()
        .map(|(id, s)| (id, xno_keys::KeyPackage::try_from(s).unwrap()))
        .collect();
    let xno_account: Bytes32 = xno_pub.verifying_key().serialize().unwrap().try_into().unwrap();

    let commit_all = |kps: &BTreeMap<Identifier, xno_keys::KeyPackage>| {
        let mut nonces = BTreeMap::new();
        let mut comms = BTreeMap::new();
        for (id, kp) in kps {
            let (n, c) = round1::commit(kp.signing_share(), &mut OsRng);
            nonces.insert(*id, n);
            comms.insert(*id, c);
        }
        (nonces, comms)
    };
    let jointly_sign = |block: &StateBlock| -> SignedBlock {
        let (nonces, comms) = commit_all(&key_packages);
        let sig = ceremony::sign_block(block, comms, &nonces, &key_packages, &xno_pub).unwrap();
        ceremony::assemble(
            block.clone(),
            sig,
            work::generate(&block.work_root(), TEST_THRESHOLD, 0),
        )
    };

    // Fund (open) the joint XNO account with the chunk value.
    let open = StateBlock {
        account: xno_account,
        previous: [0u8; 32],
        representative: xno_account,
        balance: chunk_xno,
        link: [0xAA; 32],
        subtype: Subtype::Open,
    };
    let f0 = ledger.process(&jointly_sign(&open)).expect("open");

    // Guard rung at f0; Bob's claim pre-signed against the post-guard
    // frontier with adaptor point T = x·G. Bob refuses to reveal x here —
    // the ceremony only ever sees T.
    let rung_block = StateBlock::change(xno_account, f0, xno_account, chunk_xno);
    let rung = Rung {
        block: rung_block.clone(),
        signature: jointly_sign(&rung_block).signature,
    };
    let bob_xno_dest = [0xB0; 32];
    let claim_block = StateBlock {
        account: xno_account,
        previous: rung_block.hash(),
        representative: xno_account,
        balance: 0,
        link: bob_xno_dest,
        subtype: Subtype::Send,
    };
    let (nonces, comms) = commit_all(&key_packages);
    let presig = ceremony::adaptor_presign_block(
        &claim_block,
        &t_point,
        comms,
        &nonces,
        &key_packages,
        &xno_pub,
    )
    .expect("presign");
    // Alice publicly checks the pre-signature before considering the XNO leg armed.
    verify_presignature(&presig, &xno_account, &claim_block.hash()).expect("presig valid");

    // ---------------------------------------------------------------
    // Bob claims the XNO chunk: guard first, then the completed claim.
    // The broadcast signature is the secret's publication.
    // ---------------------------------------------------------------
    let rung_signed = ceremony::assemble(
        rung_block.clone(),
        rung.signature,
        work::generate(&rung_block.work_root(), TEST_THRESHOLD, 0),
    );
    ledger.process(&rung_signed).expect("guard settles");

    let claim_sig = complete_presignature(&presig, &bob_x.to_bytes()).expect("complete");
    let claim_signed = ceremony::assemble(
        claim_block.clone(),
        claim_sig,
        work::generate(&claim_block.work_root(), TEST_THRESHOLD, 0),
    );
    let claim_hash = ledger.process(&claim_signed).expect("claim settles");
    assert_eq!(ledger.accounts[&xno_account].1, 0, "XNO chunk paid to Bob");

    // ---------------------------------------------------------------
    // Alice extracts x from the on-chain signature and sweeps the XMR
    // chunk ALONE: reconstructs the joint secret via the public MuSig
    // binding constants, then single-signs the CLSAG.
    // ---------------------------------------------------------------
    let on_chain = ledger.blocks[&claim_hash].clone();
    let extracted = extract_secret(&presig, &on_chain.signature).expect("extract");
    let x = Option::<Scalar>::from(Scalar::from_canonical_bytes(extracted)).unwrap();
    assert_eq!(x, bob_x, "extracted secret is exactly Bob's contribution");

    // Public binding constants from either party's ThresholdKeys.
    let alice_keys =
        musig_threshold_keys(xmr_ctx, &alice_xmr.to_bytes(), &spend_pubs).expect("keys");
    let Interpolation::Constant(bindings) = alice_keys.interpolation().clone() else {
        panic!("musig keys use constant interpolation");
    };
    // Map contribution → binding constant by participant order (sorted pubs).
    let alice_pub = (&alice_xmr * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    let idx_of = |pk: &Bytes32| spend_pubs.iter().position(|p| p == pk).unwrap();
    let b_alice = bindings[idx_of(&alice_pub)];
    let b_bob = bindings[idx_of(&t_point)];

    let joint_secret = b_alice * alice_xmr + b_bob * x;
    assert_eq!(
        (&joint_secret * ED25519_BASEPOINT_TABLE).compress().to_bytes(),
        joint_xmr_pub,
        "reconstructed secret opens the joint XMR key"
    );

    // Sweep: single-party CLSAG over a ring containing the funded output.
    let offset = Option::<Scalar>::from(Scalar::from_canonical_bytes(key_offset)).unwrap();
    let full_output_secret = joint_secret + offset;

    let ring_len = 8usize;
    let real_index = 5usize;
    let mut ring = Vec::new();
    for i in 0..ring_len {
        if i == real_index {
            ring.push([output_key, out_commitment]);
        } else {
            ring.push([
                (&rand_scalar() * ED25519_BASEPOINT_TABLE).compress().to_bytes(),
                commitment(&rand_scalar().to_bytes(), OsRng.next_u64()).unwrap(),
            ]);
        }
    }
    let ring_points: Vec<_> = ring
        .iter()
        .map(|[k, c]| {
            [
                CompressedPoint::from(*k).decompress().unwrap(),
                CompressedPoint::from(*c).decompress().unwrap(),
            ]
        })
        .collect();
    let mut msg = [0u8; 32];
    OsRng.fill_bytes(&mut msg);
    let mask_scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(mask)).unwrap();

    let (clsag, pseudo_out) = Clsag::sign(
        &mut OsRng,
        vec![(
            Zeroizing::new(MScalar::from(full_output_secret)),
            ClsagContext::new(
                Decoys::new((1..=ring_len as u64).collect(), real_index as u8, ring_points)
                    .unwrap(),
                MCommitment::new(MScalar::from(mask_scalar), chunk_xmr),
            )
            .unwrap(),
        )],
        {
            let mut wide = [0u8; 64];
            OsRng.fill_bytes(&mut wide);
            MScalar::from(Scalar::from_bytes_mod_order_wide(&wide))
        },
        msg,
    )
    .unwrap()
    .swap_remove(0);

    // The sweep verifies: image from the full secret, ring as broadcast.
    let image = monero_side::cosign::expected_key_image(&output_key, &full_output_secret);
    let compressed_ring: Vec<[CompressedPoint; 2]> = ring
        .iter()
        .map(|[k, c]| [CompressedPoint::from(*k), CompressedPoint::from(*c)])
        .collect();
    clsag
        .verify(
            compressed_ring,
            &CompressedPoint::from(image),
            &CompressedPoint::from(pseudo_out.compress().to_bytes()),
            &msg,
        )
        .expect("Alice's sweep CLSAG verifies");

    // ---------------------------------------------------------------
    // Negative control: without Bob's broadcast, Alice can NOT sweep —
    // the pre-signature alone reveals nothing (it is not a valid
    // signature, so nothing was published to extract from).
    // ---------------------------------------------------------------
    let mut fake_sig = [0u8; 64];
    fake_sig[..32].copy_from_slice(&presig.r_adapted);
    fake_sig[32..].copy_from_slice(&presig.s_hat);
    assert!(
        !signing::nano_verify::verify(&xno_account, &claim_block.hash(), &fake_sig),
        "pre-signature is not broadcastable"
    );
    // And an unrelated valid signature from the same account extracts nothing.
    assert!(extract_secret(&presig, &rung_signed.signature).is_err());

    let _ = alice_keys.original_secret_share().deref();
}
