//! Real-chain validation of the I10 joint-account derivation.
//!
//! Derives a 2-of-2 MuSig joint SPEND key + shared view key with our
//! `isolation` code, encodes the corresponding stagenet address, and
//! reconstructs the joint spend SECRET (Σ bindingᵢ·secretᵢ — the exact value
//! Alice reconstructs to sweep in the atomic swap). Prints the address + keys
//! so a wallet can be restored from them and shown to control real funds sent
//! to the address. Proves our joint-address derivation matches a real chain.

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use zeroize::Zeroizing;

use modular_frost::dkg::Interpolation;
use monero_side::cosign::musig_threshold_keys;
use monero_side::isolation::{aggregate_spend, shared_view_key};
use monero_wallet::address::Network;
use monero_wallet::ed25519::{CompressedPoint, Scalar as MScalar};
use monero_wallet::ViewPair;

fn scalar_from_seed(seed: &[u8; 32]) -> Scalar {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(seed);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn main() {
    // Two parties' XMR spend secrets (fixed seeds → reproducible address).
    let alice = scalar_from_seed(&[0x11; 32]);
    let bob = scalar_from_seed(&[0x22; 32]);
    let ctx = [0x42u8; 32];

    let a_pub = (&alice * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    let b_pub = (&bob * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    let mut spend_pubs = vec![a_pub, b_pub];
    spend_pubs.sort();

    // Joint MuSig spend public key + shared view secret (our isolation layer).
    let joint_pub = aggregate_spend(ctx, &spend_pubs).expect("aggregate");
    let view_secret_bytes = shared_view_key(ctx, &[0x01; 32], &[0x02; 32]);
    let view_scalar =
        Option::<Scalar>::from(Scalar::from_canonical_bytes(view_secret_bytes)).expect("view");

    // Reconstruct the joint spend SECRET s = b_a·alice + b_b·bob (the value a
    // sweeper combines from the two contributions) and check s·G == joint_pub.
    let alice_keys = musig_threshold_keys(ctx, &alice.to_bytes(), &spend_pubs).expect("keys");
    let Interpolation::Constant(bindings) = alice_keys.interpolation().clone() else {
        panic!("musig keys use constant interpolation");
    };
    let idx = |pk: &[u8; 32]| spend_pubs.iter().position(|p| p == pk).unwrap();
    let b_a = bindings[idx(&a_pub)];
    let b_b = bindings[idx(&b_pub)];
    let joint_secret = b_a * alice + b_b * bob;
    let joint_secret_bytes: [u8; 32] = joint_secret.to_bytes();

    // Verify the reconstructed secret opens the joint public key.
    let recon = Option::<Scalar>::from(Scalar::from_canonical_bytes(joint_secret_bytes))
        .expect("joint secret canonical");
    assert_eq!(
        (&recon * ED25519_BASEPOINT_TABLE).compress().to_bytes(),
        joint_pub,
        "reconstructed joint secret opens the joint spend key"
    );

    // Encode the stagenet address for (joint_spend_pub, view_pub).
    let spend_pt = CompressedPoint::from(joint_pub).decompress().expect("decompress joint pub");
    let vp = ViewPair::new(spend_pt, Zeroizing::new(MScalar::from(view_scalar))).expect("viewpair");
    let address = vp.legacy_address(Network::Stagenet);

    println!("ADDRESS={address}");
    println!("SPEND_KEY={}", hex::encode(joint_secret_bytes));
    println!("VIEW_KEY={}", hex::encode(view_secret_bytes));
}
