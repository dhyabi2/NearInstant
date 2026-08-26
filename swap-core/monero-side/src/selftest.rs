//! In-process self-test of the 2-of-2 CLSAG co-signing (I5) — the exact
//! primitive a real two-party Monero *refund* needs (neither party alone can
//! sign a spend of the joint output). Mirrors the `two_of_two_clsag_cosign_verifies`
//! battery test, but callable from `src` so it can be exposed to the browser via
//! wasm (`wasm-monero::xmr_cosign_selftest`) — proving the CLSAG multisig
//! compiles and runs in-browser without any counterparty or network.

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use rand_core::{OsRng, RngCore};

use crate::cosign::{cosign_in_process, musig_threshold_keys, verify_clsag, StateSpend};
use crate::isolation::{
    aggregate_spend, commitment, receiver_key_offset, sender_one_time_key, shared_view_key, Bytes32,
};

fn rand_scalar() -> Scalar {
    let mut wide = [0u8; 64];
    OsRng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}
fn pubkey(secret: &Scalar) -> Bytes32 {
    (secret * ED25519_BASEPOINT_TABLE).compress().to_bytes()
}

struct Joint {
    context: Bytes32,
    alice_spend: Scalar,
    bob_spend: Scalar,
    spend_pubs: Vec<Bytes32>,
    joint_spend_pub: Bytes32,
    view_key: Bytes32,
    view_pub: Bytes32,
}

fn setup_joint() -> Option<Joint> {
    let mut context = [0u8; 32];
    OsRng.fill_bytes(&mut context);
    let alice_spend = rand_scalar();
    let bob_spend = rand_scalar();
    let mut spend_pubs = vec![pubkey(&alice_spend), pubkey(&bob_spend)];
    spend_pubs.sort();
    let joint_spend_pub = aggregate_spend(context, &spend_pubs)?;
    let mut view_a = [0u8; 32];
    let mut view_b = [0u8; 32];
    OsRng.fill_bytes(&mut view_a);
    OsRng.fill_bytes(&mut view_b);
    let view_key = shared_view_key(context, &view_a, &view_b);
    let view_scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(view_key))?;
    let view_pub = pubkey(&view_scalar);
    Some(Joint { context, alice_spend, bob_spend, spend_pubs, joint_spend_pub, view_key, view_pub })
}

fn state_spend_fixture(j: &Joint, ring_len: usize, real_index: usize) -> Option<StateSpend> {
    let r = rand_scalar().to_bytes();
    let (tx_pub, output_key) = sender_one_time_key(&r, &j.view_pub, &j.joint_spend_pub, 0)?;
    let key_offset = receiver_key_offset(&j.view_key, &tx_pub, &j.joint_spend_pub, 0, &output_key)?;
    let amount = OsRng.next_u64();
    let mask = rand_scalar().to_bytes();
    let real_commitment = commitment(&mask, amount)?;
    let mut ring = Vec::new();
    for i in 0..ring_len {
        if i == real_index {
            ring.push([output_key, real_commitment]);
        } else {
            ring.push([pubkey(&rand_scalar()), commitment(&rand_scalar().to_bytes(), OsRng.next_u64())?]);
        }
    }
    let mut msg = [0u8; 32];
    OsRng.fill_bytes(&mut msg);
    Some(StateSpend {
        ring,
        ring_indices: (1..=ring_len as u64).collect(),
        real_index,
        key_offset,
        mask,
        amount,
        pseudo_mask: rand_scalar().to_bytes(),
        msg,
    })
}

/// Run the whole 2-of-2 CLSAG ceremony in-process and verify the signature.
/// Returns true iff the co-signed CLSAG verifies against the ring/key-image/
/// pseudo-out/message — the property a real refund co-signature relies on.
pub fn cosign_selftest() -> bool {
    let Some(j) = setup_joint() else { return false };
    let Ok(ka) = musig_threshold_keys(j.context, &j.alice_spend.to_bytes(), &j.spend_pubs) else { return false };
    let Ok(kb) = musig_threshold_keys(j.context, &j.bob_spend.to_bytes(), &j.spend_pubs) else { return false };
    let Some(spend) = state_spend_fixture(&j, 11, 4) else { return false };
    let Ok((clsag, key_image, pseudo_out)) = cosign_in_process(&spend, vec![ka, kb]) else { return false };
    verify_clsag(&clsag, &spend.ring, &key_image, &pseudo_out, &spend.msg)
        && Some(pseudo_out) == spend.pseudo_out()
}
