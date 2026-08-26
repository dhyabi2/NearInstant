//! Real stagenet SWEEP of the joint output using OUR reconstructed joint key,
//! built and signed with monero-wallet's SignableTransaction (single-signer —
//! the exact shape of Alice's atomic-swap XMR sweep) and broadcast to stagenet.
//!
//! Run (network): cargo run -p monero-side --example sweep_joint -- <node> <dest_addr>

use std::env;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use rand_core::OsRng;
use zeroize::Zeroizing;

use modular_frost::dkg::Interpolation;
use monero_side::cosign::musig_threshold_keys;
use monero_side::isolation::{aggregate_spend, shared_view_key};

use monero_simple_request_rpc::prelude::*;
use monero_simple_request_rpc::SimpleRequestTransport;
use monero_wallet::address::{MoneroAddress, Network};
use monero_wallet::ed25519::{CompressedPoint, Scalar as MScalar};
use monero_wallet::ringct::RctType;
use monero_wallet::send::{Change, SignableTransaction};
use monero_wallet::{OutputWithDecoys, Scanner, ViewPair};

fn scalar_from_seed(seed: &[u8; 32]) -> Scalar {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(seed);
    Scalar::from_bytes_mod_order_wide(&wide)
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let node = args.get(1).cloned().unwrap_or_else(|| "http://stagenet.xmr-tw.org:38081".into());
    let dest_str = args.get(2).cloned().expect("usage: sweep_joint <node> <dest_stagenet_addr>");

    // --- Reconstruct the joint keys (same derivation as joint_address). ---
    let alice = scalar_from_seed(&[0x11; 32]);
    let bob = scalar_from_seed(&[0x22; 32]);
    let ctx = [0x42u8; 32];
    let a_pub = (&alice * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    let b_pub = (&bob * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    let mut spend_pubs = vec![a_pub, b_pub];
    spend_pubs.sort();
    let joint_pub = aggregate_spend(ctx, &spend_pubs).expect("aggregate");
    let view_secret_bytes = shared_view_key(ctx, &[0x01; 32], &[0x02; 32]);
    let view_scalar =
        Option::<Scalar>::from(Scalar::from_canonical_bytes(view_secret_bytes)).expect("view");
    let alice_keys = musig_threshold_keys(ctx, &alice.to_bytes(), &spend_pubs).expect("keys");
    let Interpolation::Constant(bindings) = alice_keys.interpolation().clone() else {
        panic!("constant interpolation");
    };
    let idx = |pk: &[u8; 32]| spend_pubs.iter().position(|p| p == pk).unwrap();
    let joint_secret = bindings[idx(&a_pub)] * alice + bindings[idx(&b_pub)] * bob;

    let spend_pt = CompressedPoint::from(joint_pub).decompress().expect("decompress");
    let view_pair = ViewPair::new(spend_pt, Zeroizing::new(MScalar::from(view_scalar))).expect("vp");

    // --- Connect + scan for the joint output. ---
    let rpc = SimpleRequestTransport::new(node).await.expect("rpc connect");
    let tip = rpc.latest_block_number().await.expect("height");
    println!("stagenet tip: {tip}");

    let mut scanner = Scanner::new(view_pair.clone());
    let mut found: Option<(usize, monero_wallet::WalletOutput)> = None;
    // Scan a recent window (the funding landed within the last ~200 blocks).
    for n in (tip.saturating_sub(400)..=tip.saturating_sub(1)).rev() {
        let block = rpc.scannable_block_by_number(n).await.expect("scannable block");
        let outs = scanner.scan(block).expect("scan").not_additionally_locked();
        if let Some(o) = outs.into_iter().next() {
            println!("found joint output {} at block {n}", o.commitment().amount);
            found = Some((n, o));
            break;
        }
    }
    let (out_block, output) = found.expect("joint output not found in the scan window");

    // --- Decoys + fee. ---
    let with_decoys = OutputWithDecoys::new(&mut OsRng, &rpc, 16, out_block, output.clone())
        .await
        .expect("decoys");
    let fee_rate = rpc.fee_rate(FeePriority::Normal, u64::MAX).await.expect("fee rate");

    // --- Build + single-signer sign with OUR reconstructed joint key. ---
    let dest = MoneroAddress::from_str(Network::Stagenet, &dest_str).expect("dest addr");
    let amount = output.commitment().amount;
    let pay = amount / 2; // send half; the rest returns as change
    let signable = SignableTransaction::new(
        RctType::ClsagBulletproofPlus,
        Zeroizing::new([0x11u8; 32]), // outgoing view key (arbitrary; hides change linkage)
        vec![with_decoys],
        vec![(dest, pay)],
        Change::fingerprintable(Some(dest)),
        vec![],
        fee_rate,
    )
    .expect("signable");

    let tx = signable
        .sign(&mut OsRng, &Zeroizing::new(MScalar::from(joint_secret)))
        .expect("sign with reconstructed joint key");

    // --- Broadcast. ---
    rpc.publish_transaction(&tx).await.expect("publish");
    println!("SWEEP BROADCAST tx_hash={}", hex::encode(tx.hash()));
}
