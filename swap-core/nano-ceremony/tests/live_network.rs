//! Live-network validation (Block 11): fetch real confirmed Nano blocks from
//! a public node and confirm our implementation agrees with the network on
//! every one — block hashing, address encode/decode, and ed25519-blake2b
//! signature verification. Read-only: no funds, no broadcasting.
//!
//! Ignored by default (needs network + `rpc` feature). Run with:
//!   cargo test -p nano-ceremony --test live_network --features rpc -- --ignored --nocapture

#![cfg(feature = "rpc")]

use nano_ceremony::block::{StateBlock, Subtype};
use nano_ceremony::{address, work, Bytes32};

const RPC: &str = "https://rpc.nano.to";

fn rpc(body: serde_json::Value) -> serde_json::Value {
    ureq::post(RPC)
        .timeout(std::time::Duration::from_secs(20))
        .send_json(body)
        .expect("rpc call")
        .into_json()
        .expect("json")
}

fn hx32(s: &str) -> Bytes32 {
    hex::decode(s).unwrap().try_into().unwrap()
}

/// Reconstruct a StateBlock from a `block_info` JSON `contents` object.
fn block_from_contents(c: &serde_json::Value) -> (StateBlock, [u8; 64], u64) {
    let account = address::decode(c["account"].as_str().unwrap()).expect("account addr");
    let representative =
        address::decode(c["representative"].as_str().unwrap()).expect("rep addr");
    let previous = hx32(c["previous"].as_str().unwrap());
    let link = hx32(c["link"].as_str().unwrap());
    let balance: u128 = c["balance"].as_str().unwrap().parse().unwrap();
    let signature: [u8; 64] = hex::decode(c["signature"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let work = u64::from_str_radix(c["work"].as_str().unwrap(), 16).unwrap();
    let block = StateBlock {
        account,
        previous,
        representative,
        balance,
        link,
        subtype: Subtype::Send, // subtype is a wire hint, not hashed
    };
    (block, signature, work)
}

#[test]
#[ignore = "hits the live Nano network"]
fn our_impl_matches_the_live_network() {
    // Walk recent history of an active, long-lived account.
    let account = "nano_1qato4k7z3spc8gq1zyd8xeqfbzsoxwo36a45ozbrxcatut7up8ohyardu1z";
    let history = rpc(serde_json::json!({
        "action": "account_history",
        "account": account,
        "count": "12",
        "raw": "true",
    }));
    let items = history["history"].as_array().expect("history array");
    assert!(!items.is_empty(), "account has history");

    let mut checked = 0usize;
    let mut sig_checked = 0usize;
    for item in items {
        // Only state-type send/receive blocks carry the fields we model.
        if item.get("type").and_then(|t| t.as_str()).is_none() {
            continue;
        }
        let hash_str = item["hash"].as_str().unwrap();
        let info = rpc(serde_json::json!({
            "action": "block_info",
            "json_block": "true",
            "hash": hash_str,
        }));
        let contents = &info["contents"];
        if contents["type"].as_str() != Some("state") {
            continue;
        }

        let (block, signature, w) = block_from_contents(contents);

        // 1. Our hash must equal the network's block hash.
        let ours = hex::encode_upper(block.hash());
        assert_eq!(ours, hash_str.to_uppercase(), "hash mismatch on {hash_str}");
        checked += 1;

        // 2. Our address codec must round-trip the account and reproduce it.
        assert_eq!(address::encode(&block.account), account);

        // 3. Our independent ed25519-blake2b verifier must accept the live
        //    network signature over our computed hash.
        assert!(
            signing::nano_verify::verify(&block.account, &block.hash(), &signature),
            "signature rejected on {hash_str}"
        );
        sig_checked += 1;

        // 4. The attached work validates at some historical threshold (v1 is
        //    the floor; newer blocks meet the higher v2 send threshold too).
        assert!(
            work::validate(&block.work_root(), w, work::THRESHOLD_EPOCH_V1),
            "work below v1 threshold on {hash_str}"
        );
    }

    assert!(checked >= 3, "validated at least a few real blocks (got {checked})");
    eprintln!("live-network: {checked} block hashes + {sig_checked} signatures matched the Nano network");
}

/// Live: OUR `RpcNode` reads the real mainnet ledger via the authenticated
/// public endpoint rpc.nano.to (Authorization header + `key` in body, matching
/// the endpoint's accepted forms). Read-only — no blocks broadcast.
///
///   NANO_RPC_KEY=<key> cargo test -p nano-ceremony --test live_network \
///     --features rpc rpc_node_reads_via_nano_to -- --ignored --nocapture
#[test]
#[ignore = "needs network + NANO_RPC_KEY"]
fn rpc_node_reads_via_nano_to() {
    use nano_ceremony::broadcast::{NanoNode, RpcNode};

    let key = std::env::var("NANO_RPC_KEY").expect("set NANO_RPC_KEY");
    let node = RpcNode::with_key("https://rpc.nano.to", key);

    // The Nano genesis account (well-known mainnet account) pubkey.
    let genesis: Bytes32 =
        hx32("E89208DD038FBB269987689621D52292AE9C35941A7484756ECCED92A65093BA");

    let frontier = node.frontier(&genesis);
    println!("frontier via rpc.nano.to: {:?}", frontier.map(hex::encode));
    assert!(frontier.is_some(), "RpcNode must read the live mainnet frontier");

    let balance = node.frontier_balance(&genesis);
    println!("confirmed balance: {balance:?}");
    assert!(balance.is_some(), "RpcNode must read the confirmed balance");
}

/// Live: OUR RpcNode requests PoW from rpc.nano.to's work service and validates
/// the returned nonce LOCALLY (never trusts the remote blindly). No funds moved.
///
///   NANO_RPC_KEY=<key> cargo test -p nano-ceremony --test live_network \
///     --features rpc work_generate_via_nano_to -- --ignored --nocapture
#[test]
#[ignore = "needs network + NANO_RPC_KEY"]
fn work_generate_via_nano_to_validates_locally() {
    use nano_ceremony::broadcast::RpcNode;

    let key = std::env::var("NANO_RPC_KEY").expect("set NANO_RPC_KEY");
    let node = RpcNode::with_key("https://rpc.nano.to", key);
    // A real mainnet block hash to generate work over (the genesis frontier).
    let root: Bytes32 =
        hx32("023B94B7D27B311666C8636954FE17F1FD2EAA97A8BAC27DE5084FBBD5C6B02C");

    let nonce = node
        .work_generate(&root, work::THRESHOLD_RECEIVE)
        .expect("remote work_generate + local validation");
    println!("nonce from rpc.nano.to: {nonce:016x}");
    assert!(work::validate(&root, nonce, work::THRESHOLD_RECEIVE));
}
