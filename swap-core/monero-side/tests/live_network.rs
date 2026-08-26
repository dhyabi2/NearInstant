//! Live-network validation of the Monero daemon client: connect to a public
//! mainnet node (no local `monerod`) and confirm `get_fee_estimate` returns a
//! sane four-tier fee schedule with a non-zero quantization mask. Read-only —
//! no funds, no scanning, no broadcast.
//!
//! Ignored by default (needs network). Run with:
//!   cargo test -p monero-side --test live_network -- --ignored --nocapture
//! Override the node via `MONERO_RPC_URL` (else the default public mainnet node).

use monero_side::rpc::Node;

#[tokio::test]
#[ignore = "hits a live public Monero node"]
async fn fee_tiers_from_public_mainnet_node() {
    let node = Node::connect_env().await.expect("connect to public node");
    let tiers = node.fee_tiers().await.expect("fee estimate");

    // The four tiers must be non-decreasing and non-zero; the mask must round.
    assert!(tiers.per_weight[0] > 0, "low tier must be non-zero");
    for w in tiers.per_weight.windows(2) {
        assert!(w[0] <= w[1], "fee tiers must be non-decreasing");
    }
    assert!(tiers.quantization_mask > 0, "quantization mask must be non-zero");
}
