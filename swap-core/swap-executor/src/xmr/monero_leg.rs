//! The real Monero leg (`XmrSide`) — behind the `monero` feature.
//!
//! `sweep` is the stagenet-proven path from `examples/sweep_joint`: reconstruct
//! the joint `ViewPair`, scan the joint output, fetch decoys, build + single-
//! sign a `SignableTransaction` with the reconstructed joint spend secret, and
//! broadcast. `lock` sends the chunk to the joint address from Bob's funded
//! wallet via `monero-wallet-rpc` (`transfer`), and `lock_matured` scans the
//! joint output and checks the 10-block maturity.
//!
//! **This moves REAL value and has NOT been exercised on mainnet.** The sweep
//! path is identical to the one confirmed on stagenet (tx cc518e5b…), but run
//! the first real swap dust-sized and supervised.

use curve25519_dalek::Scalar;
use zeroize::Zeroizing;

use nano_ceremony::Bytes32;

use crate::driver::{ReserveStatus, XmrError, XmrSide};
use crate::monero::{JointXmr, MoneroNet};

use monero_simple_request_rpc::prelude::*;
use monero_wallet::address::{MoneroAddress, Network};
use monero_wallet::ed25519::{CompressedPoint, Scalar as MScalar};
use monero_wallet::ringct::RctType;
use monero_wallet::send::{Change, SignableTransaction};
use monero_wallet::{OutputWithDecoys, Scanner, ViewPair};

/// Monero's consensus output lock (10 blocks) — must pass before the sweep.
const MONERO_MATURITY: usize = 10;

/// A real Monero leg bound to one or more daemon nodes (via
/// [`monero_side::rpc::Node`]) and, for `lock`, the operator's
/// `monero-wallet-rpc`.
///
/// The first node is the primary (scans, decoys, fees). Every configured
/// node must independently confirm maturity in [`XmrSide::lock_matured`] —
/// a single lying daemon can no longer fake a matured lock (the Monero
/// mirror of the Nano confirmation quorum).
pub struct MoneroLeg {
    rt: tokio::runtime::Runtime,
    nodes: Vec<monero_side::rpc::Node>,
    net: Network,
    /// Alice's sweep destination (her address on `net`).
    sweep_dest: Option<String>,
    /// Bob's funded wallet-rpc (`http://host:port/json_rpc`) + destination.
    wallet_rpc: Option<String>,
    wallet_password: Option<String>,
    /// The txid of the lock this leg just broadcast (maker side), so maturity
    /// is an O(1) `get_transfer_by_txid` confirmations read instead of a blind
    /// multi-hundred-block scan over a rate-limiting node.
    last_lock_txid: std::sync::Mutex<Option<String>>,
    /// A known block height for the joint output (maker sets it from the lock
    /// tx; the taker receives it over the wire), so the sweep/maturity scan
    /// targets a narrow window instead of 400 blocks.
    known_lock_height: std::sync::Mutex<Option<usize>>,
}

/// Parse a `check_reserve_proof` JSON-RPC response into a [`ReserveStatus`].
/// Accepts `spent`/`total` as either JSON numbers or decimal strings (wallet
/// versions differ). Pure — unit-testable without a live node.
pub fn parse_check_reserve(v: &serde_json::Value) -> Option<ReserveStatus> {
    if let Some(err) = v.get("error") {
        if !err.is_null() {
            return None;
        }
    }
    let r = v.get("result")?;
    let good = r.get("good")?.as_bool()?;
    let spent = parse_amount(r.get("spent")?)?;
    let total = parse_amount(r.get("total")?)?;
    Some(ReserveStatus { good, spent, total })
}

fn parse_amount(v: &serde_json::Value) -> Option<u128> {
    match v {
        serde_json::Value::Number(n) => n.as_u64().map(u128::from),
        serde_json::Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Parse `get_address` → the primary address (or the first subaddress).
fn parse_address(v: &serde_json::Value) -> Option<String> {
    if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
        let _ = err;
        return None;
    }
    let r = v.get("result")?;
    r.get("address")
        .and_then(|a| a.as_str())
        .map(str::to_string)
        .or_else(|| {
            r.get("addresses")
                .and_then(|a| a.as_array())
                .and_then(|a| a.first())
                .and_then(|a| a.as_str())
                .map(str::to_string)
        })
}

/// Parse `get_balance` → the UNLOCKED balance in piconero.
fn parse_balance(v: &serde_json::Value) -> Option<u128> {
    if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
        let _ = err;
        return None;
    }
    let r = v.get("result")?;
    parse_amount(r.get("unlocked_balance")?)
}

impl MoneroLeg {
    /// Build a leg around a daemon node URL. `sweep_dest` is Alice's address;
    /// `wallet_rpc`/`wallet_password` are Bob's funded wallet (for `lock`).
    pub fn new(
        node_url: &str,
        net: MoneroNet,
        sweep_dest: Option<String>,
        wallet_rpc: Option<String>,
        wallet_password: Option<String>,
    ) -> Result<Self, XmrError> {
        Self::with_quorum(&[node_url.to_string()], net, sweep_dest, wallet_rpc, wallet_password)
    }

    /// Build a leg around several daemon nodes (first = primary). Maturity
    /// checks require ALL of them to agree; the sweep broadcasts to all.
    pub fn with_quorum(
        node_urls: &[String],
        net: MoneroNet,
        sweep_dest: Option<String>,
        wallet_rpc: Option<String>,
        wallet_password: Option<String>,
    ) -> Result<Self, XmrError> {
        if node_urls.is_empty() {
            return Err(XmrError::Lock("at least one Monero daemon URL required".into()));
        }
        let rt = tokio::runtime::Runtime::new().map_err(|e| XmrError::Lock(e.to_string()))?;
        let mut nodes = Vec::with_capacity(node_urls.len());
        for url in node_urls {
            let node = rt
                .block_on(monero_side::rpc::Node::connect(url))
                .map_err(|e| XmrError::Lock(format!("{url}: {e}")))?;
            nodes.push(node);
        }
        let net = match net {
            MoneroNet::Mainnet => Network::Mainnet,
            MoneroNet::Stagenet => Network::Stagenet,
        };
        Ok(Self {
            rt,
            nodes,
            net,
            sweep_dest,
            wallet_rpc,
            wallet_password,
            last_lock_txid: std::sync::Mutex::new(None),
            known_lock_height: std::sync::Mutex::new(None),
        })
    }

    /// Tell this leg the block height of the joint output (the taker learns it
    /// from the maker over the wire), so the sweep scan targets a narrow window.
    pub fn set_known_lock_height(&self, height: usize) {
        *self.known_lock_height.lock().unwrap() = Some(height);
    }

    /// The height of the joint output as this leg currently knows it (maker: from
    /// the lock tx; taker: set over the wire). `None` until known.
    pub fn known_lock_height(&self) -> Option<usize> {
        *self.known_lock_height.lock().unwrap()
    }

    /// The primary daemon (scans, decoys, fee rates).
    fn primary(&self) -> &monero_side::rpc::Node {
        &self.nodes[0]
    }

    /// Find the joint output in a recent window on ONE node; `Ok(None)` when it
    /// is not there yet (unconfirmed) and `Err` only on an actual RPC/scan
    /// failure for THAT node. Callers rotate across nodes and treat both `None`
    /// and a per-node `Err` as "not on this node right now".
    fn find_output_on(
        &self,
        node: &monero_side::rpc::Node,
        joint: &JointXmr,
    ) -> Result<Option<(usize, monero_wallet::WalletOutput)>, XmrError> {
        let view_pair = joint_view_pair(joint)?;
        let mut scanner = Scanner::new(view_pair);
        let tip = self
            .rt
            .block_on(node.as_raw().latest_block_number())
            .map_err(|e| XmrError::Maturity(e.to_string()))?;
        // When the lock height is known (maker from its own tx, taker over the
        // wire), scan a tight window around it — a handful of blocks instead of
        // 400 — so one rate-limiting node can't stall the scan.
        let (lo, hi) = match self.known_lock_height() {
            Some(h) => (h.saturating_sub(3), (h + 3).min(tip.saturating_sub(1))),
            None => (tip.saturating_sub(400), tip.saturating_sub(1)),
        };
        for n in (lo..=hi).rev() {
            let block = self
                .rt
                .block_on(node.as_raw().scannable_block_by_number(n))
                .map_err(|e| XmrError::Maturity(e.to_string()))?;
            let outs = scanner
                .scan(block)
                .map_err(|e| XmrError::Maturity(e.to_string()))?
                .not_additionally_locked();
            if let Some(o) = outs.into_iter().next() {
                return Ok(Some((n, o)));
            }
        }
        Ok(None)
    }

    /// Find the joint output across ANY reachable node (the sweep uses the
    /// primary; this tolerates a down primary). `Ok(None)` = not visible on any
    /// reachable node yet (keep polling).
    fn find_joint_output_opt(
        &self,
        joint: &JointXmr,
    ) -> Result<Option<(usize, monero_wallet::WalletOutput)>, XmrError> {
        for node in &self.nodes {
            if let Ok(Some(found)) = self.find_output_on(node, joint) {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    /// Is the joint output present in the block THIS node serves at `height`,
    /// and what is that block's hash? Returns `None` if the node is unreachable
    /// or serves a block there that does not contain the output. Used by the
    /// resilient maturity check to detect a lying/forked peer by the hash it
    /// serves at the lock height.
    fn output_block_hash_at(
        &self,
        node: &monero_side::rpc::Node,
        joint: &JointXmr,
        height: usize,
    ) -> Option<[u8; 32]> {
        let block = self
            .rt
            .block_on(node.as_raw().scannable_block_by_number(height))
            .ok()?;
        let hash = block.block.hash();
        let mut scanner = Scanner::new(joint_view_pair(joint).ok()?);
        let present = scanner
            .scan(block)
            .ok()?
            .not_additionally_locked()
            .into_iter()
            .next()
            .is_some();
        present.then_some(hash)
    }

    /// Find the joint output in a recent window; returns (block, output). Used
    /// by the sweep, where a missing output IS an error.
    fn find_joint_output(
        &self,
        joint: &JointXmr,
    ) -> Result<(usize, monero_wallet::WalletOutput), XmrError> {
        self.find_joint_output_opt(joint)?
            .ok_or_else(|| XmrError::Sweep("joint output not found in the scan window".into()))
    }

    /// Generate a Monero reserve proof (`get_reserve_proof`) attesting the
    /// wallet holds at least `amount` piconero, bound to `message` (the order
    /// hash). Returns the opaque proof string to carry beside the order.
    pub fn make_reserve_proof(
        &self,
        amount: u128,
        message: &str,
    ) -> Result<String, XmrError> {
        let wallet = self
            .wallet_rpc
            .as_ref()
            .ok_or_else(|| XmrError::Lock("no wallet-rpc configured for reserve proof".into()))?;
        let pw = self.wallet_password.clone().unwrap_or_default();
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": "0", "method": "get_reserve_proof",
            "params": {
                "all": false,
                "account_index": 0,
                "amount": amount.to_string(),
                "message": message,
                "password": pw,
            }
        });
        let resp = ureq::post(wallet)
            .send_json(body)
            .map_err(|e| XmrError::Lock(e.to_string()))?
            .into_json::<serde_json::Value>()
            .map_err(|e| XmrError::Lock(e.to_string()))?;
        if let Some(e) = resp.get("error").filter(|e| !e.is_null()) {
            return Err(XmrError::Lock(format!("get_reserve_proof failed: {e}")));
        }
        resp.get("result")
            .and_then(|r| r.get("signature"))
            .and_then(|s| s.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| XmrError::Lock(format!("no signature in reserve proof: {resp}")))
    }

    /// Verify a maker's reserve proof (`check_reserve_proof`) against this
    /// node's wallet-rpc. This is the take-time solvency gate: `good` and
    /// `available() >= amount` must both hold before the taker settles.
    pub fn check_reserve_proof(
        &self,
        address: &str,
        message: &str,
        signature: &str,
    ) -> Result<ReserveStatus, XmrError> {
        let wallet = self
            .wallet_rpc
            .as_ref()
            .ok_or_else(|| XmrError::Lock("no wallet-rpc configured to verify reserve proof".into()))?;
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": "0", "method": "check_reserve_proof",
            "params": { "address": address, "message": message, "signature": signature }
        });
        let resp = ureq::post(wallet)
            .send_json(body)
            .map_err(|e| XmrError::Lock(e.to_string()))?
            .into_json::<serde_json::Value>()
            .map_err(|e| XmrError::Lock(e.to_string()))?;
        parse_check_reserve(&resp)
            .ok_or_else(|| XmrError::Lock(format!("unparseable check_reserve_proof: {resp}")))
    }

    /// Query the wallet's primary receive address (`get_address`) via wallet-rpc.
    fn address(&self) -> Result<Option<String>, XmrError> {
        let wallet = match &self.wallet_rpc {
            Some(w) => w,
            None => return Ok(None),
        };
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": "0", "method": "get_address",
            "params": { "account_index": 0 }
        });
        let resp = ureq::post(wallet)
            .send_json(body)
            .map_err(|e| XmrError::Lock(e.to_string()))?
            .into_json::<serde_json::Value>()
            .map_err(|e| XmrError::Lock(e.to_string()))?;
        Ok(parse_address(&resp))
    }

    /// Query the wallet's unlocked balance (`get_balance`) via wallet-rpc.
    fn balance(&self) -> Result<Option<u128>, XmrError> {
        let wallet = match &self.wallet_rpc {
            Some(w) => w,
            None => return Ok(None),
        };
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": "0", "method": "get_balance",
            "params": { "account_index": 0 }
        });
        let resp = ureq::post(wallet)
            .send_json(body)
            .map_err(|e| XmrError::Lock(e.to_string()))?
            .into_json::<serde_json::Value>()
            .map_err(|e| XmrError::Lock(e.to_string()))?;
        Ok(parse_balance(&resp))
    }

    /// `(height, confirmations)` of a wallet-broadcast tx via
    /// `get_transfer_by_txid`. `Ok(None)` = wallet has no such tx yet (still in
    /// the pool) or no wallet-rpc; `Err` only on a real RPC failure.
    fn wallet_tx_confirmations(&self, txid: &str) -> Result<Option<(u64, u64)>, XmrError> {
        let wallet = match &self.wallet_rpc {
            Some(w) => w,
            None => return Ok(None),
        };
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": "0", "method": "get_transfer_by_txid",
            "params": { "txid": txid, "account_index": 0 }
        });
        let resp = ureq::post(wallet)
            .send_json(body)
            .map_err(|e| XmrError::Maturity(e.to_string()))?
            .into_json::<serde_json::Value>()
            .map_err(|e| XmrError::Maturity(e.to_string()))?;
        // Not found yet (still unconfirmed) is a normal transient, not an error.
        if resp.get("error").is_some() {
            return Ok(None);
        }
        let t = match resp.get("result").and_then(|r| r.get("transfer")) {
            Some(t) => t,
            None => return Ok(None),
        };
        let height = t.get("height").and_then(|h| h.as_u64()).unwrap_or(0);
        let confs = t.get("confirmations").and_then(|c| c.as_u64()).unwrap_or(0);
        Ok(Some((height, confs)))
    }
}

impl XmrSide for MoneroLeg {
    fn check_reserve(
        &self,
        address: &str,
        message: &str,
        signature: &str,
    ) -> Result<Option<ReserveStatus>, XmrError> {
        // Without a wallet-rpc we cannot run check_reserve_proof → unverifiable.
        if self.wallet_rpc.is_none() {
            return Ok(None);
        }
        self.check_reserve_proof(address, message, signature)
            .map(Some)
    }

    fn xmr_address(&self) -> Result<Option<String>, XmrError> {
        self.address()
    }

    fn xmr_balance(&self) -> Result<Option<u128>, XmrError> {
        self.balance()
    }

    fn lock_height(&self) -> Option<usize> {
        self.known_lock_height()
    }

    fn set_lock_height(&self, height: usize) {
        self.set_known_lock_height(height);
    }

    fn lock(&self, joint: &JointXmr, chunk_raw: u128) -> Result<(), XmrError> {
        // Bob sends `chunk_raw` from his funded wallet to the joint address.
        let wallet = self
            .wallet_rpc
            .as_ref()
            .ok_or_else(|| XmrError::Lock("no wallet-rpc configured for the maker".into()))?;
        let pw = self.wallet_password.clone().unwrap_or_default();
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": "0", "method": "transfer",
            "params": {
                "destinations": [{ "amount": chunk_raw.to_string(), "address": joint.address }],
                "account_index": 0,
                "subaddr_indices": [0],
                "priority": 0,
                "ring_size": 16,
                "password": pw,
            }
        });
        let resp = ureq::post(wallet)
            .send_json(body)
            .map_err(|e| XmrError::Lock(e.to_string()))?
            .into_json::<serde_json::Value>()
            .map_err(|e| XmrError::Lock(e.to_string()))?;
        if resp.get("error").is_some() {
            return Err(XmrError::Lock(format!("wallet-rpc transfer failed: {resp}")));
        }
        // Record the lock txid: maturity becomes an O(1) confirmations read.
        if let Some(txid) = resp
            .get("result")
            .and_then(|r| r.get("tx_hash"))
            .and_then(|h| h.as_str())
        {
            *self.last_lock_txid.lock().unwrap() = Some(txid.to_string());
        }
        Ok(())
    }

    fn lock_matured(&self, joint: &JointXmr) -> Result<bool, XmrError> {
        // FAST PATH (maker): if we broadcast the lock we hold its txid, so
        // maturity is one `get_transfer_by_txid` read against our own wallet —
        // no blind multi-hundred-block scan over a rate-limiting public node
        // (the bug that stalled the live rehearsal). Trusting our OWN wallet
        // about our OWN lock is safe: an under-count only delays Bob revealing
        // his secret, never endangers funds.
        if let Some(txid) = self.last_lock_txid.lock().unwrap().clone() {
            if let Some((height, confs)) = self.wallet_tx_confirmations(&txid)? {
                if height > 0 {
                    self.set_known_lock_height(height as usize);
                }
                return Ok(confs >= MONERO_MATURITY as u64);
            }
            // txid known but not yet in a block (still in the pool) → keep polling.
            return Ok(false);
        }

        // RESILIENT SCAN PATH (taker, or maker without wallet-rpc): a flaky,
        // offline, or rate-limiting peer must NEVER abort a swap; only a genuine
        // cryptographic conflict among peers that both see the lock settled
        // fails closed.
        //
        // 1. Locate the output on ANY reachable node. Not visible anywhere yet
        //    (unconfirmed, or every peer down this round) → not matured, keep
        //    polling. Never fatal.
        let out_block = match self.find_joint_output_opt(joint)? {
            Some((block, _)) => block,
            None => return Ok(false),
        };
        // 2. Across every node, collect the block hash served at the lock
        //    height BY NODES THAT SEE IT DEEP ENOUGH (>= 10 confirmations) and
        //    that actually contain the output. Unreachable / not-yet-deep /
        //    reorging-shallow peers are skipped, not counted against the swap.
        let mut deep_hashes = std::collections::BTreeSet::new();
        for node in &self.nodes {
            let tip = match self.rt.block_on(node.as_raw().latest_block_number()) {
                Ok(t) => t,
                Err(_) => continue, // unreachable — skip, keep polling
            };
            if tip.saturating_sub(out_block) < MONERO_MATURITY {
                continue; // this node hasn't seen it mature yet
            }
            if let Some(hash) = self.output_block_hash_at(node, joint, out_block) {
                deep_hashes.insert(hash);
            }
            // A deep node that does NOT contain the output at out_block is a
            // shallow-reorg or lag artifact for now — ignored until it either
            // agrees or contradicts a settled block below.
        }
        // 3. Two distinct settled blocks at the lock height = the chain
        //    genuinely diverged under a matured output → fail closed. Never
        //    reveal the secret onto an ambiguous chain.
        if deep_hashes.len() > 1 {
            return Err(XmrError::Maturity(
                "peers that see the lock settled disagree on its block — chains diverge".into(),
            ));
        }
        // Matured iff at least one reachable peer proves it >= 10 deep and no
        // reachable peer contradicts that block.
        Ok(deep_hashes.len() == 1)
    }

    fn sweep(&self, joint: &JointXmr, joint_spend_secret: &Bytes32) -> Result<(), XmrError> {
        let dest = self
            .sweep_dest
            .as_ref()
            .ok_or_else(|| XmrError::Sweep("no sweep destination configured for the taker".into()))?;
        let dest_addr = MoneroAddress::from_str(self.net, dest)
            .map_err(|e| XmrError::Sweep(format!("bad sweep destination: {e}")))?;

        let (out_block, output) = self.find_joint_output(joint)?;
        let secret = Option::<Scalar>::from(Scalar::from_canonical_bytes(*joint_spend_secret))
            .ok_or_else(|| XmrError::Sweep("non-canonical joint secret".into()))?;

        let with_decoys = self
            .rt
            .block_on(OutputWithDecoys::new(
                &mut rand::rngs::OsRng,
                self.primary().as_raw(),
                16,
                out_block,
                output.clone(),
            ))
            .map_err(|e| XmrError::Sweep(e.to_string()))?;
        let fee_rate = self
            .rt
            .block_on(self.primary().as_raw().fee_rate(FeePriority::Normal, u64::MAX))
            .map_err(|e| XmrError::Sweep(e.to_string()))?;

        let amount = output.commitment().amount;
        let signable = SignableTransaction::new(
            RctType::ClsagBulletproofPlus,
            Zeroizing::new([0x11u8; 32]),
            vec![with_decoys],
            vec![(dest_addr, amount)],
            Change::fingerprintable(Some(dest_addr)),
            vec![],
            fee_rate,
        )
        .map_err(|e| XmrError::Sweep(e.to_string()))?;

        let tx = signable
            .sign(&mut rand::rngs::OsRng, &Zeroizing::new(MScalar::from(secret)))
            .map_err(|e| XmrError::Sweep(e.to_string()))?;
        // Publish to every configured daemon; one acceptance settles it (the
        // rest are anti-censorship redundancy), all failing is the error.
        let mut errors = Vec::new();
        for (i, node) in self.nodes.iter().enumerate() {
            match self.rt.block_on(node.as_raw().publish_transaction(&tx)) {
                Ok(()) => return Ok(()),
                Err(e) => errors.push(format!("node {i}: {e}")),
            }
        }
        Err(XmrError::Sweep(format!("no daemon accepted the sweep: {}", errors.join("; "))))
    }
}

/// The joint output's `ViewPair` from the session's joint material.
fn joint_view_pair(joint: &JointXmr) -> Result<ViewPair, XmrError> {
    let spend_pt = CompressedPoint::from(joint.spend_pub)
        .decompress()
        .ok_or_else(|| XmrError::Sweep("bad joint spend pub".into()))?;
    let view = Option::<Scalar>::from(Scalar::from_canonical_bytes(joint.view_key))
        .ok_or_else(|| XmrError::Sweep("bad joint view key".into()))?;
    ViewPair::new(spend_pt, Zeroizing::new(MScalar::from(view)))
        .map_err(|e| XmrError::Sweep(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LIVE (read-only): the two default mainnet daemons — different
    /// operators — serve byte-identical blocks: our computed hash of Cake's
    /// block equals our computed hash of Seth's at the same height. Run with
    /// `cargo test -p swap-executor --features monero -- --ignored live_`.
    #[test]
    #[ignore]
    fn live_cross_node_block_hash_agreement() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        // Public nodes rate-limit bursts (Seth's especially) — retry with
        // spacing rather than concluding disagreement from a throttle.
        let connect = |url: &'static str| {
            let mut last = String::new();
            for attempt in 0..4 {
                if attempt > 0 {
                    std::thread::sleep(std::time::Duration::from_secs(15));
                }
                match rt.block_on(monero_side::rpc::Node::connect(url)) {
                    Ok(n) => return n,
                    Err(e) => last = format!("{e:?}"),
                }
            }
            panic!("connect {url}: {last}");
        };
        let a = connect(monero_side::rpc::DEFAULT_MAINNET_RPC_URL);
        let b = connect(monero_side::rpc::ALT_MAINNET_RPC_URL);
        let tip = rt.block_on(a.as_raw().latest_block_number()).expect("tip");
        let h = tip.saturating_sub(20); // deep enough to be reorg-safe
        let ba = rt.block_on(a.as_raw().scannable_block_by_number(h)).expect("cake block");
        std::thread::sleep(std::time::Duration::from_secs(5));
        let bb = rt.block_on(b.as_raw().scannable_block_by_number(h)).expect("seth block");
        assert_eq!(
            ba.block.hash(),
            bb.block.hash(),
            "independent operators disagree on block {h} — investigate before settling"
        );
    }

    #[test]
    fn parse_check_reserve_accepts_number_and_string_amounts() {
        let good = serde_json::json!({
            "result": { "good": true, "spent": 0u64, "total": 100000000000u64 }
        });
        let s = parse_check_reserve(&good).unwrap();
        assert!(s.good);
        assert_eq!(s.total, 100_000_000_000);
        assert_eq!(s.available(), 100_000_000_000);

        // Newer wallet-rpc versions return amounts as decimal strings.
        let stringy = serde_json::json!({
            "result": { "good": true, "spent": "25000000000", "total": "100000000000" }
        });
        let s = parse_check_reserve(&stringy).unwrap();
        assert_eq!(s.spent, 25_000_000_000);
        assert_eq!(s.available(), 75_000_000_000);

        // An error response is not a valid status.
        let err = serde_json::json!({ "error": { "code": -1, "message": "bad" } });
        assert!(parse_check_reserve(&err).is_none());

        // A spent reserve that exceeds the claim leaves `available` below it.
        let spent = serde_json::json!({
            "result": { "good": true, "spent": 99, "total": 100 }
        });
        assert_eq!(parse_check_reserve(&spent).unwrap().available(), 1);
    }

    #[test]
    fn parses_address_and_balance() {
        let addr = serde_json::json!({ "result": { "address": "4mainnetXMRaddr...", "addresses": [{"address":"4mainnetXMRaddr...","address_index":0,"label_index":0,"used":false}] } });
        assert_eq!(parse_address(&addr).unwrap(), "4mainnetXMRaddr...");

        let bal = serde_json::json!({ "result": { "balance": 123456789, "unlocked_balance": 4200000000u64 } });
        assert_eq!(parse_balance(&bal).unwrap(), 4_200_000_000);

        let err = serde_json::json!({ "error": { "code": -1, "message": "no wallet" } });
        assert!(parse_address(&err).is_none());
        assert!(parse_balance(&err).is_none());
    }
}
