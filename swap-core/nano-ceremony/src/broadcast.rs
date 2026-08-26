//! Node abstraction and saturation broadcast.
//!
//! The claim discipline (I3) needs a broadcast that reaches representatives
//! fast and a confirmation check; the trait keeps the ledger reachable from
//! tests (mock ledgers) and production (RPC nodes) identically.

use crate::block::SignedBlock;
use crate::Bytes32;

/// Outcome of submitting a block to one node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessResult {
    /// Accepted; the node returned the block hash.
    Accepted(Bytes32),
    /// Rejected (fork, gap, bad work, bad signature…), with the node's reason.
    Rejected(String),
    /// The node could not be reached.
    Unreachable(String),
}

/// A Nano node (or mock ledger) that can accept blocks and report state.
pub trait NanoNode {
    /// Submit a block (`process` RPC).
    fn process(&self, block: &SignedBlock) -> ProcessResult;
    /// Whether a block is confirmed.
    fn confirmed(&self, hash: &Bytes32) -> bool;
    /// The account's current frontier hash, if the account exists.
    fn frontier(&self, account: &Bytes32) -> Option<Bytes32>;
    /// The account's current CONFIRMED frontier balance in raw, if known.
    /// Audit #10: the guard ladder is only value-free when its rungs carry the
    /// true confirmed balance; `GuardLadder::from_confirmed` sources it here so
    /// a caller cannot silently build a burn ladder. Default `None` = the node
    /// cannot answer (callers must then refuse to trust the ladder).
    fn frontier_balance(&self, _account: &Bytes32) -> Option<u128> {
        None
    }
    /// Fetch a confirmed block by hash (its full wire form, including the
    /// signature). A taker needs this to read the counterparty's revealed
    /// secret off the settled claim. Default `None` = the node cannot answer.
    fn block(&self, _hash: &Bytes32) -> Option<SignedBlock> {
        None
    }
}

/// Broadcast a block to every node, returning per-node results. Success is
/// *any* acceptance — the block only needs to reach the network once; the
/// fan-out buys latency and censorship resistance, not consensus.
pub fn saturation_broadcast(
    nodes: &[&dyn NanoNode],
    block: &SignedBlock,
) -> Vec<ProcessResult> {
    // Defense-in-depth (audit #18): never fan a locally-invalid block out to
    // many nodes. Signature is validated here; PoW validation requires the
    // network threshold (unknown to this fn) and is the caller's job via
    // `work::validate` before calling — see `broadcast_and_confirm` callers.
    if !block.verify_signature() {
        return vec![ProcessResult::Rejected("local: bad signature".into())];
    }
    nodes.iter().map(|n| n.process(block)).collect()
}

/// True if at least one node accepted the broadcast.
pub fn any_accepted(results: &[ProcessResult]) -> bool {
    results
        .iter()
        .any(|r| matches!(r, ProcessResult::Accepted(_)))
}

/// Broadcast a frontier-advancing block and BLOCK until it is *confirmed*
/// (cemented) by at least `quorum` nodes, or `attempts` polls elapse.
///
/// Audit #1: a secret-revealing claim must never be completed on the strength
/// of mere acceptance — a reorg between accept and confirm lets the
/// counterparty settle their refund on the stale frontier and still read the
/// secret from the broadcast claim, taking both legs. The I3 guard rung must
/// be *confirmed* (its frontier advance cemented, invalidating every
/// stale-frontier signature) before the claim is completed and broadcast.
///
/// Returns `Ok(hash)` once confirmed, `Err` if not confirmed within the
/// budget (the caller MUST abort the swap rather than reveal the secret).
///
/// The `nodes` set MUST be caller-trusted and independent — in particular it
/// must NOT include a node the counterparty operates. Two race findings drive
/// the hardening below:
///
/// - **C1 (single-node confirmation forge):** the old `quorum.max(1)` floor let
///   ONE lying node (e.g. the counterparty's) return `confirmed=true` and
///   satisfy the gate with zero latency, so Bob revealed the secret against an
///   uncemented rung. A secret-reveal gate must never let one node decide:
///   `quorum` is now a hard `>= 2` and there must be `>= 2` nodes.
/// - **H3 (partial-broadcast masking):** confirmation is now counted ONLY over
///   the subset of nodes that actually *accepted* the block. A node that never
///   received it (unreachable at broadcast) cannot contribute a `confirmed`
///   vote from stale gossip.
pub fn broadcast_and_confirm(
    nodes: &[&dyn NanoNode],
    block: &SignedBlock,
    quorum: usize,
    attempts: usize,
    poll: &mut dyn FnMut(),
) -> Result<Bytes32, &'static str> {
    // C1: no single node may decide cementing of a secret-reveal gate.
    if nodes.len() < 2 {
        return Err("secret-reveal confirmation needs >= 2 independent nodes");
    }
    if quorum < 2 {
        return Err("confirmation quorum must be >= 2 for a secret-reveal gate");
    }
    if quorum > nodes.len() {
        return Err("quorum exceeds the node count");
    }

    let results = saturation_broadcast(nodes, block);
    // H3: only nodes that ACCEPTED the block may be polled for confirmation.
    let accepted: Vec<usize> = results
        .iter()
        .enumerate()
        .filter(|(_, r)| matches!(r, ProcessResult::Accepted(_)))
        .map(|(i, _)| i)
        .collect();
    if accepted.len() < quorum {
        return Err("fewer nodes accepted the block than the confirmation quorum requires");
    }

    let hash = block.block.hash();
    for _ in 0..attempts.max(1) {
        let confirmed = accepted
            .iter()
            .filter(|&&i| nodes[i].confirmed(&hash))
            .count();
        if confirmed >= quorum {
            return Ok(hash);
        }
        poll();
    }
    Err("block not confirmed within budget — abort, do not reveal the secret")
}

/// Resolve an account's live balance from a quorum of independent nodes.
///
/// Returns `None` when fewer than `quorum` nodes can answer. The result is the
/// **minimum** reported balance, so a single lying-high node cannot manufacture
/// a funded result — an honest low report always wins. (A lying-low node can
/// only cause a false `Insufficient`, never a false `Funded`, which is the safe
/// direction for a proof-of-funds gate.)
///
/// This is the balance source behind `dex_core::pof::FundsStatus` — the piece
/// that turns "signed claim" into "funds actually present on the live ledger".
pub fn frontier_balance_quorum(
    nodes: &[&dyn NanoNode],
    account: &Bytes32,
    quorum: usize,
) -> Option<u128> {
    if quorum < 2 || nodes.len() < quorum {
        return None;
    }
    let balances: Vec<u128> = nodes
        .iter()
        .filter_map(|n| n.frontier_balance(account))
        .collect();
    if balances.len() < quorum {
        return None;
    }
    balances.iter().copied().min()
}

/// Broadcast a SECRET-BEARING block (a completed adaptor claim, whose signature
/// exposes the swap secret `x`) safely.
///
/// **C2 (secret leaked on a lost frontier race):** bare `saturation_broadcast`
/// validates only the local signature, then fans the block — secret included —
/// to every node, inspecting acceptance *afterwards*. If the target frontier
/// has already moved, every node rejects the claim as stale, yet the
/// secret-bearing signature has already reached each node's socket, letting the
/// counterparty read `x` and sweep the XMR while no XNO moved.
///
/// This send is guarded: for each node we first check that it still reports the
/// claim's target frontier (`frontier(account) == block.previous`) and only
/// then transmit. A node whose frontier has moved never receives the secret.
/// Combined with confirming the guard rung first (via [`broadcast_and_confirm`],
/// which cements `block.previous`), the frontier is stable, so this check is
/// reliable rather than racy. Returns per-node results; nodes that were skipped
/// carry `Rejected("frontier moved — secret withheld")`.
pub fn broadcast_secret_claim(nodes: &[&dyn NanoNode], block: &SignedBlock) -> Vec<ProcessResult> {
    if !block.verify_signature() {
        return vec![ProcessResult::Rejected("local: bad signature".into())];
    }
    let account = block.block.account;
    let target_prev = block.block.previous;
    nodes
        .iter()
        .map(|n| match n.frontier(&account) {
            Some(f) if f == target_prev => n.process(block),
            _ => ProcessResult::Rejected("frontier moved — secret withheld from this node".into()),
        })
        .collect()
}

/// An RPC-backed node.
#[cfg(feature = "rpc")]
pub struct RpcNode {
    url: String,
    timeout: std::time::Duration,
    /// Optional API key for authenticated public RPCs (e.g. rpc.nano.to). When
    /// set it is sent BOTH as an `Authorization` header and as a `key` field in
    /// the JSON body, matching the public endpoint's accepted forms.
    key: Option<String>,
}

#[cfg(feature = "rpc")]
impl RpcNode {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            timeout: std::time::Duration::from_secs(10),
            key: None,
        }
    }

    /// An authenticated endpoint (e.g. `RpcNode::with_key("https://rpc.nano.to", key)`).
    pub fn with_key(url: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            timeout: std::time::Duration::from_secs(10),
            key: Some(key.into()),
        }
    }

    fn call(&self, body: &serde_json::Value) -> Result<serde_json::Value, String> {
        let mut req = ureq::post(&self.url).timeout(self.timeout);
        // Merge the key into the body and header when present.
        let sent = if let Some(k) = &self.key {
            req = req.set("Authorization", k);
            let mut b = body.clone();
            if let Some(obj) = b.as_object_mut() {
                obj.insert("key".into(), serde_json::Value::String(k.clone()));
            }
            b
        } else {
            body.clone()
        };
        req.send_json(sent)
            .map_err(|e| e.to_string())?
            .into_json()
            .map_err(|e| e.to_string())
    }

    /// Request proof-of-work from the endpoint's work service (e.g.
    /// rpc.nano.to's GPU `work_generate`) for `root` at `threshold`. The
    /// returned nonce is ALWAYS validated locally with [`crate::work::validate`]
    /// before being returned — a remote work provider is never trusted blindly
    /// (matching the BlackBird/VELA pattern). Work generation moves no funds.
    pub fn work_generate(&self, root: &Bytes32, threshold: u64) -> Result<u64, String> {
        let body = serde_json::json!({
            "action": "work_generate",
            "hash": hex::encode_upper(root),
            "difficulty": format!("{threshold:016x}"),
        });
        let v = self.call(&body)?;
        let work_hex = v
            .get("work")
            .and_then(|w| w.as_str())
            .ok_or_else(|| format!("no work in response: {v}"))?;
        let nonce = u64::from_str_radix(work_hex, 16).map_err(|e| e.to_string())?;
        if crate::work::validate(root, nonce, threshold) {
            Ok(nonce)
        } else {
            Err("remote work failed local validation".into())
        }
    }
}

#[cfg(feature = "rpc")]
impl NanoNode for RpcNode {
    fn process(&self, block: &SignedBlock) -> ProcessResult {
        let expected = block.block.hash();
        match self.call(&block.to_process_json()) {
            Ok(v) => {
                if let Some(hash) = v.get("hash").and_then(|h| h.as_str()) {
                    match hex::decode(hash)
                        .ok()
                        .and_then(|b| <Bytes32>::try_from(b.as_slice()).ok())
                    {
                        // The returned hash must be THIS block's hash — a lying
                        // (or confused) node returning an unrelated hash must not
                        // count as acceptance of our block.
                        Some(h) if h == expected => ProcessResult::Accepted(h),
                        Some(_) => ProcessResult::Rejected("node returned a mismatched hash".into()),
                        None => ProcessResult::Rejected(format!("unparseable hash: {hash}")),
                    }
                } else {
                    ProcessResult::Rejected(v.to_string())
                }
            }
            Err(e) => ProcessResult::Unreachable(e),
        }
    }

    fn confirmed(&self, hash: &Bytes32) -> bool {
        let body = serde_json::json!({
            "action": "block_info",
            "json_block": "true",
            "hash": hex::encode_upper(hash),
        });
        matches!(
            self.call(&body),
            Ok(v) if v.get("confirmed").and_then(|c| c.as_str()) == Some("true")
        )
    }

    fn frontier(&self, account: &Bytes32) -> Option<Bytes32> {
        let body = serde_json::json!({
            "action": "account_info",
            "account": crate::address::encode(account),
        });
        let v = self.call(&body).ok()?;
        let hash = v.get("frontier")?.as_str()?;
        <Bytes32>::try_from(hex::decode(hash).ok()?.as_slice()).ok()
    }

    fn frontier_balance(&self, account: &Bytes32) -> Option<u128> {
        // account_info reports the confirmed balance when include_confirmed is
        // set; use confirmed_balance so an unconfirmed fork can't feed us a
        // stale figure to build the ladder against.
        let body = serde_json::json!({
            "action": "account_info",
            "account": crate::address::encode(account),
            "include_confirmed": "true",
        });
        let v = self.call(&body).ok()?;
        let bal = v
            .get("confirmed_balance")
            .or_else(|| v.get("balance"))?
            .as_str()?;
        bal.parse::<u128>().ok()
    }

    fn block(&self, hash: &Bytes32) -> Option<SignedBlock> {
        use crate::block::{SignedBlock, StateBlock, Subtype};
        let body = serde_json::json!({
            "action": "block_info",
            "json_block": "true",
            "hash": hex::encode_upper(hash),
        });
        let v = self.call(&body).ok()?;
        let c = v.get("contents")?;
        let account = crate::address::decode(c.get("account")?.as_str()?)?;
        let previous = {
            let s = c.get("previous")?.as_str()?;
            <Bytes32>::try_from(hex::decode(s).ok()?.as_slice()).ok()?
        };
        let representative = crate::address::decode(c.get("representative")?.as_str()?)?;
        let balance: u128 = c.get("balance")?.as_str()?.parse().ok()?;
        let link = {
            let s = c.get("link")?.as_str()?;
            <Bytes32>::try_from(hex::decode(s).ok()?.as_slice()).ok()?
        };
        let signature: [u8; 64] = hex::decode(c.get("signature")?.as_str()?)
            .ok()?
            .try_into()
            .ok()?;
        let work = u64::from_str_radix(c.get("work")?.as_str()?, 16).ok()?;
        // The subtype is not hashed (wire hint only); any value preserves the
        // block hash, so a placeholder is safe for signature extraction.
        let block = StateBlock {
            account,
            previous,
            representative,
            balance,
            link,
            subtype: Subtype::Send,
        };
        // Belt and braces: the reconstructed block must hash to the requested one.
        if block.hash() != *hash {
            return None;
        }
        Some(SignedBlock {
            block,
            signature,
            work,
        })
    }
}
