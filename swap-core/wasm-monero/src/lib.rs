//! Stage 5: the Monero swap leg in the browser.
//!
//! Everything cryptographic — 2-of-2 MuSig joint address derivation, joint
//! spend-secret reconstruction, output scanning (view-key scan of real
//! blocks), decoy selection, and CLSAG/Bulletproof+ transaction build +
//! sign — runs inside this wasm module with the SAME crates the native,
//! on-chain-proven sweep uses (monero-side Stage 2). The one thing a browser
//! cannot do natively is open an HTTP connection from Rust, so the daemon
//! transport is supplied by JS: a single `async (route, body) -> bytes`
//! function backed by `fetch`, plugged in as a [`monero_daemon_rpc::HttpTransport`].
//!
//! The wasm surface mirrors the native sweep exactly:
//!   joint address (`xmr_joint_info`) -> scan (`XmrNode.scan`) ->
//!   build+sign (`XmrNode.sweep_sign`) -> broadcast (`XmrNode.publish`).

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use zeroize::Zeroizing;

use modular_frost::dkg::Interpolation;
use monero_side::cosign::musig_threshold_keys;
use monero_side::isolation::{aggregate_spend, shared_view_key};
use monero_wallet::address::Network;
use monero_wallet::ed25519::{CompressedPoint, Scalar as MScalar};
use monero_wallet::ViewPair;

/// The 2-of-2 joint Monero identity both parties derive independently.
pub struct JointInfo {
    /// The joint MuSig spend public key.
    pub spend_pub: [u8; 32],
    /// The shared (both-party-known) view secret.
    pub view_key: [u8; 32],
    /// The standard address for (spend_pub, view_key·G) on `network`.
    pub address: String,
}

fn parse_network(s: &str) -> Result<Network, String> {
    match s {
        "mainnet" => Ok(Network::Mainnet),
        "stagenet" => Ok(Network::Stagenet),
        "testnet" => Ok(Network::Testnet),
        _ => Err(format!("unknown network {s:?} (mainnet|stagenet|testnet)")),
    }
}

fn arr32(b: &[u8], what: &str) -> Result<[u8; 32], String> {
    b.try_into().map_err(|_| format!("{what} must be 32 bytes, got {}", b.len()))
}

/// Derive the joint spend key, shared view key and address — the same
/// derivation the native Stage-2 flow proved against real stagenet funds.
pub fn joint_info(
    ctx: [u8; 32],
    spend_pub_a: [u8; 32],
    spend_pub_b: [u8; 32],
    view_half_a: [u8; 32],
    view_half_b: [u8; 32],
    network: Network,
) -> Result<JointInfo, String> {
    let mut spend_pubs = vec![spend_pub_a, spend_pub_b];
    spend_pubs.sort();
    let joint_pub = aggregate_spend(ctx, &spend_pubs).ok_or("aggregate: invalid spend keys")?;
    let view_key = shared_view_key(ctx, &view_half_a, &view_half_b);
    let view_scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(view_key))
        .ok_or("shared view key is not canonical")?;
    let spend_pt = CompressedPoint::from(joint_pub)
        .decompress()
        .ok_or("joint spend key does not decompress")?;
    let vp = ViewPair::new(spend_pt, Zeroizing::new(MScalar::from(view_scalar)))
        .map_err(|e| format!("view pair: {e:?}"))?;
    Ok(JointInfo {
        spend_pub: joint_pub,
        view_key,
        address: vp.legacy_address(network).to_string(),
    })
}

/// Reconstruct the joint spend SECRET from both parties' secrets — the value
/// the XNO-side sweeper holds once the adaptor reveals the counterparty's
/// share: s = b₁·s₁ + b₂·s₂ with the MuSig binding factors.
pub fn joint_secret(
    ctx: [u8; 32],
    my_secret: [u8; 32],
    their_secret: [u8; 32],
) -> Result<[u8; 32], String> {
    let mine = Option::<Scalar>::from(Scalar::from_canonical_bytes(my_secret))
        .ok_or("my secret is not canonical")?;
    let theirs = Option::<Scalar>::from(Scalar::from_canonical_bytes(their_secret))
        .ok_or("their secret is not canonical")?;
    let my_pub = (&mine * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    let their_pub = (&theirs * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    let mut spend_pubs = vec![my_pub, their_pub];
    spend_pubs.sort();
    let keys = musig_threshold_keys(ctx, &my_secret, &spend_pubs)
        .map_err(|e| format!("musig keys: {e:?}"))?;
    let Interpolation::Constant(bindings) = keys.interpolation().clone() else {
        return Err("musig keys must use constant interpolation".into());
    };
    let idx = |pk: &[u8; 32]| spend_pubs.iter().position(|p| p == pk).expect("own pub present");
    let joint = bindings[idx(&my_pub)] * mine + bindings[idx(&their_pub)] * theirs;

    // The reconstructed secret must open the joint spend key.
    let expect = aggregate_spend(ctx, &spend_pubs).ok_or("aggregate: invalid spend keys")?;
    if (&joint * ED25519_BASEPOINT_TABLE).compress().to_bytes() != expect {
        return Err("reconstructed secret does not open the joint spend key".into());
    }
    Ok(joint.to_bytes())
}

// ---------------------------------------------------------------------------
// wasm surface
// ---------------------------------------------------------------------------

use wasm_bindgen::prelude::*;

/// secret·G, compressed — a party's Monero spend public key.
#[wasm_bindgen]
pub fn xmr_spend_pub(secret: &[u8]) -> Result<Vec<u8>, JsValue> {
    let s = arr32(secret, "secret").map_err(js)?;
    let sc = Option::<Scalar>::from(Scalar::from_canonical_bytes(s))
        .ok_or_else(|| js("secret is not a canonical scalar".into()))?;
    Ok((&sc * ED25519_BASEPOINT_TABLE).compress().to_bytes().to_vec())
}

/// Joint address derivation for JS. Returns JSON
/// `{address, spend_pub, view_key}` (hex where binary).
#[wasm_bindgen]
pub fn xmr_joint_info(
    ctx: &[u8],
    spend_pub_a: &[u8],
    spend_pub_b: &[u8],
    view_half_a: &[u8],
    view_half_b: &[u8],
    network: &str,
) -> Result<String, JsValue> {
    let info = joint_info(
        arr32(ctx, "ctx").map_err(js)?,
        arr32(spend_pub_a, "spend_pub_a").map_err(js)?,
        arr32(spend_pub_b, "spend_pub_b").map_err(js)?,
        arr32(view_half_a, "view_half_a").map_err(js)?,
        arr32(view_half_b, "view_half_b").map_err(js)?,
        parse_network(network).map_err(js)?,
    )
    .map_err(js)?;
    Ok(serde_json::json!({
        "address": info.address,
        "spend_pub": hex::encode(info.spend_pub),
        "view_key": hex::encode(info.view_key),
    })
    .to_string())
}

/// Joint spend-secret reconstruction for JS (32 bytes).
#[wasm_bindgen]
pub fn xmr_joint_secret(
    ctx: &[u8],
    my_secret: &[u8],
    their_secret: &[u8],
) -> Result<Vec<u8>, JsValue> {
    joint_secret(
        arr32(ctx, "ctx").map_err(js)?,
        arr32(my_secret, "my_secret").map_err(js)?,
        arr32(their_secret, "their_secret").map_err(js)?,
    )
    .map(|s| s.to_vec())
    .map_err(js)
}

/// Ring size. Named so both the send and sweep paths cannot drift apart.
const RING_LEN: u8 = 16;
/// Upper bound on the daemon-quoted fee rate, in piconero per weight unit.
/// Honest rates sit around 20k; this allows ~500x that, so it never fires on a
/// real node, but it stops a hostile one quoting a wallet-draining rate.
const MAX_FEE_PER_WEIGHT: u64 = 10_000_000;
/// Cap on inputs per transaction: more inputs mean a bigger, costlier tx and a
/// slower build, and a wallet needing more than this should consolidate first.
const MAX_INPUTS: usize = 16;

fn js(e: String) -> JsValue {
    JsValue::from_str(&e)
}

// ---------------------------------------------------------------------------
// Personal (single-key) Monero wallet, standard-derivation so the account is
// importable into any Monero wallet (e.g. Cake) from its spend key.
// ---------------------------------------------------------------------------

/// A personal Monero identity derived from a 32-byte master seed.
pub struct Personal {
    /// Private spend key (Cake import = this key).
    pub spend_secret: [u8; 32],
    /// Private view key = Keccak256(spend_secret) reduced — the Monero standard.
    pub view_secret: [u8; 32],
    /// Public spend key.
    pub spend_pub: [u8; 32],
    /// The standard address for this account on `network`.
    pub address: String,
}

/// Standard Monero derivation: a canonical spend scalar domain-separated from
/// the wallet seed, then the view key as Keccak256(spend) reduced (so importing
/// the spend key into any Monero wallet reproduces this exact address).
pub fn personal_identity(seed: &[u8; 32], network: Network) -> Result<Personal, String> {
    use blake2::digest::{consts::U32, Digest as _};
    use sha3::Keccak256;

    // Spend secret: canonical scalar from Blake2b-256("xmr-spend" || seed).
    let mut h = blake2::Blake2b::<U32>::new();
    h.update(b"nearinstant-xmr-spend-v1");
    h.update(seed);
    let spend_secret = Scalar::from_bytes_mod_order(h.finalize().into());

    // View secret: sc_reduce32(Keccak256(spend_secret)) — Monero standard.
    let vk = Keccak256::digest(spend_secret.to_bytes());
    let view_secret = Scalar::from_bytes_mod_order(vk.into());

    let spend_pub = (&spend_secret * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    let spend_pt = CompressedPoint::from(spend_pub)
        .decompress()
        .ok_or("spend key does not decompress")?;
    let vp = ViewPair::new(spend_pt, Zeroizing::new(MScalar::from(view_secret)))
        .map_err(|e| format!("view pair: {e:?}"))?;
    Ok(Personal {
        spend_secret: spend_secret.to_bytes(),
        view_secret: view_secret.to_bytes(),
        spend_pub,
        address: vp.legacy_address(network).to_string(),
    })
}

/// Personal wallet identity for JS. Returns JSON `{address, spend_pub, view_key,
/// spend_secret}` (hex). `spend_secret` is the account's private key — the
/// caller (a Web Worker) must keep it confined and only surface it for backup.
#[wasm_bindgen]
pub fn xmr_personal(seed: &[u8], network: &str) -> Result<String, JsValue> {
    let p = personal_identity(&arr32(seed, "seed").map_err(js)?, parse_network(network).map_err(js)?)
        .map_err(js)?;
    Ok(serde_json::json!({
        "address": p.address,
        "spend_pub": hex::encode(p.spend_pub),
        "view_key": hex::encode(p.view_secret),
        "spend_secret": hex::encode(p.spend_secret),
    })
    .to_string())
}

/// Self-test the 2-of-2 CLSAG co-signing (I5) in the browser: run the whole
/// multisig ceremony in-process over a synthetic joint output and verify the
/// resulting CLSAG. This is the exact primitive a real two-party Monero *refund*
/// needs (neither party can sign a spend of the joint lock output alone). Proves
/// it compiles and runs in wasm without a counterparty or network.
#[cfg(test)]
mod deriv_tests {
    use super::*;

    /// Our spend key is a domain-separated Blake2b of the seed (NOT the Monero
    /// standard sc_reduce32(seed)), so the SEED is not portable to other Monero
    /// wallets. The view key, however, must stay standard — view =
    /// sc_reduce32(Keccak256(spend)) — because that is what makes the SPEND KEY
    /// importable into Cake/Feather and the funds recoverable. Guard it.
    #[test]
    fn view_key_is_monero_standard() {
        use sha3::{Digest as _, Keccak256};
        for i in 0u8..8 {
            let seed = [i.wrapping_mul(37).wrapping_add(11); 32];
            let p = personal_identity(&seed, Network::Mainnet).unwrap();
            let expected =
                Scalar::from_bytes_mod_order(Keccak256::digest(p.spend_secret).into()).to_bytes();
            assert_eq!(p.view_secret, expected, "view key drifted from Monero standard");
        }
    }

    /// And record the fact that the SEED is deliberately not standard, so this
    /// is never mistaken for a bug and "fixed" in a way that orphans wallets.
    #[test]
    fn seed_is_not_monero_standard_by_design() {
        let seed = [7u8; 32];
        let p = personal_identity(&seed, Network::Mainnet).unwrap();
        let monero_standard = Scalar::from_bytes_mod_order(seed).to_bytes();
        assert_ne!(p.spend_secret, monero_standard);
    }
}

#[wasm_bindgen]
pub fn xmr_cosign_selftest() -> bool {
    monero_side::selftest::cosign_selftest()
}

#[cfg(target_arch = "wasm32")]
mod node_client {
    //! The daemon client: JS supplies `fetch`, Rust supplies everything else.

    use super::*;
    use monero_daemon_rpc::{prelude::*, HttpTransport, MoneroDaemon};
    use monero_wallet::address::MoneroAddress;
    use monero_wallet::ringct::RctType;
    use monero_wallet::send::{Change, SignableTransaction};
    use monero_wallet::transaction::Transaction;
    use monero_wallet::{OutputWithDecoys, Scanner, WalletOutput};
    use rand_core::{OsRng, RngCore};
    use send_wrapper::SendWrapper;
    use std::future::Future;
    use wasm_bindgen_futures::JsFuture;

    /// [`HttpTransport`] over a JS `async (route: string, body: Uint8Array)
    /// -> Uint8Array` function (fetch under the hood). `SendWrapper` provides
    /// the `Send + Sync` bounds the trait wants — sound because wasm in a
    /// browser is single-threaded, so the wrapped values never cross threads.
    #[derive(Clone)]
    struct FetchTransport {
        post_fn: SendWrapper<js_sys::Function>,
    }

    impl HttpTransport for FetchTransport {
        fn post(
            &self,
            route: &str,
            body: Vec<u8>,
            _response_size_limit: Option<usize>,
        ) -> impl Send + Future<Output = Result<Vec<u8>, InterfaceError>> {
            let post_fn = self.post_fn.clone();
            let route = route.to_string();
            SendWrapper::new(async move {
                let arr = js_sys::Uint8Array::from(body.as_slice());
                let promise = post_fn
                    .call2(&JsValue::NULL, &JsValue::from_str(&route), &arr)
                    .map_err(|e| conn_err(&route, &e))?;
                let resolved = JsFuture::from(js_sys::Promise::resolve(&promise))
                    .await
                    .map_err(|e| conn_err(&route, &e))?;
                let bytes = js_sys::Uint8Array::new(&resolved);
                Ok(bytes.to_vec())
            })
        }
    }

    fn conn_err(route: &str, e: &JsValue) -> InterfaceError {
        InterfaceError::InterfaceError(format!(
            "js fetch failed for {route}: {}",
            e.as_string().unwrap_or_else(|| format!("{e:?}"))
        ))
    }

    /// A connected Monero daemon, everything routed through the JS fetch.
    #[wasm_bindgen]
    pub struct XmrNode {
        daemon: MoneroDaemon<FetchTransport>,
    }

    #[wasm_bindgen]
    impl XmrNode {
        /// Connect (probes the daemon once). `post_fn(route, body) -> Promise<Uint8Array>`.
        pub async fn connect(post_fn: js_sys::Function) -> Result<XmrNode, JsValue> {
            let transport = FetchTransport { post_fn: SendWrapper::new(post_fn) };
            let daemon = MoneroDaemon::new(transport)
                .await
                .map_err(|e| js(format!("daemon connect: {e:?}")))?;
            Ok(XmrNode { daemon })
        }

        /// Current chain height (the number of the next block).
        pub async fn height(&self) -> Result<u32, JsValue> {
            let n = self
                .daemon
                .latest_block_number()
                .await
                .map_err(|e| js(format!("height: {e:?}")))?;
            Ok(u32::try_from(n + 1).map_err(|_| js("height overflow".into()))?)
        }

        /// View-key scan of blocks `[from, to]` (inclusive, descending) for
        /// outputs paid to the joint address. Returns JSON
        /// `{block, amount, output}` (output = hex WalletOutput, spendable
        /// input to `sweep_sign`) for the first hit, or `null`. `on_block`,
        /// if given, is called with each block number scanned.
        pub async fn scan(
            &self,
            spend_pub: &[u8],
            view_key: &[u8],
            from: u32,
            to: u32,
            on_block: Option<js_sys::Function>,
        ) -> Result<JsValue, JsValue> {
            let spend = arr32(spend_pub, "spend_pub").map_err(js)?;
            let view = arr32(view_key, "view_key").map_err(js)?;
            let view_scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(view))
                .ok_or_else(|| js("view key is not canonical".into()))?;
            let spend_pt = CompressedPoint::from(spend)
                .decompress()
                .ok_or_else(|| js("spend key does not decompress".into()))?;
            let pair = ViewPair::new(spend_pt, Zeroizing::new(MScalar::from(view_scalar)))
                .map_err(|e| js(format!("view pair: {e:?}")))?;
            let mut scanner = Scanner::new(pair);
            for n in (from..=to).rev() {
                if let Some(cb) = &on_block {
                    let _ = cb.call1(&JsValue::NULL, &JsValue::from_f64(f64::from(n)));
                }
                let block = self
                    .daemon
                    .scannable_block_by_number(n as usize)
                    .await
                    .map_err(|e| js(format!("block {n}: {e:?}")))?;
                let outs = scanner
                    .scan(block)
                    .map_err(|e| js(format!("scan {n}: {e:?}")))?
                    .not_additionally_locked();
                if let Some(o) = outs.into_iter().next() {
                    let json = serde_json::json!({
                        "block": n,
                        "amount": o.commitment().amount.to_string(),
                        "output": hex::encode(o.serialize()),
                    });
                    return Ok(JsValue::from_str(&json.to_string()));
                }
            }
            Ok(JsValue::NULL)
        }

        /// View-key scan of `[from, to]` (inclusive) returning EVERY owned,
        /// spendable output as JSON `[{block, amount, index, output}]` — the
        /// wallet sums these (minus locally-known-spent) for the balance and
        /// picks one to fund a send. `index` is the output's global on-chain
        /// index, a stable id for spent-tracking. `on_block` reports progress.
        pub async fn scan_all(
            &self,
            spend_pub: &[u8],
            view_key: &[u8],
            from: u32,
            to: u32,
            on_block: Option<js_sys::Function>,
        ) -> Result<String, JsValue> {
            let spend = arr32(spend_pub, "spend_pub").map_err(js)?;
            let view = arr32(view_key, "view_key").map_err(js)?;
            let view_scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(view))
                .ok_or_else(|| js("view key is not canonical".into()))?;
            let spend_pt = CompressedPoint::from(spend)
                .decompress()
                .ok_or_else(|| js("spend key does not decompress".into()))?;
            let pair = ViewPair::new(spend_pt, Zeroizing::new(MScalar::from(view_scalar)))
                .map_err(|e| js(format!("view pair: {e:?}")))?;
            let mut scanner = Scanner::new(pair);
            let mut found = Vec::new();
            for n in from..=to {
                if let Some(cb) = &on_block {
                    let _ = cb.call1(&JsValue::NULL, &JsValue::from_f64(f64::from(n)));
                }
                let block = self
                    .daemon
                    .scannable_block_by_number(n as usize)
                    .await
                    .map_err(|e| js(format!("block {n}: {e:?}")))?;
                let outs = scanner
                    .scan(block)
                    .map_err(|e| js(format!("scan {n}: {e:?}")))?
                    .not_additionally_locked();
                for o in outs {
                    found.push(serde_json::json!({
                        "block": n,
                        "amount": o.commitment().amount.to_string(),
                        "index": o.index_on_blockchain().to_string(),
                        "output": hex::encode(o.serialize()),
                    }));
                }
            }
            Ok(serde_json::Value::Array(found).to_string())
        }

        /// Build and sign a personal send spending ONE OR MORE outputs.
        ///
        /// `inputs_json` is `[{"output": "<hex>", "block": <n>}, ...]` from
        /// [`Self::scan_all`]. Previously this took a single output, so a
        /// wallet whose balance was split across several outputs could not
        /// spend it at all — the caller had to find one output covering the
        /// whole amount plus fee, or give up.
        ///
        /// Real decoys + live fee (sanity-capped); the builder errors if the
        /// inputs cannot cover amount+fee (fail-closed). Returns JSON
        /// `{tx, tx_hash, fee, inputs}` (hex); broadcast with [`Self::publish`].
        pub async fn send(
            &self,
            inputs_json: &str,
            spend_secret: &[u8],
            dest: &str,
            amount_atomic: &str,
            change_address: &str,
            network: &str,
        ) -> Result<String, JsValue> {
            let parsed: serde_json::Value = serde_json::from_str(inputs_json)
                .map_err(|e| js(format!("inputs must be JSON: {e}")))?;
            let arr = parsed
                .as_array()
                .ok_or_else(|| js("inputs must be an array of {output, block}".into()))?;
            let mut refs: Vec<(String, u32)> = Vec::with_capacity(arr.len());
            for v in arr {
                let output = v
                    .get("output")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| js("each input needs an \"output\" hex string".into()))?
                    .to_string();
                let block = v
                    .get("block")
                    .and_then(|x| x.as_u64())
                    .ok_or_else(|| js("each input needs a numeric \"block\"".into()))?
                    as u32;
                refs.push((output, block));
            }
            if refs.is_empty() {
                return Err(js("no inputs given".into()));
            }
            if refs.len() > MAX_INPUTS {
                return Err(js(format!("too many inputs ({}), max {MAX_INPUTS}", refs.len())));
            }
            let secret = arr32(spend_secret, "spend_secret").map_err(js)?;
            let secret = Option::<Scalar>::from(Scalar::from_canonical_bytes(secret))
                .ok_or_else(|| js("spend secret is not canonical".into()))?;
            let net = parse_network(network).map_err(js)?;
            let dest = MoneroAddress::from_str(net, dest)
                .map_err(|e| js(format!("dest address: {e:?}")))?;
            let change = MoneroAddress::from_str(net, change_address)
                .map_err(|e| js(format!("change address: {e:?}")))?;
            let amount: u64 = amount_atomic
                .parse()
                .map_err(|_| js("amount must be a whole number of piconero".into()))?;

            // Decoys per input. Sequential, not concurrent: each call hits the
            // daemon and we would rather be slow than hammer a public node.
            let mut with_decoys = Vec::with_capacity(refs.len());
            for (out_hex, blk) in &refs {
                let raw = hex::decode(out_hex).map_err(|e| js(format!("output hex: {e}")))?;
                let output = WalletOutput::read(&mut raw.as_slice())
                    .map_err(|e| js(format!("output decode: {e}")))?;
                with_decoys.push(
                    OutputWithDecoys::new(
                        &mut OsRng,
                        &self.daemon,
                        RING_LEN,
                        *blk as usize,
                        output,
                    )
                    .await
                    .map_err(|e| js(format!("decoys: {e:?}")))?,
                );
            }
            // The daemon's fee rate is attacker-controlled and the crate
            // documents it as MUST-sanity-check; u64::MAX disabled the check
            // entirely, so a hostile node could quote a rate that ate the
            // wallet. MAX_FEE_PER_WEIGHT is far above any honest rate and far
            // below a draining one.
            let fee_rate = self
                .daemon
                .fee_rate(FeePriority::Normal, MAX_FEE_PER_WEIGHT)
                .await
                .map_err(|e| js(format!("fee rate rejected (node may be quoting an absurd fee): {e:?}")))?;

            let mut outgoing_view = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(outgoing_view.as_mut());
            let signable = SignableTransaction::new(
                RctType::ClsagBulletproofPlus,
                outgoing_view,
                with_decoys,
                vec![(dest, amount)],
                Change::fingerprintable(Some(change)),
                vec![],
                fee_rate,
            )
            .map_err(|e| js(format!("cannot build (inputs may not cover amount + fee): {e:?}")))?;
            let fee = signable.necessary_fee();
            let tx = signable
                .sign(&mut OsRng, &Zeroizing::new(MScalar::from(secret)))
                .map_err(|e| js(format!("sign: {e:?}")))?;
            Ok(serde_json::json!({
                "tx": hex::encode(tx.serialize()),
                "tx_hash": hex::encode(tx.hash()),
                "fee": fee.to_string(),
                "inputs": refs.len(),
            })
            .to_string())
        }

        /// Build and sign the sweep of `output` (hex, from [`Self::scan`])
        /// with the reconstructed joint spend secret: real decoys from the
        /// daemon, live fee rate, CLSAG/Bulletproof+. Half the amount is an
        /// explicit payment to `dest` and the remainder returns to `dest` as
        /// change, so everything minus the fee lands at `dest` (the exact
        /// shape of the on-chain-proven native sweep). Returns JSON
        /// `{tx, tx_hash}` (hex); nothing is broadcast until [`Self::publish`].
        pub async fn sweep_sign(
            &self,
            output_hex: &str,
            block: u32,
            joint_secret: &[u8],
            dest: &str,
            network: &str,
        ) -> Result<String, JsValue> {
            let raw = hex::decode(output_hex).map_err(|e| js(format!("output hex: {e}")))?;
            let output = WalletOutput::read(&mut raw.as_slice())
                .map_err(|e| js(format!("output decode: {e}")))?;
            let secret = arr32(joint_secret, "joint_secret").map_err(js)?;
            let secret = Option::<Scalar>::from(Scalar::from_canonical_bytes(secret))
                .ok_or_else(|| js("joint secret is not canonical".into()))?;
            let net = parse_network(network).map_err(js)?;
            let dest = MoneroAddress::from_str(net, dest)
                .map_err(|e| js(format!("dest address: {e:?}")))?;

            let with_decoys =
                OutputWithDecoys::new(&mut OsRng, &self.daemon, RING_LEN, block as usize, output.clone())
                    .await
                    .map_err(|e| js(format!("decoys: {e:?}")))?;
            let fee_rate = self
                .daemon
                .fee_rate(FeePriority::Normal, MAX_FEE_PER_WEIGHT)
                .await
                .map_err(|e| js(format!("fee rate: {e:?}")))?;

            let mut outgoing_view = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(outgoing_view.as_mut());
            let amount = output.commitment().amount;
            let signable = SignableTransaction::new(
                RctType::ClsagBulletproofPlus,
                outgoing_view,
                vec![with_decoys],
                vec![(dest, amount / 2)],
                Change::fingerprintable(Some(dest)),
                vec![],
                fee_rate,
            )
            .map_err(|e| js(format!("signable: {e:?}")))?;
            let tx = signable
                .sign(&mut OsRng, &Zeroizing::new(MScalar::from(secret)))
                .map_err(|e| js(format!("sign: {e:?}")))?;
            Ok(serde_json::json!({
                "tx": hex::encode(tx.serialize()),
                "tx_hash": hex::encode(tx.hash()),
            })
            .to_string())
        }

        /// Broadcast a signed transaction (hex). Returns its hash.
        pub async fn publish(&self, tx_hex: &str) -> Result<String, JsValue> {
            let raw = hex::decode(tx_hex).map_err(|e| js(format!("tx hex: {e}")))?;
            let tx = Transaction::read(&mut raw.as_slice())
                .map_err(|e| js(format!("tx decode: {e}")))?;
            self.daemon
                .publish_transaction(&tx)
                .await
                .map_err(|e| js(format!("publish: {e:?}")))?;
            Ok(hex::encode(tx.hash()))
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use node_client::*;

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar_from_seed(seed: &[u8; 32]) -> Scalar {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(seed);
        Scalar::from_bytes_mod_order_wide(&wide)
    }

    /// A personal wallet derives a valid standard Monero address (mainnet "4",
    /// stagenet "5"), deterministic from the seed, with view = Keccak(spend) so
    /// importing the spend key into any Monero wallet reproduces the address.
    #[test]
    fn personal_wallet_derivation_is_standard_and_deterministic() {
        use sha3::{Digest, Keccak256};
        let seed = [0x7u8; 32];
        let m = personal_identity(&seed, Network::Mainnet).expect("mainnet");
        let s = personal_identity(&seed, Network::Stagenet).expect("stagenet");
        assert!(m.address.starts_with('4'), "mainnet address starts with 4: {}", m.address);
        assert!(s.address.starts_with('5'), "stagenet address starts with 5: {}", s.address);
        assert_eq!(m.spend_secret, s.spend_secret, "keys are network-independent");

        // Deterministic.
        assert_eq!(personal_identity(&seed, Network::Mainnet).unwrap().address, m.address);
        // Different seed → different account.
        assert_ne!(personal_identity(&[0x8; 32], Network::Mainnet).unwrap().address, m.address);

        // view = sc_reduce(Keccak256(spend)) — the Monero standard.
        let expect_view = Scalar::from_bytes_mod_order(Keccak256::digest(m.spend_secret).into());
        assert_eq!(m.view_secret, expect_view.to_bytes());

        // The address round-trips through the real address parser to the same keys.
        let parsed = monero_wallet::address::MoneroAddress::from_str(Network::Mainnet, &m.address)
            .expect("valid address");
        assert_eq!(parsed.spend().compress().to_bytes(), m.spend_pub);
    }

    /// The derivation must match the native Stage-2 flow byte for byte — the
    /// fixtures are the values `joint_address` prints for its fixed seeds,
    /// whose address held (and was swept of) real stagenet funds.
    #[test]
    fn joint_derivation_matches_the_on_chain_proven_fixture() {
        let alice = scalar_from_seed(&[0x11; 32]);
        let bob = scalar_from_seed(&[0x22; 32]);
        let ctx = [0x42u8; 32];
        let a_pub = (&alice * ED25519_BASEPOINT_TABLE).compress().to_bytes();
        let b_pub = (&bob * ED25519_BASEPOINT_TABLE).compress().to_bytes();

        let info = joint_info(ctx, a_pub, b_pub, [0x01; 32], [0x02; 32], Network::Stagenet)
            .expect("joint info");
        assert_eq!(
            info.address,
            "5BCrVM7isJxbLh75xCEg41eaDeJp24wHpSwGwZKiA41zX2GSqFLD5SGjPyoCgQvHbnJXbE5uyYSQfj5eMZfQZaQNTb8QuRz"
        );
        assert_eq!(
            hex::encode(info.view_key),
            "6148bd815c287cfb6c606333e4cbc275f6a695c53071ac8e12653d7cce89790c"
        );

        let secret = joint_secret(ctx, alice.to_bytes(), bob.to_bytes()).expect("joint secret");
        assert_eq!(
            hex::encode(secret),
            "d14170dfb087b010ea1ee7d260468999012f21cb04512d738c6fbf38f3af8600"
        );
        // Symmetric: Bob reconstructs the identical secret from his side.
        let from_bob = joint_secret(ctx, bob.to_bytes(), alice.to_bytes()).expect("bob side");
        assert_eq!(secret, from_bob);
    }
}
