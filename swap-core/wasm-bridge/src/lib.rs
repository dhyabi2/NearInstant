//! Block 9b: the real protocol engine, compiled for the browser.
//!
//! `atomic_chunk_demo` runs the genuine Nano-side atomic flow — FROST
//! ed25519-blake2b 2-of-2 keygen, joint account, guard rung, adaptor
//! pre-signature bound to the counterparty's secret point, completion,
//! and on-chain-signature secret extraction — with the same crates the
//! native tests exercise, and returns every artifact as hex so the UI can
//! display real cryptography instead of theater. (Demo-sized PoW threshold;
//! everything else is protocol-real.)

use std::collections::BTreeMap;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use rand_core::{OsRng, RngCore};
use wasm_bindgen::prelude::*;

use nano_ceremony::block::{StateBlock, Subtype};
use nano_ceremony::{address, ceremony, guard, work};
use signing::adaptor::{
    adaptor_sign, aggregate_presignature, complete_presignature, extract_secret,
    verify_presignature, AdaptorSession, PreSignature,
};
use signing::{aggregate, keys, round1, round2, Identifier, SigningPackage};

use blake2::digest::consts::U32 as Blake2bU32;
use blake2::{Blake2b, Digest};

const DEMO_THRESHOLD: u64 = 0xFF00_0000_0000_0000;

/// How long a browser-signed order stays valid (seconds). Bounds replay of a
/// captured order; the relay sweeps anything past its expiry.
const ORDER_TTL_SECS: u64 = 3_600;

fn commit_all(
    kps: &BTreeMap<Identifier, keys::KeyPackage>,
) -> (
    BTreeMap<Identifier, round1::SigningNonces>,
    BTreeMap<Identifier, round1::SigningCommitments>,
) {
    let mut nonces = BTreeMap::new();
    let mut comms = BTreeMap::new();
    for (id, kp) in kps {
        let (n, c) = round1::commit(kp.signing_share(), &mut OsRng);
        nonces.insert(*id, n);
        comms.insert(*id, c);
    }
    (nonces, comms)
}

/// Two-party distributed keygen (no trusted dealer) — the real keygen a swap
/// uses. Returns both parties' key packages + the shared public key package.
fn dkg_2of2() -> (BTreeMap<Identifier, keys::KeyPackage>, keys::PublicKeyPackage) {
    use std::collections::BTreeMap as Map;
    let alice_id = Identifier::try_from(1u16).unwrap();
    let bob_id = Identifier::try_from(2u16).unwrap();

    let (a_r1s, a_r1p) = keys::dkg::part1(alice_id, OsRng).unwrap();
    let (b_r1s, b_r1p) = keys::dkg::part1(bob_id, OsRng).unwrap();

    let mut a_r1 = Map::new();
    a_r1.insert(bob_id, b_r1p.clone());
    let mut b_r1 = Map::new();
    b_r1.insert(alice_id, a_r1p.clone());

    let (a_r2s, a_r2) = keys::dkg::part2(a_r1s, &a_r1).unwrap();
    let (b_r2s, b_r2) = keys::dkg::part2(b_r1s, &b_r1).unwrap();

    let a_to_b = a_r2.get(&bob_id).unwrap().clone();
    let b_to_a = b_r2.get(&alice_id).unwrap().clone();
    let mut a_recv = Map::new();
    a_recv.insert(bob_id, b_to_a);
    let mut b_recv = Map::new();
    b_recv.insert(alice_id, a_to_b);

    let (a_kp, a_pub) = keys::dkg::part3(&a_r2s, &a_r1, &a_recv).unwrap();
    let (b_kp, b_pub) = keys::dkg::part3(&b_r2s, &b_r1, &b_recv).unwrap();
    debug_assert_eq!(
        a_pub.verifying_key().serialize().unwrap(),
        b_pub.verifying_key().serialize().unwrap()
    );

    let mut kps = Map::new();
    kps.insert(alice_id, a_kp);
    kps.insert(bob_id, b_kp);
    (kps, a_pub)
}

/// Run one real atomic chunk (Nano leg) and return a JSON string of every
/// artifact. Takes ~a few ms of curve math plus demo PoW.
#[wasm_bindgen]
pub fn atomic_chunk_demo(chunk_raw: u64) -> String {
    let chunk = chunk_raw.max(1) as u128;

    // 2-of-2 joint account — real distributed keygen, NO trusted dealer.
    let (kps, pubkeys) = dkg_2of2();
    let account: [u8; 32] = pubkeys
        .verifying_key()
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();

    let jointly_sign = |block: &StateBlock| -> [u8; 64] {
        let (nonces, comms) = commit_all(&kps);
        ceremony::sign_block(block, comms, &nonces, &kps, &pubkeys).unwrap()
    };

    // Fund the joint account.
    let open = StateBlock {
        account,
        previous: [0u8; 32],
        representative: account,
        balance: chunk,
        link: [0xAA; 32],
        subtype: Subtype::Open,
    };
    let open_sig = jointly_sign(&open);
    let frontier = open.hash();

    // Guard rung (I3) + Bob's adaptor secret x with T = x·G.
    let rung_block = StateBlock::change(account, frontier, account, chunk);
    let rung_sig = jointly_sign(&rung_block);
    let rung = guard::Rung {
        block: rung_block.clone(),
        signature: rung_sig,
    };
    let ladder_ok = rung.verify(&account, chunk);

    let mut wide = [0u8; 64];
    OsRng.fill_bytes(&mut wide);
    let x = Scalar::from_bytes_mod_order_wide(&wide);
    let t_point = (&x * ED25519_BASEPOINT_TABLE).compress().to_bytes();

    // Claim block pre-signed against the post-guard frontier.
    let claim = StateBlock {
        account,
        previous: rung_block.hash(),
        representative: account,
        balance: 0,
        link: [0xB0; 32],
        subtype: Subtype::Send,
    };
    let (nonces, comms) = commit_all(&kps);
    let presig =
        ceremony::adaptor_presign_block(&claim, &t_point, comms, &nonces, &kps, &pubkeys)
            .expect("presign");
    let presig_valid = verify_presignature(&presig, &account, &claim.hash()).is_ok();

    // The pre-signature must NOT verify as a Nano signature by itself.
    let mut fake = [0u8; 64];
    fake[..32].copy_from_slice(&presig.r_adapted);
    fake[32..].copy_from_slice(&presig.s_hat);
    let presig_invalid_alone = !signing::nano_verify::verify(&account, &claim.hash(), &fake);

    // Bob completes with x; the broadcast signature reveals x to Alice.
    let claim_sig = complete_presignature(&presig, &x.to_bytes()).expect("complete");
    let claim_valid = signing::nano_verify::verify(&account, &claim.hash(), &claim_sig);
    let extracted = extract_secret(&presig, &claim_sig).expect("extract");
    let extraction_exact = extracted == x.to_bytes();

    // Demo PoW for the claim (real algorithm, demo threshold).
    let claim_work = work::generate(&claim.work_root(), DEMO_THRESHOLD, 0);
    let work_ok = work::validate(&claim.work_root(), claim_work, DEMO_THRESHOLD);

    format!(
        concat!(
            "{{\"account\":\"{}\",",
            "\"open_sig\":\"{}\",",
            "\"guard_ok\":{},",
            "\"claim_hash\":\"{}\",",
            "\"adaptor_point\":\"{}\",",
            "\"presig_s\":\"{}\",",
            "\"presig_valid\":{},",
            "\"presig_invalid_alone\":{},",
            "\"claim_sig\":\"{}\",",
            "\"claim_valid\":{},",
            "\"secret\":\"{}\",",
            "\"extraction_exact\":{},",
            "\"work\":\"{:016x}\",",
            "\"work_ok\":{}}}"
        ),
        address::encode(&account),
        hex::encode(open_sig),
        ladder_ok,
        hex::encode(claim.hash()),
        hex::encode(t_point),
        hex::encode(presig.s_hat),
        presig_valid,
        presig_invalid_alone,
        hex::encode(claim_sig),
        claim_valid,
        hex::encode(extracted),
        extraction_exact,
        claim_work,
        work_ok,
    )
}

/// Version tag for the UI.
#[wasm_bindgen]
pub fn engine_version() -> String {
    "swap-core wasm · FROST ed25519-blake2b · real curves".into()
}

/// Produce a real signed order (ed25519-blake2b) as hex wire bytes, for the
/// browser to gossip to the live relay. Inlines the dex-core order wire
/// format so the wasm stays light (signing crate only, no Monero deps).
#[wasm_bindgen]
pub fn make_test_order(now_secs: u64) -> String {
    let key = signing::SigningKey::new(&mut OsRng);
    let vk = signing::VerifyingKey::from(&key);
    let maker: [u8; 32] = vk.serialize().unwrap().try_into().unwrap();

    let mut r = [0u8; 8];
    OsRng.fill_bytes(&mut r);
    let jitter = (u64::from_le_bytes(r) % 200) as i64 - 100;
    let rate_pico: u128 = (3_750_000_000i64 + jitter * 1_000_000) as u128;
    let side: u8 = r[0] & 1; // 0 = sell XNO, 1 = sell XMR
    let amount: u128 = 100u128 * 10u128.pow(30);
    // Audit (stale-forever expiry): expiry is now + a bounded TTL sourced from
    // the JS clock, not a hardcoded far-future constant. A captured order is
    // replayable only within ORDER_TTL_SECS, not for decades.
    let expiry: u64 = now_secs.saturating_add(ORDER_TTL_SECS);
    let nonce = u64::from_le_bytes(r);
    let pof = [0xEEu8; 32];

    // Canonical body encoding (must match dex_core::order::OrderBody::encode).
    let mut body = Vec::with_capacity(129);
    body.extend_from_slice(b"XNOXMR-ORDER-v1\0");
    body.extend_from_slice(&maker);
    body.push(side);
    body.extend_from_slice(&amount.to_be_bytes());
    body.extend_from_slice(&rate_pico.to_be_bytes());
    body.extend_from_slice(&expiry.to_be_bytes());
    body.extend_from_slice(&nonce.to_be_bytes());
    body.extend_from_slice(&pof);

    let sig = key.sign(OsRng, &body);
    let sig_bytes: [u8; 64] = sig.serialize().unwrap().try_into().unwrap();
    let mut wire = body;
    wire.extend_from_slice(&sig_bytes);
    hex::encode(wire)
}

/// Sign a specific order (side 0=sell XNO, 1=sell XMR) with the given amount
/// in milli-XNO and rate in micro (XMR-per-XNO × 1e6). `now_secs` is the JS
/// wall clock (seconds); the order expires `now_secs + ORDER_TTL_SECS`.
/// Returns hex wire bytes, or an empty string if the amount would overflow.
/// Same canonical encoding as dex_core::order.
#[wasm_bindgen]
pub fn make_order(
    side: u8,
    amount_milli_xno: u64,
    rate_micro: u64,
    nonce: u64,
    now_secs: u64,
) -> String {
    let key = signing::SigningKey::new(&mut OsRng);
    let vk = signing::VerifyingKey::from(&key);
    let maker: [u8; 32] = vk.serialize().unwrap().try_into().unwrap();

    // Audit (amount overflow): checked_mul instead of `*`. A silent wrap in the
    // release build would sign an amount the maker never intended; on overflow
    // we refuse (empty string) rather than emit a corrupt order.
    let amount: u128 = match (amount_milli_xno as u128).checked_mul(10u128.pow(27)) {
        Some(a) => a, // milli → raw
        None => return String::new(),
    };
    let rate_pico: u128 = (rate_micro as u128) * 1_000_000; // micro → pico (max ~1.8e25, no overflow)
    let side = if side == 0 { 0u8 } else { 1u8 };
    let expiry: u64 = now_secs.saturating_add(ORDER_TTL_SECS);

    let mut body = Vec::with_capacity(129);
    body.extend_from_slice(b"XNOXMR-ORDER-v1\0");
    body.extend_from_slice(&maker);
    body.push(side);
    body.extend_from_slice(&amount.to_be_bytes());
    body.extend_from_slice(&rate_pico.to_be_bytes());
    // Audit (stale-forever expiry): bounded TTL from the JS clock, not a
    // hardcoded constant — a captured order is replayable only within the TTL.
    body.extend_from_slice(&expiry.to_be_bytes());
    body.extend_from_slice(&nonce.to_be_bytes());
    body.extend_from_slice(&[0xEEu8; 32]);
    let sig = key.sign(OsRng, &body);
    let sig_bytes: [u8; 64] = sig.serialize().unwrap().try_into().unwrap();
    let mut wire = body;
    wire.extend_from_slice(&sig_bytes);
    hex::encode(wire)
}

/// A persistent browser identity: a fresh ed25519 key pair returned as
/// `{"seed": <hex32>, "pubkey": <hex32>}`. The caller stores the seed (e.g. in
/// localStorage) and passes it to `make_order_seeded` / `make_pof` so the maker
/// keeps ONE identity across orders instead of a throwaway key per order.
#[wasm_bindgen]
pub fn gen_identity() -> String {
    let key = signing::SigningKey::new(&mut OsRng);
    let vk = signing::VerifyingKey::from(&key);
    let pubkey: [u8; 32] = vk.serialize().unwrap().try_into().unwrap();
    format!(
        "{{\"seed\":\"{}\",\"pubkey\":\"{}\"}}",
        hex::encode(key.serialize()),
        hex::encode(pubkey)
    )
}

/// Stage 6 custody: stretch a human passphrase into a 32-byte wallet seed with
/// Argon2id (memory-hard — a stolen page or shoulder-surfed passphrase still
/// costs the attacker the full KDF per guess). Runs inside a Web Worker whose
/// scope the DOM cannot read, so the seed never touches the page. `salt` must
/// be ≥ 8 bytes and STABLE for an account (store it, e.g. localStorage). Params
/// are the OWASP-recommended Argon2id floor (19 MiB, t=2, p=1); `mem_kib` may
/// raise the memory cost. Returns the 32-byte seed (feed to `seed_account` /
/// `sign_state_block`), or an empty vec on bad input.
#[wasm_bindgen]
pub fn argon2id_seed(passphrase: &str, salt: &[u8], mem_kib: u32) -> Vec<u8> {
    use argon2::{Algorithm, Argon2, Params, Version};
    if salt.len() < 8 {
        return Vec::new();
    }
    let m = mem_kib.max(19 * 1024);
    let Ok(params) = Params::new(m, 2, 1, Some(32)) else {
        return Vec::new();
    };
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    if a2.hash_password_into(passphrase.as_bytes(), salt, &mut out).is_err() {
        return Vec::new();
    }
    // The wallet key is an ed25519 scalar, so reduce the KDF output into the
    // canonical scalar range (bias ≈ 2⁻¹²⁴, negligible) — the result is a valid
    // signing seed for `seed_account` / `sign_state_block`.
    Scalar::from_bytes_mod_order(out).to_bytes().to_vec()
}

/// Argon2id as a raw 32-byte key-derivation function (NOT reduced to a curve
/// scalar): the wallet uses this to derive an AES-256-GCM key that encrypts the
/// random wallet seed at rest. Same memory-hard parameters as `argon2id_seed`
/// (OWASP floor 19 MiB, t=2, p=1; `mem_kib` may raise it). `salt` ≥ 8 bytes.
/// Returns the full 32-byte tag, or an empty vec on bad input.
#[wasm_bindgen]
pub fn argon2id_raw(passphrase: &str, salt: &[u8], mem_kib: u32) -> Vec<u8> {
    use argon2::{Algorithm, Argon2, Params, Version};
    if salt.len() < 8 {
        return Vec::new();
    }
    let m = mem_kib.max(19 * 1024);
    let Ok(params) = Params::new(m, 2, 1, Some(32)) else {
        return Vec::new();
    };
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    if a2.hash_password_into(passphrase.as_bytes(), salt, &mut out).is_err() {
        return Vec::new();
    }
    out.to_vec()
}

/// Load a signing key from a 32-byte hex seed (as returned by `gen_identity`).
fn key_from_seed(seed_hex: &str) -> Option<signing::SigningKey> {
    let bytes = hex::decode(seed_hex.trim()).ok()?;
    signing::SigningKey::deserialize(&bytes).ok()
}

/// Sign a Nano proof-of-funds with the identity seed: a statement that the
/// account controls at least `amount_raw` (decimal string, raw units). Returns
/// `{"hash": <hex32>, "wire": <hex>}` — `hash` is the value to put in the
/// order's `pof_hash` field; `wire` is the signed proof (gossiped beside the
/// order via the peer `0x02` frame). Format matches `dex_core::pof::NanoFundsProof`.
#[wasm_bindgen]
pub fn make_pof(
    seed_hex: &str,
    amount_raw: &str,
    as_of_block: u64,
    expires: u64,
    nonce: u64,
) -> String {
    let Some(key) = key_from_seed(seed_hex) else { return String::new() };
    let vk = signing::VerifyingKey::from(&key);
    let account: [u8; 32] = vk.serialize().unwrap().try_into().unwrap();
    let Ok(amount) = amount_raw.parse::<u128>() else { return String::new() };

    let mut msg = Vec::with_capacity(91);
    msg.extend_from_slice(b"XNOXMR-NANO-POF-v1\0");
    msg.extend_from_slice(&account);
    msg.extend_from_slice(&amount.to_be_bytes());
    msg.extend_from_slice(&as_of_block.to_be_bytes());
    msg.extend_from_slice(&expires.to_be_bytes());
    msg.extend_from_slice(&nonce.to_be_bytes());

    // hash = Blake2b-256(message) (matches dex_core::pof::NanoFundsProof::hash).
    let mut h = Blake2b::<Blake2bU32>::new();
    h.update(&msg);
    let hash: [u8; 32] = h.finalize().into();

    let sig = key.sign(OsRng, &msg);
    let sig_bytes: [u8; 64] = sig.serialize().unwrap().try_into().unwrap();
    let mut wire = msg;
    wire.extend_from_slice(&sig_bytes);

    format!("{{\"hash\":\"{}\",\"wire\":\"{}\"}}", hex::encode(hash), hex::encode(wire))
}

/// Sign an order with the identity seed and an explicit `pof_hash` (from
/// `make_pof`), so the order carries a REAL proof-of-funds commitment instead
/// of the `NO_POF` sentinel. `side` 0 = sell XNO, 1 = sell XMR; `amount_milli_xno`
/// is milli-XNO; `rate_micro` is XMR-per-XNO × 1e6. Returns hex wire bytes.
#[wasm_bindgen]
pub fn make_order_seeded(
    seed_hex: &str,
    side: u8,
    amount_milli_xno: u64,
    rate_micro: u64,
    nonce: u64,
    now_secs: u64,
    pof_hash_hex: &str,
) -> String {
    let Some(key) = key_from_seed(seed_hex) else { return String::new() };
    let vk = signing::VerifyingKey::from(&key);
    let maker: [u8; 32] = vk.serialize().unwrap().try_into().unwrap();
    let Ok(pof_hash) = <[u8; 32]>::try_from(hex::decode(pof_hash_hex.trim()).unwrap_or_default())
    else {
        return String::new();
    };

    let amount: u128 = match (amount_milli_xno as u128).checked_mul(10u128.pow(27)) {
        Some(a) => a,
        None => return String::new(),
    };
    let rate_pico: u128 = (rate_micro as u128) * 1_000_000;
    let side = if side == 0 { 0u8 } else { 1u8 };
    let expiry: u64 = now_secs.saturating_add(ORDER_TTL_SECS);

    let mut body = Vec::with_capacity(129);
    body.extend_from_slice(b"XNOXMR-ORDER-v1\0");
    body.extend_from_slice(&maker);
    body.push(side);
    body.extend_from_slice(&amount.to_be_bytes());
    body.extend_from_slice(&rate_pico.to_be_bytes());
    body.extend_from_slice(&expiry.to_be_bytes());
    body.extend_from_slice(&nonce.to_be_bytes());
    body.extend_from_slice(&pof_hash);
    let sig = key.sign(OsRng, &body);
    let sig_bytes: [u8; 64] = sig.serialize().unwrap().try_into().unwrap();
    let mut wire = body;
    wire.extend_from_slice(&sig_bytes);
    hex::encode(wire)
}

// ---------------------------------------------------------------------------
// Browser ceremony client (fix B, stage 2): the REAL FROST 2-of-2 DKG as a
// step-driven state machine, so a browser drives it over the JS MailboxWire
// (web/mailbox.js) with all async I/O in JS — no blocking, no native sockets.
// State lives in this struct in WASM memory across calls; JS holds the handle.
//
// Flow (both parties, symmetric): new(my,their) → round1_out() → send;
// recv peer's round1 → set_peer_round1() → round2_out() → send; recv peer's
// round2 → set_peer_round2() returns the 32-byte joint Nano account. Both
// parties end on the identical account.
// ---------------------------------------------------------------------------

fn jserr<E: core::fmt::Debug>(e: E) -> JsValue {
    JsValue::from_str(&format!("{e:?}"))
}
fn jsmsg(s: &str) -> JsValue {
    JsValue::from_str(s)
}

#[wasm_bindgen]
pub struct BrowserDkg {
    their_id: Identifier,
    r1_secret: Option<keys::dkg::Round1Secret>,
    r1_out: Vec<u8>,
    r1_map: BTreeMap<Identifier, keys::dkg::Round1Package>,
    r2_secret: Option<keys::dkg::Round2Secret>,
    r2_out: Vec<u8>,
    account: Option<[u8; 32]>,
    /// Retained after part3 so this party can go on to SIGN (its own share
    /// only) — this is what turns a joint account into a working swap signer.
    kp: Option<Vec<u8>>,
    pubkeys: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl BrowserDkg {
    /// Begin the DKG (runs part1). `my_id`/`their_id` are the two party ids
    /// (1 and 2, opposite on each side).
    #[wasm_bindgen(constructor)]
    pub fn new(my_id: u16, their_id: u16) -> Result<BrowserDkg, JsValue> {
        let my = Identifier::try_from(my_id).map_err(jserr)?;
        let their = Identifier::try_from(their_id).map_err(jserr)?;
        let (r1_secret, r1_pkg) = keys::dkg::part1(my, OsRng).map_err(jserr)?;
        let r1_out = r1_pkg.serialize().map_err(jserr)?;
        Ok(BrowserDkg {
            their_id: their,
            r1_secret: Some(r1_secret),
            r1_out,
            r1_map: BTreeMap::new(),
            r2_secret: None,
            r2_out: Vec::new(),
            account: None,
            kp: None,
            pubkeys: None,
        })
    }

    /// Deterministic DKG for reproducible per-session joint accounts: identical
    /// to `new` but seeds part1's randomness from a 32-byte session seed
    /// (derive it from your wallet seed + a unique session id). part2/part3 are
    /// already pure, so the whole DKG — and thus the joint account — is a
    /// deterministic function of the two seeds. SAFE: this fixes the long-term
    /// KEY SHARES (like an HD wallet), never the per-signature nonces, which
    /// stay fresh (see `sign_commit`). Reuse a seed only with a unique session
    /// id so every swap gets its own account.
    #[wasm_bindgen(js_name = newSeeded)]
    pub fn new_seeded(my_id: u16, their_id: u16, seed: &[u8]) -> Result<BrowserDkg, JsValue> {
        use rand_core::SeedableRng;
        let my = Identifier::try_from(my_id).map_err(jserr)?;
        let their = Identifier::try_from(their_id).map_err(jserr)?;
        let s: [u8; 32] = seed.try_into().map_err(|_| jsmsg("seed must be 32 bytes"))?;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(s);
        let (r1_secret, r1_pkg) = keys::dkg::part1(my, &mut rng).map_err(jserr)?;
        let r1_out = r1_pkg.serialize().map_err(jserr)?;
        Ok(BrowserDkg {
            their_id: their,
            r1_secret: Some(r1_secret),
            r1_out,
            r1_map: BTreeMap::new(),
            r2_secret: None,
            r2_out: Vec::new(),
            account: None,
            kp: None,
            pubkeys: None,
        })
    }

    /// Our round-1 package to send to the peer.
    pub fn round1_out(&self) -> Vec<u8> {
        self.r1_out.clone()
    }

    /// Feed the peer's round-1 package; runs part2 and prepares our round-2
    /// package (fetch it with `round2_out`).
    pub fn set_peer_round1(&mut self, bytes: &[u8]) -> Result<(), JsValue> {
        let their = keys::dkg::Round1Package::deserialize(bytes).map_err(jserr)?;
        self.r1_map.insert(self.their_id, their);
        let secret = self.r1_secret.take().ok_or_else(|| jsmsg("round1 already consumed"))?;
        let (r2_secret, r2_map) = keys::dkg::part2(secret, &self.r1_map).map_err(jserr)?;
        let mine = r2_map
            .get(&self.their_id)
            .cloned()
            .ok_or_else(|| jsmsg("no round2 package for peer"))?;
        self.r2_out = mine.serialize().map_err(jserr)?;
        self.r2_secret = Some(r2_secret);
        Ok(())
    }

    /// Our round-2 package to send to the peer.
    pub fn round2_out(&self) -> Vec<u8> {
        self.r2_out.clone()
    }

    /// Feed the peer's round-2 package; runs part3 and returns the 32-byte
    /// joint Nano account both parties share.
    pub fn set_peer_round2(&mut self, bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
        let their = keys::dkg::Round2Package::deserialize(bytes).map_err(jserr)?;
        let mut r2_map = BTreeMap::new();
        r2_map.insert(self.their_id, their);
        let secret = self.r2_secret.take().ok_or_else(|| jsmsg("round2 already consumed"))?;
        let (kp, pubkeys) = keys::dkg::part3(&secret, &self.r1_map, &r2_map).map_err(jserr)?;
        let account: [u8; 32] = pubkeys
            .verifying_key()
            .serialize()
            .map_err(jserr)?
            .try_into()
            .map_err(|_| jsmsg("verifying key not 32 bytes"))?;
        self.account = Some(account);
        self.kp = Some(kp.serialize().map_err(jserr)?);
        self.pubkeys = Some(pubkeys.serialize().map_err(jserr)?);
        Ok(account.to_vec())
    }

    /// The joint account once the DKG has finished (hex `nano_…` account is
    /// derivable from these 32 bytes).
    pub fn account(&self) -> Option<Vec<u8>> {
        self.account.map(|a| a.to_vec())
    }

    /// This party's serialized key package (its OWN secret share) — feed it,
    /// with `public_key_package`, into a `BrowserSigner` to sign or adaptor-
    /// pre-sign. Available only after the DKG has finished.
    pub fn key_package(&self) -> Option<Vec<u8>> {
        self.kp.clone()
    }

    /// The shared public key package (same on both parties). Feed it into a
    /// `BrowserSigner`. Available only after the DKG has finished.
    pub fn public_key_package(&self) -> Option<Vec<u8>> {
        self.pubkeys.clone()
    }
}

/// Stage-3 browser ceremony: a step-driven 2-of-2 FROST signer and adaptor
/// pre-signer, each party holding ONLY its own share. Seeded from a finished
/// `BrowserDkg` (`key_package()` + `public_key_package()`), it lets a browser
/// jointly sign Nano blocks (the open + guard rungs) and produce the adaptor
/// pre-signature for the claim — the cryptographic core of a helper-free swap.
///
/// One round at a time. Plain signing: `sign_commit` → exchange → `sign_share`
/// → exchange → `aggregate_sig`. Adaptor pre-sign: `presign_commit` (with the
/// adaptor point) → exchange → `presign_share` → exchange → `aggregate_presig`.
/// The JS side shuttles the opaque byte blobs over the MailboxWire.
#[wasm_bindgen]
pub struct BrowserSigner {
    their_id: Identifier,
    kp: keys::KeyPackage,
    pubkeys: keys::PublicKeyPackage,
    message: Vec<u8>,
    adaptor_point: Option<[u8; 32]>,
    nonces: Option<round1::SigningNonces>,
    comms: BTreeMap<Identifier, round1::SigningCommitments>,
    shares: BTreeMap<Identifier, round2::SignatureShare>,
    package: Option<SigningPackage>,
    session: Option<AdaptorSession>,
}

impl BrowserSigner {
    /// Start a fresh round: fresh nonces, clear the previous round's state,
    /// and register our own commitment. Returns our serialized commitment.
    fn begin(&mut self, message: &[u8], adaptor_point: Option<[u8; 32]>) -> Result<Vec<u8>, JsValue> {
        let (nonces, comm) = round1::commit(self.kp.signing_share(), &mut OsRng);
        self.message = message.to_vec();
        self.adaptor_point = adaptor_point;
        self.comms.clear();
        self.shares.clear();
        self.package = None;
        self.session = None;
        self.comms.insert(*self.kp.identifier(), comm);
        self.nonces = Some(nonces);
        comm.serialize().map_err(jserr)
    }
}

#[wasm_bindgen]
impl BrowserSigner {
    /// Build a signer from a finished DKG's serialized key material.
    #[wasm_bindgen(constructor)]
    pub fn new(
        key_package: &[u8],
        public_key_package: &[u8],
        _my_id: u16,
        their_id: u16,
    ) -> Result<BrowserSigner, JsValue> {
        let kp = keys::KeyPackage::deserialize(key_package).map_err(jserr)?;
        let pubkeys = keys::PublicKeyPackage::deserialize(public_key_package).map_err(jserr)?;
        let their = Identifier::try_from(their_id).map_err(jserr)?;
        Ok(BrowserSigner {
            their_id: their,
            kp,
            pubkeys,
            message: Vec::new(),
            adaptor_point: None,
            nonces: None,
            comms: BTreeMap::new(),
            shares: BTreeMap::new(),
            package: None,
            session: None,
        })
    }

    /// The 32-byte joint Nano account (verifying key).
    pub fn account(&self) -> Result<Vec<u8>, JsValue> {
        self.pubkeys.verifying_key().serialize().map_err(jserr)
    }

    /// Begin a plain signing round on `message` (a 32-byte block hash).
    pub fn sign_commit(&mut self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.begin(message, None)
    }

    /// Begin an adaptor pre-signing round on `message` for `adaptor_point`
    /// (`T = x·G`, 32 bytes).
    pub fn presign_commit(&mut self, message: &[u8], adaptor_point: &[u8]) -> Result<Vec<u8>, JsValue> {
        let t: [u8; 32] = adaptor_point.try_into().map_err(|_| jsmsg("adaptor point must be 32 bytes"))?;
        self.begin(message, Some(t))
    }

    /// Feed the peer's commitment (from either commit step).
    pub fn set_peer_commit(&mut self, bytes: &[u8]) -> Result<(), JsValue> {
        let c = round1::SigningCommitments::deserialize(bytes).map_err(jserr)?;
        self.comms.insert(self.their_id, c);
        Ok(())
    }

    /// Produce our plain signature share (also kept for aggregation).
    pub fn sign_share(&mut self) -> Result<Vec<u8>, JsValue> {
        let nonces = self.nonces.as_ref().ok_or_else(|| jsmsg("call sign_commit first"))?;
        let pkg = SigningPackage::new(self.comms.clone(), &self.message);
        let share = round2::sign(&pkg, nonces, &self.kp).map_err(jserr)?;
        self.shares.insert(*self.kp.identifier(), share);
        self.package = Some(pkg);
        Ok(share.serialize().as_slice().to_vec())
    }

    /// Produce our adaptor signature share (also kept for aggregation).
    pub fn presign_share(&mut self) -> Result<Vec<u8>, JsValue> {
        let nonces = self.nonces.as_ref().ok_or_else(|| jsmsg("call presign_commit first"))?;
        let t = self.adaptor_point.ok_or_else(|| jsmsg("no adaptor point set"))?;
        let session = AdaptorSession::new(self.comms.clone(), &self.message, &t).map_err(jserr)?;
        let share = adaptor_sign(&session, nonces, &self.kp).map_err(jserr)?;
        self.shares.insert(*self.kp.identifier(), share);
        self.session = Some(session);
        Ok(share.serialize().as_slice().to_vec())
    }

    /// Feed the peer's signature share (plain or adaptor).
    pub fn set_peer_share(&mut self, bytes: &[u8]) -> Result<(), JsValue> {
        let s = round2::SignatureShare::deserialize(bytes).map_err(jserr)?;
        self.shares.insert(self.their_id, s);
        Ok(())
    }

    /// Aggregate the plain shares into the 64-byte Nano-valid joint signature.
    pub fn aggregate_sig(&mut self) -> Result<Vec<u8>, JsValue> {
        let pkg = self.package.as_ref().ok_or_else(|| jsmsg("call sign_share first"))?;
        let sig = aggregate(pkg, &self.shares, &self.pubkeys).map_err(jserr)?;
        sig.serialize().map_err(jserr)
    }

    /// Aggregate the adaptor shares into a 96-byte pre-signature
    /// (`r_adapted ‖ s_hat ‖ adaptor_point`).
    pub fn aggregate_presig(&mut self) -> Result<Vec<u8>, JsValue> {
        let session = self.session.as_ref().ok_or_else(|| jsmsg("call presign_share first"))?;
        let presig = aggregate_presignature(session, &self.shares, &self.pubkeys).map_err(jserr)?;
        Ok(presig_bytes(&presig))
    }
}

/// Serialize a pre-signature to 96 bytes.
fn presig_bytes(p: &PreSignature) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(&p.r_adapted);
    out.extend_from_slice(&p.s_hat);
    out.extend_from_slice(&p.adaptor_point);
    out
}

/// Parse a 96-byte pre-signature.
fn presig_parse(b: &[u8]) -> Result<PreSignature, JsValue> {
    if b.len() != 96 {
        return Err(jsmsg("pre-signature must be 96 bytes"));
    }
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    let mut t = [0u8; 32];
    r.copy_from_slice(&b[..32]);
    s.copy_from_slice(&b[32..64]);
    t.copy_from_slice(&b[64..]);
    Ok(PreSignature { r_adapted: r, s_hat: s, adaptor_point: t })
}

/// Complete a 96-byte pre-signature with the 32-byte adaptor secret `x`,
/// yielding the 64-byte Nano wire signature. Broadcasting it reveals `x`.
#[wasm_bindgen]
pub fn presig_complete(presig: &[u8], secret: &[u8]) -> Result<Vec<u8>, JsValue> {
    let p = presig_parse(presig)?;
    let x: [u8; 32] = secret.try_into().map_err(|_| jsmsg("secret must be 32 bytes"))?;
    complete_presignature(&p, &x).map(|s| s.to_vec()).map_err(jserr)
}

/// Extract the adaptor secret `x` from a broadcast signature and the
/// pre-signature it completed (`x = s − ŝ`). This is how the XNO-seller learns
/// the Monero sweep secret the instant the claim is published.
#[wasm_bindgen]
pub fn presig_extract(presig: &[u8], signature: &[u8]) -> Result<Vec<u8>, JsValue> {
    let p = presig_parse(presig)?;
    let sig: [u8; 64] = signature.try_into().map_err(|_| jsmsg("signature must be 64 bytes"))?;
    extract_secret(&p, &sig).map(|x| x.to_vec()).map_err(jserr)
}

/// Verify the adaptor relation of a pre-signature against the joint `account`
/// and 32-byte message — provable from public data alone.
#[wasm_bindgen]
pub fn presig_verify(presig: &[u8], account: &[u8], message: &[u8]) -> bool {
    match presig_parse(presig) {
        Ok(p) => verify_presignature(&p, account, message).is_ok(),
        Err(_) => false,
    }
}

/// Verify a completed 64-byte signature as a real Nano signature for
/// `account` over `message`.
#[wasm_bindgen]
pub fn nano_check(account: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(a), Ok(s)) = (
        <[u8; 32]>::try_from(account),
        <[u8; 64]>::try_from(signature),
    ) else {
        return false;
    };
    signing::nano_verify::verify(&a, message, &s)
}

/// Generate a fresh adaptor secret `x` and its point `T = x·G` (32 ‖ 32 bytes).
/// In a real swap the XMR-seller does this: `T` becomes the adaptor point (its
/// Monero spend key), and revealing `x` by completing the Nano claim is what
/// hands the sweep secret to the counterparty. Exposed so the browser side that
/// owns the Monero key can produce the pair.
#[wasm_bindgen]
pub fn gen_adaptor() -> Vec<u8> {
    let mut wide = [0u8; 64];
    OsRng.fill_bytes(&mut wide);
    let x = Scalar::from_bytes_mod_order_wide(&wide);
    let t = (&x * ED25519_BASEPOINT_TABLE).compress().to_bytes();
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&x.to_bytes());
    out.extend_from_slice(&t);
    out
}

// ---------------------------------------------------------------------------
// Stage 4 (browser): the Nano-block order beacon + in-browser PoW + single-key
// state blocks. The beacon codec inlines dex_core::beacon (same precedent as
// the order wire format above — keeps the wasm free of dex-core's deps); a
// native test cross-checks it against dex-core bit for bit.
// ---------------------------------------------------------------------------

const BEACON_NS_PREFIX: &[u8] = b"xnoxmr-beacon-v1";
const BEACON_VERSION: u8 = 1;
const BEACON_PRICE_BITS: u32 = 40;
const BEACON_CHECK_BITS: u32 = 11;

fn blake2b32(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2b::<Blake2bU32>::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn beacon_checksum(body: u64) -> u64 {
    let d = blake2b32(&[b"beacon-check", &body.to_le_bytes()]);
    u64::from_le_bytes(d[..8].try_into().unwrap()) & ((1 << BEACON_CHECK_BITS) - 1)
}

/// The deterministic burn account (32 bytes) for a market side.
/// `side`: 0 = sell XNO, 1 = sell XMR. Mirrors `dex_core::beacon::namespace_account`.
#[wasm_bindgen]
pub fn beacon_account(pair: &str, side: u8) -> Vec<u8> {
    blake2b32(&[BEACON_NS_PREFIX, &[0x00], pair.as_bytes(), &[0x00], &[if side == 0 { 0 } else { 1 }]])
        .to_vec()
}

/// The namespace account as a `nano_…` address (what the receivable RPC takes).
#[wasm_bindgen]
pub fn beacon_address(pair: &str, side: u8) -> String {
    let a: [u8; 32] = beacon_account(pair, side).try_into().unwrap();
    address::encode(&a)
}

/// Encode an order intent into the raw dust amount (decimal string, < 2^64).
/// Empty string if `price_e9` overflows its 40-bit field.
#[wasm_bindgen]
pub fn beacon_encode(side: u8, price_e9: u64, size_log2: u8) -> String {
    if price_e9 >= 1 << BEACON_PRICE_BITS {
        return String::new();
    }
    let body: u64 = ((BEACON_VERSION as u64) << 60)
        | (((if side == 0 { 0u64 } else { 1 }) as u64) << 59)
        | (price_e9 << 19)
        | ((size_log2 as u64) << 11);
    (body | beacon_checksum(body)).to_string()
}

/// Decode a receivable raw amount (decimal string) back into an intent as
/// JSON `{"side":n,"price_e9":n,"size_log2":n}`, or empty string for anything
/// that is not beacon-encoded (junk dust, bad checksum, wrong version).
#[wasm_bindgen]
pub fn beacon_decode(amount_raw: &str) -> String {
    let Ok(amount) = amount_raw.trim().parse::<u128>() else { return String::new() };
    if amount >> 64 != 0 {
        return String::new();
    }
    let word = amount as u64;
    let body = word & !((1 << BEACON_CHECK_BITS) - 1);
    if word & ((1 << BEACON_CHECK_BITS) - 1) != beacon_checksum(body) {
        return String::new();
    }
    if (body >> 60) as u8 != BEACON_VERSION {
        return String::new();
    }
    format!(
        "{{\"side\":{},\"price_e9\":{},\"size_log2\":{}}}",
        (body >> 59) & 1,
        (body >> 19) & ((1u64 << BEACON_PRICE_BITS) - 1),
        (body >> 11) & 0xFF
    )
}

/// Nano mainnet work thresholds, as hex strings the JS side can hold as BigInt.
#[wasm_bindgen]
pub fn work_thresholds() -> String {
    format!(
        "{{\"send\":\"{:016x}\",\"receive\":\"{:016x}\"}}",
        work::THRESHOLD_SEND,
        work::THRESHOLD_RECEIVE
    )
}

/// Search `count` nonces from `start` for work over `root` meeting `threshold`.
/// Returns the nonce or `undefined` — the browser calls this in chunks from an
/// async loop (or a Worker) so the UI stays alive; the found nonce is verified
/// by any Nano node exactly like node-generated work.
#[wasm_bindgen]
pub fn work_search(root: &[u8], threshold: u64, start: u64, count: u64) -> Option<u64> {
    let r: [u8; 32] = root.try_into().ok()?;
    let mut nonce = start;
    for _ in 0..count {
        if work::validate(&r, nonce, threshold) {
            return Some(nonce);
        }
        nonce = nonce.wrapping_add(1);
    }
    None
}

/// Validate a work nonce against a threshold (mirror of the node's check).
#[wasm_bindgen]
pub fn work_check(root: &[u8], nonce: u64, threshold: u64) -> bool {
    match <[u8; 32]>::try_from(root) {
        Ok(r) => work::validate(&r, nonce, threshold),
        Err(_) => false,
    }
}

/// The identity seed's public half as JSON `{"pubkey":hex,"address":"nano_…"}`
/// — a browser identity IS a Nano account; fund it to publish beacons.
#[wasm_bindgen]
pub fn seed_account(seed_hex: &str) -> String {
    let Some(key) = key_from_seed(seed_hex) else { return String::new() };
    let vk = signing::VerifyingKey::from(&key);
    let pk: [u8; 32] = vk.serialize().unwrap().try_into().unwrap();
    format!("{{\"pubkey\":\"{}\",\"address\":\"{}\"}}", hex::encode(pk), address::encode(&pk))
}

/// Encode a 32-byte public key as a `nano_…` address (empty on bad length).
#[wasm_bindgen]
pub fn nano_address_encode(public_key: &[u8]) -> String {
    match <[u8; 32]>::try_from(public_key) {
        Ok(a) => address::encode(&a),
        Err(_) => String::new(),
    }
}

/// Decode a `nano_…`/`xrb_…` address to its 32-byte public key (empty on error).
#[wasm_bindgen]
pub fn nano_address_decode(addr: &str) -> Vec<u8> {
    address::decode(addr.trim()).map(|a| a.to_vec()).unwrap_or_default()
}

/// Build and sign a Nano state block with the identity seed (single-key
/// account — used for beacon publishes and pocketing dust; joint 2-of-2 blocks
/// go through `BrowserSigner`). Inputs are hex/decimal strings; `subtype` is
/// one of open|receive|send|change. Returns the full `process` RPC body as
/// JSON (work left as the placeholder `"WORK"` for the caller to fill) plus
/// `hash` and `work_root`, or empty string on bad input.
#[wasm_bindgen]
pub fn sign_state_block(
    seed_hex: &str,
    previous_hex: &str,
    representative_hex: &str,
    balance_raw: &str,
    link_hex: &str,
    subtype: &str,
) -> String {
    let Some(key) = key_from_seed(seed_hex) else { return String::new() };
    let vk = signing::VerifyingKey::from(&key);
    let account: [u8; 32] = vk.serialize().unwrap().try_into().unwrap();
    let (Ok(previous), Ok(representative), Ok(link)) = (
        <[u8; 32]>::try_from(hex::decode(previous_hex.trim()).unwrap_or_default()),
        <[u8; 32]>::try_from(hex::decode(representative_hex.trim()).unwrap_or_default()),
        <[u8; 32]>::try_from(hex::decode(link_hex.trim()).unwrap_or_default()),
    ) else {
        return String::new();
    };
    let Ok(balance) = balance_raw.trim().parse::<u128>() else { return String::new() };
    let st = match subtype {
        "open" => Subtype::Open,
        "receive" => Subtype::Receive,
        "send" => Subtype::Send,
        "change" => Subtype::Change,
        _ => return String::new(),
    };
    let block = StateBlock { account, previous, representative, balance, link, subtype: st };
    let hash = block.hash();
    let sig = key.sign(OsRng, &hash);
    let sig_bytes: [u8; 64] = sig.serialize().unwrap().try_into().unwrap();
    if !signing::nano_verify::verify(&account, &hash, &sig_bytes) {
        return String::new();
    }
    format!(
        concat!(
            "{{\"hash\":\"{}\",\"work_root\":\"{}\",\"process\":{{",
            "\"action\":\"process\",\"json_block\":\"true\",\"subtype\":\"{}\",",
            "\"block\":{{\"type\":\"state\",\"account\":\"{}\",\"previous\":\"{}\",",
            "\"representative\":\"{}\",\"balance\":\"{}\",\"link\":\"{}\",",
            "\"signature\":\"{}\",\"work\":\"WORK\"}}}}}}"
        ),
        hex::encode(hash),
        hex::encode(block.work_root()),
        st.as_str(),
        address::encode(&account),
        hex::encode_upper(previous),
        address::encode(&representative),
        balance,
        hex::encode_upper(link),
        hex::encode_upper(sig_bytes),
    )
}

/// The canonical 32-byte hash of a Nano state block, without signing it. The
/// swap driver needs this to bind the adaptor pre-signature to the REAL claim
/// block both parties agree on (the send that pays the XMR-seller their XNO),
/// rather than an arbitrary message. Same field encoding as `sign_state_block`.
#[wasm_bindgen]
pub fn state_block_hash(
    account_hex: &str,
    previous_hex: &str,
    representative_hex: &str,
    balance_raw: &str,
    link_hex: &str,
    subtype: &str,
) -> Vec<u8> {
    let (Ok(account), Ok(previous), Ok(representative), Ok(link)) = (
        <[u8; 32]>::try_from(hex::decode(account_hex.trim()).unwrap_or_default()),
        <[u8; 32]>::try_from(hex::decode(previous_hex.trim()).unwrap_or_default()),
        <[u8; 32]>::try_from(hex::decode(representative_hex.trim()).unwrap_or_default()),
        <[u8; 32]>::try_from(hex::decode(link_hex.trim()).unwrap_or_default()),
    ) else {
        return Vec::new();
    };
    let Ok(balance) = balance_raw.trim().parse::<u128>() else { return Vec::new() };
    let st = match subtype {
        "open" => Subtype::Open,
        "receive" => Subtype::Receive,
        "send" => Subtype::Send,
        "change" => Subtype::Change,
        _ => return Vec::new(),
    };
    StateBlock { account, previous, representative, balance, link, subtype: st }
        .hash()
        .to_vec()
}

/// Self-test the I1 puzzle-escrow refund backstop in the browser: escrow a random
/// scalar share across `m` RSW time-lock instances, run the cut-and-choose audit,
/// verify, then SOLVE each kept puzzle and confirm the recovered scalar matches
/// the original. Proves the time-lock refund primitive compiles and runs in wasm
/// (num-bigint-dig modular exponentiation) without any counterparty. Small,
/// fast params (m=8, 130-bit primes, t=512); returns a JSON status.
/// Self-test the bilateral grief-bond (H-series) in the browser: build a 2-of-2
/// bond, pre-sign both parties' early-exit chains, and verify them. This is the
/// anti-grief primitive that lets an always-on maker be safe (a griefer forfeits
/// their bond to the victim). Proves it compiles and runs in wasm.
#[wasm_bindgen]
pub fn pledge_selftest() -> bool {
    pledge::selftest::pledge_selftest()
}

#[wasm_bindgen]
pub fn escrow_selftest() -> String {
    use curve25519_dalek::scalar::Scalar;
    use puzzle_escrow::escrow::{
        choose_audit, escrow_make, escrow_open, escrow_solve, escrow_verify,
    };
    use rand_core::OsRng;
    let mut rng = OsRng;
    let share = Scalar::random(&mut rng);
    let (public, secret) = escrow_make(&mut rng, &share, 8, 130, 512);
    let audit = choose_audit(&mut rng, 8);
    let openings = escrow_open(&secret, &audit);
    let (verify_ok, kept) = match escrow_verify(&public, &audit, &openings) {
        Ok(k) => (true, k),
        Err(_) => (false, Vec::new()),
    };
    let mut recovered = 0usize;
    let mut all_ok = !kept.is_empty();
    for &i in &kept {
        match escrow_solve(&public, i) {
            Ok(r) if r == share => recovered += 1,
            _ => all_ok = false,
        }
    }
    format!(
        "{{\"verify_ok\":{},\"kept\":{},\"recovered\":{},\"all_recovered\":{}}}",
        verify_ok,
        kept.len(),
        recovered,
        all_ok && recovered == kept.len()
    )
}

#[cfg(test)]
mod beacon_tests {
    use super::*;
    use dex_core::beacon as reference;
    use dex_core::order::Side;

    // The inlined codec must match dex_core::beacon bit for bit — namespace
    // accounts and amounts round-trip through BOTH implementations.
    #[test]
    fn beacon_codec_matches_dex_core_exactly() {
        for (side_u8, side) in [(0u8, Side::SellXno), (1u8, Side::SellXmr)] {
            assert_eq!(
                beacon_account("XNO/XMR", side_u8),
                reference::namespace_account("XNO/XMR", side).to_vec(),
                "namespace mismatch"
            );
            for (price, size) in [(0u64, 0u8), (3_750_000, 100), ((1 << 40) - 1, 255)] {
                let ours = beacon_encode(side_u8, price, size);
                let theirs =
                    reference::encode(&reference::Intent { side, price_e9: price, size_log2: size })
                        .unwrap();
                assert_eq!(ours, theirs.to_string(), "encode mismatch");
                let decoded = beacon_decode(&ours);
                assert_eq!(
                    decoded,
                    format!("{{\"side\":{side_u8},\"price_e9\":{price},\"size_log2\":{size}}}"),
                    "decode mismatch"
                );
            }
        }
        // Overflow refused, junk rejected — same as the reference.
        assert_eq!(beacon_encode(0, 1 << 40, 0), "");
        assert_eq!(beacon_decode("0"), "");
        assert_eq!(beacon_decode("1000000"), "");
        assert_eq!(beacon_decode(&(1u128 << 100).to_string()), "");
    }

    #[test]
    fn single_key_block_signs_and_work_searches() {
        let id = gen_identity();
        let seed = id.split("\"seed\":\"").nth(1).unwrap().split('"').next().unwrap().to_string();
        let acct = seed_account(&seed);
        assert!(acct.contains("\"address\":\"nano_"));

        let out = sign_state_block(
            &seed,
            &hex::encode([0u8; 32]),
            &hex::encode([7u8; 32]),
            "1000000000000000000000000",
            &hex::encode([9u8; 32]),
            "open",
        );
        assert!(out.contains("\"subtype\":\"open\""), "no block: {out}");
        let hash_hex = out.split("\"hash\":\"").nth(1).unwrap().split('"').next().unwrap();
        let root_hex = out.split("\"work_root\":\"").nth(1).unwrap().split('"').next().unwrap();
        assert_eq!(hash_hex.len(), 64);
        // Open block: work root is the account key.
        let pk_hex = acct.split("\"pubkey\":\"").nth(1).unwrap().split('"').next().unwrap();
        assert_eq!(root_hex, pk_hex);

        // Chunked search finds demo-threshold work and it validates.
        let root = hex::decode(root_hex).unwrap();
        let mut found = None;
        let mut start = 0u64;
        while found.is_none() {
            found = work_search(&root, DEMO_THRESHOLD, start, 4096);
            start += 4096;
        }
        assert!(work_check(&root, found.unwrap(), DEMO_THRESHOLD));

        // Address round trip.
        let addr = acct.split("\"address\":\"").nth(1).unwrap().split('"').next().unwrap();
        assert_eq!(hex::encode(nano_address_decode(addr)), pk_hex);
    }
}

#[cfg(test)]
mod custody_tests {
    use super::*;

    // Argon2id KDF: deterministic, params-sensitive, and matching an
    // independent reference vector for the OWASP-floor parameters we ship.
    #[test]
    fn argon2id_seed_is_deterministic_and_known() {
        let salt = b"xnoxmr-salt-0001";
        let a = argon2id_seed("correct horse battery staple", salt, 0);
        let b = argon2id_seed("correct horse battery staple", salt, 0);
        assert_eq!(a, b, "same input → same seed");
        assert_eq!(a.len(), 32);

        // Different passphrase or salt → different seed.
        assert_ne!(a, argon2id_seed("Correct horse battery staple", salt, 0));
        assert_ne!(a, argon2id_seed("correct horse battery staple", b"different-salt-01", 0));

        // Known answer for argon2id(v=0x13, m=19456, t=2, p=1, 32-byte tag)
        // over ("password","saltsaltsaltsalt"), then reduced into the canonical
        // ed25519 scalar range. The pre-reduction raw tag is
        //   4fde6aed2db4e6d7fd588e078583990c842630c01b9ed69c1974c892ed205d3f
        // which matches the reference argon2 implementation (argon2-cffi); the
        // reduction only clears the high bits that exceed the group order.
        let kat = argon2id_seed("password", b"saltsaltsaltsalt", 0);
        assert_eq!(
            hex::encode(&kat),
            "886289d6de8aafcf7a82a71ee995fccd832630c01b9ed69c1974c892ed205d0f"
        );

        // Salt shorter than 8 bytes is rejected.
        assert!(argon2id_seed("x", b"short", 0).is_empty());
    }
}

#[cfg(test)]
mod signer_tests {
    use super::*;

    // The step-driven BrowserSigner reproduces sign_block + adaptor_presign but
    // with each party holding only its own share and exchanging opaque bytes —
    // the exact shape the browser drives over the MailboxWire.
    #[test]
    fn two_party_sign_and_adaptor_via_browser_signer() {
        let (kps, pubkeys) = dkg_2of2();
        let a_id = Identifier::try_from(1u16).unwrap();
        let b_id = Identifier::try_from(2u16).unwrap();
        let pk = pubkeys.serialize().unwrap();
        let mut sa = BrowserSigner::new(&kps[&a_id].serialize().unwrap(), &pk, 1, 2).unwrap();
        let mut sb = BrowserSigner::new(&kps[&b_id].serialize().unwrap(), &pk, 2, 1).unwrap();
        let acct = sa.account().unwrap();
        assert_eq!(acct, sb.account().unwrap());

        // Plain 2-of-2 signature: each commits, exchanges, shares, aggregates.
        let msg = [7u8; 32];
        let (ca, cb) = (sa.sign_commit(&msg).unwrap(), sb.sign_commit(&msg).unwrap());
        sa.set_peer_commit(&cb).unwrap();
        sb.set_peer_commit(&ca).unwrap();
        let (ssa, ssb) = (sa.sign_share().unwrap(), sb.sign_share().unwrap());
        sa.set_peer_share(&ssb).unwrap();
        sb.set_peer_share(&ssa).unwrap();
        let sig = sa.aggregate_sig().unwrap();
        assert_eq!(sig, sb.aggregate_sig().unwrap(), "joint signatures differ");
        assert!(nano_check(&acct, &msg, &sig), "not a valid Nano signature");

        // Adaptor pre-signature bound to x, completed, x extracted.
        let ad = gen_adaptor();
        let (x, t) = (&ad[..32], &ad[32..]);
        let msg2 = [9u8; 32];
        let (pca, pcb) = (sa.presign_commit(&msg2, t).unwrap(), sb.presign_commit(&msg2, t).unwrap());
        sa.set_peer_commit(&pcb).unwrap();
        sb.set_peer_commit(&pca).unwrap();
        let (psa, psb) = (sa.presign_share().unwrap(), sb.presign_share().unwrap());
        sa.set_peer_share(&psb).unwrap();
        sb.set_peer_share(&psa).unwrap();
        let pre = sa.aggregate_presig().unwrap();
        assert_eq!(pre, sb.aggregate_presig().unwrap(), "pre-signatures differ");
        assert!(presig_verify(&pre, &acct, &msg2), "adaptor relation fails");
        assert!(!nano_check(&acct, &msg2, &pre[..64]), "pre-sig wrongly valid alone");
        let claim = presig_complete(&pre, x).unwrap();
        assert!(nano_check(&acct, &msg2, &claim), "completed signature invalid");
        assert_eq!(presig_extract(&pre, &claim).unwrap(), x.to_vec(), "extracted secret != x");
    }
}
