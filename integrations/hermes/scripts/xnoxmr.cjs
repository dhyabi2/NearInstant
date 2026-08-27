#!/usr/bin/env node
/*
 * xnoxmr.cjs — headless CLI over the trustless XNO<->XMR DEX.
 *
 * Exists so an agent (Hermes or otherwise) can observe the book, price an
 * offer, and run a maker loop WITHOUT a browser. It deliberately CANNOT settle
 * a swap: see `settle` below and SKILL.md "What this refuses to do".
 *
 * Everything here drives the SAME modules the web app uses — web/beacon.js and
 * the wasm engines — so the agent and the page cannot drift apart.
 */
"use strict";
const path = require("path");
const fs = require("fs");
const ROOT = path.resolve(__dirname, "../../..");
const wasm = require(path.join(ROOT, "swap-core/wasm-bridge/pkg-node/wasm_bridge.js"));
const B = require(path.join(ROOT, "web/beacon.js"));

const PAIR = "XNO/XMR";
const OFFER_TTL_SECS = 600;          // must match web/index.html
const GRACE_MS = 120000;             // keep answering takes on a just-superseded rendezvous this long
const DEFAULT_OFFER_XNO = 50;        // default REQUESTED size when --size omitted; always capped down to fundable balance (see fundableXno)
const RAW = 10n ** 30n;

const env = (k, d) => (process.env[k] && process.env[k].trim()) || d;
const WORK_URL = env("XNOXMR_WORK_URL", "https://www.nearinstant.xyz");
const NANO_NODES = env("XNOXMR_NANO_NODES",
  "https://node.somenano.com/proxy,https://nanoslo.0x.no/proxy,https://rpc.nano.to,https://rpc.nano-gpt.com,https://rainstorm.city/api")
  .split(",").map(s => s.trim()).filter(Boolean);

const TP = require(path.join(ROOT, "web/two_party.js"));   // certify() - the same code the app gates on
// Optional nano.to API key: sent as an Authorization header AND as `key` in the
// JSON body for *.nano.to hosts (rpc.nano.to); appended to the ws.nano.to URL.
const NANO_KEY = env("XNOXMR_NANO_RPC_KEY", "");
const keyedFetch = !NANO_KEY ? undefined : async (url, init) => {
  try {
    if (/(^|\.)nano\.to$/i.test(new URL(url).hostname)) {
      init = Object.assign({}, init);
      init.headers = Object.assign({}, init.headers, { Authorization: NANO_KEY });
      if (typeof init.body === "string" && init.body[0] === "{") {
        try { const b = JSON.parse(init.body); if (b && !b.key) { b.key = NANO_KEY; init.body = JSON.stringify(b); } } catch (e) {}
      }
    }
  } catch (e) {}
  return fetch(url, init);
};
const beacon = B.makeBeacon(wasm, { workUrl: WORK_URL, fetch: keyedFetch });
const MIN_ACCEPT_BPS = 30;   // must match web/index.html CERT.MIN_ACCEPT_BPS
const out = (o) => console.log(JSON.stringify(o, null, 2));
let DIE_SOFT = false;   // watch mode: refusals throw instead of killing the process
let WATCH_MODE = false; // persistent process: settlement may run in the background
let __settling = null;  // { slot, block, at } — one settlement at a time per offer
let __resuming = null;  // { sid, at } — one crash-recovery resume at a time (background under watch)
const die = (msg, extra) => { out(Object.assign({ ok: false, error: msg }, extra || {})); if (DIE_SOFT) { const e = new Error(msg); e.soft = true; throw e; } process.exit(1); };

// ---- wallet (read from .env; never printed) --------------------------------
function loadEnvFile() {
  const p = path.join(ROOT, ".env");
  if (!fs.existsSync(p)) return {};
  const o = {};
  for (const line of fs.readFileSync(p, "utf8").split("\n")) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (m) o[m[1]] = m[2].trim();
  }
  return o;
}
function makerSeed() {
  const e = loadEnvFile();
  const seed = env("XNOXMR_MAKER_SEED", e.WALLET_A_SEED);
  if (!seed || !/^[0-9a-fA-F]{64}$/.test(seed)) return null;
  return seed;
}

// ---- price (same two oracles, same fail-closed rule as the app) ------------
const SANE_MIN = 0.0002, SANE_MAX = 0.5, AGREE_TOL = 0.06;
async function fetchJson(url, ms) {
  const c = new AbortController(); const t = setTimeout(() => c.abort(), ms || 8000);
  try { const r = await fetch(url, { signal: c.signal }); if (!r.ok) throw new Error("HTTP " + r.status); return await r.json(); }
  finally { clearTimeout(t); }
}
async function marketPriceOnce() {
  const got = [];
  try { const j = await fetchJson("https://api.coingecko.com/api/v3/simple/price?ids=nano,monero&vs_currencies=usd");
    const p = j.nano.usd / j.monero.usd; if (p > SANE_MIN && p < SANE_MAX) got.push(p); } catch (e) {}
  try { const [a, b] = await Promise.all([
      fetchJson("https://api.coinpaprika.com/v1/tickers/nano-nano"),
      fetchJson("https://api.coinpaprika.com/v1/tickers/xmr-monero")]);
    const p = a.quotes.USD.price / b.quotes.USD.price; if (p > SANE_MIN && p < SANE_MAX) got.push(p); } catch (e) {}
  try { const [a, b] = await Promise.all([
      fetchJson("https://api.coincap.io/v2/assets/nano"),
      fetchJson("https://api.coincap.io/v2/assets/monero")]);
    const p = parseFloat(a.data.priceUsd) / parseFloat(b.data.priceUsd); if (p > SANE_MIN && p < SANE_MAX) got.push(p); } catch (e) {}
  if (got.length < 2) return { ok: false, reason: "need >=2 price sources; holding to be safe" };
  const mean = got.reduce((s, x) => s + x, 0) / got.length;
  if ((Math.max(...got) - Math.min(...got)) / mean > AGREE_TOL)
    return { ok: false, reason: "price sources disagree, holding to be safe" };
  return { ok: true, mid: mean, sources: got.length, at: Date.now() };
}
// Transient oracle blips (one source timing out, a burst of ticks hitting a
// rate limit) must not stall the maker or pull a live offer. Three layers:
// a 45 s cache (a tick burst reuses one fetch), retry with backoff, and a
// stale-but-≤60 s fallback — certify() still sees the TRUE fetch time via
// `at`, so nothing older than its 60 s gate is ever acted on.
let __midCache = null;   // { at, res }
async function marketPrice() {
  if (__midCache && Date.now() - __midCache.at < 45000) return __midCache.res;
  let last = null;
  for (const delay of [0, 3000, 8000]) {
    if (delay) await new Promise((r) => setTimeout(r, delay));
    last = await marketPriceOnce();
    if (last.ok) { __midCache = { at: Date.now(), res: last }; return last; }
  }
  if (__midCache && Date.now() - __midCache.at < 60000) return Object.assign({}, __midCache.res, { stale: true });
  return last;
}

// ---- quote (mirrors RATE/quoteBps/sigmaDaily in web/index.html) ------------
const RATE = { T_EXPOSURE_MIN: 35, K_ADV: 0.40, BETA: 0.85, A: 1.00,
               FLOOR_BPS: 30, CAP_BPS: 500,
               SIGMA_SEED: 0.06, SIGMA_MIN: 0.015, SIGMA_MAX: 0.30 };

// Persisted mid history, the CLI's mirror of the page's xnoxmr_pricehist_v1.
// Without it the CLI quoted at SIGMA_SEED forever (117 bps) while the page
// quoted from measured volatility (~60-90 bps calm) — the same market priced
// two different ways by "the same" logic. Same file shape, same estimator.
const PH_FILE = env("XNOXMR_PRICEHIST", path.join(ROOT, ".xnoxmr-pricehist.json"));
const PH_MAX_AGE_MS = 60 * 60 * 1000, PH_MAX = 240;
function phLoad() {
  try {
    const v = JSON.parse(fs.readFileSync(PH_FILE, "utf8"));
    if (!Array.isArray(v)) return [];
    const now = Date.now();
    return v.filter(x => x && typeof x.p === "number" && isFinite(x.p) && x.p > 0
                      && typeof x.at === "number" && x.at <= now
                      && (now - x.at) < PH_MAX_AGE_MS).slice(-PH_MAX);
  } catch (e) { return []; }
}
function phPush(mid) {
  const h = phLoad(); h.push({ p: mid, at: Date.now() });
  try { fs.writeFileSync(PH_FILE, JSON.stringify(h.slice(-PH_MAX))); } catch (e) {}
  return h;
}
// Identical estimator to web/index.html sigmaDaily().
function sigmaDaily(h) {
  if (h.length < 6) return RATE.SIGMA_SEED;
  const rs = [];
  for (let i = 1; i < h.length; i++) {
    const dtMin = (h[i].at - h[i - 1].at) / 60000;
    if (!(dtMin > 0.2) || h[i - 1].p <= 0 || h[i].p <= 0) continue;
    if (h[i].p === h[i - 1].p) continue;
    rs.push(Math.log(h[i].p / h[i - 1].p) / Math.sqrt(dtMin));
  }
  if (rs.length < 4) return RATE.SIGMA_SEED;
  const abs = rs.map(Math.abs).sort((a, b) => a - b);
  const cap = 4 * (abs[Math.floor(abs.length / 2)] || 1e-9);
  let v = 0;
  for (const r of rs) { const c = Math.max(-cap, Math.min(cap, r)); v += c * c; }
  const daily = Math.sqrt(v / rs.length) * Math.sqrt(1440);
  return Math.max(RATE.SIGMA_MIN, Math.min(RATE.SIGMA_MAX, daily));
}
function quoteBps(sigD, stress) {
  const sigT = sigD * Math.sqrt(RATE.T_EXPOSURE_MIN / 1440);
  const bps = (RATE.K_ADV + RATE.BETA * RATE.A) * sigT * 10000 * (stress || 1);
  return Math.round(Math.max(RATE.FLOOR_BPS, Math.min(RATE.CAP_BPS, bps)));
}

// ---- agent state (survives across cron invocations) ------------------------
// Hermes runs each tick as a fresh process, so everything a maker loop needs
// to remember lives in one small JSON file: the live offer, its intent, and
// when it was posted. Git-ignored.
const STATE_FILE = env("XNOXMR_STATE", path.join(ROOT, ".xnoxmr-agent.json"));
const LOCK_FILE = STATE_FILE + ".lock";
function stLoad() { try { return JSON.parse(fs.readFileSync(STATE_FILE, "utf8")) || {}; } catch (e) { return {}; } }
function stSave(o) { fs.writeFileSync(STATE_FILE, JSON.stringify(o, null, 1)); try { fs.chmodSync(STATE_FILE, 0o600); } catch (e) {} }
// One tick at a time. A stale lock (>10 min, a crashed tick) is reclaimed.
function lockAcquire() {
  try {
    const st = fs.statSync(LOCK_FILE);
    // A lock left by a process that is no longer alive is stale no matter how
    // fresh its mtime — a killed tick (SIGKILL, OOM, container stop) can never
    // release it, and waiting out the 10-min age fallback needlessly blocks
    // every tick in between (filed 50739e9d1791). Reclaim immediately if the
    // recorded PID is dead; otherwise keep the age guard for a genuinely live
    // (or foreign/unreadable) holder.
    let alive = false;
    try {
      const pid = parseInt(fs.readFileSync(LOCK_FILE, "utf8").trim(), 10);
      if (pid > 0) { try { process.kill(pid, 0); alive = true; } catch (e) { alive = !!(e && e.code === "EPERM"); } }
    } catch (e) {}
    if (alive && Date.now() - st.mtimeMs < 10 * 60 * 1000) return false;
    fs.unlinkSync(LOCK_FILE);
  } catch (e) {}
  try { fs.writeFileSync(LOCK_FILE, String(process.pid), { flag: "wx" }); return true; } catch (e) { return false; }
}
// On-chain-fund markers persisted per session. Their presence means an
// irreversible step happened, so such a session must be RESUMED (complete /
// refund / recover), never abandoned. Absence means setup only — safe to drop.
const MOVED_KEYS = ["open", "fund", "lock", "lockseen", "refund", "x", "claim", "sweep"];
function lockRelease() { try { fs.unlinkSync(LOCK_FILE); } catch (e) {} }
const LR = require(path.join(ROOT, "web/ledger_relay.js"));
const MB = require(path.join(ROOT, "web/mailbox.js"));
const XMR = require(path.join(ROOT, "swap-core/wasm-monero/pkg-node/wasm_monero.js"));
const HW = require(path.join(ROOT, "web/headless_wallet.js"));
const MONERO_NODES = env("XNOXMR_MONERO_NODES",
  "https://xmr.hexide.com:443,https://node.sethforprivacy.com:443,https://xmr-node.cakewallet.com:18081")
  .split(",").map(s => s.trim()).filter(Boolean);
const STATE_DIR = env("XNOXMR_STATE_DIR", path.join(ROOT, ".xnoxmr-wallet"));
let __wallet = null;
function walletFor(seed) {
  if (!__wallet) __wallet = HW.makeHeadlessWallet({ wasm, xmr: XMR, beacon, urls: NANO_NODES, moneroNodes: MONERO_NODES, seedHex: seed, stateDir: STATE_DIR, network: "mainnet" });
  return __wallet;
}
function relayFor(seed) { return LR.makeLedgerRelay({ beacon, wasm, urls: NANO_NODES, seed }); }

// HONESTY GUARD — never advertise liquidity the wallet cannot actually fund.
// An offer's size is a promise: a taker sees "~N XNO available" and expects a
// real fill. Posting more than the wallet can settle is phantom liquidity and
// bad-faith. side 0 sells XNO -> cap to spendable XNO (verified on-chain, fast).
// side 1 sells XMR -> the maker must deliver XMR = size*price; XMR balance is
// not cheaply verifiable headlessly, so the operator must DECLARE fundable XMR
// (--xmr <amount> or XNOXMR_XMR_LIQUIDITY) and we cap to it; with none declared
// we refuse to post rather than advertise XMR the wallet may not hold.
function declaredXmr(args) {
  const raw = args.xmr != null ? args.xmr : process.env.XNOXMR_XMR_LIQUIDITY;
  if (raw == null) return null;
  const v = parseFloat(raw);
  return v > 0 ? v : null;
}
async function fundableXno(seed, side, ask, args) {
  if (side === 0) {
    const acct = JSON.parse(wasm.seed_account(seed));
    try {
      const j = await beacon._internals.rpc(NANO_NODES, { action: "account_balance", account: acct.address });
      return { xno: Number(BigInt(j.balance || "0") / (10n ** 24n)) / 1e6 };
    } catch (e) { return { xno: null, reason: "could not read the wallet's XNO balance to size the offer" }; }
  }
  // side 1 sells XMR: cap to VERIFIED on-chain spendable XMR (read-only, fast).
  // Never advertise XMR the wallet cannot actually deliver. A --xmr declaration
  // can only LOWER the cap, never raise it above what the chain confirms.
  let spendableXmr = null, note = null, behind = 0;
  try {
    const bal = await walletFor(seed).xmrRefresh(() => {}, { readOnly: true });
    spendableXmr = parseFloat(bal.spendable); behind = bal.behind || 0;
    if (!bal.caughtUp) note = "xmr scan " + behind + " blocks behind — spendable may be understated; run `xmr scan`";
  } catch (e) { note = "could not read XMR balance (" + String(e.message || e).slice(0, 60) + ")"; }
  const declared = declaredXmr(args);
  let xmr;
  if (spendableXmr != null) {
    xmr = declared != null ? Math.min(declared, spendableXmr) : spendableXmr;   // truth caps; declaration can only lower
  } else if (declared != null) {
    xmr = declared; note = (note ? note + "; " : "") + "trusting --xmr (unverified — no Monero node/scan)";
  } else {
    return { xno: null, reason: "side 1 sells XMR: no spendable XMR found and none declared. Set XNOXMR_MONERO_NODES + run `xmr scan`, or declare --xmr <amount>." };
  }
  if (!(xmr > 0)) return { xno: null, reason: "side 1: no spendable XMR to back an offer (spendable " + (spendableXmr != null ? spendableXmr.toFixed(6) : "unknown") + " XMR" + (behind ? ", scan " + behind + " blocks behind — run `xmr scan`" : "") + ")" };
  return { xno: ask > 0 ? xmr / ask : null, xmrCap: xmr, spendableXmr, note };
}
// The wire carries size as size_log2 — a power-of-two EXPONENT (8 bits), so the
// size a taker decodes is quantised DOWN to 2^size_log2. Snap a requested size
// to that on-chain-canonical value up front and certify/advertise/report THAT,
// so the operator's number matches the book (requesting 800 XNO advertises
// 2^109/1e30 ≈ 649). It is the safe direction (never over-advertises) but coarse
// (up to ~2x under the request); precise sizes need a wider size field (a
// versioned wire change), not this.
function quantizeSize(reqXno) {
  const reqRaw = BigInt(Math.round(reqXno * 1e6)) * (10n ** 24n);
  const size_log2 = Math.max(0, Math.min(255, Math.floor(Math.log2(Number(reqRaw)))));
  const advXno = Math.pow(2, size_log2 - Math.log2(1e30));
  const advRaw = BigInt(Math.round(advXno * 1e6)) * (10n ** 24n);
  return { size_log2, advXno, advRaw };
}

// Largest XNO a posted intent can carry: 2^size_log2 raw, exactly as the app.
const maxXnoRawOf = (intent) => {
  const l = BigInt(Math.max(0, Math.min(255, intent.size_log2 | 0))); const sizeRaw = 2n ** l;
  if (intent.side === 0) return sizeRaw.toString();
  return ((sizeRaw / (10n ** 18n)) * (10n ** 30n) / (BigInt(intent.price_e9) * 1000n)).toString();
};
const certifyFor = (side, price, minBps) => (deal) =>
  TP.certify(deal, side === 0, price, { minBps: minBps == null ? MIN_ACCEPT_BPS : minBps, maxAgeMs: 60000 });

// ---- commands --------------------------------------------------------------
const CMDS = {};

CMDS.health = async () => {
  const r = { ok: true, checks: {} };
  const nodes = [];
  for (const u of NANO_NODES) {
    const t0 = Date.now();
    try { const j = await beacon._internals.rpc([u], { action: "block_count" });
      nodes.push({ node: u, ok: !!(j && j.count != null), ms: Date.now() - t0 }); }
    catch (e) { nodes.push({ node: u, ok: false, error: String(e.message || e).slice(0, 60) }); }
  }
  r.checks.nano_nodes = nodes;
  r.checks.nano_quorum_ok = nodes.filter(n => n.ok).length >= 2;
  const pr = await marketPrice();
  r.checks.price = pr.ok ? { ok: true, mid: pr.mid, sources: pr.sources } : { ok: false, reason: pr.reason };
  const t0 = Date.now();
  try { const w = await beacon._internals.generateWork(NANO_NODES, "A".repeat(64), B.THRESH.send, null);
    r.checks.pow = { ok: true, seconds: +((Date.now() - t0) / 1000).toFixed(1), via: WORK_URL }; }
  catch (e) { r.checks.pow = { ok: false, error: String(e.message || e).slice(0, 80) }; }
  const seed = makerSeed();
  if (seed) {
    const acct = JSON.parse(wasm.seed_account(seed));
    let bal = null;
    try { const j = await beacon._internals.rpc(NANO_NODES, { action: "account_balance", account: acct.address });
      bal = { xno: Number(BigInt(j.balance || "0") / (10n ** 24n)) / 1e6,
              receivable: Number(BigInt(j.receivable || j.pending || "0") / (10n ** 24n)) / 1e6 }; } catch (e) {}
    r.checks.maker_wallet = { address: acct.address, balance: bal };
  } else r.checks.maker_wallet = { configured: false, note: "set XNOXMR_MAKER_SEED or WALLET_A_SEED in .env" };
  // Monero side (read-only, fast): balance + scan state + node reachability. A
  // side-1 (sell XMR) maker must be able to preflight the asset it is selling.
  if (seed && MONERO_NODES.length) {
    try {
      const bal = await walletFor(seed).xmrRefresh(() => {}, { readOnly: true });
      r.checks.maker_xmr = { total: bal.total, spendable: bal.spendable, tip: bal.tip,
        blocks_behind: bal.behind, caught_up: bal.caughtUp, nodes: MONERO_NODES.length,
        hint: bal.caughtUp ? undefined : "run `xmr scan` to catch up before posting side-1 offers" };
    } catch (e) { r.checks.maker_xmr = { ok: false, error: String(e.message || e).slice(0, 100),
        note: "Monero nodes unreachable — side-1 (sell XMR) offers cannot be verified" }; }
  } else if (seed) {
    r.checks.maker_xmr = { configured: false, note: "no XNOXMR_MONERO_NODES set — side-1 (sell XMR) offers cannot be verified" };
  }
  r.ok = r.checks.nano_quorum_ok && r.checks.price.ok && r.checks.pow.ok;
  out(r);
};

// xmr: read-only balance, or a BOUNDED chain scan to catch up (Monero has no
// balance RPC — outputs must be scanned; the first scan of a fresh wallet is
// slow, so bound it with --max-blocks and run it on a cron to stay current).
CMDS.xmr = async (args) => {
  const seed = makerSeed(); if (!seed) return die("no maker wallet configured");
  if (!MONERO_NODES.length) return die("no XNOXMR_MONERO_NODES configured");
  const action = args._[1] || "balance";
  if (action === "balance") {
    const bal = await walletFor(seed).xmrRefresh(() => {}, { readOnly: true });
    return out({ ok: true, action: "balance", total: bal.total, spendable: bal.spendable,
      tip: bal.tip, blocks_behind: bal.behind, caught_up: bal.caughtUp });
  }
  if (action === "scan") {
    const maxBlocks = args["max-blocks"] ? parseInt(args["max-blocks"], 10) : 20000;
    const maxChunks = Math.max(1, Math.ceil(maxBlocks / 20));
    let last = null;
    const bal = await walletFor(seed).xmrRefresh((m) => { last = m; }, { maxChunks });
    return out({ ok: true, action: "scan", tip: bal.tip, blocks_behind: bal.behind,
      caught_up: bal.caughtUp, total: bal.total, spendable: bal.spendable, progress: last });
  }
  return die("usage: xmr balance | xmr scan [--max-blocks N]");
};

CMDS.book = async (args) => {
  const side = args.side === "0" ? 0 : args.side === "1" ? 1 : null;
  if (side === null) return die("book needs --side 0 (makers selling XNO) or --side 1 (makers selling XMR)");
  const pr = await marketPrice();
  const offers = await beacon.scanLive(NANO_NODES, PAIR, side, OFFER_TTL_SECS);
  const rows = offers.map((o) => {
    const price = o.intent.price_e9 / 1e9;
    const sizeXno = Math.pow(2, o.intent.size_log2 - Math.log2(1e30));
    const r = { maker: o.maker, price_xmr_per_xno: price, size_xno: +sizeXno.toFixed(4), block: o.blockHash };
    if (pr.ok) {
      const dev = (price - pr.mid) / pr.mid;
      const takerDev = side === 1 ? -dev : dev;      // positive = worse for taker
      r.vs_market_pct = +(-takerDev * 100).toFixed(2);   // positive = better for taker
      r.usable = takerDev <= 0.03 && takerDev >= -0.25;
    }
    return r;
  });
  out({ ok: true, side, market_mid: pr.ok ? pr.mid : null,
        market_note: pr.ok ? undefined : pr.reason, count: rows.length, offers: rows });
};

CMDS.quote = async (args) => {
  const pr = await marketPrice();
  if (!pr.ok) return die(pr.reason, { hint: "fail-closed: never quote without two agreeing sources" });
  const hist = phPush(pr.mid);
  const sigD = args.sigma ? parseFloat(args.sigma) : sigmaDaily(hist);
  const stress = args.stress ? parseFloat(args.stress) : 1;
  const bps = quoteBps(sigD, stress);
  const side = args.side === "0" ? 0 : 1;
  const margin = bps / 10000;
  const ask = pr.mid * (side === 0 ? 1 + margin : 1 - margin);
  const minRaw = TP.minViableXnoRaw(Math.round(ask * 1e9), side === 0, pr.mid, null, MIN_ACCEPT_BPS);
  out({ ok: true, side, market_mid: pr.mid,
        min_take_xno: minRaw ? Number(BigInt(minRaw) / (10n ** 24n)) / 1e6 : null,
        sigma_daily: +sigD.toFixed(4),
        sigma_source: args.sigma ? "override" : (hist.length < 6 ? "seed (run quote a few times to measure)" : "measured from " + hist.length + " mids"),
        stress,
        spread_bps: bps, spread_pct: +(bps / 100).toFixed(3),
        ask_xmr_per_xno: +ask.toFixed(12), price_e9: Math.round(ask * 1e9),
        cap: "unlimited" });
};

CMDS.offer = async (args) => {
  const seed = makerSeed();
  if (!seed) return die("no maker wallet configured", { hint: "set XNOXMR_MAKER_SEED, or WALLET_A_SEED in .env" });
  const action = args._[1];
  if (action !== "post" && action !== "withdraw") return die("usage: offer post|withdraw --side 0|1 [--size <xno>]");
  const side = args.side === "0" ? 0 : 1;
  if (!args.live) return die("refusing to touch the ledger without --live", {
    note: "offer post/withdraw publishes a real Nano block. Re-run with --live once you mean it." });

  if (action === "withdraw") {
    const h = await beacon.publish(NANO_NODES, seed, PAIR, { side, price_e9: 0, size_log2: 0 }, () => {});
    const st = stLoad(); st.offer = null; st.lastWithdraw = { at: Date.now(), block: h }; stSave(st);
    return out({ ok: true, action: "withdraw", side, block: h });
  }
  const pr = await marketPrice();
  if (!pr.ok) return die(pr.reason, { hint: "fail-closed: no quote, no offer" });
  const sigD = args.sigma ? parseFloat(args.sigma) : sigmaDaily(phPush(pr.mid));
  const bps = quoteBps(sigD, 1);
  const margin = bps / 10000;
  const ask = pr.mid * (side === 0 ? 1 + margin : 1 - margin);
  const requested = args.size ? parseFloat(args.size) : DEFAULT_OFFER_XNO;
  if (!(requested > 0)) return die("--size must be positive");
  // Cap to what the wallet can actually fund; refuse rather than post phantom liquidity.
  const fund = await fundableXno(seed, side, ask, args);
  if (fund.xno == null) return die("refusing to post: " + fund.reason);
  const wanted = Math.min(requested, fund.xno);
  if (!(wanted > 0)) return die("refusing to post: no fundable balance to back this offer", { side, fundable_xno: fund.xno });
  // Snap to the on-chain-representable size so what we certify, advertise, and
  // report all equal what a taker decodes from the block.
  const { size_log2, advXno, advRaw } = quantizeSize(wanted);
  const sizeXno = advXno;
  const capped = sizeXno < requested;
  const sizeRaw = advRaw;
  const intent = { side, price_e9: Math.round(ask * 1e9), size_log2 };
  // CERTIFIED WIN or nothing: a full fill at this ask, valued at the mid we
  // just validated, net of the Monero fee, must clear the floor - or we do not
  // post. Same certify() the app runs.
  const hyp = { xnoRaw: sizeRaw.toString(), priceE9: String(intent.price_e9),
                xmrAtomic: ((sizeRaw * BigInt(intent.price_e9) * 1000n) / (10n ** 30n)).toString() };
  const cert = TP.certify(hyp, side === 0, { ok: true, mid: pr.mid, sources: pr.sources, at: pr.at || Date.now() }, { minBps: MIN_ACCEPT_BPS });
  if (!cert.ok) return die("refusing to post: offer is not a certified win", { certificate: cert });
  const block = await beacon.publish(NANO_NODES, seed, PAIR, intent, () => {});
  { const st = stLoad(); st.offer = { block: String(block).toLowerCase(), intent, side, sizeXno, mid: pr.mid, ask, bps, cert, at: Date.now() }; stSave(st); }
  out({ ok: true, action: "post", side, spread_bps: bps, sigma_daily: +sigD.toFixed(4), size_xno: sizeXno,
        requested_xno: requested, capped_to_fundable: capped, fundable_xno: +Number(fund.xno).toFixed(6),
        certified: { net_bps: cert.netBps, net_xmr: Number(cert.netAtomic) / 1e12, fee_xmr: Number(cert.feeAtomic) / 1e12, mid: cert.mid },
        price_e9: intent.price_e9, ask_xmr_per_xno: +ask.toFixed(12), block,
        ttl_seconds: OFFER_TTL_SECS });
};

// verify: is THIS deal a certified win right now? The agent runs this before
// any action it is considering. `--price_e9` defaults to the current quote, so
// with only --side and --xno it answers "would my own quote be a win".
CMDS.verify = async (args) => {
  const side = args.side === "0" ? 0 : args.side === "1" ? 1 : null;
  const xno = parseFloat(args.xno);
  if (side === null || !(xno > 0)) return die("usage: verify --side 0|1 --xno <amount> [--price_e9 <p>] [--min_bps n]");
  const pr = await marketPrice();
  const price = pr.ok ? { ok: true, mid: pr.mid, sources: pr.sources, at: pr.at || Date.now() } : { ok: false, reason: pr.reason };
  let priceE9 = args.price_e9 ? parseInt(args.price_e9, 10) : null;
  if (!priceE9) {
    if (!pr.ok) return die(pr.reason, { hint: "fail-closed: no price, no quote, no verification" });
    const bps = quoteBps(sigmaDaily(phPush(pr.mid)), 1);
    priceE9 = Math.round(pr.mid * (side === 0 ? 1 + bps / 10000 : 1 - bps / 10000) * 1e9);
  }
  const xnoRaw = BigInt(Math.round(xno * 1e6)) * (10n ** 24n);
  const deal = { xnoRaw: xnoRaw.toString(), priceE9: String(priceE9),
                 xmrAtomic: ((xnoRaw * BigInt(priceE9) * 1000n) / (10n ** 30n)).toString() };
  const minBps = args.min_bps ? parseInt(args.min_bps, 10) : MIN_ACCEPT_BPS;
  const cert = TP.certify(deal, side === 0, price, { minBps });
  out({ ok: cert.ok, verdict: cert.ok ? "CERTIFIED WIN" : "REFUSE", reason: cert.reason,
        side, maker_role: side === 0 ? "A (sells XNO)" : "B (sells XMR)", xno,
        price_e9: priceE9, market_mid: price.ok ? price.mid : null, sources: price.sources || 0,
        net_bps: cert.netBps, net_xmr: cert.netAtomic != null ? Number(cert.netAtomic) / 1e12 : null,
        gross_xmr: cert.grossAtomic != null ? Number(cert.grossAtomic) / 1e12 : null,
        fee_xmr_assumed: Number(TP.XMR_TX_FEE_ATOMIC_DEFAULT) / 1e12, min_bps: minBps,
        min_viable_xno_at_this_price: (() => { const m = price.ok ? TP.minViableXnoRaw(priceE9, side === 0, price.mid, null, minBps) : null;
                                              return m ? Number(BigInt(m) / (10n ** 24n)) / 1e6 : null; })(),
        certificate: cert });
  if (!cert.ok) process.exit(1);
};

// status: my resting offer, re-certified at the CURRENT market, with a verdict.
async function offerStatus() {
  const st = stLoad();
  if (!st.offer) return { hasOffer: false };
  const o = st.offer, pr = await marketPrice();
  const ageS = Math.round((Date.now() - o.at) / 1000);
  const r = { hasOffer: true, block: o.block, side: o.side, sizeXno: o.sizeXno, ask: o.ask, postedAt: o.at, ageSeconds: ageS,
              ttlSeconds: OFFER_TTL_SECS, expired: ageS > OFFER_TTL_SECS };
  if (!pr.ok) return Object.assign(r, { verdict: "WITHDRAW", reason: "no trustworthy price: " + pr.reason });
  const xnoRaw = BigInt(Math.round(o.sizeXno * 1e6)) * (10n ** 24n);
  const hyp = { xnoRaw: xnoRaw.toString(), priceE9: String(o.intent.price_e9), xmrAtomic: ((xnoRaw * BigInt(o.intent.price_e9) * 1000n) / (10n ** 30n)).toString() };
  const cert = TP.certify(hyp, o.side === 0, { ok: true, mid: pr.mid, sources: pr.sources, at: pr.at || Date.now() }, { minBps: MIN_ACCEPT_BPS, baseline: o.cert, maxUnrealizedLossBps: 50 });
  const sigD = sigmaDaily(phPush(pr.mid)); const wantBps = quoteBps(sigD, 1);
  const drift = Math.abs(pr.mid - o.mid) / o.mid;
  r.market = { mid: pr.mid, driftSincePostPct: +(drift * 100).toFixed(3), quoteNowBps: wantBps };
  r.certifiedNow = { ok: cert.ok, netBps: cert.netBps, unrealizedBps: cert.unrealizedBps, reason: cert.reason };
  if (r.expired) Object.assign(r, { verdict: "REPOST", reason: "offer TTL expired" });
  else if (!cert.ok) Object.assign(r, { verdict: "WITHDRAW", reason: "no longer a certified win: " + cert.reason });
  else if (drift >= Math.max(0.0025, 0.4 * o.bps / 10000)) Object.assign(r, { verdict: "REPRICE", reason: "mid drifted " + (drift * 100).toFixed(2) + "% (trigger " + (Math.max(0.0025, 0.4 * o.bps / 10000) * 100).toFixed(2) + "%)" });
  else Object.assign(r, { verdict: "HOLD", reason: "certified, net " + cert.netBps + " bps" });
  return r;
}
CMDS.status = async () => out(Object.assign({ ok: true }, await offerStatus()));

// peek: READ-ONLY. Every take-request on my offer, validated and certified,
// without replying. Nothing is committed.
CMDS.peek = async () => {
  const seed = makerSeed(); if (!seed) return die("no maker wallet configured");
  const st = stLoad(); if (!st.offer) return out({ ok: true, hasOffer: false, takes: [] });
  const pr = await marketPrice(); const price = pr.ok ? { ok: true, mid: pr.mid, sources: pr.sources, at: pr.at || Date.now() } : { ok: false, reason: pr.reason };
  const rows = await TP.peekTakes(relayFor(seed), st.offer.block, st.offer.intent, maxXnoRawOf(st.offer.intent), certifyFor(st.offer.side, price));
  out({ ok: true, hasOffer: true, block: st.offer.block, takes: rows.map(r => ({ slot: r.slot, valid: r.valid, answered: r.answered, reason: r.reason,
        deal: r.deal ? { xno: Number(BigInt(r.deal.xnoRaw) / (10n ** 24n)) / 1e6, xmr: Number(r.deal.xmrAtomic) / 1e12, priceE9: r.deal.priceE9 } : null,
        certified: r.cert ? { ok: r.cert.ok, netBps: r.cert.netBps, reason: r.cert.reason } : null })) });
};

// decline: tell a taker on a given slot we will not fill, with a reason.
CMDS.decline = async (args) => {
  const seed = makerSeed(); if (!seed) return die("no maker wallet configured");
  const st = stLoad(); if (!st.offer) return die("no live offer");
  const slot = parseInt(args.slot, 10); if (!(slot >= 0)) return die("usage: decline --slot n [--reason text] --live");
  if (!args.live) return die("refusing to write to the relay without --live");
  await TP.postDecline(relayFor(seed), st.offer.block, slot, args.reason || "maker cannot fill this right now");
  out({ ok: true, declined: slot });
};

// receive: pocket any incoming (receivable) XNO. Nano is PULL-BASED - a send sits
// as "receivable" until the recipient publishes a receive block, so incoming funds
// are NOT in the spendable balance until pocketed. There is nothing to keep a socket
// open for in a cron process: each run polls `receivable` and, with --live, pockets.
// Cron this alongside `tick` (or rely on tick's own auto-receive) so new funds land.
CMDS.receive = async (args) => {
  const seed = makerSeed(); if (!seed) return die("no maker wallet configured", { hint: "set XNOXMR_MAKER_SEED or WALLET_A_SEED in .env" });
  const live = !!args.live;
  const w = walletFor(seed);
  const addr = w.address();
  const rcv = await beacon._internals.rpc(NANO_NODES, { action: "receivable", account: addr, count: "50", threshold: "1" });
  const blocks = rcv && rcv.blocks && typeof rcv.blocks === "object" ? rcv.blocks : {};
  const pending = Object.entries(blocks).map(([h, a]) => ({ block: h, xno: HW.fmtXno(BigInt(typeof a === "object" ? a.amount : a)) }));
  if (!pending.length) { const bal = await w.balance(); return out({ ok: true, address: addr, pending: [], pocketed: "0", balance: bal.xno, note: "nothing receivable" }); }
  if (!live) return out({ ok: true, address: addr, pending, pocketed: "0", note: "DRY: pass --live to pocket " + pending.length + " receivable block(s)" });
  const res = await w.receive(() => {});
  const bal = await w.balance();
  out({ ok: true, address: addr, pocketed: HW.fmtXno(res.pocketed), balance: bal.xno, blocks: pending.length });
};

// tick: ONE safe iteration of the whole unattended maker loop. Idempotent.
//   health -> (unhealthy: withdraw) -> status -> HOLD | REPRICE/REPOST | WITHDRAW
//   -> peek takes -> certified take: HAND OFF (report, keep offer); not a win:
//   decline it so the taker stops waiting. Never settles.
CMDS.tick = async (args) => {
  if (!lockAcquire()) return die("another tick is running (lock held)", { lock: LOCK_FILE });
  const log = [], act = (m) => log.push(m);
  try {
    const seed = makerSeed(); if (!seed) return die("no maker wallet configured");
    const live = !!args.live;
    const side = args.side === "0" ? 0 : 1;
    // auto-receive: pocket any incoming XNO first, so new liquidity is spendable this cycle
    let received = null;
    if (live) { try { const r = await walletFor(seed).receive(() => {}); if (r.pocketed > 0n) { received = HW.fmtXno(r.pocketed); act("received " + received + " XNO (was receivable) -> pocketed"); } } catch (e) { act("auto-receive skipped (non-fatal): " + (e && e.message || e)); } }
    // AUTO-RESUME unfinished settlement sessions (crash recovery). The claim
    // presig and the refund pre-signature are PERSISTED, so a dead process's
    // swap either completes, refunds (XNO side), or recovers the locked XMR
    // from the counterparty's refund — with no counterparty online.
    if (AUTOSETTLE && live && !__settling && !__resuming) {   // never double-run a settling or already-resuming session
      try {
        const files = fs.existsSync(STATE_DIR) ? fs.readdirSync(STATE_DIR).filter((f) => f.startsWith("sess_") && f.endsWith(".json")) : [];
        for (const f of files) {
          let o; try { o = JSON.parse(fs.readFileSync(path.join(STATE_DIR, f), "utf8")); } catch (e) { continue; }
          if (!o || o.done || !o.party) continue;
          const sid = f.replace(/^sess_/, "").replace(/\.json$/, "");
          const store = fileStore(sid);
          const roleIsA = !!o.party.roleIsA;
          if (roleIsA && !(o.open && o.refund)) {
            if (!o.fund) { store.set("done", { at: Date.now(), result: { abandoned: true } }); act("abandoned session " + sid.slice(0, 10) + " (nothing moved)"); }
            else act("session " + sid.slice(0, 10) + " funded but joint never opened — needs the counterparty; keeping for manual recovery");
            continue;
          }
          if (!roleIsA && !o.lock) { store.set("done", { at: Date.now(), result: { abandoned: true } }); act("abandoned session " + sid.slice(0, 10) + " (nothing locked)"); continue; }
          const wApi = walletFor(seed);
          const priceFn = async () => { const p2 = await marketPrice(); return p2.ok ? { ok: true, mid: p2.mid, sources: p2.sources, at: Date.now() } : { ok: false, reason: p2.reason }; };
          // Under watch the resume (which may scan Monero / wait on chains for
          // minutes) runs in the BACKGROUND, so recovering an old session never
          // blocks the accept loop — the maker keeps taking new offers while a
          // prior session settles/refunds/recovers. A cron tick (own process)
          // keeps it synchronous.
          const bgNote = (m) => console.error("[resume " + sid.slice(0, 10) + "] " + m);
          const rdeps = { wasm, xmr: XMR, beacon, urls: NANO_NODES, walletApi: wApi, moneroPost: wApi.moneroPost(),
                          note: WATCH_MODE ? bgNote : ((m) => act("resume: " + m)), store, price: priceFn, abortBps: 1, maxUnrealizedLossBps: 50, maxStress: 2,
                          recoverWaitMs: 60 * 1000, fundWaitMs: FUND_WAIT_MS, confTarget: (o.instant && o.instant.confs) || undefined,
                          claimWaitMs: Math.max(60 * 1000, 60 * 60 * 1000 - (Date.now() - ((o.presigned && o.presigned.at) || Date.now()))) };
          const runResume = () => {
            const rp = TP.restore(wasm, o.party, null);
            // Resume-over-refund: re-join the co-signing rounds and COMPLETE the
            // swap after a restart, instead of waiting for the peer to unwind.
            try { const shr = o.shared; if (shr && shr.hex && TP.attachResume) TP.attachResume(MB, rp, { shared: shr.hex, init: !!shr.init, relay: relayFor(seed), store }); } catch (e) {}
            return (roleIsA ? TP.runA : TP.runB)(rdeps, rp);
          };
          if (WATCH_MODE) {
            __resuming = { sid, at: Date.now() };
            runResume()
              .then((res) => { const r = res || {}; store.set("done", { at: Date.now(), result: r }); bgNote(r.refunded ? "REFUNDED" : r.recovered ? "RECOVERED" : "SETTLED ok"); })
              .catch((e) => bgNote("pending (retries next resume): " + String((e && e.message) || e).slice(0, 120)))
              .finally(() => { __resuming = null; });
            act("resuming unfinished swap " + sid.slice(0, 10) + " in the background — maker loop stays responsive");
          } else {
            act("resuming unfinished swap " + sid.slice(0, 10) + "…");
            try {
              const res = await runResume() || {};
              store.set("done", { at: Date.now(), result: res });
              act("resumed " + sid.slice(0, 10) + ": " + (res.refunded ? "REFUNDED" : res.recovered ? "RECOVERED" : "SETTLED"));
            } catch (e) { act("resume " + sid.slice(0, 10) + " pending: " + String((e && e.message) || e).slice(0, 120)); }
          }
          break;   // one session per tick keeps the tick bounded
        }
      } catch (e) { act("session scan skipped: " + (e && e.message || e)); }
    }
    const pr = await marketPrice();
    const st = stLoad();
    // Remember a block we are about to leave, so the grace window can still
    // answer a take that lands on its rendezvous just after we moved on.
    const recordSuperseded = (old) => {
      if (!old || !old.block) return;
      st.recent = (st.recent || []).filter((x) => x && x.block && (Date.now() - x.at) < GRACE_MS);
      st.recent.push({ block: old.block, intent: old.intent, side: old.side, at: Date.now() });
      st.recent = st.recent.slice(-3);
    };
    const publishWithdraw = async () => { if (!live) { act("DRY: would withdraw"); return; }
      const h = await beacon.publish(NANO_NODES, seed, PAIR, { side: st.offer ? st.offer.side : side, price_e9: 0, size_log2: 0 }, () => {});
      recordSuperseded(st.offer);
      st.offer = null; st.lastWithdraw = { at: Date.now(), block: h }; stSave(st); act("withdrew " + String(h).slice(0, 10)); };
    const publishPost = async () => {
      const sigD = sigmaDaily(phPush(pr.mid)); const bps = quoteBps(sigD, 1); const margin = bps / 10000;
      const ask = pr.mid * (side === 0 ? 1 + margin : 1 - margin);
      const requested = args.size ? parseFloat(args.size) : DEFAULT_OFFER_XNO;
      // Cap to fundable balance; refuse rather than advertise phantom liquidity.
      const fund = await fundableXno(seed, side, ask, args);
      if (fund.xno == null) { act("NOT posting: " + fund.reason); return "refused"; }
      const wanted = Math.min(requested, fund.xno);
      if (!(wanted > 0)) { act("NOT posting: no fundable balance to back an offer (fundable ~" + Number(fund.xno || 0).toFixed(3) + " XNO)"); return "refused"; }
      // Snap to the on-chain-representable size so the reported/advertised figure matches the book.
      const { size_log2, advXno, advRaw } = quantizeSize(wanted);
      const sizeXno = advXno;
      if (sizeXno < requested) act("size " + sizeXno.toFixed(3) + " XNO (requested " + requested + "; capped to fundable + quantised to the on-chain step)");
      const sizeRaw = advRaw;
      const intent = { side, price_e9: Math.round(ask * 1e9), size_log2 };
      const hyp = { xnoRaw: sizeRaw.toString(), priceE9: String(intent.price_e9), xmrAtomic: ((sizeRaw * BigInt(intent.price_e9) * 1000n) / (10n ** 30n)).toString() };
      const cert = TP.certify(hyp, side === 0, { ok: true, mid: pr.mid, sources: pr.sources, at: pr.at || Date.now() }, { minBps: MIN_ACCEPT_BPS });
      if (!cert.ok) { act("NOT posting: not a certified win (" + cert.reason + ")"); return "refused"; }
      if (!live) { act("DRY: would post " + sizeXno + " XNO at " + ask.toFixed(9) + " (" + bps + " bps, net " + cert.netBps + " bps)"); return "would"; }
      const block = await beacon.publish(NANO_NODES, seed, PAIR, intent, () => {});
      recordSuperseded(st.offer);
      st.offer = { block: String(block).toLowerCase(), intent, side, sizeXno, mid: pr.mid, ask, bps, cert, at: Date.now() }; stSave(st);
      act("posted " + sizeXno + " XNO at " + ask.toFixed(9) + " (" + bps + " bps, net " + cert.netBps + " bps) " + String(block).slice(0, 10)); return "posted"; };

    // 1. no trustworthy price -> nothing may rest on the book
    if (!pr.ok) {
      act("oracle unhealthy: " + pr.reason);
      // While a take is PENDING on the resting offer, a transient no-quote
      // must HOLD, never withdraw/repost — pulling the block orphans the take
      // (and the take's own relay chunks can be what rate-limited the oracle).
      let pendingTake = false;
      if (st.offer) { try { const rl = relayFor(seed);
        for (let i = 0; i < 8 && !pendingTake; i++) {
          if (await rl.fetch(TP.rvBox(st.offer.block), i) && !(await rl.fetch(TP.rvRespBox(st.offer.block), i))) pendingTake = true;
        } } catch (e) {} }
      if (pendingTake) { act("a take is PENDING — holding the offer through the oracle blip"); return out({ ok: true, live, actions: log, verdict: "HOLD" }); }
      if (st.offer) await publishWithdraw();
      return out({ ok: true, live, actions: log, verdict: "PAUSED" });
    }
    // 2. TAKES FIRST — a resting offer may already have demand, and answering
    // it takes strict priority over managing the offer. A take lives on the
    // BLOCK it was posted to, so any withdraw/reprice/repost of that block while
    // a valid take is still unanswered ORPHANS the taker (filed 3763062928e0:
    // mid drifted past the reprice trigger between the click and this tick, the
    // block was repriced away, the take was lost). handleTake is factored out so
    // the pre-withdraw guard in step 3 can answer a take that only became
    // visible AFTER this first peek — closing that race for good.
    let handoff = null, settled = null;
    const price = { ok: true, mid: pr.mid, sources: pr.sources, at: pr.at || Date.now() };
    const handleTake = async (r, ctx) => {
      ctx = ctx || st.offer;
      if (r.answered || !r.valid) return;                         // junk/answered: nothing to do
      if (!(r.cert && r.cert.ok)) { act("declining slot " + r.slot + ": " + (r.cert && r.cert.reason)); if (live) await TP.postDecline(relayFor(seed), ctx.block, r.slot, r.cert && r.cert.reason); return; }
      handoff = r;
      if (!(AUTOSETTLE && live)) {
        act("CERTIFIED TAKE on slot " + r.slot + ": net " + r.cert.netBps + " bps - HAND OFF (autosettle off)");
        // Tell the taker NOW instead of letting them wait out the 10-min window.
        if (live) { try { await TP.postDecline(relayFor(seed), ctx.block, r.slot, "maker is in hand-off mode (autosettle off) — a human must settle; retry in a few minutes or pick another offer"); act("told the taker not to wait (hand-off decline)"); } catch (e) {} }
        return;
      }
      if (__settling) {
        // One settlement at a time per offer. A second certified taker gets an
        // INSTANT decline (retry after the repost) rather than silently queueing.
        if (__settling.slot === r.slot) act("slot " + r.slot + " is the take already settling — in progress");
        else { act("certified take on slot " + r.slot + " while slot " + __settling.slot + " settles — declining so they re-take after the repost");
               try { await TP.postDecline(relayFor(seed), ctx.block, r.slot, "maker is settling another take on this offer — it re-posts when done; please take again then"); } catch (e) {} }
        return;
      }
      act("CERTIFIED TAKE on slot " + r.slot + ": net " + r.cert.netBps + " bps - accepting");
      try {
        const cf = (dl) => certifyFor(ctx.side, price)(dl);
        const authSign = (msg) => { try { return wasm.msg_sign(seed, msg); } catch (e) { return null; } };
        // Instant tier: only on side 0 (WE fund the XNO, so WE carry the early-
        // release risk), only within the size cap, and only when the certified
        // net already carries the risk premium on top of the normal floor.
        let instantOffer;
        if (INSTANT_CONFS >= 1 && ctx.side === 0) {
          const dealXno = Number(BigInt(r.deal.xnoRaw) / (10n ** 24n)) / 1e6;
          if (dealXno <= INSTANT_MAX_XNO && r.cert.netBps >= MIN_ACCEPT_BPS + INSTANT_EXTRA_BPS) {
            instantOffer = { confs: INSTANT_CONFS };
            act("⚡ instant tier offered: releasing after " + INSTANT_CONFS + " confs (net " + r.cert.netBps + " bps ≥ " + (MIN_ACCEPT_BPS + INSTANT_EXTRA_BPS) + " bps premium floor, " + dealXno.toFixed(2) + " ≤ " + INSTANT_MAX_XNO + " XNO cap)");
          }
        }
        const hs = await TP.makerPollTake(MB, relayFor(seed), ctx.block, ctx.intent, maxXnoRawOf(ctx.intent), cf, authSign, instantOffer);
        if (hs && hs.deal && hs.shared) {
          const offerSnap = ctx;
          const runSettle = (note) => settleTake(seed, offerSnap, { deal: hs.deal, cert: hs.cert, shared: hs.shared, slot: hs.slot, instant: hs.instant }, note);
          if (WATCH_MODE) {
            // Settlement takes 25-40 min; awaiting it INSIDE the tick froze the
            // whole maker loop. Under watch it runs in the background; the loop
            // keeps peeking/declining and holds the offer until done.
            __settling = { slot: hs.slot, block: offerSnap.block, at: Date.now() };
            runSettle((m) => console.error("[settle] " + m))
              .then((res) => {
                console.error("[settle] finished: " + (res && res.declined ? "declined: " + (res.reason || "") : res && res.refunded ? "refunded: " + (res.reason || "") : "SETTLED ok"));
                if (res && res.done && !res.declined && !res.refunded) { const s2 = stLoad(); s2.offer = null; stSave(s2); }
              })
              .catch((e) => console.error("[settle] error (session persists; auto-resume retries): " + (e && e.message || e)))
              .finally(() => { __settling = null; });
            act("settlement STARTED in the background (slot " + hs.slot + ") — maker loop stays responsive");
          } else {
            const res = await runSettle((m) => act(m));
            if (res.declined || res.refunded) act((res.declined ? "declined" : "refunded") + " during settlement: " + (res.reason || ""));
            else { act("SETTLED autonomously ok"); settled = res; st.offer = null; stSave(st); }
          }
        } else if (hs && hs.declined) { act("re-certify at reply time declined: " + hs.declined); }
      } catch (e) { act("settlement error (safe to retry next tick): " + (e && e.message || e)); }
    };
    if (st.offer) {
      const rows = await TP.peekTakes(relayFor(seed), st.offer.block, st.offer.intent, maxXnoRawOf(st.offer.intent), certifyFor(st.offer.side, price));
      for (const r of rows) await handleTake(r, st.offer);
    }
    // GRACE WINDOW: a take can land on a rendezvous we JUST repriced away (the
    // taker's page had not caught the repost yet). Keep answering takes on the
    // last few superseded blocks for GRACE_MS — honour one that still certifies
    // at the current market, decline the rest so the taker stops waiting. This
    // closes the reprice/resubmit race regardless of what the taker does.
    {
      const recent = (st.recent || []).filter((x) => x && x.block && (Date.now() - x.at) < GRACE_MS && (!st.offer || x.block !== st.offer.block));
      for (const rb of recent) {
        if (__settling) break;
        try {
          const rows2 = await TP.peekTakes(relayFor(seed), rb.block, rb.intent, maxXnoRawOf(rb.intent), certifyFor(rb.side, price));
          for (const r of rows2) if (!r.answered && r.valid) { act("grace: answering take on superseded block " + String(rb.block).slice(0, 10) + " slot " + r.slot); await handleTake(r, rb); }
        } catch (e) { act("grace peek skipped: " + (e && e.message || e)); }
      }
    }
    // 3. the resting offer itself
    const status = await offerStatus();
    // ROOT-CAUSE GUARD (filed 3763062928e0): a take lives on the block it was
    // posted to, so NEVER withdraw/reprice/repost a block that still has an
    // unanswered VALID take — that orphans the taker. Re-peek right before we
    // would pull the block; this catches a take that only became visible AFTER
    // step 2's peek (the market-drift race). Answer it here — accept if it
    // certifies, decline if not — and if accepting started a settlement, HOLD
    // the block and repost once it clears. If every late take was declined, the
    // block is clean and the original verdict proceeds. This also protects the
    // TTL/REPOST path, not just REPRICE.
    if (st.offer && status.hasOffer && status.verdict !== "HOLD" && !__settling && !handoff) {
      try {
        const rows2 = await TP.peekTakes(relayFor(seed), st.offer.block, st.offer.intent, maxXnoRawOf(st.offer.intent), certifyFor(st.offer.side, price));
        const late = rows2.filter((r) => r.valid && !r.answered);
        if (late.length) {
          act(status.verdict + " deferred: " + late.length + " unanswered take(s) on " + String(st.offer.block).slice(0, 10) + " — answering before any repost so none is orphaned");
          for (const r of late) await handleTake(r);
          if (__settling || handoff) { status.verdict = "HOLD"; status.reason = "answered a late take on the block; repost deferred"; }
        }
      } catch (e) { act("pre-withdraw take-guard skipped (non-fatal): " + (e && e.message || e)); }
    }
    let postOutcome = null;   // "posted" | "would" | "refused" — what publishPost actually did this cycle
    if (__settling) { act("settlement in progress (slot " + __settling.slot + ", " + Math.round((Date.now() - __settling.at) / 1000) + "s) — holding the offer; no reprice/withdraw"); }
    else if (handoff) { act("holding the offer for the human settling the certified take"); }
    else if (!status.hasOffer) { act("no offer resting"); postOutcome = await publishPost(); }
    else if (status.verdict === "HOLD") act("HOLD: " + status.reason);
    else if (status.verdict === "WITHDRAW") { act("WITHDRAW: " + status.reason); await publishWithdraw(); }
    else { act(status.verdict + ": " + status.reason); await publishWithdraw(); postOutcome = await publishPost(); }
    // Verdict reflects what ACTUALLY happened. When there was a resting offer,
    // status.verdict (HOLD/WITHDRAW/REPRICE/REPOST) is the meaningful outcome.
    // When there was NO offer, the outcome is POSTED only if we truly posted —
    // otherwise REFUSE (bug fix: it used to default to POSTED on a refusal).
    const postVerdict = postOutcome === "posted" ? "POSTED"
                      : postOutcome === "would" ? "WOULD_POST"
                      : postOutcome === "refused" ? "REFUSE" : null;
    out({ ok: true, live, received, autosettle: AUTOSETTLE, settled: settled ? { realized: settled.realized || null } : null,
          settling: __settling ? { slot: __settling.slot, seconds: Math.round((Date.now() - __settling.at) / 1000) } : null,
          verdict: __settling ? "SETTLING" : settled ? "SETTLED" : handoff ? (AUTOSETTLE ? "SETTLING" : "HANDOFF") : (status.verdict || postVerdict || (live ? "POSTED" : "WOULD_POST")), actions: log,
          handoff: handoff ? { block: st.offer.block, slot: handoff.slot, deal: handoff.deal, certificate: handoff.cert,
                               next: "A human opens https://www.nearinstant.xyz, unlocks the maker wallet, and settles. This agent will not." } : null,
          offer: stLoad().offer ? { block: stLoad().offer.block, ask: stLoad().offer.ask, sizeXno: stLoad().offer.sizeXno, ageSeconds: Math.round((Date.now() - stLoad().offer.at) / 1000) } : null });
  } finally { lockRelease(); }
};

// Autonomous settlement. GATED behind BOTH --live and XNOXMR_AUTOSETTLE=1,
// because it moves real funds with no human. It runs the maker's exact
// settlement driver with the headless wallet, and every irreversible step is
// still certified by the SAME gates the app uses - a losing or moving market
// makes runB decline before locking and runA take the refund. "Autonomous"
// never means "unconditional": the machine enforces the certified-win rule a
// human would, without a human present.
async function settleTake(seed, offer, take, note) {
  const walletApi = walletFor(seed);
  const rand = (n) => { const b = new Uint8Array(n); require("crypto").webcrypto.getRandomValues(b); return b; };
  const relay = relayFor(seed);
  const d = await MB.derive(Buffer.from(take.shared, "hex"), false);
  const wire = new MB.MailboxWire([relay], d.send, d.recv, d.key); wire.pollMs = 3000; wire.timeoutMs = 240000;
  const sessionId = offer.block + "-M";
  const store = fileStore(sessionId);
  const roleIsA = offer.side === 0;
  note("running the joint ceremony...");
  const party = await TP.ceremony(wasm, XMR, rand, "mainnet", wire, roleIsA, take.deal, note, walletApi.account());
  store.set("party", party.snapshot());
  store.set("acceptCert", take.cert);
  if (take.instant && take.instant.confs) store.set("instant", take.instant);   // persist the tier: a resumed session must honour it
  if (take.shared) store.set("shared", { hex: take.shared, init: false });      // resume-over-refund: rebuild step channels after a restart
  const priceFn = async () => { const pr = await marketPrice(); return pr.ok ? { ok: true, mid: pr.mid, sources: pr.sources, at: pr.at || Date.now() } : { ok: false, reason: pr.reason }; };
  const deps = { wasm, xmr: XMR, beacon, urls: NANO_NODES, walletApi, moneroPost: walletApi.moneroPost(),
                 note, store, price: priceFn, abortBps: 1, maxUnrealizedLossBps: 50, maxStress: 2, fundWaitMs: FUND_WAIT_MS,
                 confTarget: (take.instant && take.instant.confs) || undefined };
  let result;
  try { result = await (roleIsA ? TP.runA : TP.runB)(deps, party) || {}; }
  catch (e) {
    // The taker never funded — end cleanly and let the offer keep resting for
    // the next taker (nothing was locked, so there is nothing to recover).
    if (e && e.fundTimeout) {
      store.set("done", { at: Date.now(), result: { abandoned: true, reason: "funding timeout" } });
      note("counterparty never funded within the window — abandoned cleanly; the offer stays live for the next taker");
      return { done: false, abandoned: true, reason: "funding timeout" };
    }
    throw e;
  }
  store.set("done", { at: Date.now(), result });
  return result;
}
function fileStore(sessionId) {
  const f = path.join(STATE_DIR, "sess_" + sessionId.replace(/[^0-9a-zA-Z_-]/g, "").slice(0, 40) + ".json");
  fs.mkdirSync(STATE_DIR, { recursive: true });
  const read = () => { try { return JSON.parse(fs.readFileSync(f, "utf8")); } catch (e) { return {}; } };
  return { get: (k) => { const o = read(); return k in o ? o[k] : null; },
           set: (k, v) => { const o = read(); o[k] = v; fs.writeFileSync(f, JSON.stringify(o)); try { fs.chmodSync(f, 0o600); } catch (e) {} } };
}
// Autonomous settlement is ON by default; disable only with XNOXMR_AUTOSETTLE=0.
const AUTOSETTLE = env("XNOXMR_AUTOSETTLE", "1") !== "0";
// How long the maker waits for the taker's XNO to fund the joint account before
// abandoning the settlement cleanly (nothing is locked at that point). Bounds a
// vanished-taker hang that would otherwise freeze the offer until a restart.
const FUND_WAIT_MS = Math.max(30000, parseInt(env("XNOXMR_FUND_WAIT_MS", "300000"), 10) || 300000);
// INSTANT TIER (idea J): on side-0 offers (maker funds XNO), release the XNO
// after N confirmations of the taker's XMR lock instead of 10. The MAKER
// carries the reorg risk beyond N — a business decision, priced via an extra
// spread requirement and capped in size. 0 = off (default). Taker-side risk is
// never changed; sweeps always use the full 10 (consensus spendability).
const INSTANT_CONFS = Math.min(9, Math.max(0, parseInt(env("XNOXMR_INSTANT_CONFS", "0"), 10) || 0));
const INSTANT_MAX_XNO = Math.max(0, parseFloat(env("XNOXMR_INSTANT_MAX_XNO", "200")) || 200);
const INSTANT_EXTRA_BPS = Math.max(0, parseInt(env("XNOXMR_INSTANT_EXTRA_BPS", "25"), 10) || 25);

CMDS.settle = async (args) => {
  args = args || {};
  // Operator tools (work regardless of the autosettle flag):
  //   settle --list                list in-flight settlement sessions
  //   settle --abandon <session>   drop a session that never moved funds
  if (args.list) {
    const files = fs.existsSync(STATE_DIR) ? fs.readdirSync(STATE_DIR).filter((f) => f.startsWith("sess_") && f.endsWith(".json")) : [];
    const sessions = files.map((f) => {
      let o = {}; try { o = JSON.parse(fs.readFileSync(path.join(STATE_DIR, f), "utf8")); } catch (e) {}
      const sid = f.replace(/^sess_/, "").replace(/\.json$/, "");
      const moved = MOVED_KEYS.filter((k) => o[k]);
      return { session: sid, done: !!(o.done), roleIsA: o.party ? !!o.party.roleIsA : null, movedFunds: moved, abandonable: !o.done && moved.length === 0 };
    });
    return out({ ok: true, sessions });
  }
  if (args.abandon) {
    const sid = String(args.abandon);
    const f = path.join(STATE_DIR, "sess_" + sid.replace(/[^0-9a-zA-Z_-]/g, "").slice(0, 40) + ".json");
    if (!fs.existsSync(f)) return die("no such session: " + sid, { hint: "run `settle --list` to see sessions" });
    let o = {}; try { o = JSON.parse(fs.readFileSync(f, "utf8")); } catch (e) {}
    if (o.done) return out({ ok: true, session: sid, note: "session was already finished/abandoned — nothing to do" });
    const moved = MOVED_KEYS.filter((k) => o[k]);
    if (moved.length) return die("refusing to abandon: funds moved on this session (" + moved.join(", ") + ")",
      { hint: "resume it instead — `tick --live` auto-resumes to complete, refund, or recover. Only abandon sessions where nothing moved." });
    fileStore(sid).set("done", { at: Date.now(), result: { abandoned: true, reason: "operator abandon" } });
    return out({ ok: true, abandoned: sid, note: "session marked abandoned (nothing had moved on-chain); it will no longer auto-resume or hold your offer" });
  }
  if (!AUTOSETTLE) { out({
    ok: false,
    refused: "autonomous settlement is DISABLED (you set XNOXMR_AUTOSETTLE=0). Unset it to re-enable — it is ON by default.",
    do_instead: "With autosettle on, settlement runs inside `tick --live`; a certified take is settled autonomously instead of handed off."
  });
  process.exit(2); }
  out({ ok: true, note: "autonomous settlement is ENABLED (default). It runs inside `tick --live`; nothing to settle standalone.",
        reminder: "every irreversible step is still certified; a losing or fast-moving market aborts safely (decline / refund). It has NOT yet completed on-chain between two real parties — watch the first real runs and use small amounts." });
};

// watch: REALTIME maker. A cron tick makes a taker wait up to the whole
// interval; watch is a persistent process that runs the same tick, then
// subscribes to the resting offer's rendezvous account over the Nano websocket
// (a take-request is an on-chain send to it) and ticks the INSTANT one lands.
CMDS.watch = async (args) => {
  const seed = makerSeed(); if (!seed) return die("no maker wallet configured");
  if (!args.live) return die("watch is a live maker loop — re-run with --live");
  DIE_SOFT = true;   // inside watch a refused tick logs and continues, never exits
  WATCH_MODE = true; // settlement runs in the BACKGROUND so the loop stays responsive
  const WS_URL0 = env("XNOXMR_NANO_WS", "wss://ws.nano.to");
  const WS_URL = (NANO_KEY && /ws\.nano\.to/.test(WS_URL0) && WS_URL0.indexOf("?") < 0) ? WS_URL0 + "/?key=" + encodeURIComponent(NANO_KEY) : WS_URL0;
  const tickMs = Math.max(30000, parseInt(env("XNOXMR_TICK_MS", "180000"), 10) || 180000);
  const TICK_TIMEOUT = Math.max(60000, parseInt(env("XNOXMR_TICK_TIMEOUT_MS", "900000"), 10) || 900000);
  const log = (m) => console.error("[watch " + new Date().toISOString().slice(11, 19) + "] " + m);
  let running = 0, queued = false;                    // running = start ts (0 = idle)
  const runTick = async (why) => {
    if (running) {
      const secs = Math.round((Date.now() - running) / 1000);
      if (Date.now() - running > TICK_TIMEOUT) {
        log("tick stuck " + secs + "s — releasing the guard (session steps are store-guarded, safe to re-enter)");
        running = 0;
      } else { queued = true; log("tick busy " + secs + "s (" + why + ") — queued"); return; }
    }
    const me = running = Date.now();
    try { log("tick (" + why + ")"); await CMDS.tick(args); }
    catch (e) { log("tick " + (e && e.soft ? "refused" : "error") + ": " + (e && e.message || e)); }
    finally { if (running === me) running = 0; if (queued) { queued = false; setTimeout(() => runTick("queued"), 250); } }
  };
  let ws = null, watched = "";
  const rvAddress = async () => {
    try {
      const st = stLoad(); if (!st.offer) return null;
      const hex = await relayFor(seed).mailboxAccountHex(TP.rvBox(st.offer.block));
      const b = new Uint8Array(hex.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.substr(i * 2, 2), 16);
      return wasm.nano_address_encode(b);
    } catch (e) { return null; }
  };
  const resub = async () => {
    const a = await rvAddress();
    if (!a || a === watched || !ws || ws.readyState !== 1) return;
    ws.send(JSON.stringify({ action: "subscribe", topic: "confirmation", options: { accounts: [a] } }));
    watched = a; log("watching rendezvous " + a.slice(0, 20) + "…");
  };
  // One take = several relay-chunk confirmations. Coalesce a burst into ONE
  // tick (trailing 2 s debounce) and space ws-triggered ticks ≥ 12 s apart —
  // seven ticks in 27 s is what rate-limited the oracle.
  let wsTimer = null, lastWsTick = 0;
  const nudge = () => {
    if (wsTimer) return;
    const wait = Math.max(2000, 12000 - (Date.now() - lastWsTick));
    log("rendezvous activity — tick in " + Math.round(wait / 1000) + "s (coalescing burst)");
    wsTimer = setTimeout(() => { wsTimer = null; lastWsTick = Date.now(); runTick("websocket"); }, wait);
  };
  const connect = () => {
    try { ws = new WebSocket(WS_URL); } catch (e) { setTimeout(connect, 15000); return; }
    ws.onopen = () => { watched = ""; resub(); };
    ws.onmessage = async (ev) => {
      try {
        // Node's native WebSocket can deliver Blob/ArrayBuffer frames; a bare
        // String(ev.data) is "[object Blob]" and JSON.parse throws — which
        // silently dropped EVERY realtime event. Decode all frame shapes.
        let raw = ev.data;
        if (typeof raw !== "string") raw = (raw && raw.text) ? await raw.text() : Buffer.from(raw).toString("utf8");
        const d = JSON.parse(raw);
        if (d && d.topic === "confirmation") nudge();
      } catch (e) { log("ws frame decode: " + (e && e.message || e)); }
    };
    ws.onclose = (ev) => { log("ws closed (code " + ((ev && ev.code) || "?") + ") — reconnecting in 5s"); ws = null; setTimeout(connect, 5000); };
    ws.onerror = (ev) => { log("ws error" + (ev && ev.message ? ": " + ev.message : "")); try { ws.close(); } catch (e) {} };
  };
  connect();
  await runTick("start");
  setInterval(resub, 10000);                       // follow reposts/reprices to the new rendezvous
  setInterval(() => runTick("interval"), tickMs);  // fallback: everything a cron tick did
  setInterval(() => { try { if (ws && ws.readyState === 1) ws.send(JSON.stringify({ action: "ping" })); } catch (e) {} }, 30000);  // keepalive: ws.nano.to drops idle sockets (~2 min)
  log("realtime maker running — ws " + WS_URL + ", fallback tick every " + Math.round(tickMs / 1000) + "s. Ctrl-C stops (state is persisted; crash recovery resumes).");
  await new Promise(() => {});                     // stay alive
};

CMDS.help = async () => out({
  ok: true,
  commands: {
    health: "preflight: nano quorum, price oracles, PoW proxy, maker wallet",
    book: "--side 0|1   live offers, ranked from the taker's side, with fairness",
    quote: "--side 0|1 [--sigma d] [--stress n]   the volatility-adaptive quote",
    "offer post": "--side 0|1 [--size xno] [--xmr amt] [--sigma d] --live   publish a real offer (size is CAPPED to fundable balance; side 1 needs --xmr or XNOXMR_XMR_LIQUIDITY)",
    "offer withdraw": "--side 0|1 --live   publish the price-0 withdraw sentinel",
    verify: "--side 0|1 --xno n [--price_e9 p] [--min_bps n]   is this deal a certified win NOW? exit 1 if not",
    status: "my resting offer re-certified at the current market: HOLD | REPRICE | WITHDRAW | REPOST",
    peek: "READ-ONLY: every take-request on my offer, validated + certified, nothing committed",
    receive: "[--live]   pocket any incoming (receivable) XNO; cron this so new funds land. Nano is pull-based.",
    decline: "--slot n [--reason text] --live   tell a taker we will not fill (they stop waiting)",
    tick: "[--side 0|1] [--size xno] [--xmr amt] [--live]   ONE safe iteration of the maker loop; offers CAPPED to fundable balance.",
    watch: "--side 0|1 [--size xno] --live   REALTIME maker: tick + Nano-websocket watch on the rendezvous, accepts takes instantly; fallback tick every XNOXMR_TICK_MS (180s)",
    "xmr balance": "read-only spendable/total XMR + scan height (side-1 makers)",
    "xmr scan": "[--max-blocks N]   advance the Monero scan to catch up (cron this for side 1)",
    settle: "autosettle status. Operator: `settle --list` shows in-flight sessions; `settle --abandon <session>` drops a setup-only session that never moved funds (refuses if it did — resume instead).",
  },
  env: { XNOXMR_MAKER_SEED: "maker wallet seed (else WALLET_A_SEED from .env)",
         XNOXMR_WORK_URL: "PoW proxy base, default https://www.nearinstant.xyz",
         XNOXMR_NANO_NODES: "comma-separated Nano RPC nodes",
         XNOXMR_FUND_WAIT_MS: "how long the maker waits for a taker's XNO before abandoning cleanly (default 300000)",
         XNOXMR_INSTANT_CONFS: "side-0 instant tier: release XNO after N Monero confs instead of 10 (0=off; YOU carry the reorg risk beyond N)",
         XNOXMR_INSTANT_MAX_XNO: "instant-tier size cap in XNO (default 200)",
         XNOXMR_INSTANT_EXTRA_BPS: "extra certified net (on top of the 30 bps floor) required to offer instant (default 25)" },
});

// ---- arg parsing -----------------------------------------------------------
function parseArgs(argv) {
  const a = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    if (t.startsWith("--")) {
      const k = t.slice(2);
      if (argv[i + 1] && !argv[i + 1].startsWith("--")) { a[k] = argv[++i]; } else a[k] = true;
    } else a._.push(t);
  }
  return a;
}
(async () => {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0] || "help";
  const fn = CMDS[cmd];
  if (!fn) return die("unknown command: " + cmd, { try: Object.keys(CMDS) });
  try { await fn(args); }
  catch (e) { die(String((e && e.message) || e), { command: cmd }); }
})();
