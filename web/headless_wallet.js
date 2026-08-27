// headless_wallet.js — the browser wallet's API with no Web Worker and no
// localStorage, for an autonomous agent (Hermes) running under Node.
//
// It is a faithful PORT of web/wallet.js + web/wallet-worker.js, not a
// rewrite: same block construction, same quorum reads, same Monero
// bookkeeping (outputs / spent-set / checkpoint), same three-phase
// sign -> mark spent -> broadcast in xmrSend that prevents double-spending a
// key image. Where the browser held the seed in a Worker, this holds it in the
// process the operator runs; nothing leaves the machine. State lives in one
// 0600 JSON file per Monero address.
"use strict";
const fs = require("fs");
const path = require("path");

const RAW_PER_XNO = 10n ** 30n;
const XMR_UNLOCK = 10;            // confirmations before an output is spendable
const LOOKBACK = 720;             // ~24h: fast first sync (guided deposits are detected live)
const MAX_INPUTS = 16;            // must match wasm-monero MAX_INPUTS

const hx = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const hb = (h) => Uint8Array.from(Buffer.from(h, "hex"));
function fmtXno(raw) { const r = BigInt(raw); const w = r / RAW_PER_XNO; const f = (r % RAW_PER_XNO).toString().padStart(30, "0").slice(0, 6).replace(/0+$/, ""); return f ? `${w}.${f}` : `${w}`; }
function parseXno(s) { const m = String(s).trim().match(/^(\d+)(?:\.(\d+))?$/); if (!m) throw new Error("enter a number"); return BigInt(m[1]) * RAW_PER_XNO + BigInt((m[2] || "").padEnd(30, "0").slice(0, 30) || "0"); }
function fmtXmr(a) { const r = BigInt(a); const w = r / (10n ** 12n); const f = (r % (10n ** 12n)).toString().padStart(12, "0").replace(/0+$/, ""); return f ? `${w}.${f}` : `${w}`; }
function parseXmr(s) { const m = String(s).trim().match(/^(\d+)(?:\.(\d+))?$/); if (!m) throw new Error("enter a number"); return BigInt(m[1]) * (10n ** 12n) + BigInt((m[2] || "").padEnd(12, "0").slice(0, 12) || "0"); }

// A fetch transport for the wasm Monero client, failing over across nodes.
function moneroPostFor(nodes) {
  const list = nodes.map((u) => String(u).replace(/\/+$/, "")).filter(Boolean);
  // Rotate the starting node per request — a lagging (stale-tip) node that still
  // answers would otherwise pin every height/conf read (see swapMoneroPost).
  let rr = 0;
  return async (route, body) => {
    const j = body.length && (body[0] === 0x7b || body[0] === 0x5b);
    let lastErr = "no Monero node answered";
    const order = list.map((_, i) => list[(rr + i) % list.length]); rr = (rr + 1) % Math.max(1, list.length);
    for (const url of order) {
      const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 12000);
      try {
        const r = await fetch(url + "/" + route, { method: "POST", body, signal: ctrl.signal, headers: { "content-type": j ? "application/json" : "application/octet-stream" } });
        if (!r.ok) { lastErr = "HTTP " + r.status; continue; }
        return new Uint8Array(await r.arrayBuffer());
      } catch (e) { lastErr = (e && e.name === "AbortError") ? ("timeout " + url) : (e && e.message || String(e)); }
      finally { clearTimeout(t); }
    }
    throw new Error(lastErr);
  };
}

function makeHeadlessWallet(opts) {
  const { wasm, xmr, beacon, urls, moneroNodes, seedHex, stateDir, network } = opts;
  if (!/^[0-9a-fA-F]{64}$/.test(seedHex || "")) throw new Error("seed must be 64 hex");
  const xmrNet = network || "mainnet";
  const B = beacon._internals;
  const acct = JSON.parse(wasm.seed_account(seedHex));
  const account = acct.pubkey, address = acct.address;
  const getUrls = () => (typeof urls === "function" ? urls() : urls);
  const getNodes = () => (typeof moneroNodes === "function" ? moneroNodes() : moneroNodes);
  fs.mkdirSync(stateDir, { recursive: true });

  // ---- Nano ---------------------------------------------------------------
  function signBlock(block) {
    const out = wasm.sign_state_block(seedHex, block.previous, block.representative, block.balance, block.link, block.subtype);
    if (!out) throw new Error("refused to sign (invalid block fields)");
    return JSON.parse(out);
  }
  async function receive(onProgress) {
    const u = getUrls();
    const info = await beacon.accountInfo(u, address);            // quorum read
    let frontier = info ? info.frontier : "0".repeat(64);
    let balance = info ? BigInt(info.balance) : 0n;
    let rep = account;
    if (info && info.representative) { const pk = wasm.nano_address_decode(info.representative); if (pk.length === 32) rep = hx(pk); }
    const rcv = await B.rpc(u, { action: "receivable", account: address, count: "20", threshold: "1" });
    const blocks = rcv && rcv.blocks && typeof rcv.blocks === "object" ? rcv.blocks : {};
    let pocketed = 0n;
    for (const [sendHash, amount] of Object.entries(blocks)) {
      const amt = BigInt(typeof amount === "object" ? amount.amount : amount);
      const isOpen = frontier === "0".repeat(64);
      balance += amt;
      const signed = signBlock({ previous: frontier, representative: rep, balance: balance.toString(), link: sendHash.toLowerCase(), subtype: isOpen ? "open" : "receive" });
      if (onProgress) onProgress(`receiving ${fmtXno(amt)} XNO…`);
      const work = await B.generateWork(u, signed.work_root, beacon.THRESH.receive, null);
      frontier = String(await B.processBlock(u, JSON.stringify(signed), work)).toLowerCase();
      pocketed += amt;
    }
    return { frontier, balance, pocketed };
  }
  async function send(destAddress, amountXno, onProgress) {
    const u = getUrls();
    const destPk = wasm.nano_address_decode(String(destAddress).trim());
    if (destPk.length !== 32) throw new Error("that is not a valid Nano address");
    const amount = parseXno(amountXno);
    if (amount <= 0n) throw new Error("amount must be more than zero");
    const info = await beacon.accountInfo(u, address);            // fail-closed on disagreement
    if (!info) throw new Error("this wallet has no funds yet");
    const balance = BigInt(info.balance);
    if (amount > balance) throw new Error(`you only have ${fmtXno(balance)} XNO`);
    let rep = account;
    if (info.representative) { const pk = wasm.nano_address_decode(info.representative); if (pk.length === 32) rep = hx(pk); }
    const signed = signBlock({ previous: info.frontier, representative: rep, balance: (balance - amount).toString(), link: hx(destPk), subtype: "send" });
    if (onProgress) onProgress(`signed send · proving work…`);
    const work = await B.generateWork(u, signed.work_root, beacon.THRESH.send, null);
    const hash = await B.processBlock(u, JSON.stringify(signed), work);
    if (onProgress) onProgress(`nano send confirmed ✓ block ${String(hash).slice(0, 12)}…`);
    return String(hash);
  }
  async function balance() {
    const info = await beacon.accountInfo(getUrls(), address);
    return info ? { raw: info.balance, xno: fmtXno(info.balance), opened: true } : { raw: "0", xno: "0", opened: false };
  }

  // ---- Monero -------------------------------------------------------------
  const identity = () => JSON.parse(xmr.xmr_personal(hb(seedHex), xmrNet));
  const stateFile = (addr) => path.join(stateDir, "xmr_" + addr.slice(0, 16) + ".json");
  const loadSt = (addr) => { try { return JSON.parse(fs.readFileSync(stateFile(addr), "utf8")); } catch (e) { return { restore: null, scannedTo: null, outputs: [], spent: [] }; } };
  const saveSt = (addr, st) => { fs.writeFileSync(stateFile(addr), JSON.stringify(st)); try { fs.chmodSync(stateFile(addr), 0o600); } catch (e) {} };
  async function connect(node) { return xmr.XmrNode.connect(moneroPostFor([node])); }

  async function xmrRefresh(onProgress, o) {
    const id = identity(); const addr = id.address; const nodes = getNodes();
    if (!nodes.length) throw new Error("no Monero node configured");
    let ni = 0;
    const scan = async (payload) => {
      let lastErr = "no Monero node answered";
      for (let tries = 0; tries < nodes.length; tries++) {
        try {
          const node = await connect(nodes[ni]); const tip = await node.height();
          if (payload.from == null) return { outputs: [], scannedTo: tip, tip };
          const from = Math.max(0, payload.from | 0), to = Math.min(tip - 1, from + (payload.maxBlocks || 20) - 1);
          const outs = from > to ? [] : JSON.parse(await node.scan_all(hb(id.spend_pub), hb(id.view_key), from, to, null));
          return { outputs: outs, scannedTo: from > to ? tip : to + 1, tip };
        } catch (e) { lastErr = e && e.message || String(e); ni = (ni + 1) % nodes.length; }
      }
      throw new Error(lastErr);
    };
    const st = loadSt(addr);
    // readOnly: one height call + the outputs already scanned, NO block scanning.
    // Fast (sub-second) verified balance for sizing/health; understated only by
    // outputs in the not-yet-scanned tail (safe — never overstates spendable).
    if (o && o.readOnly) {
      let tip = st.scannedTo || 0;
      try { const r = await scan({ from: null }); tip = r.tip; } catch (e) {}
      // A never-scanned wallet only ever scans the last LOOKBACK blocks, so
      // report "behind" against that start, not against genesis (avoids a
      // scary "3.7M blocks behind" on a fresh wallet).
      const start = st.scannedTo != null ? st.scannedTo : Math.max(0, tip - LOOKBACK);
      const spent0 = new Set(st.spent); let total0 = 0n, spend0 = 0n;
      for (const out of st.outputs) { if (spent0.has(out.index)) continue; const a = BigInt(out.amount); total0 += a; if (tip - out.block >= XMR_UNLOCK) spend0 += a; }
      return { total: fmtXmr(total0), spendable: fmtXmr(spend0), pending: total0 > spend0, tip, state: st,
               caughtUp: start >= tip, behind: Math.max(0, tip - start), started: st.scannedTo != null, scanned: false };
    }
    if (st.scannedTo == null) { const r = await scan({ from: null }); st.restore = Math.max(0, r.tip - LOOKBACK); st.scannedTo = st.restore; saveSt(addr, st); }
    let tip = st.scannedTo;
    const maxChunks = (o && o.maxChunks) || 5000;
    for (let g = 0; g < maxChunks; g++) {
      const r = await scan({ from: st.scannedTo, maxBlocks: 20 });
      tip = r.tip;
      for (const out of r.outputs) if (!st.outputs.some((x) => x.index === out.index)) st.outputs.push(out);
      st.scannedTo = r.scannedTo; saveSt(addr, st);
      if (onProgress) onProgress(`scan ${st.scannedTo.toLocaleString()} / ${tip.toLocaleString()} · ${st.outputs.length} output(s)`);
      if (r.scannedTo >= r.tip) break;
    }
    const spent = new Set(st.spent); let total = 0n, spendable = 0n;
    for (const out of st.outputs) { if (spent.has(out.index)) continue; const a = BigInt(out.amount); total += a; if (tip - out.block >= XMR_UNLOCK) spendable += a; }
    return { total: fmtXmr(total), spendable: fmtXmr(spendable), pending: total > spendable, tip, state: st, caughtUp: st.scannedTo >= tip, behind: Math.max(0, tip - st.scannedTo) };
  }
  async function xmrSend(destAddress, amountXmr, onProgress) {
    const id = identity(); const addr = id.address; const nodes = getNodes();
    const dest = String(destAddress).trim();
    if (!/^[1-9A-HJ-NP-Za-km-z]{95,106}$/.test(dest)) throw new Error("that is not a valid Monero address");
    const amount = parseXmr(amountXmr); if (amount <= 0n) throw new Error("amount must be more than zero");
    const bal = await xmrRefresh(onProgress);
    const st = bal.state; const spent = new Set(st.spent);
    const FEE_BASE = 100000000n, FEE_PER_INPUT = 30000000n;
    const spendable = st.outputs.filter((o) => !spent.has(o.index) && bal.tip - o.block >= XMR_UNLOCK).sort((a, b) => (BigInt(a.amount) > BigInt(b.amount) ? 1 : -1));
    const chosen = []; let sum = 0n;
    for (const o of spendable) { chosen.push(o); sum += BigInt(o.amount); if (sum >= amount + FEE_BASE + FEE_PER_INPUT * BigInt(chosen.length)) break; if (chosen.length >= MAX_INPUTS) break; }
    const need = amount + FEE_BASE + FEE_PER_INPUT * BigInt(Math.max(1, chosen.length));
    if (!chosen.length || sum < need) throw new Error(chosen.length >= MAX_INPUTS ? `balance split across too many small outputs (max ${MAX_INPUTS} per send)` : `not enough spendable XMR: need about ${fmtXmr(need)} including fee, ${fmtXmr(spendable.reduce((a, o) => a + BigInt(o.amount), 0n))} is unlocked and unspent`);
    // PHASE 1 — build and sign EXACTLY ONCE (failing over here is safe: nothing broadcast yet)
    let signed = null, lastErr = "no Monero node answered";
    for (const n of nodes) {
      try { const node = await connect(n);
        signed = JSON.parse(await node.send(JSON.stringify(chosen.map((o) => ({ output: o.output, block: o.block }))), hb(id.spend_secret), dest, amount.toString(), id.address, xmrNet)); break; }
      catch (e) { lastErr = e && e.message || String(e); if (onProgress) onProgress(`build via ${n} failed: ${lastErr} → failover`); }
    }
    if (!signed) throw new Error(lastErr);
    // PHASE 2 — mark spent BEFORE broadcasting (a false positive hides an output until rescan; a false negative double-spends)
    for (const o of chosen) st.spent.push(o.index); saveSt(addr, st);
    if (onProgress) onProgress(`fee ${fmtXmr(BigInt(signed.fee || 0))} XMR (${signed.inputs} input${signed.inputs > 1 ? "s" : ""}) · broadcasting…`);
    // PHASE 3 — broadcast the SAME bytes; relaying one tx to several nodes is a no-op
    let hash = null;
    for (const n of nodes) { try { const node = await connect(n); hash = await node.publish(signed.tx); break; } catch (e) { lastErr = e && e.message || String(e); } }
    if (!hash) throw new Error("signed the transaction but no node accepted the broadcast (" + lastErr + "). Tx " + String(signed.tx_hash).slice(0, 12) + "… — check an explorer before retrying; never re-sign.");
    if (onProgress) onProgress(`xmr broadcast ✓ tx ${String(hash).slice(0, 12)}…`);
    return { tx_hash: hash, fee: signed.fee };
  }

  return {
    account: () => account, address: () => address, balance, receive, send,
    xmrAddress: async () => identity().address, xmrRefresh, xmrSend,
    moneroPost: () => moneroPostFor(getNodes()),
    _fmtXno: fmtXno, _fmtXmr: fmtXmr, _signBlock: signBlock,
  };
}
module.exports = { makeHeadlessWallet, moneroPostFor, fmtXno, fmtXmr, parseXno, parseXmr };
