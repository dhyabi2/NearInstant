// beacon_live_test.cjs — REAL, no mocks. Posts a beacon offer to the LIVE Nano
// ledger and reads it back with the same scanLive() the app uses, then proves
// the lifecycle on real chain data: supersede (newest-per-maker wins by account
// height) and cancel (a price-0 withdraw sentinel drops the maker). Finally it
// withdraws, leaving the ledger clean.
//
// Needs a funded maker wallet. Provide it via BEACON_WALLET=/path/to.json
// (JSON: {"seed":"<hex64>","nano":"nano_..."}) or the default test wallet at
// ~/.nearinstant_e2e_wallet.json. Without one it SKIPS (exit 0) rather than
// pretend — there is no mock fallback by design.
//
// Run: node web/beacon_live_test.cjs
"use strict";
const os = require("os");
const path = require("path");
const wasm = require("../swap-core/wasm-bridge/pkg-node/wasm_bridge.js");
const B = require("./beacon.js");

const URLS = ["https://rpc.nano.to", "https://rainstorm.city/api",
  "https://node.somenano.com/proxy", "https://nanoslo.0x.no/proxy"];
const PAIR = "XNO/XMR", SIDE = 0;

function loadWallet() {
  const p = process.env.BEACON_WALLET || path.join(os.homedir(), ".nearinstant_e2e_wallet.json");
  try { const w = require(p); if (w && w.seed && w.nano) return w; } catch (e) {}
  return null;
}

(async () => {
  const w = loadWallet();
  if (!w) { console.log("SKIP beacon_live_test: no funded wallet (set BEACON_WALLET). No mock fallback."); return; }
  const beacon = B.makeBeacon(wasm, {});
  const maker = w.nano;
  const mine = (live) => live.filter(o => o.maker === maker);
  const post = async (price_e9, label) => {
    process.stdout.write(`  ${label}: publishing price_e9=${price_e9} … `);
    const h = await beacon.publish(URLS, w.seed, PAIR, { side: SIDE, price_e9, size_log2: 100 }, () => {});
    process.stdout.write("block " + h.slice(0, 12) + "…\n");
    await new Promise(r => setTimeout(r, 10000));
    return mine(await beacon.scanLive(URLS, PAIR, SIDE, 3600));
  };
  const assert = (cond, msg) => { if (!cond) { console.error("FAIL: " + msg); process.exit(1); } console.log("  ok: " + msg); };

  console.log("maker:", maker);
  // 1) post + read back
  const a = await post(900000, "POST");
  assert(a.length === 1 && a[0].intent.price_e9 === 900000, "offer posted and read back live (scanLive)");
  const h1 = a[0].height;
  // 2) supersede: newer height wins, only one live
  const b = await post(950000, "SUPERSEDE");
  assert(b.length === 1 && b[0].intent.price_e9 === 950000 && b[0].height > h1, "re-post supersedes by account height");
  // 3) cancel: withdraw sentinel drops the maker
  const c = await post(0, "CANCEL");
  assert(c.length === 0, "withdraw sentinel (price 0) removes the maker");

  console.log("OK: real on-chain beacon post + supersede + cancel proven (no mocks). Ledger clean.");
})().catch(e => { console.error("ERR", e && e.stack || e); process.exit(1); });
