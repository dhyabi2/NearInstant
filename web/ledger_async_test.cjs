"use strict";
// REAL async test (no mocks): Party A posts an arbitrary blob to the LIVE Nano
// ledger, then a READ-ONLY Party B (no seed, A can be offline) recovers the
// exact bytes from the ledger. Proves one-online-at-a-time message passing.
const crypto = require("crypto");
const wasm = require("../swap-core/wasm-bridge/pkg-node/wasm_bridge.js");
const B = require("./beacon.js");
const LR = require("./ledger_relay.js");
const os = require("os"), path = require("path");
function loadWallet(){ const f = process.env.BEACON_WALLET || path.join(os.homedir(), ".nearinstant_e2e_wallet.json"); try { const w = require(f); if (w && w.seed) return w; } catch(e){} return null; }

const URLS = ["https://rpc.nano.to", "https://rainstorm.city/api",
  "https://node.somenano.com/proxy", "https://nanoslo.0x.no/proxy"];

(async () => {
  const wallet = loadWallet();
  if (!wallet) { console.log("SKIP ledger_async_test: no funded wallet (set BEACON_WALLET). No mock fallback."); return; }
  const beacon = B.makeBeacon(wasm, {});
  // unique mailbox per run so we read exactly this message
  const mailbox = "async-" + crypto.randomBytes(6).toString("hex");
  const blob = new Uint8Array(crypto.randomBytes(200));   // 200 bytes → 7 chunks
  console.log("mailbox:", mailbox, "| blob:", blob.length, "bytes, sha256",
    crypto.createHash("sha256").update(blob).digest("hex").slice(0, 16) + "…");

  // ---- Party A: post on-chain, then "go offline" ----
  const sender = LR.makeLedgerRelay({ beacon, wasm, urls: URLS, seed: wallet.seed });
  console.log("A: posting to the ledger…");
  const t0 = Date.now();
  await sender.post(mailbox, 0, blob);
  console.log(`A: posted ${Math.ceil(blob.length / 32)} chunks in ${((Date.now() - t0) / 1000).toFixed(1)}s. A is now OFFLINE.`);

  await new Promise(r => setTimeout(r, 10000)); // propagation

  // ---- Party B: READ-ONLY (no seed) — recover from the ledger ----
  const reader = LR.makeLedgerRelay({ beacon, wasm, urls: URLS });   // note: no seed
  console.log("B: (read-only) fetching from the ledger…");
  let got = null;
  for (let i = 0; i < 6 && !got; i++) { got = await reader.fetch(mailbox, 0); if (!got) await new Promise(r => setTimeout(r, 5000)); }
  if (!got) { console.error("FAIL: B could not recover the message"); process.exit(1); }
  const same = got.length === blob.length && got.every((v, i) => v === blob[i]);
  console.log("B: recovered", got.length, "bytes, sha256",
    crypto.createHash("sha256").update(Buffer.from(got)).digest("hex").slice(0, 16) + "…");
  console.log(same ? "OK: exact bytes recovered from the ledger — async, no server, no storage." : "FAIL: bytes differ");
  process.exit(same ? 0 : 1);
})().catch(e => { console.error("ERR", e && e.stack || e); process.exit(1); });
