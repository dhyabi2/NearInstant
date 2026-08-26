#!/usr/bin/env node
// Stage 5 GOLD proof: an ACCEPTED broadcast. Sweeps a freshly-funded joint
// output (faucet tx 5456176e… to the ctx=0x43 joint address) entirely with the
// wasm engine and expects the stagenet node to ACCEPT and relay it — the one
// thing the double-spend proof couldn't show. Waits for the 10-block unlock.
//
//   node web/xmr_gold_proof.cjs
const wasm = require("../swap-core/wasm-monero/pkg-node/wasm_monero.js");

const NODES = ["http://stagenet.xmr-tw.org:38081", "http://node.monerodevs.org:38089"];
const CTX = new Uint8Array(32).fill(0x43);
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
function sfs(f) { let v = 0n; for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(f); v %= L;
  const o = new Uint8Array(32); for (let i = 0; i < 32; i++) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; }
const hb = (h) => Uint8Array.from(Buffer.from(h, "hex"));
function postFor(base) {
  return async (route, body) => {
    const j = body.length && (body[0] === 0x7b || body[0] === 0x5b);
    const r = await fetch(base + "/" + route, { method: "POST", body,
      headers: { "content-type": j ? "application/json" : "application/octet-stream" } });
    if (!r.ok) throw new Error("HTTP " + r.status);
    return new Uint8Array(await r.arrayBuffer());
  };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const a = sfs(0x11), b = sfs(0x22);
  const info = JSON.parse(wasm.xmr_joint_info(
    CTX, wasm.xmr_spend_pub(a), wasm.xmr_spend_pub(b),
    new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), "stagenet"));
  console.log("joint address:", info.address);

  let base = null, node = null;
  for (const u of NODES) { try { node = await wasm.XmrNode.connect(postFor(u)); base = u; break; } catch (e) {} }
  if (!node) throw new Error("no stagenet node reachable");

  // Find the funded output and wait until it is 10+ blocks deep (spendable).
  let hit = null, block = 0;
  for (let attempt = 0; attempt < 40; attempt++) {
    const tip = await node.height();
    const scan = await node.scan(hb(info.spend_pub), hb(info.view_key), tip - 200, tip - 1, null);
    if (scan) {
      const s = JSON.parse(scan);
      hit = s; block = s.block;
      const confs = tip - block;
      console.log(`tip ${tip}, output at ${block} (${confs} confs), amount ${s.amount}`);
      if (confs >= 10) break;
    } else {
      console.log("output not visible yet…");
    }
    await sleep(60000); // ~1 block
  }
  if (!hit || (await node.height()) - block < 10)
    throw new Error("output never reached 10 confirmations in the wait window");

  // Reconstruct the joint secret and sweep everything back to the joint address
  // (send half + change to the same address = all funds minus fee return there).
  const secret = wasm.xmr_joint_secret(CTX, a, b);
  const signed = JSON.parse(await node.sweep_sign(hit.output, block, secret, info.address, "stagenet"));
  console.log("swept + signed in wasm — tx_hash", signed.tx_hash, `(${signed.tx.length / 2} bytes)`);

  // Broadcast — expect ACCEPTANCE this time.
  const res = await fetch(base + "/send_raw_transaction", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ tx_as_hex: signed.tx }),
  });
  const flags = await res.json();
  if (flags.status !== "OK" || flags.not_relayed) {
    throw new Error("node did not accept the sweep: " + JSON.stringify(flags));
  }
  console.log("\nACCEPTED ✓ node relayed our wasm-built sweep — tx", signed.tx_hash);
  console.log("GOLD: a real Monero transaction, scanned/decoyed/built/signed entirely in the");
  console.log("      browser engine over JS fetch, accepted and relayed by stagenet.");
})().catch((e) => { console.error("FAIL:", e.message); process.exit(1); });
