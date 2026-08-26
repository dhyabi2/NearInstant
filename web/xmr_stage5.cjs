#!/usr/bin/env node
// Stage 5 proof: the Monero swap leg running IN THE WASM ENGINE with chain
// access supplied by JS fetch — the exact browser shape.
//
// Against a real public stagenet node, entirely through wasm-monero:
//   1. derive the 2-of-2 joint address (must equal the address that held and
//      settled real stagenet funds in the native Stage-2 proof),
//   2. view-key-scan the real funding block and find the real joint output,
//   3. reconstruct the joint spend secret (adaptor-reveal shape),
//   4. fetch real decoys + the live fee rate and build + sign a CLSAG/BP+
//      sweep of that output,
//   5. broadcast it. The output was already swept on-chain in 2022-block
//      2188337, so the ONLY acceptable node answer is a double-spend
//      rejection — which proves the node parsed and validated our
//      wasm-built transaction as well-formed up to the spent key image.
//
// Run: node web/xmr_stage5.cjs   (needs swap-core/wasm-monero/pkg-node — see
//      deploy/browser_ceremony_test.sh)

const assert = require("assert");
const wasm = require("../swap-core/wasm-monero/pkg-node/wasm_monero.js");

const NODES = [
  "http://stagenet.xmr-tw.org:38081",
  "http://node.monerodevs.org:38089",
  "http://node2.monerodevs.org:38089",
];

// Native Stage-2 fixtures (fixed seeds; address funded 0.02 sXMR in block
// 2188323, swept by our native code in 2188337).
const CTX = new Uint8Array(32).fill(0x42);
const VIEW_A = new Uint8Array(32).fill(0x01);
const VIEW_B = new Uint8Array(32).fill(0x02);
const FUND_BLOCK = 2188323;
const EXPECT_ADDR =
  "5BCrVM7isJxbLh75xCEg41eaDeJp24wHpSwGwZKiA41zX2GSqFLD5SGjPyoCgQvHbnJXbE5uyYSQfj5eMZfQZaQNTb8QuRz";
const EXPECT_AMOUNT = "20000000000"; // 0.02 sXMR in piconero

// scalar_from_seed: wide reduction of seed||0^32 mod l — high half zero, so
// it's just the little-endian seed value mod the ed25519 group order.
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
function scalarFromSeed(fill) {
  let v = 0n;
  for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(fill);
  v %= L;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

function postFnFor(base) {
  return async (route, body) => {
    const isJson = body.length && (body[0] === 0x7b || body[0] === 0x5b); // { or [
    const res = await fetch(base + "/" + route, {
      method: "POST",
      body,
      headers: { "content-type": isJson ? "application/json" : "application/octet-stream" },
    });
    if (!res.ok) throw new Error("HTTP " + res.status + " from " + base + "/" + route);
    return new Uint8Array(await res.arrayBuffer());
  };
}

async function main() {
  // --- 1. joint identity, derived by the wasm engine ------------------------
  const alice = scalarFromSeed(0x11), bob = scalarFromSeed(0x22);
  const aPub = wasm.xmr_spend_pub(alice), bPub = wasm.xmr_spend_pub(bob);
  const info = JSON.parse(wasm.xmr_joint_info(CTX, aPub, bPub, VIEW_A, VIEW_B, "stagenet"));
  assert.strictEqual(info.address, EXPECT_ADDR, "joint address matches the funded fixture");
  console.log("1) joint address (wasm) =", info.address.slice(0, 20) + "… ✓ matches on-chain-proven fixture");

  // --- 2. connect through JS fetch (browser shape) --------------------------
  let node = null, used = null;
  for (const base of NODES) {
    try {
      node = await wasm.XmrNode.connect(postFnFor(base));
      used = base;
      break;
    } catch (e) { console.log("   (node unreachable, trying next:", base + ")"); }
  }
  assert.ok(node, "at least one public stagenet node reachable");
  const height = await node.height();
  assert.ok(height > FUND_BLOCK, "stagenet tip past the funding block");
  console.log("2) connected to", used, "— height", height);

  // --- 3. scan the REAL funding block, find the REAL joint output -----------
  const spendPub = Uint8Array.from(Buffer.from(info.spend_pub, "hex"));
  const viewKey = Uint8Array.from(Buffer.from(info.view_key, "hex"));
  const hit = JSON.parse(await node.scan(spendPub, viewKey, FUND_BLOCK, FUND_BLOCK, null));
  assert.ok(hit, "joint output found in the funding block");
  assert.strictEqual(hit.amount, EXPECT_AMOUNT, "scanned amount is the funded 0.02 sXMR");
  console.log("3) scanned block", hit.block, "— found the real joint output:", hit.amount, "piconero");

  // --- 4. reconstruct the joint secret + build + sign the sweep -------------
  const secret = wasm.xmr_joint_secret(CTX, alice, bob);
  assert.strictEqual(Buffer.from(secret).toString("hex"),
    "d14170dfb087b010ea1ee7d260468999012f21cb04512d738c6fbf38f3af8600",
    "reconstructed joint secret matches the fixture");
  const signed = JSON.parse(
    await node.sweep_sign(hit.output, hit.block, secret, EXPECT_ADDR, "stagenet"));
  assert.ok(signed.tx.length > 2000, "serialized tx is a real CLSAG/BP+ transaction");
  assert.strictEqual(signed.tx_hash.length, 64, "tx hash present");
  console.log("4) sweep built + signed in wasm — real decoys, live fee; tx_hash", signed.tx_hash.slice(0, 16) + "…,",
    (signed.tx.length / 2) + " bytes");

  // --- 5. broadcast: the only correct outcome is a DOUBLE-SPEND rejection ---
  let verdict = null;
  try {
    await node.publish(signed.tx);
    verdict = "accepted";
  } catch (e) { verdict = String(e); }
  assert.notStrictEqual(verdict, "accepted", "node must not accept a double spend");
  // The wasm error surfaces the rejection but some nodes leave the reason
  // string empty — read the node's structured verdict flags directly.
  const res = await fetch(used + "/send_raw_transaction", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ tx_as_hex: signed.tx, do_not_relay: true }),
  });
  const flags = await res.json();
  assert.strictEqual(flags.status, "Failed", "node rejects the tx");
  // monerod's tx-pool raises invalid_input for ANY input-check failure,
  // double spends included — the discriminator is double_spend itself: a
  // malformed ring/CLSAG would set invalid_input WITHOUT double_spend.
  assert.strictEqual(flags.double_spend, true,
    "rejected as a double spend (tx otherwise valid); node said: " + JSON.stringify(flags));
  for (const bad of ["invalid_output", "low_mixin", "overspend", "too_big", "fee_too_low",
                     "sanity_check_failed", "too_few_outputs", "tx_extra_too_big"]) {
    assert.ok(!flags[bad], "node flagged " + bad + ": " + JSON.stringify(flags));
  }
  console.log("5) broadcast rejected with double_spend=true (already-swept key image), no structural flags ✓ — node validated our wasm-built tx");

  console.log("\nOK: Stage 5 core proven — scan, decoys, fee, CLSAG/BP+ build+sign all ran in the wasm engine over JS fetch against real stagenet.");
}

main().catch((e) => { console.error("FAIL:", e); process.exit(1); });
