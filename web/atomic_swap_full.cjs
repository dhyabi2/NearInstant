// Full cross-chain atomic swap — the WHOLE choreography end to end, in JS, with
// both real wasm engines: wasm-bridge (Nano FROST + adaptor) and wasm-monero
// (joint Monero key). Two independent parties over the MailboxWire + a dumb
// relay run DKG → joint Nano account, derive the joint Monero address, co-sign
// the adaptor pre-signature on the real claim block, the XMR-seller completes
// it (revealing x), and the XNO-seller extracts x and reconstructs the joint
// Monero secret that opens the joint address. Proves the ONE secret unlocks
// both legs — the atomic link — with each party holding only its own shares.
//
//   node web/atomic_swap_full.cjs
const crypto = require("crypto");
const M = require("./mailbox.js");
const W = require("../swap-core/wasm-bridge/pkg-node/wasm_bridge.js");
const X = require("../swap-core/wasm-monero/pkg-node/wasm_monero.js");
const { Party, runAtomicSwap } = require("./swap_driver.js");

// hex → Uint8Array
const hb = (h) => Uint8Array.from(Buffer.from(h, "hex"));
// A canonical ed25519 scalar from 64 random bytes (reduced), as a Monero secret.
function moneroSecret() {
  const wide = crypto.randomBytes(64);
  // reduce mod l via BigInt (little-endian)
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  let v = 0n;
  for (let i = 63; i >= 0; i--) v = (v << 8n) | BigInt(wide[i]);
  v %= L;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

(async () => {
  const ctx = new Uint8Array(32); crypto.randomFillSync(ctx);

  // XMR-seller (A) and XNO-seller (B), each with its own Monero spend key.
  const A = new Party(W, X, {
    role: "xmr-seller", ctx, moneroSecret: moneroSecret(), viewHalf: crypto.randomBytes(32),
  });
  const B = new Party(W, X, {
    role: "xno-seller", ctx, moneroSecret: moneroSecret(), viewHalf: crypto.randomBytes(32),
  });

  // MailboxWire duplex over a shared in-memory relay (each party still only
  // ever touches its own mailboxes / its own key shares).
  const store = new Map();
  const relay = {
    async post(m, s, b) { store.set(m + "/" + s, b); return true; },
    async fetch(m, s) { return store.get(m + "/" + s) || null; },
  };
  const shared = new Uint8Array(32); crypto.randomFillSync(shared);
  const da = await M.derive(shared, true), db = await M.derive(shared, false);
  const wa = new M.MailboxWire([relay], da.send, da.recv, da.key);
  const wb = new M.MailboxWire([relay], db.send, db.recv, db.key);
  wa.pollMs = wb.pollMs = 5; wa.timeoutMs = wb.timeoutMs = 8000;
  const swap = async (aOut, bOut) => {
    await Promise.all([wa.send(aOut), wb.send(bOut)]);
    return Promise.all([wa.recv(), wb.recv()]);
  };

  // A representative real claim block (the send from the joint Nano account
  // paying the XMR-seller their XNO). Values are illustrative but hashed
  // canonically; on a live swap these come from the funded joint account.
  const claim = {
    previous: "b".repeat(64),
    representative: "0".repeat(64),
    balance: "0", // all funds sent to the XMR-seller
    link: crypto.randomBytes(32).toString("hex"), // XMR-seller's XNO destination
  };

  console.log("Full atomic XNO⇄XMR swap — both engines, two parties, one relay:\n");
  const res = await runAtomicSwap(A, B, swap, claim, "stagenet", (s) => console.log("  " + s));

  // Independent cross-checks on the collected artifacts.
  const assert = (c, m) => { if (!c) { console.error("FAIL:", m); process.exit(1); } };
  assert(res.jointMoneroAddress.startsWith("5"), "joint Monero stagenet address");
  assert(res.jointNanoAccount.length === 64, "joint Nano account");
  assert(res.claimHash.length === 64, "claim hash");
  assert(res.preSignature.length === 192, "96-byte pre-signature");
  assert(res.claimSignature.length === 128, "64-byte claim signature");
  assert(res.adaptorPoint.length === 64, "adaptor point present");
  assert(res.jointMoneroSecretOpensAddress === true, "joint Monero secret opens the address");

  console.log("\nartifacts:");
  console.log("  joint Monero address :", res.jointMoneroAddress);
  console.log("  joint Nano account   :", res.jointNanoAccount);
  console.log("  adaptor point (T=x·G):", res.adaptorPoint.slice(0, 32) + "…");
  console.log("  claim signature      :", res.claimSignature.slice(0, 32) + "…");
  console.log("\nOK: one secret unlocked BOTH legs — the XMR-seller's Nano claim and the");
  console.log("    XNO-seller's Monero sweep — proven end to end in the browser engines.");
})().catch((e) => { console.error("ERR", e); process.exit(1); });
