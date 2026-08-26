// Validate the funded-swap orchestrator's crypto + Nano block construction with
// NO on-chain broadcasts: derive the joint accounts, run the adaptor ceremony,
// confirm one secret opens both legs, and confirm a jointly-signed Nano open
// block verifies. Real fund moves are tested separately, live, with confirms.
//
//   node web/funded_swap_check.cjs
const assert = require("assert");
const { webcrypto } = require("crypto");
const wasm = require("../swap-core/wasm-bridge/pkg-node/wasm_bridge.js");
const xmr = require("../swap-core/wasm-monero/pkg-node/wasm_monero.js");
const FS = require("./funded_swap.js");

const rand = (n) => webcrypto.getRandomValues(new Uint8Array(n));
const hb = (h) => Uint8Array.from(Buffer.from(h, "hex"));

(async () => {
  const s = FS.prepare(wasm, xmr, rand, "mainnet");
  assert(s.jointMonero.address.startsWith("4"), "joint Monero is a mainnet address");
  assert(s.jointNanoAddress.startsWith("nano_"), "joint Nano address derived");
  console.log("1) joint Monero", s.jointMonero.address.slice(0, 14) + "…, joint Nano", s.jointNanoAddress.slice(0, 16) + "…");

  // A jointly-signed Nano OPEN block for the joint account must verify — this
  // is exactly the block that pockets the swap funding into the joint account.
  const acctHex = s.jointNanoAccount;
  const openHash = wasm.state_block_hash(acctHex, "0".repeat(64), acctHex,
    "100000000000000000000000000", "1".repeat(64), "open"); // 0.0001 XNO
  const openSig = FS.jointSign(s, openHash);
  assert(wasm.nano_check(hb(acctHex), openHash, openSig), "joint OPEN block signature verifies");
  const built = FS.nanoProcessJson(wasm, {
    accountHex: acctHex, previous: "0".repeat(64), repHex: acctHex,
    balance: "100000000000000000000000000", link: "1".repeat(64), subtype: "open", sig: openSig,
  });
  assert(built.signedJson.includes('"type":"state"') && built.workRoot.length === 64, "process JSON assembled");
  console.log("2) joint OPEN block jointly signed + verifies ✓ (real 2-of-2, pockets the funding)");

  // The adaptor claim: a jointly pre-signed SEND from the joint account, bound
  // to T = the XMR-seller's Monero key; completing it reveals x.
  const claimHash = wasm.state_block_hash(acctHex, built.hashHex, acctHex,
    "0", s.jointNanoAccount, "send"); // send all to B's dest (here the joint acct, illustrative)
  const pre = FS.adaptorPresign(s, claimHash, s.T);
  assert(wasm.presig_verify(pre, s._account, claimHash), "claim pre-signature verifies");
  const alone = Uint8Array.from(pre).subarray(0, 64);
  assert(!wasm.nano_check(s._account, claimHash, alone), "pre-sig not valid on its own");
  const claimSig = wasm.presig_complete(pre, s.x);
  assert(wasm.nano_check(s._account, claimHash, claimSig), "completed claim verifies");
  const revealed = wasm.presig_extract(pre, claimSig);
  assert(FS._eq(revealed, s.x), "the claim reveals exactly x");
  console.log("3) adaptor claim jointly pre-signed, completes, reveals x ✓");

  // Atomic link: the revealed x + A's share opens the joint Monero key → sweep.
  const jointSecret = xmr.xmr_joint_secret(s.ctx, s.A_xmr, revealed);
  const opens = xmr.xmr_spend_pub(jointSecret);
  assert(FS._eq(opens, hb(s.jointMonero.spend_pub)), "revealed x opens the joint Monero key");
  console.log("4) revealed x opens the joint Monero key → the XMR is sweepable ✓");

  console.log("\nOK: funded-swap orchestrator validated — derivations, real 2-of-2 joint Nano");
  console.log("    open block, adaptor claim, and the one-secret-unlocks-both-legs link.");
  console.log("    (No funds moved; the on-chain funding/lock/claim/sweep run live with confirms.)");
})().catch((e) => { console.error("FAIL:", e.message); process.exit(1); });
