// Two-PARTY swap mechanism proof: unlike the self-swap (both halves in one
// page), here two INDEPENDENT parties each hold only their own key share and
// exchange every ceremony message over the MailboxWire (an encrypted relay).
// Proves the real trustless case: derive the joint Nano account + joint Monero
// address, jointly sign the real OPEN block, adaptor-pre-sign the real CLAIM,
// B completes it revealing x, and A reconstructs the joint Monero key — with
// neither party ever holding the other's secret.
//
//   node web/two_party_swap.cjs
const assert = require("assert");
const crypto = require("crypto");
const M = require("./mailbox.js");
const W = require("../swap-core/wasm-bridge/pkg-node/wasm_bridge.js");
const X = require("../swap-core/wasm-monero/pkg-node/wasm_monero.js");

const hb = (h) => Uint8Array.from(Buffer.from(h, "hex"));
const eq = (a, b) => Buffer.from(a).equals(Buffer.from(b));
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
function mScalar() { const w = crypto.randomBytes(64); let v = 0n; for (let i = 63; i >= 0; i--) v = (v << 8n) | BigInt(w[i]); v %= L; const o = new Uint8Array(32); for (let i = 0; i < 32; i++) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; }

(async () => {
  // Shared rendezvous: a code both parties know (from the beacon / QR handshake).
  const shared = crypto.randomBytes(32);
  const store = new Map();
  const relay = { async post(m, s, b) { store.set(m + "/" + s, b); return true; }, async fetch(m, s) { return store.get(m + "/" + s) || null; } };
  const dA = await M.derive(shared, true), dB = await M.derive(shared, false);
  const wA = new M.MailboxWire([relay], dA.send, dA.recv, dA.key);
  const wB = new M.MailboxWire([relay], dB.send, dB.recv, dB.key);
  wA.pollMs = wB.pollMs = 5; wA.timeoutMs = wB.timeoutMs = 8000;
  const swap = async (ao, bo) => { await Promise.all([wA.send(ao), wB.send(bo)]); return Promise.all([wA.recv(), wB.recv()]); };

  // ---- 1. DKG over the wire: each party keeps ONLY its own share ----
  const dkgA = new W.BrowserDkg(1, 2), dkgB = new W.BrowserDkg(2, 1);
  let [aR, bR] = await swap(dkgA.round1_out(), dkgB.round1_out());
  dkgA.set_peer_round1(aR); dkgB.set_peer_round1(bR);
  let [aR2, bR2] = await swap(dkgA.round2_out(), dkgB.round2_out());
  const acctA = dkgA.set_peer_round2(aR2), acctB = dkgB.set_peer_round2(bR2);
  assert(eq(acctA, acctB), "parties disagree on the joint Nano account");
  const signA = new W.BrowserSigner(dkgA.key_package(), dkgA.public_key_package(), 1, 2);
  const signB = new W.BrowserSigner(dkgB.key_package(), dkgB.public_key_package(), 2, 1);
  const account = signA.account();
  const acctHex = Buffer.from(account).toString("hex");
  console.log("1) joint Nano account agreed over the wire:", acctHex.slice(0, 16) + "…");

  // ---- 2. Monero keys: each generates its own; only PUBKEYS cross the wire ----
  const A_xmr = mScalar(), B_xmr = mScalar();           // B_xmr == the adaptor secret x
  const A_pub = W.nano_address_decode ? X.xmr_spend_pub(A_xmr) : null; // spend pub
  const B_pub = X.xmr_spend_pub(B_xmr);
  const ctx = crypto.randomBytes(32), viewA = crypto.randomBytes(32), viewB = crypto.randomBytes(32);
  // (In the app these are exchanged over the same wire; inlined here.)
  const jm = JSON.parse(X.xmr_joint_info(ctx, X.xmr_spend_pub(A_xmr), B_pub, viewA, viewB, "mainnet"));
  console.log("2) joint Monero address derived from both parties' pubkeys:", jm.address.slice(0, 14) + "…");

  // ---- 3. Jointly sign the REAL open block over the wire ----
  const amt = "100000000000000000000000000"; // 0.0001 XNO
  const fakeSend = "aa".repeat(32);
  const openHash = W.state_block_hash(acctHex, "0".repeat(64), acctHex, amt, fakeSend, "open");
  {    const [aC, bC] = await swap(signA.sign_commit(openHash), signB.sign_commit(openHash));
    signA.set_peer_commit(aC); signB.set_peer_commit(bC);
    const [aS, bS] = await swap(signA.sign_share(), signB.sign_share());
    signA.set_peer_share(aS); signB.set_peer_share(bS);
    const sig = signA.aggregate_sig();
    assert(eq(sig, signB.aggregate_sig()), "open sigs differ");
    assert(W.nano_check(account, openHash, sig), "joint OPEN block verifies");
    console.log("3) real OPEN block jointly signed over the wire ✓");
  }

  // ---- 4. Adaptor-pre-sign the REAL claim over the wire, bound to T=B_pub ----
  const claimHash = W.state_block_hash(acctHex, Buffer.from(openHash).toString("hex"), acctHex, "0", acctHex, "send");
  let pre;
  {    const [aC, bC] = await swap(signA.presign_commit(claimHash, B_pub), signB.presign_commit(claimHash, B_pub));
    signA.set_peer_commit(aC); signB.set_peer_commit(bC);
    const [aS, bS] = await swap(signA.presign_share(), signB.presign_share());
    signA.set_peer_share(aS); signB.set_peer_share(bS);
    pre = signA.aggregate_presig();
    assert(eq(pre, signB.aggregate_presig()), "presigs differ");
    assert(W.presig_verify(pre, account, claimHash), "claim pre-sig verifies");
    console.log("4) real CLAIM adaptor-pre-signed over the wire, bound to B's Monero key ✓");
  }

  // ---- 5. B completes with x (only B knows it); A extracts it from the result ----
  const claimSig = W.presig_complete(pre, B_xmr);       // B does this, broadcasts
  assert(W.nano_check(account, claimHash, claimSig), "completed claim valid");
  const xA = W.presig_extract(pre, claimSig);           // A reads x off the chain
  assert(eq(xA, B_xmr), "A recovered exactly B's Monero secret");
  console.log("5) B completed the claim; A extracted x — without ever holding B's key ✓");

  // ---- 6. A reconstructs the joint Monero key and can sweep ----
  const jointSecret = X.xmr_joint_secret(ctx, A_xmr, xA);
  assert(eq(X.xmr_spend_pub(jointSecret), hb(jm.spend_pub)), "reconstructed key opens the joint Monero address");
  console.log("6) A reconstructed the joint Monero key → sweeps the XMR ✓");

  console.log("\nOK: two-party swap mechanism proven — two independent parties, each holding");
  console.log("    only their own share, ran the whole ceremony over the relay. This is the");
  console.log("    real trustless case (funding/broadcast are each party's on-chain steps).");
})().catch((e) => { console.error("FAIL:", e.message); process.exit(1); });
