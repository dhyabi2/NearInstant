// settle_e2e.cjs — PROVE the settlement orchestrator (runA + runB) executes end
// to end, with REAL crypto (DKG, adaptor, joint Monero secret) and a mocked
// in-memory Nano+Monero chain. Both parties run concurrently over the real
// MailboxWire. This is the "prove it once" before autonomous settlement is
// enabled: it exercises the exact drivers the CLI's settleTake() calls.
"use strict";
const crypto = require("crypto");
const M = require("./mailbox.js");
const W = require("../swap-core/wasm-bridge/pkg-node/wasm_bridge.js");
const X = require("../swap-core/wasm-monero/pkg-node/wasm_monero.js");
const TP = require("./two_party.js");

const hx = (b) => Buffer.from(b).toString("hex");
const hb = (h) => Uint8Array.from(Buffer.from(h, "hex"));
const rand = (n) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; };
let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log("  PASS " + m)) : (fail++, console.log("  FAIL " + m)); };

// ---- shared in-memory chains ----------------------------------------------
const MID = 0.00093;                                  // XMR per XNO
const XMR_TIP = 3_000_000;
function makeChains() {
  const nano = { rcv: {}, acct: {}, blk: {} };        // receivables, account frontier, blocks by hash
  const xmr = { outs: [] };
  const decode = (a) => hx(W.nano_address_decode(a));
  function hashOf(signedJson) {
    const j = JSON.parse(signedJson).process, b = j.block;
    return hx(W.state_block_hash(decode(b.account), b.previous.toLowerCase(), decode(b.representative),
      b.balance, b.link.toLowerCase(), j.subtype)).toLowerCase();
  }
  const rpc = async (_urls, req) => {
    if (req.action === "receivable") return { blocks: nano.rcv[req.account] || {} };
    if (req.action === "account_info") { const a = nano.acct[req.account]; return a ? { frontier: a.frontier, balance: a.balance } : { error: "not found" }; }
    if (req.action === "blocks_info") { const out = {}; for (const h of req.hashes) if (nano.blk[h]) out[h] = { contents: { signature: nano.blk[h].signature } }; return { blocks: out }; }
    if (req.action === "block_info") return nano.blk[String(req.hash).toLowerCase()] ? { confirmed: "true" } : { error: "unknown" };
    if (req.action === "block_count") return { count: "1" };
    return {};
  };
  const beaconOf = (addrOf) => ({
    THRESH: { send: 0n, receive: 0n },
    accountInfo: async (_u, addr) => { const a = nano.acct[addr]; return a ? { frontier: a.frontier, balance: a.balance, representative: null } : null; },
    _internals: {
      rpc, generateWork: async () => "WORK",
      processBlock: async (_u, signedJson) => {
        const j = JSON.parse(signedJson).process, b = j.block;
        const h = hashOf(signedJson);
        nano.acct[b.account] = { frontier: h, balance: b.balance };
        nano.blk[h] = { signature: b.signature.toLowerCase() };
        return h;
      },
    },
  });
  // Monero node mock: height + scan for a spend_pub, + sweep/publish.
  const xmrNode = {
    height: async () => XMR_TIP,
    scan_all: async (spendPub, _view, from, to) => {
      const sp = hx(spendPub);
      return JSON.stringify(xmr.outs.filter(o => o.spend_pub === sp && o.block >= from && o.block <= to)
        .map(o => ({ block: o.block, amount: o.amount, index: o.index, output: o.output })));
    },
    sweep_sign: async () => JSON.stringify({ tx: "5357454550", tx_hash: hx(rand(32)) }),
    publish: async () => hx(rand(32)),
  };
  const xmrMod = { XmrNode: { connect: async () => xmrNode }, xmr_joint_secret: X.xmr_joint_secret, xmr_spend_pub: X.xmr_spend_pub };
  return { nano, xmr, beaconOf, xmrMod, xmrNode };
}

(async () => {
  console.log("Full two-party settlement over the real ceremony + mocked chain\n");

  // wires
  const store = new Map();
  const relay = { async post(m, s, b) { store.set(m + "/" + s, b); return true; }, async fetch(m, s) { return store.get(m + "/" + s) || null; } };
  const shared = rand(32);
  const da = await M.derive(shared, true), db = await M.derive(shared, false);
  const wa = new M.MailboxWire([relay], da.send, da.recv, da.key);
  const wb = new M.MailboxWire([relay], db.send, db.recv, db.key);
  wa.pollMs = wb.pollMs = 20; wa.timeoutMs = wb.timeoutMs = 90000;

  // wallet accounts (valid Nano keys) for the claim/refund destinations
  const seedA = JSON.parse(W.gen_identity()).seed, seedB = JSON.parse(W.gen_identity()).seed;
  const acctAHex = JSON.parse(W.seed_account(seedA)).pubkey;
  const acctBHex = JSON.parse(W.seed_account(seedB)).pubkey;

  // a certified-win deal: B (maker, sells XMR, side 1) posts price 0.8% below mid
  const priceE9 = Math.round(MID * 0.992 * 1e9);
  const xnoRaw = (50n * 10n ** 30n).toString();
  const deal = { offerHash: "cafe".repeat(16), side: 1, priceE9: String(priceE9),
    xnoRaw, xmrAtomic: ((BigInt(xnoRaw) * BigInt(priceE9) * 1000n) / (10n ** 30n)).toString() };

  // ceremony: A = XNO-seller (roleIsA true), B = XMR-seller (false)
  const [pA, pB] = await Promise.all([
    TP.ceremony(W, X, rand, "mainnet", wa, true, deal, () => {}, acctAHex),
    TP.ceremony(W, X, rand, "mainnet", wb, false, deal, () => {}, acctBHex),
  ]);
  ok(pA.jointNanoAccount === pB.jointNanoAccount, "both derived the same joint Nano account");
  ok(pA.jointMonero.address === pB.jointMonero.address, "both derived the same joint Monero address");

  const chains = makeChains();
  const price = async () => ({ ok: true, mid: MID, sources: 2, at: Date.now() });

  // A's wallet: funds the joint Nano (creates a receivable), plus xmr address.
  const walletA = {
    account: () => hx(pA._account),
    send: async (addr, _amt) => { const sh = hx(rand(32)); chains.nano.rcv[addr] = { [sh]: { amount: deal.xnoRaw } }; return sh; },
    receive: async () => {}, xmrAddress: async () => pA.jointMonero.address,
    xmrSend: async () => { throw new Error("A must not lock XMR"); },
  };
  // B's wallet: locks XMR into the joint address (adds a Monero output).
  const walletB = {
    account: () => hx(pB._account),
    send: async () => { throw new Error("B must not fund XNO"); }, receive: async () => {},
    xmrAddress: async () => acctBHex,
    xmrSend: async (addr, _amt) => {
      chains.xmr.outs.push({ spend_pub: hx(hb(pB.jointMonero.spend_pub)), view_key: pB.jointMonero.view_key,
        amount: deal.xmrAtomic, block: XMR_TIP - 30, index: "1", output: hx(rand(64)) });
      return { tx_hash: hx(rand(32)) };
    },
  };
  const mkStore = () => { const m = new Map(); return { get: k => m.has(k) ? m.get(k) : null, set: (k, v) => m.set(k, v) }; };
  const depsFor = (party, wallet) => { const st = mkStore();
    st.set("acceptCert", TP.certify(deal, party.roleIsA, { ok: true, mid: MID, sources: 2, at: Date.now() }, { minBps: -1e9, feeAtomic: "0" }));
    return { wasm: W, xmr: chains.xmrMod, beacon: chains.beaconOf(), urls: ["mock"], walletApi: wallet,
      moneroPost: async () => new Uint8Array(), note: () => {}, store: st, price,
      feeAtomic: "0", maxUnrealizedLossBps: 50, maxStress: 2, lockWaitMs: 20000 };
  };

  console.log("\nrunning runA (XNO-seller) and runB (XMR-seller) concurrently…");
  const [rA, rB] = await Promise.all([ TP.runA(depsFor(pA, walletA), pA), TP.runB(depsFor(pB, walletB), pB) ]);

  ok(rB && rB.done && !rB.declined && !rB.refunded, "B settled: locked XMR, claimed the XNO (reveals x)");
  ok(rA && rA.done && !rA.refunded, "A settled: funded XNO, extracted x, swept the XMR");
  ok(rB.realized && rB.realized.role === "B", "B recorded realised result from the chain");
  ok(rA.realized && rA.realized.role === "A", "A recorded realised result from the chain");

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 0 + (fail && 1) : 0);
})().catch(e => { console.log("HARNESS ERROR:", e.message, "\n", e.stack); process.exit(1); });
