// Stage-2 proof: the REAL FROST 2-of-2 DKG (WASM) driven by two parties over
// the browser MailboxWire (web/mailbox.js) + a shared dumb relay — both derive
// the identical joint account, with all async I/O in JS. This is the pattern a
// browser uses to run the swap ceremony with no helper and no fixed relay.
//
//   node web/dkg_over_mailbox.cjs
const fs = require("fs");
const os = require("os");
const path = require("path");
const M = require("./mailbox.js");
const wasm = require("../swap-core/wasm-bridge/pkg-node/wasm_bridge.js");

function FileRelay(dir) {
  return {
    async post(m, s, b) {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, `${m}_${s}.bin`), Buffer.from(b));
      return true;
    },
    async fetch(m, s) {
      const p = path.join(dir, `${m}_${s}.bin`);
      if (!fs.existsSync(p)) return null;
      return new Uint8Array(fs.readFileSync(p));
    },
  };
}

(async () => {
  const shared = new Uint8Array(32);
  require("crypto").randomFillSync(shared); // the per-swap rendezvous seed
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dkg-mb-"));
  const relay = FileRelay(dir);

  // Two independent parties, each with its own WASM DKG state + mailbox wire.
  const a = await M.derive(shared, true);   // initiator
  const b = await M.derive(shared, false);  // responder
  const wireA = new M.MailboxWire([relay], a.send, a.recv, a.key);
  const wireB = new M.MailboxWire([relay], b.send, b.recv, b.key);
  wireA.pollMs = 5; wireB.pollMs = 5; wireA.timeoutMs = 5000; wireB.timeoutMs = 5000;

  const dkgA = new wasm.BrowserDkg(1, 2);
  const dkgB = new wasm.BrowserDkg(2, 1);

  // Round 1: both send, both receive.
  await Promise.all([wireA.send(dkgA.round1_out()), wireB.send(dkgB.round1_out())]);
  // aRecv1 = what A received (B's package); bRecv1 = what B received (A's).
  const [aRecv1, bRecv1] = await Promise.all([wireA.recv(), wireB.recv()]);
  dkgA.set_peer_round1(aRecv1);
  dkgB.set_peer_round1(bRecv1);

  // Round 2: both send, both receive; finish.
  await Promise.all([wireA.send(dkgA.round2_out()), wireB.send(dkgB.round2_out())]);
  const [aRecv2, bRecv2] = await Promise.all([wireA.recv(), wireB.recv()]);
  const accountA = Buffer.from(dkgA.set_peer_round2(aRecv2)).toString("hex");
  const accountB = Buffer.from(dkgB.set_peer_round2(bRecv2)).toString("hex");

  fs.rmSync(dir, { recursive: true, force: true });
  if (accountA === accountB && accountA.length === 64) {
    console.log("PASS: real FROST DKG over browser MailboxWire →", accountA);
    console.log("=== both browser parties derived the identical joint account ===");
  } else {
    console.error("FAIL:", accountA, "!=", accountB);
    process.exit(1);
  }
})().catch(e => { console.error("ERR", e); process.exit(1); });
