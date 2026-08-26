// Stage-3 proof: the REAL 2-of-2 FROST signing + adaptor pre-signature ceremony
// driven entirely from JavaScript by two independent parties, each holding ONLY
// its own key share, talking over the browser MailboxWire (web/mailbox.js) + a
// shared dumb relay. This is the cryptographic core of a helper-free browser
// swap: joint account (DKG) → joint block signature → adaptor pre-signature
// bound to the counterparty's secret → completion → secret extraction.
//
//   node web/swap_ceremony_over_mailbox.cjs
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
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

const eq = (a, b) => Buffer.from(a).equals(Buffer.from(b));
function assert(cond, msg) { if (!cond) { console.error("FAIL:", msg); process.exit(1); } }

(async () => {
  const shared = new Uint8Array(32);
  crypto.randomFillSync(shared);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "swap-mb-"));
  const relay = FileRelay(dir);

  const a = await M.derive(shared, true);
  const b = await M.derive(shared, false);
  const wireA = new M.MailboxWire([relay], a.send, a.recv, a.key);
  const wireB = new M.MailboxWire([relay], b.send, b.recv, b.key);
  for (const w of [wireA, wireB]) { w.pollMs = 5; w.timeoutMs = 8000; }

  // One send+recv both ways. aRecv = what A received (B's blob), and vice versa.
  const swap = async (aOut, bOut) => {
    await Promise.all([wireA.send(aOut), wireB.send(bOut)]);
    return Promise.all([wireA.recv(), wireB.recv()]);
  };

  // ---- 1. DKG: two browsers derive the identical joint account -------------
  const dkgA = new wasm.BrowserDkg(1, 2);
  const dkgB = new wasm.BrowserDkg(2, 1);
  {
    const [aR, bR] = await swap(dkgA.round1_out(), dkgB.round1_out());
    dkgA.set_peer_round1(aR); dkgB.set_peer_round1(bR);
    const [aR2, bR2] = await swap(dkgA.round2_out(), dkgB.round2_out());
    const acctA = Buffer.from(dkgA.set_peer_round2(aR2)).toString("hex");
    const acctB = Buffer.from(dkgB.set_peer_round2(bR2)).toString("hex");
    assert(acctA === acctB && acctA.length === 64, "DKG joint account mismatch");
    console.log("1) DKG        → joint account", acctA.slice(0, 16) + "…");
  }

  // Seed each party's signer from its OWN share only.
  const signA = new wasm.BrowserSigner(dkgA.key_package(), dkgA.public_key_package(), 1, 2);
  const signB = new wasm.BrowserSigner(dkgB.key_package(), dkgB.public_key_package(), 2, 1);
  const account = Buffer.from(signA.account());
  assert(eq(account, signB.account()), "signers disagree on account");

  // ---- 2. Joint plain signature over a 32-byte message ---------------------
  const msg = new Uint8Array(32); crypto.randomFillSync(msg);
  {
    const [aC, bC] = await swap(signA.sign_commit(msg), signB.sign_commit(msg));
    signA.set_peer_commit(aC); signB.set_peer_commit(bC);
    const [aS, bS] = await swap(signA.sign_share(), signB.sign_share());
    signA.set_peer_share(aS); signB.set_peer_share(bS);
    const sigA = signA.aggregate_sig(), sigB = signB.aggregate_sig();
    assert(eq(sigA, sigB), "joint signatures differ");
    assert(wasm.nano_check(account, msg, sigA), "joint signature is not a valid Nano signature");
    console.log("2) FROST sign → identical 64-byte Nano signature, verifies ✓");
  }

  // ---- 3. Adaptor pre-signature bound to x, completed, x extracted ---------
  {
    const adaptor = Buffer.from(wasm.gen_adaptor());       // 32-byte x ‖ 32-byte T
    const x = adaptor.subarray(0, 32), T = adaptor.subarray(32);
    const msg2 = new Uint8Array(32); crypto.randomFillSync(msg2);

    const [aC, bC] = await swap(signA.presign_commit(msg2, T), signB.presign_commit(msg2, T));
    signA.set_peer_commit(aC); signB.set_peer_commit(bC);
    const [aS, bS] = await swap(signA.presign_share(), signB.presign_share());
    signA.set_peer_share(aS); signB.set_peer_share(bS);
    const preA = Buffer.from(signA.aggregate_presig());
    const preB = Buffer.from(signB.aggregate_presig());
    assert(eq(preA, preB), "pre-signatures differ");
    assert(wasm.presig_verify(preA, account, msg2), "pre-signature fails adaptor relation");

    // The pre-signature must NOT verify as a Nano signature on its own.
    const alone = Buffer.concat([preA.subarray(0, 32), preA.subarray(32, 64)]);
    assert(!wasm.nano_check(account, msg2, alone), "pre-signature wrongly valid on its own");

    // Complete with x → valid signature; broadcasting it reveals x.
    const claimSig = Buffer.from(wasm.presig_complete(preA, x));
    assert(wasm.nano_check(account, msg2, claimSig), "completed signature invalid");
    const xOut = Buffer.from(wasm.presig_extract(preA, claimSig));
    assert(eq(xOut, x), "extracted secret ≠ x");
    console.log("3) adaptor    → pre-sig verifies, invalid alone, completes, x recovered ✓");
  }

  fs.rmSync(dir, { recursive: true, force: true });
  console.log("\nPASS: full 2-of-2 signing + adaptor ceremony ran in-browser (JS) over the MailboxWire,");
  console.log("      each party holding only its own share — no helper, no trusted dealer.");
})().catch(e => { console.error("ERR", e); process.exit(1); });
