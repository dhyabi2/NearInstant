// Funded self-swap orchestrator, runs OUR trustless XNO⇄XMR atomic swap with
// real funds, acting as BOTH parties (maker + taker) from one wallet so a
// single operator can test the whole mechanism on-chain.
//
// Roles: A = XNO-seller (funds the joint Nano account, sweeps the XMR),
//        B = XMR-seller (locks XMR, completes the Nano claim, revealing x).
// The adaptor secret x = B's Monero spend secret; T = x·G. Once B's claim is
// broadcast, x is public and A reconstructs the joint Monero key to sweep.
//
// Every fund-moving broadcast is returned as a prepared, signed artifact for
// the caller to confirm/broadcast, this module never auto-moves value.

(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.XnoxmrFundedSwap = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  const hx = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  const HX = (b) => hx(b).toUpperCase();
  const hb = (h) => { const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; };
  const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

  // A canonical ed25519 scalar (Monero spend secret) from CSPRNG.
  function mScalar(rand) {
    let v = 0n; const b = rand(32);
    for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); v %= L;
    const o = new Uint8Array(32); for (let i = 0; i < 32; i++) { o[i] = Number(v & 0xffn); v >>= 8n; } return o;
  }

  // Derive all swap material: ephemeral Monero keys for both sides, the joint
  // Monero address, and the joint Nano account (real 2-of-2 DKG). `rand(n)`
  // returns n CSPRNG bytes. Returns handles used by the later steps.
  function prepare(wasm, xmr, rand, network) {
    const ctx = rand(32);
    const A_xmr = mScalar(rand);          // XNO-seller's Monero share
    const B_xmr = mScalar(rand);          // XMR-seller's Monero share == adaptor x
    const A_pub = xmr.xmr_spend_pub(A_xmr), B_pub = xmr.xmr_spend_pub(B_xmr);
    const viewA = rand(32), viewB = rand(32);
    const jm = JSON.parse(xmr.xmr_joint_info(ctx, A_pub, B_pub, viewA, viewB, network));

    // Real distributed keygen for the joint Nano account (both halves here).
    const dkgA = new wasm.BrowserDkg(1, 2), dkgB = new wasm.BrowserDkg(2, 1);
    dkgA.set_peer_round1(dkgB.round1_out()); dkgB.set_peer_round1(dkgA.round1_out());
    const acctA = dkgA.set_peer_round2(dkgB.round2_out());
    const acctB = dkgB.set_peer_round2(dkgA.round2_out());
    if (!eq(acctA, acctB)) throw new Error("joint Nano DKG mismatch");
    const signA = new wasm.BrowserSigner(dkgA.key_package(), dkgA.public_key_package(), 1, 2);
    const signB = new wasm.BrowserSigner(dkgB.key_package(), dkgB.public_key_package(), 2, 1);
    const account = signA.account();
    if (!eq(account, signB.account())) throw new Error("signer account mismatch");

    const swap = finalize(wasm, {
      ctx, A_xmr, B_xmr, viewA, viewB, T: B_pub,
      kpA: dkgA.key_package(), pubA: dkgA.public_key_package(),
      kpB: dkgB.key_package(), pubB: dkgB.public_key_package(),
      jointMonero: jm,
    });
    assertTBinding(xmr, swap, network);   // T must match the joint Monero key
    return swap;
  }

  // Rebuild the live handles (and a serialisable snapshot for recovery) from
  // the raw material, used both by prepare() and to restore a persisted swap.
  function finalize(wasm, m) {
    const signA = new wasm.BrowserSigner(m.kpA, m.pubA, 1, 2);
    const signB = new wasm.BrowserSigner(m.kpB, m.pubB, 2, 1);
    const account = signA.account();
    return {
      ctx: m.ctx, A_xmr: m.A_xmr, B_xmr: m.B_xmr, x: m.B_xmr, T: m.T,
      viewA: m.viewA, viewB: m.viewB,
      jointMonero: m.jointMonero,
      jointNanoAccount: hx(account),
      jointNanoAddress: wasm.nano_address_encode(account),
      _account: account, _signA: signA, _signB: signB, _wasm: wasm,
      // A plain object safe to JSON.stringify for recovery.
      snapshot() {
        return {
          ctx: hx(m.ctx), A_xmr: hx(m.A_xmr), B_xmr: hx(m.B_xmr), T: hx(m.T),
          viewA: hx(m.viewA), viewB: hx(m.viewB),
          kpA: hx(m.kpA), pubA: hx(m.pubA), kpB: hx(m.kpB), pubB: hx(m.pubB),
          jointMonero: m.jointMonero,
          jointNanoAddress: wasm.nano_address_encode(account),
        };
      },
    };
  }

  // Rebuild a swap from a snapshot() object (e.g. after a page reload).
  function restore(wasm, snap) {
    return finalize(wasm, {
      ctx: hb(snap.ctx), A_xmr: hb(snap.A_xmr), B_xmr: hb(snap.B_xmr), T: hb(snap.T),
      viewA: hb(snap.viewA), viewB: hb(snap.viewB),
      kpA: hb(snap.kpA), pubA: hb(snap.pubA), kpB: hb(snap.kpB), pubB: hb(snap.pubB),
      jointMonero: snap.jointMonero,
    });
  }

  // T-binding (audit B1). The adaptor point T is the Monero spend-pub whose
  // secret x the claim reveals. It MUST be exactly the spend-pub the joint
  // Monero address commits to — otherwise the revealed x would not reconstruct
  // the joint key, letting the XMR-seller take the XNO while stranding the
  // XMR-buyer's Monero. Recompute the joint address from OUR share's pub and T;
  // a mismatch (a malicious peer key, OR a tampered snapshot) aborts before any
  // funds move. Fail-closed and cheap; safe to run on every settlement.
  function assertTBinding(xmr, s, network) {
    const A_pub = xmr.xmr_spend_pub(s.A_xmr);
    const chk = JSON.parse(xmr.xmr_joint_info(s.ctx, A_pub, s.T, s.viewA, s.viewB, network || "mainnet"));
    if (!s.jointMonero || chk.address !== s.jointMonero.address || chk.spend_pub !== s.jointMonero.spend_pub)
      throw new Error("adaptor T does not match the joint Monero key (T-binding) — refusing to proceed");
  }

  // 2-of-2 FROST joint signature over a 32-byte message (both halves here).
  function jointSign(s, msg) {
    const A = s._signA, B = s._signB;
    A.begin ? A.begin() : 0; B.begin ? B.begin() : 0;
    const aC = A.sign_commit(msg), bC = B.sign_commit(msg);
    A.set_peer_commit(bC); B.set_peer_commit(aC);
    const aS = A.sign_share(), bS = B.sign_share();
    A.set_peer_share(bS); B.set_peer_share(aS);
    const sig = A.aggregate_sig();
    if (!eq(sig, B.aggregate_sig())) throw new Error("joint sig mismatch");
    return sig;
  }

  // 2-of-2 adaptor PRE-signature over `msg`, bound to point T.
  function adaptorPresign(s, msg, T) {
    const A = s._signA, B = s._signB;
    A.begin ? A.begin() : 0; B.begin ? B.begin() : 0;
    const aC = A.presign_commit(msg, T), bC = B.presign_commit(msg, T);
    A.set_peer_commit(bC); B.set_peer_commit(aC);
    const aS = A.presign_share(), bS = B.presign_share();
    A.set_peer_share(bS); B.set_peer_share(aS);
    const pre = A.aggregate_presig();
    if (!eq(pre, B.aggregate_presig())) throw new Error("presig mismatch");
    return pre;
  }

  // Assemble a broadcastable Nano process-block from a joint signature.
  // `workRoot` is the account pubkey for an open block, else the previous hash.
  function nanoProcessJson(wasm, { accountHex, previous, repHex, balance, link, subtype, sig }) {
    const hash = wasm.state_block_hash(accountHex, previous, repHex, balance, link, subtype);
    if (!hash.length) throw new Error("could not hash block");
    const workRoot = subtype === "open" ? accountHex : previous;
    return {
      hashHex: hx(hash),
      workRoot: HX(hb(workRoot)),
      signedJson: JSON.stringify({
        process: {
          action: "process", json_block: "true", subtype,
          block: {
            type: "state",
            account: wasm.nano_address_encode(hb(accountHex)),
            previous: HX(hb(previous)),
            representative: wasm.nano_address_encode(hb(repHex)),
            balance: String(balance),
            link: HX(hb(link)),
            signature: HX(sig),
            work: "WORK",
          },
        },
      }),
    };
  }

  // ---- Two-party mode: the two signers exchange every ceremony message over
  // a MailboxWire relay, each holding ONLY its own share. `M` is the mailbox
  // module; `relay` is any {post,fetch} store (in-page for a solo test, or an
  // HttpRelay for two real browsers). Returns the same handle shape as prepare,
  // plus wire-driven jointSign/adaptorPresign that route over the relay.
  async function prepareTwoPartyWired(wasm, xmr, rand, network, M, relay, shared) {
    const s = prepare(wasm, xmr, rand, network);
    const dA = await M.derive(shared, true), dB = await M.derive(shared, false);
    const wA = new M.MailboxWire([relay], dA.send, dA.recv, dA.key);
    const wB = new M.MailboxWire([relay], dB.send, dB.recv, dB.key);
    wA.pollMs = wB.pollMs = 30; wA.timeoutMs = wB.timeoutMs = 20000;
    s._wA = wA; s._wB = wB;
    s._duplex = async (aOut, bOut) => { await Promise.all([wA.send(aOut), wB.send(bOut)]); return Promise.all([wA.recv(), wB.recv()]); };
    return s;
  }
  async function jointSignWire(s, msg) {
    const A = s._signA, B = s._signB, d = s._duplex;
    const [aC, bC] = await d(A.sign_commit(msg), B.sign_commit(msg));
    A.set_peer_commit(bC); B.set_peer_commit(aC);
    const [aS, bS] = await d(A.sign_share(), B.sign_share());
    A.set_peer_share(bS); B.set_peer_share(aS);
    const sig = A.aggregate_sig();
    if (!eq(sig, B.aggregate_sig())) throw new Error("joint sig mismatch over wire");
    return sig;
  }
  async function adaptorPresignWire(s, msg, T) {
    const A = s._signA, B = s._signB, d = s._duplex;
    const [aC, bC] = await d(A.presign_commit(msg, T), B.presign_commit(msg, T));
    A.set_peer_commit(bC); B.set_peer_commit(aC);
    const [aS, bS] = await d(A.presign_share(), B.presign_share());
    A.set_peer_share(bS); B.set_peer_share(aS);
    const pre = A.aggregate_presig();
    if (!eq(pre, B.aggregate_presig())) throw new Error("presig mismatch over wire");
    return pre;
  }

  return { prepare, restore, jointSign, adaptorPresign, nanoProcessJson, assertTBinding,
    prepareTwoPartyWired, jointSignWire, adaptorPresignWire, _hx: hx, _HX: HX, _hb: hb, _eq: eq };
});
