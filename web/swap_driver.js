// Stage 5+ swap driver: the FULL cross-chain atomic choreography in one place,
// composing the Nano adaptor engine (wasm-bridge: BrowserDkg / BrowserSigner /
// presig_*) with the Monero engine (wasm-monero: xmr_spend_pub / xmr_joint_info
// / xmr_joint_secret). Pure JS, runs in a browser and in Node.
//
// Roles (fixed invariant, both directions of the product map onto it):
//   • XMR-seller  locks XMR in the 2-of-2 joint Monero address, and later
//     COMPLETES + broadcasts the Nano claim with its spend secret x (revealing
//     it) to receive its XNO. Its Monero spend key is the adaptor (x, T=x·G).
//   • XNO-seller  funds the 2-of-2 joint Nano account, holds the adaptor
//     PRE-signature on the claim, and the instant the claim is broadcast
//     extracts x and combines it with its own Monero share to SWEEP the XMR.
//
// The atomicity is one secret doing double duty: the value that unlocks the
// XMR-seller's Nano claim IS exactly the Monero share the XNO-seller is missing
// from the joint spend key. This module proves and drives that linkage; it does
// not itself move funds (funding/lock/broadcast/sweep are the caller's on-chain
// steps via beacon.js + XmrNode), it produces every signed artifact they need.

(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.XnoxmrSwap = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const hx = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

  // A swap party. `W` = wasm-bridge module, `X` = wasm-monero module.
  // `moneroSecret` is this party's 32-byte Monero spend secret (canonical
  // scalar). `ctx` is the 32-byte shared swap context.
  class Party {
    constructor(W, X, opts) {
      this.W = W;
      this.X = X;
      this.ctx = opts.ctx;
      this.role = opts.role; // "xmr-seller" | "xno-seller"
      this.moneroSecret = opts.moneroSecret;
      this.moneroPub = X.xmr_spend_pub(this.moneroSecret);
      // view-key halves (both parties contribute; shared view key is derived)
      this.viewHalf = opts.viewHalf;
      this.id = opts.role === "xmr-seller" ? 1 : 2;
      this.peerId = this.id === 1 ? 2 : 1;
    }

    // The joint Monero address, derivable by either party from public data.
    jointMonero(peerMoneroPub, peerViewHalf, network) {
      const a = this.role === "xmr-seller" ? this.moneroPub : peerMoneroPub;
      const b = this.role === "xmr-seller" ? peerMoneroPub : this.moneroPub;
      const va = this.role === "xmr-seller" ? this.viewHalf : peerViewHalf;
      const vb = this.role === "xmr-seller" ? peerViewHalf : this.viewHalf;
      return JSON.parse(this.X.xmr_joint_info(this.ctx, a, b, va, vb, network));
    }
  }

  // Run one full atomic swap between two Party objects over a `swap(aOut,bOut)`
  // duplex (send both, receive both, same shape the ceremony proof uses), with
  // an agreed claim block. Returns the collected real artifacts + a step log.
  // `A` must be the xmr-seller, `B` the xno-seller (matches Party ids 1/2).
  async function runAtomicSwap(A, B, swap, claim, network, log) {
    const W = A.W, X = A.X;
    const say = log || (() => {});
    const out = {};

    // 0. adaptor (x, T) = the XMR-seller's Monero spend key. The XNO-seller is
    //    missing exactly this share of the joint Monero key.
    const x = A.moneroSecret;
    const T = A.moneroPub;
    out.adaptorPoint = hx(T);

    // 1. joint Monero address, both parties compute the identical value.
    const jmA = A.jointMonero(B.moneroPub, B.viewHalf, network);
    const jmB = B.jointMonero(A.moneroPub, A.viewHalf, network);
    if (jmA.address !== jmB.address) throw new Error("joint Monero address mismatch");
    out.jointMoneroAddress = jmA.address;
    say("1) joint Monero address (both agree): " + jmA.address.slice(0, 16) + "…");

    // 2. DKG → the 2-of-2 joint Nano account (each keeps only its own share).
    const dkgA = new W.BrowserDkg(A.id, A.peerId);
    const dkgB = new W.BrowserDkg(B.id, B.peerId);
    {
      const [aR, bR] = await swap(dkgA.round1_out(), dkgB.round1_out());
      dkgA.set_peer_round1(aR); dkgB.set_peer_round1(bR);
      const [aR2, bR2] = await swap(dkgA.round2_out(), dkgB.round2_out());
      const acctA = dkgA.set_peer_round2(aR2), acctB = dkgB.set_peer_round2(bR2);
      if (!eq(acctA, acctB)) throw new Error("joint Nano account mismatch");
      out.jointNanoAccount = hx(acctA);
    }
    const signA = new W.BrowserSigner(dkgA.key_package(), dkgA.public_key_package(), A.id, A.peerId);
    const signB = new W.BrowserSigner(dkgB.key_package(), dkgB.public_key_package(), B.id, B.peerId);
    const account = signA.account();
    if (!eq(account, signB.account())) throw new Error("signers disagree on account");
    say("2) joint Nano account (2-of-2 DKG): " + hx(account).slice(0, 16) + "…");

    // 3. The claim block: the send FROM the joint Nano account that pays the
    //    XMR-seller their XNO. Both parties compute its canonical hash.
    const claimHash = W.state_block_hash(
      hx(account), claim.previous, claim.representative, claim.balance, claim.link, "send");
    if (!claimHash.length) throw new Error("could not hash the claim block");
    out.claimHash = hx(claimHash);
    say("3) claim block hashed (real Nano send from the joint account): " + hx(claimHash).slice(0, 16) + "…");

    // 4. Adaptor PRE-signature on the claim, bound to T. Both co-sign; neither
    //    can finish it alone, and it is not a valid signature by itself.
    const msg = Uint8Array.from(claimHash);
    {
      const [aC, bC] = await swap(signA.presign_commit(msg, T), signB.presign_commit(msg, T));
      signA.set_peer_commit(aC); signB.set_peer_commit(bC);
      const [aS, bS] = await swap(signA.presign_share(), signB.presign_share());
      signA.set_peer_share(aS); signB.set_peer_share(bS);
      var pre = signA.aggregate_presig();
      const preB = signB.aggregate_presig();
      if (!eq(pre, preB)) throw new Error("pre-signatures differ");
      if (!W.presig_verify(pre, account, msg)) throw new Error("pre-signature fails adaptor relation");
      if (W.nano_check(account, msg, Uint8Array.from(pre).subarray(0, 64)))
        throw new Error("pre-signature wrongly valid on its own");
      out.preSignature = hx(pre);
      say("4) adaptor pre-signature on the claim, bound to the XMR key, verifies, invalid alone ✓");
    }

    // 5. XMR-seller COMPLETES the claim with x and (would) broadcast it to take
    //    its XNO. Completing reveals x.
    const claimSig = W.presig_complete(pre, x);
    if (!W.nano_check(account, msg, claimSig)) throw new Error("completed claim signature invalid");
    out.claimSignature = hx(claimSig);
    say("5) XMR-seller completes + broadcasts the Nano claim → takes XNO, revealing x on chain");

    // 6. XNO-seller EXTRACTS x from the public claim signature, and it is
    //    exactly the XMR-seller's Monero share.
    const xOut = W.presig_extract(pre, claimSig);
    if (!eq(xOut, x)) throw new Error("extracted secret ≠ the XMR spend secret");
    say("6) XNO-seller extracts x from the on-chain claim, it IS the missing Monero share ✓");

    // 7. XNO-seller reconstructs the joint Monero spend secret (its own share +
    //    the revealed x) and it opens the joint Monero address → it can sweep.
    const jointSecret = X.xmr_joint_secret(A.ctx, B.moneroSecret, xOut);
    const opensPub = X.xmr_spend_pub(jointSecret);
    if (!eq(opensPub, Uint8Array.from(Buffer0(jmA.spend_pub))))
      throw new Error("reconstructed joint Monero secret does not open the joint address");
    out.jointMoneroSecretOpensAddress = true;
    say("7) reconstructed joint Monero secret opens the joint address, XNO-seller can sweep the XMR ✓");

    return out;
  }

  // hex → Uint8Array (Buffer-free, browser-safe).
  function Buffer0(hexStr) {
    const a = new Uint8Array(hexStr.length / 2);
    for (let i = 0; i < a.length; i++) a[i] = parseInt(hexStr.substr(i * 2, 2), 16);
    return a;
  }

  return { Party, runAtomicSwap, _hx: hx };
});
