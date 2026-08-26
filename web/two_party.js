// two_party.js — REAL two-party swap: two strangers' browsers, each holding
// ONLY its own key material, settle an XNO⇄XMR atomic swap against each other.
//
// Roles (fixed by the adaptor invariant):
//   A = XNO-seller: funds the joint Nano account, verifies the XMR lock,
//       delivers the adaptor pre-signature, extracts x from B's broadcast
//       claim, sweeps the XMR.
//   B = XMR-seller: locks XMR into the joint address, co-signs, completes the
//       claim with x (revealing it on-chain), receives the XNO.
// An offer's side decides who is who: side 1 (maker sells XMR) → maker=B,
// taker=A; side 0 → maker=A, taker=B.
//
// Matchmaking is serverless: the rendezvous mailbox is derived from the offer's
// beacon block hash; the taker posts a take-request there (via the ledger
// relay), the maker replies, both run WebCrypto ECDH (P-256) and derive the
// private MailboxWire for the ceremony. A man-in-the-middle who wins the race
// simply BECOMES the counterparty — atomicity and the price bound in the deal
// protect funds either way, so the rendezvous needs no prior trust.
//
// This module holds ceremony + signing + settlement logic; every fund-moving
// broadcast goes through the deps the page injects (walletApi / beacon), and
// each completed step is persisted before the next (crash-safe resume), the
// same discipline as the proven self-swap driver.
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.XnoxmrTwoParty = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const te = new TextEncoder();
  const hx = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  const hb = (h) => { const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; };
  const eq = (a, b) => a && b && a.length === b.length && a.every((v, i) => v === b[i]);
  const jsonBytes = (o) => te.encode(JSON.stringify(o));
  const bytesJson = (b) => JSON.parse(new TextDecoder().decode(b));
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  function mScalar(rand) {
    let v = 0n; const b = rand(32);
    for (let i = 31; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); v %= L;
    const o = new Uint8Array(32); for (let i = 0; i < 32; i++) { o[i] = Number(v & 0xffn); v >>= 8n; } return o;
  }

  // ---------- amounts: bind the DEAL to the posted offer ----------
  // xnoRaw: raw Nano units (1 XNO = 1e30). xmrAtomic: piconero (1 XMR = 1e12).
  // xmrAtomic = xno * price(XMR/XNO) → xnoRaw * price_e9 * 1e3 / 1e30.
  function dealFromOffer(offer, xnoRawStr) {
    const xnoRaw = BigInt(xnoRawStr);
    if (xnoRaw <= 0n) throw new Error("amount must be positive");
    const priceE9 = BigInt(offer.intent.price_e9);
    const xmrAtomic = (xnoRaw * priceE9 * 1000n) / (10n ** 30n);
    if (xmrAtomic <= 0n) throw new Error("amount too small for this price");
    return { offerHash: offer.blockHash, side: offer.intent.side, priceE9: priceE9.toString(), xnoRaw: xnoRaw.toString(), xmrAtomic: xmrAtomic.toString() };
  }
  // The maker re-derives and checks the deal against ITS posted offer — the
  // price/size a taker sends is never trusted.
  function makerValidateDeal(deal, myIntent, maxXnoRaw) {
    if (String(deal.priceE9) !== String(myIntent.price_e9)) throw new Error("deal price does not match my posted offer");
    if (BigInt(deal.xnoRaw) > BigInt(maxXnoRaw)) throw new Error("deal size exceeds my offer");
    const expect = (BigInt(deal.xnoRaw) * BigInt(deal.priceE9) * 1000n) / (10n ** 30n);
    if (expect.toString() !== String(deal.xmrAtomic)) throw new Error("deal amounts inconsistent");
    return true;
  }

  // ---------- profit certification ----------
  // "Verified profit before execution" has to mean something specific in a
  // protocol with a 25-40 minute settlement, so it is defined once here and
  // used at EVERY point where a party is about to do something it cannot undo:
  //   1. the maker accepting a take   (makerPollTake, via `certify`)
  //   2. B before locking its Monero  (runB, via gateOrAbort)
  //   3. A before pre-signing the claim (runA, via gateOrAbort -> refund)
  // plus continuous re-checks while waiting (coOpen for B, waitJointXmrLock
  // for A), which are the only windows where backing out is free.
  //
  // A certificate is a plain record of what was known at decision time: the
  // mid, how fresh it was, how many sources agreed, the fee assumed, and the
  // resulting net. It is persisted so realised results can be audited against
  // it later instead of against a hope.
  const XMR_TX_FEE_ATOMIC_DEFAULT = 200000000n;     // 0.0002 XMR, conservative
  const MID_MAX_AGE_MS_DEFAULT = 60 * 1000;

  // Value a deal from ONE party's side at a mid (XMR per XNO). A always sells
  // XNO and receives XMR; B always sells XMR and receives XNO. Amounts are
  // integers end to end: xnoRaw (1e30/XNO), xmrAtomic (1e12/XMR).
  function partyProfit(deal, roleIsA, midXmrPerXno, feeAtomic) {
    const xnoRaw = BigInt(deal.xnoRaw), xmrAtomic = BigInt(deal.xmrAtomic);
    const fee = feeAtomic == null ? XMR_TX_FEE_ATOMIC_DEFAULT : BigInt(feeAtomic);
    // XNO leg valued in piconero at mid: xnoRaw/1e30 * mid * 1e12 = xnoRaw*mid/1e18
    const midE18 = BigInt(Math.round(midXmrPerXno * 1e18));
    const xnoValueAtomic = (xnoRaw * midE18) / (10n ** 36n);
    const gross = roleIsA ? (xmrAtomic - xnoValueAtomic) : (xnoValueAtomic - xmrAtomic);
    const outlay = roleIsA ? xnoValueAtomic : xmrAtomic;
    const net = gross - fee;
    const netBps = outlay > 0n ? Number((net * 10000n) / outlay) : 0;
    return { grossAtomic: gross.toString(), feeAtomic: fee.toString(), netAtomic: net.toString(),
             outlayAtomic: outlay.toString(), netBps, xnoValueAtomic: xnoValueAtomic.toString() };
  }
  // Smallest fill (in XNO raw) at which THIS price is still a certified win
  // for the given role, after the fixed Monero fee. The fee does not scale
  // with size, so below some size every price is a loss; that size is what a
  // taker must be told, and what an accept gate will refuse under.
  function minViableXnoRaw(priceE9, roleIsA, mid, feeAtomic, minBps) {
    const mk = (xnoRaw) => { const r = BigInt(xnoRaw); return { xnoRaw: r.toString(), priceE9: String(priceE9),
      xmrAtomic: ((r * BigInt(priceE9) * 1000n) / (10n ** 30n)).toString() }; };
    const wins = (xnoRaw) => partyProfit(mk(xnoRaw), roleIsA, mid, feeAtomic).netBps >= (minBps || 0);
    let hi = 10n ** 30n * 1000n;                 // 1000 XNO: if even this loses, the price itself is a loss
    if (!wins(hi)) return null;
    let lo = 0n;
    for (let i = 0; i < 60 && hi - lo > 10n ** 24n; i++) {   // to 1e-6 XNO
      const m = (lo + hi) / 2n; if (wins(m)) hi = m; else lo = m;
    }
    return hi.toString();
  }
  // The maker's side of a deal follows the offer side: side 1 = maker sells XMR (B).
  function makerProfit(deal, side, mid, feeAtomic) { return partyProfit(deal, side === 0, mid, feeAtomic); }

  // Build a certificate. `price` is {ok, mid, sources, at, reason?} from the
  // caller's oracle. Fails closed on anything it cannot vouch for.
  function certify(deal, roleIsA, price, opts) {
    opts = opts || {};
    const now = opts.now || Date.now();
    const minBps = opts.minBps == null ? 0 : opts.minBps;
    const base = { at: now, roleIsA, minBps, deal: { xnoRaw: String(deal.xnoRaw), xmrAtomic: String(deal.xmrAtomic), priceE9: String(deal.priceE9) } };
    if (!price || !price.ok) return Object.assign(base, { ok: false, reason: "no trustworthy price: " + ((price && price.reason) || "unavailable") });
    if (!(price.sources >= 2)) return Object.assign(base, { ok: false, reason: "need >=2 agreeing price sources, have " + (price.sources || 0) });
    const ageMs = price.at ? Math.max(0, now - price.at) : 0;
    const maxAge = opts.maxAgeMs == null ? MID_MAX_AGE_MS_DEFAULT : opts.maxAgeMs;
    if (ageMs > maxAge) return Object.assign(base, { ok: false, reason: "price is " + Math.round(ageMs / 1000) + "s old (limit " + Math.round(maxAge / 1000) + "s)" });
    const pr = partyProfit(deal, roleIsA, price.mid, opts.feeAtomic);
    const out = Object.assign(base, pr, { mid: price.mid, sources: price.sources, ageMs, stress: price.stress || 1 });
    // ACTIVE MONITORING, not a snapshot. `price.stress` comes from the oracle's
    // pump/dump guards (a jump vs the recent median, velocity over 10 min, or
    // drift over 30 min). A market that is MOVING is not certifiable for an
    // irreversible step even if its current level still shows a win: by the
    // time the step lands, the level has moved.
    const maxStress = opts.maxStress == null ? 2 : opts.maxStress;
    if (out.stress >= maxStress) {
      return Object.assign(out, { ok: false, reason: "market is moving too fast to certify (" + (price.stressWhy || ("stress " + out.stress)) + ")" });
    }
    // UNREALISED P&L. Once a deal is accepted its value keeps moving with the
    // mid until settlement lands. `baseline` is the certificate the deal was
    // accepted on; the difference is the unrealised gain or loss right now.
    // A deal that has bled more than the allowed amount since acceptance is
    // refused even if it is still marginally positive - the trend is the
    // information, and it is pointing the wrong way.
    if (opts.baseline && opts.baseline.netAtomic != null && opts.baseline.mid) {
      const unreal = BigInt(pr.netAtomic) - BigInt(opts.baseline.netAtomic);
      const outlay = BigInt(pr.outlayAtomic || "0");
      out.baselineMid = opts.baseline.mid;
      out.midDriftPct = +(((price.mid - opts.baseline.mid) / opts.baseline.mid) * 100).toFixed(4);
      out.unrealizedAtomic = unreal.toString();
      out.unrealizedBps = outlay > 0n ? Number((unreal * 10000n) / outlay) : 0;
      const maxLoss = opts.maxUnrealizedLossBps == null ? 50 : opts.maxUnrealizedLossBps;
      if (out.unrealizedBps < -maxLoss) {
        return Object.assign(out, { ok: false, reason: "unrealised loss of " + (-out.unrealizedBps) + " bps since acceptance exceeds the " + maxLoss + " bps limit (mid moved " + out.midDriftPct + "%)" });
      }
    }
    const ok = pr.netBps >= minBps;
    return Object.assign(out, { ok, reason: ok ? null : ("net " + pr.netBps + " bps is below the " + minBps + " bps required") });
  }

  // Re-certify right before an irreversible step. Returns the certificate;
  // `ok:false` means DO NOT PROCEED. "Certified win" is the only pass: a step
  // that cannot be verified is refused, never waved through. No oracle, no
  // action.
  async function gate(deps, party, label, minBps) {
    if (!deps.price) {
      const c = { ok: false, unverified: true, reason: "no price oracle supplied - cannot certify " + label, label, at: Date.now() };
      if (deps.note) deps.note(label + ": REFUSED - " + c.reason);
      return c;
    }
    let price;
    try { price = await deps.price(); } catch (e) { price = { ok: false, reason: String(e && e.message || e) }; }
    // The certificate the deal was ACCEPTED on is the baseline. A swap has ONE
    // price, and the two parties sit on opposite sides of it: the taker pays
    // the maker's spread, so the taker's net-vs-mid is NEGATIVE by design. A
    // pre-irreversible gate therefore must NOT re-demand an absolute win (that
    // would abort every taker) — it must only confirm the deal has not moved
    // materially WORSE than when it was accepted. So the absolute floor is
    // disabled here; safety comes from the unrealised-loss-vs-baseline, stress,
    // freshness and source-count checks inside certify(). Without a baseline we
    // cannot mark to market, so we fail closed.
    const baseline = deps.store ? (deps.store.get("acceptCert") || null) : null;
    if (!baseline) {
      const c = { ok: false, reason: "no accept certificate to check the market against", label, at: Date.now() };
      if (deps.note) deps.note(label + ": REFUSED - " + c.reason);
      if (deps.store) { const log = deps.store.get("certs") || []; log.push(c); deps.store.set("certs", log.slice(-40)); }
      return c;
    }
    const threshold = minBps != null ? minBps : -1e9;   // no absolute-win floor at the gate
    const cert = certify(party.deal, party.roleIsA, price, {
      minBps: threshold, feeAtomic: deps.feeAtomic, baseline,
      maxUnrealizedLossBps: deps.maxUnrealizedLossBps, maxStress: deps.maxStress });
    cert.label = label;
    if (deps.store) { const log = deps.store.get("certs") || []; log.push(cert); deps.store.set("certs", log.slice(-40)); }
    if (deps.note) deps.note(cert.ok
      ? label + ": verified, net " + cert.netBps + " bps at mid " + Number(cert.mid).toFixed(9)
        + (cert.unrealizedBps != null ? " (unrealised " + (cert.unrealizedBps >= 0 ? "+" : "") + cert.unrealizedBps + " bps since accept)" : "")
      : label + ": REFUSED - " + cert.reason);
    return cert;
  }

  // ---------- rendezvous: take-request over a PUBLIC relay box ----------
  const rvBox = (offerHash) => "take-v1:" + String(offerHash).toLowerCase();
  const rvRespBox = (offerHash) => "resp-v1:" + String(offerHash).toLowerCase();

  async function ecdhMake() {
    const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    return { kp, pub };
  }
  async function ecdhShared(myKp, theirPubRaw) {
    const theirKey = await crypto.subtle.importKey("raw", theirPubRaw, { name: "ECDH", namedCurve: "P-256" }, false, []);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: theirKey }, myKp.privateKey, 256));
  }

  // Taker: post a take-request for the offer; wait for the maker's reply; return
  // the private duplex wire (taker = initiator). relay: post/fetch (LedgerRelay).
  // The rendezvous box is PUBLIC and unauthenticated, and both sides used to
  // use slot 0 only. Anyone could park junk in slot 0 of any live offer: the
  // maker's validation threw, the maker retired and re-posted the offer (a Nano
  // send + PoW), and the squatter refilled slot 0 — a free, permanent DoS on any
  // maker, for the cost of one relay write. Both sides now walk a small window
  // of slots and pair request/response on the SAME slot, so junk in one slot
  // cannot hide an honest take-request behind it.
  const RV_SLOTS = 8;

  async function takerHandshake(M, relay, offer, deal, onProgress) {
    const { kp, pub } = await ecdhMake();
    if (onProgress) onProgress("posting take-request to the offer's rendezvous…");
    // Take the first free slot; a racing taker just loses the maker's pick.
    let slot = -1;
    for (let i = 0; i < RV_SLOTS; i++) {
      if (!(await relay.fetch(rvBox(offer.blockHash), i))) { slot = i; break; }
    }
    if (slot < 0) throw new Error("this offer's rendezvous is full — try another offer");
    await relay.post(rvBox(offer.blockHash), slot, jsonBytes({ v: 1, pub: hx(pub), deal }));
    if (onProgress) onProgress("waiting for the maker to accept… the maker must be online and accepting (times out in 10 min)");
    let resp = null;
    const deadline = Date.now() + 10 * 60 * 1000, start = Date.now();
    while (!resp && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 4000));
      resp = await relay.fetch(rvRespBox(offer.blockHash), slot);
      if (!resp && onProgress) onProgress("still waiting for the maker to accept… " + Math.round((Date.now() - start) / 1000) + "s (a maker must be running its accept loop — Smart Offer, or an agent with autosettle on)");
    }
    if (!resp) throw new Error("no maker accepted within 10 min — nobody was online accepting this offer. Both sides must be live at once: take an offer whose maker is actively running, or run the maker (Smart Offer) yourself on the other side.");
    const rj = bytesJson(resp);
    // A typed decline: the maker read our request and refused it (usually
    // because it is no longer a certified win for them). Fail in seconds, not
    // after a ten-minute timeout. It is only a message - a forged one can waste
    // a retry, never move funds.
    if (rj.decline) { const e = new Error("maker declined: " + String(rj.decline).slice(0, 200)); e.declined = true; throw e; }
    if (!rj.pub) throw new Error("maker reply was malformed");
    const shared = await ecdhShared(kp, hb(rj.pub));
    const d = await M.derive(shared, true);
    // `shared` is returned so a headless session can PERSIST it and rebuild the
    // wire after a crash: the AES key inside the wire is non-extractable, so
    // without the shared secret a restarted process could never talk to its
    // peer again. Only the two parties can know it; store it like a seed.
    return { wire: new M.MailboxWire([relay], d.send, d.recv, d.key), makerPub: rj.pub, shared: hx(shared), slot };
  }

  // Maker: check the rendezvous for a take-request on my live offer. If one is
  // there, validate the deal, reply with my ECDH pub, return the wire (maker =
  // responder) + the validated deal. Returns null when nobody has taken it.
  // `certifyFn` (optional): async (deal) -> certificate. When supplied, a take
  // that matches our posted price but is NO LONGER PROFITABLE at the current
  // market is declined before we reply - the posted price may be minutes old.
  // A decline is reported as {declined: reason} so the caller reprices instead
  // of treating it as junk.
  async function makerPollTake(M, relay, offerHash, myIntent, maxXnoRaw, certifyFn) {
    let sawJunk = false, declined = null;
    for (let slot = 0; slot < RV_SLOTS; slot++) {
      const req = await relay.fetch(rvBox(offerHash), slot);
      if (!req) continue;
      let rj;
      // A malformed or invalid request is SKIPPED, not fatal: it is just one
      // squatted slot, and an honest taker may be sitting in the next one.
      try {
        rj = bytesJson(req);
        makerValidateDeal(rj.deal, myIntent, maxXnoRaw);
      } catch (e) { sawJunk = true; continue; }
      if (certifyFn) {
        let cert = null;
        try { cert = await certifyFn(rj.deal); } catch (e) { cert = { ok: false, reason: String(e && e.message || e) }; }
        if (!cert || !cert.ok) {
          declined = (cert && cert.reason) || "not certified";
          // Tell the taker now, on their own slot, so they stop waiting.
          try { await postDecline(relay, offerHash, slot, declined); } catch (e) {}
          continue;
        }
        rj.cert = cert;
      }
      const { kp, pub } = await ecdhMake();
      await relay.post(rvRespBox(offerHash), slot, jsonBytes({ v: 1, pub: hx(pub) }));
      const shared = await ecdhShared(kp, hb(rj.pub));
      const d = await M.derive(shared, false);
      return { wire: new M.MailboxWire([relay], d.send, d.recv, d.key), deal: rj.deal, cert: rj.cert || null, shared: hx(shared), slot };
    }
    // A valid take we refused on price outranks junk: our quote is stale.
    if (declined) return { declined };
    // Every slot empty or junk. Signal junk so the caller can rate-limit its
    // response instead of re-posting the offer on every single tick.
    return sawJunk ? { junk: true } : null;
  }

  // Maker: post a typed decline into the taker's response slot.
  async function postDecline(relay, offerHash, slot, reason) {
    return relay.post(rvRespBox(offerHash), slot, jsonBytes({ v: 1, decline: String(reason || "declined").slice(0, 200) }));
  }

  // Maker, READ-ONLY: list every take-request on my offer with its certificate,
  // WITHOUT replying. Replying is a commitment (it starts the handshake), and an
  // unattended agent that cannot settle must never make it. This is how such an
  // agent detects demand, certifies it, and hands off or declines. Returns
  // [{slot, deal, valid, cert, reason}]. Never throws on bad slots.
  async function peekTakes(relay, offerHash, myIntent, maxXnoRaw, certifyFn) {
    const outList = [];
    for (let slot = 0; slot < RV_SLOTS; slot++) {
      let req; try { req = await relay.fetch(rvBox(offerHash), slot); } catch (e) { continue; }
      if (!req) continue;
      let answered = null; try { answered = await relay.fetch(rvRespBox(offerHash), slot); } catch (e) {}
      const row = { slot, answered: !!answered };
      try {
        const rj = bytesJson(req);
        makerValidateDeal(rj.deal, myIntent, maxXnoRaw);
        row.deal = rj.deal; row.valid = true;
        if (certifyFn) { try { row.cert = await certifyFn(rj.deal); } catch (e) { row.cert = { ok: false, reason: String(e && e.message || e) }; } }
      } catch (e) { row.valid = false; row.reason = String(e && e.message || e).slice(0, 120); }
      outList.push(row);
    }
    return outList;
  }

  // ---------- role-split ceremony (each side holds ONLY its own half) ----------
  // Message flow (lockstep; the wire's duplex boxes make send-then-recv safe):
  //   1. both send {monero spend pub, view half, dkg round1}
  //   2. both send dkg round2
  //   3. both derive the joint account + joint Monero address and CONFIRM they
  //      match; A additionally enforces T-binding (T = B's spend pub).
  // roleIsA: true for the XNO-seller. Returns the party's swap handle — its own
  // shares + signer only; the peer's secrets never exist in this context.
  async function ceremony(wasm, xmr, rand, network, wire, roleIsA, deal, onProgress, myWalletAcctHex) {
    const myXmrShare = mScalar(rand);              // A_xmr for A; B_xmr (= x) for B
    const myPub = xmr.xmr_spend_pub(myXmrShare);
    const myView = rand(32);
    const myId = roleIsA ? 1 : 2, theirId = roleIsA ? 2 : 1;
    const dkg = new wasm.BrowserDkg(myId, theirId);
    if (onProgress) onProgress("ceremony: exchanging keys (round 1)…");
    await wire.send(jsonBytes({ pub: hx(myPub), view: hx(myView), r1: hx(dkg.round1_out()) }));
    const m1 = bytesJson(await wire.recv());
    const theirPub = hb(m1.pub), theirView = hb(m1.view);
    dkg.set_peer_round1(hb(m1.r1));
    if (onProgress) onProgress("ceremony: exchanging keys (round 2)…");
    await wire.send(jsonBytes({ r2: hx(dkg.round2_out()) }));
    const m2 = bytesJson(await wire.recv());
    const account = dkg.set_peer_round2(hb(m2.r2));
    // Joint Monero address: A's pub + B's pub in role order; ctx from the deal
    // (both derive it identically from the offer hash → same address).
    const ctxBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", te.encode("xnoxmr-2p-ctx-v1:" + deal.offerHash)));
    const A_pub = roleIsA ? myPub : theirPub, B_pub = roleIsA ? theirPub : myPub;
    const viewA = roleIsA ? myView : theirView, viewB = roleIsA ? theirView : myView;
    const jm = JSON.parse(xmr.xmr_joint_info(ctxBytes, A_pub, B_pub, viewA, viewB, network));
    // Confirm both sides agree on account + address (cheap, catches any drift).
    if (onProgress) onProgress("ceremony: confirming joint accounts…");
    // Also exchange wallet accounts: B learns A's Nano account (the refund
    // destination); each party's claim/sweep goes to its OWN wallet.
    await wire.send(jsonBytes({ acct: hx(account), xmr: jm.address, wallet: myWalletAcctHex || "" }));
    const m3 = bytesJson(await wire.recv());
    if (m3.acct !== hx(account) || m3.xmr !== jm.address) throw new Error("joint-account mismatch with peer — aborting");
    const peerWalletAcct = String(m3.wallet || "");
    // T-binding (A's side of audit B1): T must be B's contribution to the joint
    // key. A recomputes the joint address from ITS OWN share + T; a lying B is
    // caught here, before any funds move.
    const T = B_pub;
    // TA = A's Monero spend pubkey. It is the adaptor point for the REFUND, the
    // mirror of T for the claim: A can only take the refund by completing a
    // pre-signature with A_xmr, which publishes A_xmr on-chain and lets B
    // reconstruct the joint Monero key and recover its lock. Without this, a
    // counterparty who walks after the XMR lock strands it permanently.
    const TA = A_pub;
    if (roleIsA) {
      const chk = JSON.parse(xmr.xmr_joint_info(ctxBytes, xmr.xmr_spend_pub(myXmrShare), T, myView, theirView, network));
      if (chk.address !== jm.address) throw new Error("adaptor T does not match the joint Monero key (T-binding)");
    }
    const signer = new wasm.BrowserSigner(dkg.key_package(), dkg.public_key_package(), myId, theirId);
    if (!eq(signer.account(), account)) throw new Error("signer account mismatch");
    return {
      roleIsA, deal, T, TA, peerWalletAcct, myWalletAcct: myWalletAcctHex || "",
      ctx: ctxBytes, myXmrShare, theirPubHex: hx(theirPub),
      viewA, viewB, jointMonero: jm,
      jointNanoAccount: hx(account), jointNanoAddress: wasm.nano_address_encode(account),
      _account: account, _signer: signer, _wire: wire, _wasm: wasm,
      // Serializable snapshot for crash-safe resume of THIS party only.
      snapshot() {
        return {
          v: 2, roleIsA, deal, T: hx(T), TA: hx(TA), ctx: hx(ctxBytes),
          peerWalletAcct, myWalletAcct: myWalletAcctHex || "",
          myXmrShare: hx(myXmrShare), theirPub: hx(theirPub),
          viewA: hx(viewA), viewB: hx(viewB), jointMonero: jm,
          kp: hx(dkg.key_package()), pubkeys: hx(dkg.public_key_package()), myId, theirId,
        };
      },
    };
  }
  // Rebuild a party handle from its snapshot (signer is stateless between
  // ceremonies; the wire must be re-derived by a fresh handshake if needed).
  function restore(wasm, snap, wire) {
    const signer = new wasm.BrowserSigner(hb(snap.kp), hb(snap.pubkeys), snap.myId, snap.theirId);
    const account = signer.account();
    return {
      roleIsA: snap.roleIsA, deal: snap.deal, T: hb(snap.T),
      TA: snap.TA ? hb(snap.TA) : null,   // null for v1 snapshots (pre-adaptor-refund)
      ctx: hb(snap.ctx),
      peerWalletAcct: snap.peerWalletAcct || "", myWalletAcct: snap.myWalletAcct || "",
      myXmrShare: hb(snap.myXmrShare), theirPubHex: snap.theirPub,
      viewA: hb(snap.viewA), viewB: hb(snap.viewB), jointMonero: snap.jointMonero,
      jointNanoAccount: hx(account), jointNanoAddress: wasm.nano_address_encode(account),
      _account: account, _signer: signer, _wire: wire, _wasm: wasm,
      snapshot() { return snap; },
    };
  }

  // ---------- role signing over the wire (one signer per browser) ----------
  async function jointSignRole(party, msg32) {
    const s = party._signer, w = party._wire;
    await w.send(s.sign_commit(msg32));
    s.set_peer_commit(await w.recv());
    await w.send(s.sign_share());
    s.set_peer_share(await w.recv());
    return s.aggregate_sig();
  }
  // `point` defaults to T (B's share, for the CLAIM). The refund passes TA.
  async function adaptorPresignRole(party, msg32, point) {
    const s = party._signer, w = party._wire;
    const adaptor = point || party.T;
    if (!adaptor) throw new Error("no adaptor point for this presignature");
    await w.send(s.presign_commit(msg32, adaptor));
    s.set_peer_commit(await w.recv());
    await w.send(s.presign_share());
    s.set_peer_share(await w.recv());
    return s.aggregate_presig();
  }

  // ---------- role-aware settlement ----------
  // deps: { wasm, xmr, beacon, urls, walletApi, moneroPost, store(get/set), note }
  // store persists per-step markers under the party's session key (crash-safe:
  // every completed action lands in store BEFORE the next starts, mirroring the
  // proven self-swap driver). Broadcast-bearing steps run through walletApi /
  // beacon exactly like the self-swap.
  const XMR_CONF = 10;

  // Every phase of the Monero wait is narrated: which blocks are being scanned
  // (with %), when the lock is found, how many confirmations it has and the
  // time left — Monero is the slow side and a silent minute reads as a hang.
  // `deadlineMs` (optional): give up and return null instead of waiting forever,
  // so the XNO funder can fall back to the refund if the lock never appears.
  async function waitJointXmrLock(deps, party, minAtomic, sinceHeight, deadlineMs) {
    deps.note("Monero: connecting to a node…");
    const node = await deps.xmr.XmrNode.connect(deps.moneroPost);
    const spendPub = hb(party.jointMonero.spend_pub), viewKey = hb(party.jointMonero.view_key);
    const want = raw2dec(minAtomic, 12);
    let round = 0;
    for (;;) {
      const tip = await node.height();
      const from0 = sinceHeight ? Math.max(0, sinceHeight - 5) : Math.max(0, tip - 720);
      const total = Math.max(1, tip - from0);
      let hit = null;
      for (let from = from0; from <= tip - 1 && !hit; from += 10) {
        const to = Math.min(from + 9, tip - 1);
        const pct = Math.min(100, Math.round((to - from0) / total * 100));
        deps.note(`Monero: scanning blocks ${from.toLocaleString()}–${to.toLocaleString()} for the ${want} XMR lock (chain at ${tip.toLocaleString()}) · ${pct}%`);
        const outs = JSON.parse(await node.scan_all(spendPub, viewKey, from, to, null));
        for (const o of outs) if (BigInt(o.amount) >= BigInt(minAtomic)) { hit = o; break; }
      }
      if (hit && tip - hit.block >= XMR_CONF) { deps.note(`Monero: lock of ${raw2dec(hit.amount, 12)} XMR confirmed ✓ (block ${hit.block.toLocaleString()}, ${tip - hit.block} confirmations)`); return { hit, tip }; }
      if (hit) {
        const conf = tip - hit.block, mins = Math.max(1, (XMR_CONF - conf) * 2);
        deps.note(`Monero: lock found at block ${hit.block.toLocaleString()} · ${conf}/${XMR_CONF} confirmations · ~${mins} min left · checking again in 45 s (safe to wait)`);
      } else {
        round++;
        deps.note(`Monero: no ${want} XMR lock on the joint address yet (chain at ${tip.toLocaleString()}) · the other side may still be sending · re-scanning in 45 s (check ${round})`);
      }
      if (deadlineMs && Date.now() > deadlineMs) {
        deps.note("Monero: the counterparty never locked within the agreed window.");
        return null;
      }
      // Nothing irreversible has happened for A yet (its XNO is refundable), so
      // this wait is also a free abort window: if the market has moved past
      // the deal, stop waiting and let the caller take the refund.
      if (deps.price && !hit) {
        const c = await gate(deps, party, "while waiting for the XMR lock");
        if (!c.ok) { deps.note("abandoning the wait: " + c.reason); return null; }
      }
      await new Promise((r) => setTimeout(r, 45000));
    }
  }

  async function coSignOpen(deps, party) {
    const I = deps.beacon._internals;
    let ent = [];
    for (;;) {
      const rcv = await I.rpc(deps.urls, { action: "receivable", account: party.jointNanoAddress, count: "5", threshold: "1" });
      const blocks = rcv && rcv.blocks && typeof rcv.blocks === "object" ? rcv.blocks : {};
      ent = Object.entries(blocks);
      if (ent.length) break;
      deps.note("waiting for the XNO funding to reach the joint account…");
      await new Promise((r) => setTimeout(r, 8000));
    }
    const [sendHash, amount] = ent[0];
    const amt = String(typeof amount === "object" ? amount.amount : amount);
    const acctHex = party.jointNanoAccount;
    const openHash = deps.wasm.state_block_hash(acctHex, "0".repeat(64), acctHex, amt, sendHash.toLowerCase(), "open");
    deps.note("co-signing the joint open with the counterparty…");
    const sig = await jointSignRole(party, openHash);
    if (!deps.wasm.nano_check(party._account, openHash, sig)) throw new Error("joint open signature invalid");
    const built = buildBlock(deps.wasm, { acctHex, previous: "0".repeat(64), balance: amt, link: sendHash.toLowerCase(), subtype: "open", sig });
    const work = await I.generateWork(deps.urls, built.workRoot, deps.beacon.THRESH.receive, null);
    const hash = await I.processBlock(deps.urls, built.signedJson, work);
    return { hash: String(hash), balance: amt };
  }

  // Refund-first (block 1a), role version: co-sign the unilateral refund
  // (joint → the XNO funder = A's wallet account) and BOTH sides hold it.
  async function coSignRefund(deps, party, openHash, refundDestHex) {
    const acctHex = party.jointNanoAccount;
    const refundHash = deps.wasm.state_block_hash(acctHex, openHash, acctHex, "0", refundDestHex, "send");
    deps.note("refund-first: co-signing the unilateral refund (held, not broadcast)…");
    const sig = await jointSignRole(party, refundHash);
    if (!deps.wasm.nano_check(party._account, refundHash, sig)) throw new Error("refund signature invalid");
    return { prev: openHash, dest: refundDestHex, sig: hx(sig) };
  }

  // Byte-exact mirror of the PROVEN funded_swap nanoProcessJson (same fields,
  // same casing, same workRoot semantics) so the broadcast path is identical.
  function buildBlock(wasm, { acctHex, previous, balance, link, subtype, sig }) {
    const HX = (b) => hx(b).toUpperCase();
    const hash = wasm.state_block_hash(acctHex, previous, acctHex, balance, link, subtype);
    if (!hash.length) throw new Error("could not hash block");
    const workRoot = subtype === "open" ? acctHex : previous;
    return {
      hashHex: hx(hash),
      workRoot: HX(hb(workRoot)),
      signedJson: JSON.stringify({
        process: {
          action: "process", json_block: "true", subtype,
          block: {
            type: "state",
            account: wasm.nano_address_encode(hb(acctHex)),
            previous: HX(hb(previous)),
            representative: wasm.nano_address_encode(hb(acctHex)),
            balance: String(balance),
            link: HX(hb(link)),
            signature: HX(sig),
            work: "WORK",
          },
        },
      }),
    };
  }

  // ---------- role settlement drivers (EXPERIMENTAL — never run on-chain) ----------
  // Each driver runs ONE party's side to completion via `deps`, persisting every
  // completed step in `deps.store` BEFORE the next starts (crash-safe resume, the
  // proven self-swap discipline). Broadcasts go through deps.walletApi/beacon.
  // The two drivers run in DIFFERENT browsers and rendezvous over party._wire for
  // each co-sign. The block hashes are deterministic, so both sides compute the
  // SAME openHash/claimHash from the on-chain funding and co-sign it; only the
  // designated side broadcasts.
  //
  // deps = { wasm, xmr, beacon, urls, walletApi, moneroPost, note, store,
  //          guard: bool }.  store = { get(k)->any|null, set(k,v) }.
  const raw2dec = (raw, scale) => {
    const s = BigInt(raw).toString().padStart(scale + 1, "0");
    return ((s.slice(0, -scale) + "." + s.slice(-scale)).replace(/0+$/, "").replace(/\.$/, "")) || "0";
  };

  // Both sides: wait for the funding, compute the (deterministic) open hash,
  // co-sign it over the wire; `broadcast` side also broadcasts it. Returns
  // { hash, balance }. Idempotent via store key "open".
  async function coOpen(deps, party, broadcast) {
    const cached = deps.store.get("open"); if (cached) return cached;
    const I = deps.beacon._internals, acctHex = party.jointNanoAccount;
    let ent = [];
    for (let round = 0; ; round++) {
      const rcv = await I.rpc(deps.urls, { action: "receivable", account: party.jointNanoAddress, count: "5", threshold: "1" });
      const b = rcv && rcv.blocks && typeof rcv.blocks === "object" ? rcv.blocks : {};
      ent = Object.entries(b); if (ent.length) break;
      // B has committed nothing yet, so this wait is a free abort window: keep
      // re-verifying the deal against the market and walk away if it has gone.
      if (!broadcast && deps.price && round % 4 === 3) {
        const c = await gate(deps, party, "while waiting for funding");
        if (!c.ok) { const err = new Error("declined before funding arrived: " + c.reason); err.declined = c; throw err; }
      }
      deps.note("waiting for the XNO funding to reach the joint account…");
      await new Promise((r) => setTimeout(r, 8000));
    }
    const [sendHash, amount] = ent[0];
    const amt = String(typeof amount === "object" ? amount.amount : amount);
    const openHash = deps.wasm.state_block_hash(acctHex, "0".repeat(64), acctHex, amt, sendHash.toLowerCase(), "open");
    deps.note("co-signing the joint open…");
    const sig = await jointSignRole(party, openHash);
    if (!deps.wasm.nano_check(party._account, openHash, sig)) throw new Error("joint open signature invalid");
    // Normalize to lowercase so BOTH parties key everything (claim previous,
    // frontier compare) off the identical string — the node returns uppercase.
    let hash = hx(openHash);
    if (broadcast) {
      const built = buildBlock(deps.wasm, { acctHex, previous: "0".repeat(64), balance: amt, link: sendHash.toLowerCase(), subtype: "open", sig });
      const work = await I.generateWork(deps.urls, built.workRoot, deps.beacon.THRESH.receive, null);
      hash = String(await I.processBlock(deps.urls, built.signedJson, work)).toLowerCase();
    }
    const out = { hash, balance: amt }; deps.store.set("open", out); return out;
  }

  // If the joint account's frontier has moved past `prevHash`, return the
  // signature of the block that spent it (hex), else null. Used by B to notice
  // a refund, and by A to notice the claim — the same on-chain event either way.
  async function frontierSigIfMoved(deps, party, prevHash) {
    const I = deps.beacon._internals;
    try {
      const info = await I.rpc(deps.urls, { action: "account_info", account: party.jointNanoAddress });
      if (!info || !info.frontier) return null;
      if (String(info.frontier).toLowerCase() === String(prevHash).toLowerCase()) return null;
      const bi = await I.rpc(deps.urls, { action: "blocks_info", hashes: [info.frontier], json_block: "true" });
      const blk = bi && bi.blocks && bi.blocks[info.frontier];
      const sig = blk && blk.contents && blk.contents.signature;
      return sig ? String(sig) : null;
    } catch (e) { return null; }
  }

  async function confirmedQuorum(deps, hash) {
    const I = deps.beacon._internals; let yes = 0;
    for (const u of deps.urls.slice(0, 3)) {
      try { const j = await I.rpc([u], { action: "block_info", hash, json_block: "true" }); if (j && (j.confirmed === "true" || j.confirmed === true)) yes++; } catch (e) {}
    }
    return deps.urls.slice(0, 3).length >= 2 ? yes >= 2 : yes >= 1;
  }

  // B = XMR-seller / maker (offer side 1). Locks XMR, co-signs, completes the
  // claim (revealing x → A gets to sweep), receives XNO via the claim to A?  No:
  // the claim sends the joint XNO to A (the taker). B's payment is the XNO it
  // already funded?  Side-1 means B SELLS XMR and BUYS XNO: A funds XNO, B locks
  // XMR; the claim moves the joint XNO to B, and A sweeps the XMR. So on side 1
  // the claim destination is B's wallet and A sweeps. Roles below follow that.
  async function runB(deps, party) {
    const S = deps.store, deal = party.deal, acctHex = party.jointNanoAccount;
    // ORDER MATTERS. The Monero lock is the one irreversible, unrecoverable
    // step in this protocol, so it goes LAST, after the counterparty's XNO is
    // already on-chain AND the adaptor refund exists. Previously the lock came
    // first: if the counterparty then walked, there was no XNO to refund, no
    // refund to take, and the XMR was stranded in the 2-of-2 address forever.
    let open;
    try { open = await coOpen(deps, party, false); }         // A broadcasts the open; B co-signs
    catch (e) { if (e && e.declined) { S.set("declined", e.declined); return { done: false, declined: true, reason: e.declined.reason }; } throw e; }
    if (!S.get("refund")) S.set("refund", await coSignRefundRole(deps, party, open.hash));
    if (!S.get("lock")) {
      // LAST CHANCE. Locking XMR is the one step B cannot undo. Re-verify the
      // deal against the market NOW, not at accept time - the funding wait
      // alone can be many minutes. Declining here costs B nothing: A takes its
      // refund and is made whole.
      const c = await gate(deps, party, "before locking XMR");
      if (!c.ok) { S.set("declined", c); return { done: false, declined: true, reason: c.reason }; }
      const amt = raw2dec(deal.xmrAtomic, 12);
      deps.note("their " + raw2dec(deal.xnoRaw, 30) + " XNO is locked and your refund is secured — locking " + amt + " XMR…");
      const tx = await deps.walletApi.xmrSend(party.jointMonero.address, amt, deps.note);
      let h = 0; try { const nd = await deps.xmr.XmrNode.connect(deps.moneroPost); h = await nd.height(); } catch (e) {}
      S.set("lock", { tx, h });
      deps.note(`Monero: lock tx ${String(tx && tx.tx_hash || tx || "").slice(0, 12)}… broadcast ✓ — ~20 min for 10 confirmations, then you claim the XNO.`);
    }
    // Did the counterparty take the refund instead? The joint account has one
    // successor: if the refund landed, our claim can never confirm, and the
    // refund signature on-chain carries A_xmr — which is exactly what we need
    // to sweep our locked XMR back. Check before spending work on the claim.
    if (!S.get("claim")) {
      const spent = await frontierSigIfMoved(deps, party, open.hash);
      if (spent) {
        deps.note("the counterparty refunded — recovering your locked XMR…");
        const rec = await recoverXmrFromRefund(deps, party, S.get("refund"), spent);
        S.set("recovered", rec);
        return { done: true, recovered: true };
      }
    }
    // Confirm-before-reveal, then complete the adaptor claim (reveals x on-chain).
    if (!S.get("claim")) {
      for (let i = 0; i < 120 && !(await confirmedQuorum(deps, open.hash)); i++) { deps.note("waiting for joint account to confirm on a quorum…"); await new Promise((r) => setTimeout(r, 5000)); }
      // The claim sends the joint XNO to the XNO-BUYER, which is B (the
      // XMR-seller) itself. B must use its OWN wallet here; A independently
      // uses its peerWalletAcct (which IS B's wallet), so both sign the exact
      // same claim block. Using peerWalletAcct here was A's wallet — a
      // different block — and the co-signature failed (InvalidShare).
      if (!party.myWalletAcct) throw new Error("no wallet account to claim the XNO to");
      const dest = party.myWalletAcct;                          // B claims the XNO to itself
      const claimHash = deps.wasm.state_block_hash(acctHex, open.hash, acctHex, "0", dest, "send");
      const pre = await adaptorPresignRole(party, claimHash);
      const claimSig = deps.wasm.presig_complete(pre, party.myXmrShare);   // B has x = its own share
      if (!deps.wasm.nano_check(party._account, claimHash, claimSig)) throw new Error("completed claim invalid");
      const built = buildBlock(deps.wasm, { acctHex, previous: open.hash, balance: "0", link: dest, subtype: "send", sig: claimSig });
      const I = deps.beacon._internals;
      const work = await I.generateWork(deps.urls, built.workRoot, deps.beacon.THRESH.send, null);
      deps.note("broadcasting the claim (reveals x)…");
      const hash = await I.processBlock(deps.urls, built.signedJson, work);
      S.set("claim", { hash: String(hash) });
      try { await deps.walletApi.receive(); } catch (e) {}   // pocket the received XNO
    }
    // What actually happened, from the chain, not from the deal terms: the XNO
    // that landed in the joint account is `open.balance` (on-chain), and B paid
    // one Monero lock transaction.
    const realized = { role: "B", receivedXnoRaw: String(open.balance), paidXmrAtomic: String(deal.xmrAtomic),
                       feeXmrAtomic: String((S.get("lock") || {}).fee || ""), at: Date.now() };
    S.set("realized", realized);
    deps.note("swap complete on your side — XNO received.");
    return { done: true, realized };
  }

  // A = XNO-seller / taker (offer side 1). Verifies the XMR lock, funds XNO,
  // co-signs+broadcasts the open, presigns the claim, extracts x from B's
  // broadcast claim, sweeps the XMR home.
  async function runA(deps, party) {
    const S = deps.store, deal = party.deal, acctHex = party.jointNanoAccount;
    // XNO goes first because it is the RECOVERABLE leg: the adaptor refund
    // below lets this side unwind unilaterally. The counterparty only commits
    // its Monero once that refund exists, so neither side is ever exposed to a
    // walk-away it cannot undo.
    if (!S.get("fund")) {
      const amt = raw2dec(deal.xnoRaw, 30);
      deps.note("funding " + amt + " XNO into the joint account…");
      const h = await deps.walletApi.send(party.jointNanoAddress, amt, deps.note);
      S.set("fund", { hash: h });
    }
    const open = await coOpen(deps, party, true);            // A broadcasts the open
    if (!S.get("refund")) S.set("refund", await coSignRefundRole(deps, party, open.hash));
    if (!S.get("lockseen")) {
      deps.note("waiting for the counterparty to lock their XMR…");
      const deadline = Date.now() + (deps.lockWaitMs || 90 * 60 * 1000);
      const res = await waitJointXmrLock(deps, party, deal.xmrAtomic, 0, deadline);
      if (!res) {
        // They never locked. Take the refund: it returns the XNO and, because
        // it is an adaptor signature, publishes our Monero share — harmless
        // here (they locked nothing) and the same path that makes them whole
        // if they HAD locked.
        const r = await broadcastRefund(deps, party, open.hash, S.get("refund"));
        S.set("refunded", r);
        deps.note("refunded — your XNO is back. No Monero was ever locked by the other side.");
        return { done: true, refunded: true };
      }
      S.set("lockseen", { block: res.hit.block, output: res.hit.output });
    }
    // LAST CHANCE for A. Once the claim is pre-signed B can complete it at will
    // and A's XNO is committed. Re-verify against the market now; if the deal
    // has gone, take the adaptor refund instead - which publishes A's Monero
    // share so B recovers its lock. Nobody loses more than a network fee.
    if (!S.get("presigned")) {
      const c = await gate(deps, party, "before committing the claim");
      if (!c.ok) {
        const r = await broadcastRefund(deps, party, open.hash, S.get("refund"));
        S.set("refunded", Object.assign(r, { reason: c.reason }));
        deps.note("refunded instead of committing: " + c.reason);
        return { done: true, refunded: true, reason: c.reason };
      }
      S.set("presigned", { at: Date.now() });
    }
    // Presign the claim (B completes it); then watch the joint account's frontier
    // for B's broadcast claim, extract x, and sweep the XMR home.
    const dest = party.peerWalletAcct || "";                  // claim XNO dest = B's wallet
    const claimHash = deps.wasm.state_block_hash(acctHex, open.hash, acctHex, "0", dest, "send");
    const pre = await adaptorPresignRole(party, claimHash);
    if (!S.get("x")) {
      const I = deps.beacon._internals;
      let claimSig = null;
      for (;;) {
        const info = await I.rpc(deps.urls, { action: "account_info", account: party.jointNanoAddress });
        if (info && info.frontier && info.frontier.toLowerCase() !== open.hash.toLowerCase()) {
          const bi = await I.rpc(deps.urls, { action: "blocks_info", hashes: [info.frontier], json_block: "true" });
          const blk = bi && bi.blocks && bi.blocks[info.frontier];
          if (blk && blk.contents && blk.contents.signature) { claimSig = deps.wasm.nano_address_decode ? blk.contents.signature : null; break; }
        }
        deps.note("waiting for the counterparty to claim (reveals x)…");
        await new Promise((r) => setTimeout(r, 8000));
      }
      const x = deps.wasm.presig_extract(pre, hb(claimSig));
      S.set("x", { x: hx(x) });
    }
    if (!S.get("sweep")) {
      const { hit } = await waitJointXmrLock(deps, party, deal.xmrAtomic, (S.get("lockseen") || {}).block || 0);
      const jointSecret = deps.xmr.xmr_joint_secret(party.ctx, party.myXmrShare, hb(S.get("x").x));
      const node = await deps.xmr.XmrNode.connect(deps.moneroPost);
      // Sweep the claimed XMR to the taker's chosen destination (an external
      // wallet). Falls back to the in-browser wallet address only if no
      // destination was provided.
      const myXmr = deps.xmrDest || await deps.walletApi.xmrAddress();
      deps.note("Monero: building the sweep to " + (deps.xmrDest ? "your destination address" : "your wallet") + " (ring signature with real decoys + fee)…");
      const signed = JSON.parse(await node.sweep_sign(hit.output, hit.block, jointSecret, myXmr, "mainnet"));
      deps.note("Monero: broadcasting the sweep…");
      const tx = await node.publish(signed.tx);
      S.set("sweep", { tx, lockedAtomic: String(hit.amount) });
      deps.note(`Monero: sweep tx ${String(tx && tx.tx_hash || tx || "").slice(0, 12)}… broadcast ✓ — it shows in your wallet after a scan and becomes spendable after 10 confirmations (~20 min)`);
    }
    // Realised from the chain: the Monero output that actually sat in the joint
    // address (`hit.amount`), less one sweep transaction fee; A paid its XNO.
    const sw = S.get("sweep") || {};
    const realized = { role: "A", receivedXmrAtomic: String(sw.lockedAtomic || deal.xmrAtomic), paidXnoRaw: String(deal.xnoRaw),
                       feeXmrAtomic: "", at: Date.now() };
    S.set("realized", realized);
    deps.note("swap complete on your side — XMR received.");
    return { done: true, realized };
  }

  // ADAPTOR refund (joint→A), bound to TA = A's Monero spend pubkey.
  //
  // This used to be a plain joint signature, which meant A could take the
  // refund while revealing nothing — so a counterparty who walked after B had
  // locked its XMR stranded that XMR permanently in the 2-of-2 joint address.
  //
  // As an adaptor pre-signature the refund is the exact mirror of the claim:
  //   claim : B completes with B_xmr (= x)  -> publishes x   -> A sweeps the XMR
  //   refund: A completes with A_xmr        -> publishes A_xmr -> B sweeps it back
  // Either way the swap unwinds and BOTH sides can recover. The reconstruction
  // is order-independent (monero-side: joint_secret_reconstruction_is_the_swap_hinge),
  // so B computes the same joint secret from (B_xmr, A_xmr).
  //
  // Returns the PRE-signature, not a usable signature: only A can complete it.
  async function coSignRefundRole(deps, party, openHash) {
    const acctHex = party.jointNanoAccount;
    // refund dest = the XNO funder = A's wallet. A = roleIsA ? me : peer.
    const dest = party.roleIsA ? party.myWalletAcct : party.peerWalletAcct;
    const refundHash = deps.wasm.state_block_hash(acctHex, openHash, acctHex, "0", dest, "send");
    if (!party.TA) throw new Error("refund needs the adaptor point TA — re-run the ceremony");
    deps.note("co-signing the refund as an adaptor pre-signature (recoverable by both sides)…");
    const pre = await adaptorPresignRole(party, refundHash, party.TA);
    // Both sides verify the pre-signature before anything irreversible happens.
    if (!deps.wasm.presig_verify(pre, party._account, refundHash)) {
      throw new Error("refund pre-signature invalid — aborting before locking funds");
    }
    return { prev: openHash, dest, hash: hx(refundHash), presig: hx(pre) };
  }

  // A: turn the refund pre-signature into a broadcastable block by completing it
  // with A_xmr. Doing so publishes A_xmr, which is what lets B recover its XMR.
  async function broadcastRefund(deps, party, openHash, refund) {
    if (!party.roleIsA) throw new Error("only the XNO funder can take the refund");
    const acctHex = party.jointNanoAccount;
    const sig = deps.wasm.presig_complete(hb(refund.presig), party.myXmrShare);
    const refundHash = deps.wasm.state_block_hash(acctHex, openHash, acctHex, "0", refund.dest, "send");
    if (!deps.wasm.nano_check(party._account, refundHash, sig)) throw new Error("completed refund invalid");
    const built = buildBlock(deps.wasm, { acctHex, previous: openHash, balance: "0", link: refund.dest, subtype: "send", sig });
    const I = deps.beacon._internals;
    const work = await I.generateWork(deps.urls, built.workRoot, deps.beacon.THRESH.send, null);
    deps.note("broadcasting the refund (publishes your Monero share so the other side can recover)…");
    const hash = await I.processBlock(deps.urls, built.signedJson, work);
    try { await deps.walletApi.receive(); } catch (e) {}
    return { hash: String(hash) };
  }

  // B: the counterparty took the refund instead of completing the swap. Extract
  // A_xmr from the on-chain refund signature and sweep the locked XMR back.
  async function recoverXmrFromRefund(deps, party, refund, refundSigHex) {
    const aShare = deps.wasm.presig_extract(hb(refund.presig), hb(refundSigHex));
    // Order-independent: (my share, their share) yields the same joint secret.
    const jointSecret = deps.xmr.xmr_joint_secret(party.ctx, party.myXmrShare, aShare);
    const { hit } = await waitJointXmrLock(deps, party, party.deal.xmrAtomic, 0);
    const node = await deps.xmr.XmrNode.connect(deps.moneroPost);
    const myXmr = await deps.walletApi.xmrAddress();
    deps.note("recovering your locked XMR (the other side refunded and revealed their share)…");
    const signed = JSON.parse(await node.sweep_sign(hit.output, hit.block, jointSecret, myXmr, "mainnet"));
    const tx = await node.publish(signed.tx);
    deps.note("Monero: recovery sweep " + String(tx && tx.tx_hash || tx || "").slice(0, 12) + "… broadcast ✓ — your XMR is coming home.");
    return { tx };
  }

  return {
    dealFromOffer, makerValidateDeal, rvBox, rvRespBox,
    takerHandshake, makerPollTake, peekTakes, postDecline,
    ceremony, restore, jointSignRole, adaptorPresignRole,
    waitJointXmrLock, coSignOpen, coSignRefund, coSignRefundRole, buildBlock,
    coOpen, confirmedQuorum, runA, runB, raw2dec,
    broadcastRefund, recoverXmrFromRefund, frontierSigIfMoved,
    partyProfit, makerProfit, certify, gate, minViableXnoRaw,
    XMR_TX_FEE_ATOMIC_DEFAULT: XMR_TX_FEE_ATOMIC_DEFAULT.toString(),
    _hx: hx, _hb: hb,
  };
});
