// Regression: "certified win before any action". Exercises the real certify()
// math, the real gate(), and the real runA/runB gates against mocked deps.
const TP = require("./two_party.js");
let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log("  PASS " + m)) : (fail++, console.log("  FAIL " + m)); };
const XNO = (n) => (BigInt(Math.round(n * 1e6)) * (10n ** 24n)).toString();
const deal = (xno, priceE9) => { const r = BigInt(XNO(xno)); return { xnoRaw: r.toString(), priceE9: String(priceE9),
  xmrAtomic: ((r * BigInt(priceE9) * 1000n) / (10n ** 30n)).toString() }; };
const P = (mid, extra) => Object.assign({ ok: true, mid, sources: 2, at: Date.now() }, extra || {});
const MID = 0.000925;

(async () => {
  console.log("1. profit math, both roles (hand-checked)");
  { // B sells 0.01 XMR-worth: at price 1% ABOVE mid B receives more XNO value than it gives -> win
    const d = deal(10, Math.round(MID * 1.01 * 1e9));           // maker side 1 => B
    const b = TP.partyProfit(d, false, MID, "0");
    // gross = xnoValue(10 XNO at mid) - xmrAtomic(10 XNO at mid*1.01) = -1% of outlay... wait: B RECEIVES 10 XNO, gives xmrAtomic
    // xmrAtomic = 10 * mid*1.01 (in XMR) ; xnoValue = 10*mid ; gross = 10*mid - 10*mid*1.01 < 0  => B loses when price ABOVE mid
    ok(BigInt(b.grossAtomic) < 0n, "B (sells XMR): price above mid is a LOSS (B gives more XMR than the XNO is worth)");
    const d2 = deal(10, Math.round(MID * 0.99 * 1e9));
    const b2 = TP.partyProfit(d2, false, MID, "0");
    ok(BigInt(b2.grossAtomic) > 0n && b2.netBps > 95 && b2.netBps < 105, `B: price 1% below mid ~= +100 bps (got ${b2.netBps})`);
    const a = TP.partyProfit(d, true, MID, "0");
    ok(BigInt(a.grossAtomic) > 0n && a.netBps > 95 && a.netBps < 105, `A (sells XNO): price 1% above mid ~= +100 bps (got ${a.netBps})`);
    const fee = TP.partyProfit(d2, false, MID);       // default fee 0.00008 XMR on ~0.00925 XMR outlay = ~86 bps
    ok(BigInt(fee.netAtomic) < BigInt(b2.netAtomic), "fee is subtracted from net");
    const d3 = deal(3, Math.round(MID * 0.99 * 1e9));  // ~$1.2: fee ~288 bps swamps the +100 bps margin
    const fee3 = TP.partyProfit(d3, false, MID);
    ok(fee3.netBps < 0, `on a ~$1 deal the 0.00008 XMR fee alone turns +100 bps into a loss (${fee3.netBps} bps) - fees matter at this size`);
  }

  console.log("\n2. certify() refuses everything it cannot vouch for");
  { const d = deal(10, Math.round(MID * 0.99 * 1e9));
    ok(!TP.certify(d, false, { ok: false, reason: "down" }).ok, "no trustworthy price -> refuse");
    ok(!TP.certify(d, false, P(MID, { sources: 1 })).ok, "one source -> refuse");
    ok(!TP.certify(d, false, P(MID, { at: Date.now() - 120000 })).ok, "120 s old price -> refuse (limit 60 s)");
    ok(TP.certify(d, false, P(MID), { minBps: 0, feeAtomic: "0" }).ok, "fresh, 2 sources, positive net -> certified");
    ok(!TP.certify(d, false, P(MID), { minBps: 200, feeAtomic: "0" }).ok, "below the required bps -> refuse");
    const c = TP.certify(d, false, P(MID, { stress: 3, stressWhy: "price jumped 12%" }), { minBps: 0, feeAtomic: "0" });
    ok(!c.ok && /moving too fast/.test(c.reason), "ACTIVE MONITORING: market in motion (stress 3) -> refuse even though level is a win");
    const base = TP.certify(d, false, P(MID), { minBps: 0, feeAtomic: "0" });
    const later = TP.certify(d, false, P(MID * 0.988), { minBps: 0, feeAtomic: "0", baseline: base, maxUnrealizedLossBps: 50 });
    ok(!later.ok && /unrealised loss/.test(later.reason), `UNREALISED P&L: mid fell 1.2% against B since accept -> refuse (${later.unrealizedBps} bps)`);
    const mild = TP.certify(d, false, P(MID * 0.998), { minBps: 0, feeAtomic: "0", baseline: base, maxUnrealizedLossBps: 50 });
    ok(mild.ok && mild.unrealizedBps < 0 && mild.unrealizedBps > -50, `small adverse drift stays certified but is REPORTED (${mild.unrealizedBps} bps)`);
    const better = TP.certify(d, false, P(MID * 1.005), { minBps: 0, feeAtomic: "0", baseline: base });
    ok(better.ok && better.unrealizedBps > 0, `favourable drift shows an unrealised GAIN (+${better.unrealizedBps} bps)`);
  }

  console.log("\n3. gate() protects vs the accept baseline, not an absolute win");
  { const party = { deal: deal(10, Math.round(MID * 0.99 * 1e9)), roleIsA: false };
    const g = await TP.gate({}, party, "test");
    ok(!g.ok && g.unverified, "no deps.price -> REFUSED, flagged unverified");
    const g2 = await TP.gate({ price: async () => P(MID), feeAtomic: "0", store: mem() }, party, "test");
    ok(!g2.ok && /no accept certificate/.test(g2.reason), "no accept baseline -> fail closed");
    // WITH a baseline and an unchanged market the gate passes — even though this
    // taker/maker's net vs mid may be negative: the spread is the AGREED price.
    const base = TP.certify(party.deal, party.roleIsA, P(MID), { minBps: -1e9, feeAtomic: "0" });
    const st3 = mem(); st3.set("acceptCert", base);
    const g3 = await TP.gate({ price: async () => P(MID), feeAtomic: "0", store: st3, maxUnrealizedLossBps: 50, maxStress: 2 }, party, "test");
    ok(g3.ok, "accept baseline + unchanged market -> passes (does not re-demand an absolute win)");
  }

  console.log("\n4. runB refuses to LOCK XMR when the market moved AGAINST the accepted deal");
  { const d = deal(10, Math.round(MID * 0.99 * 1e9));
    const st = mem(); st.set("open", { hash: "ab".repeat(32), balance: d.xnoRaw }); st.set("refund", { presig: "00" });
    st.set("acceptCert", TP.certify(d, false, P(MID), { minBps: -1e9, feeAtomic: "0" }));  // B accepted here
    let locked = false;
    const deps = { store: st, note: () => {}, feeAtomic: "0", maxUnrealizedLossBps: 50, maxStress: 2,
      price: async () => P(MID * 0.90),             // mid fell 10%: the XNO B receives is worth far less
      walletApi: { xmrSend: async () => { locked = true; return "tx"; } }, xmr: {}, beacon: { _internals: {} } };
    const party = { deal: d, roleIsA: false, jointNanoAccount: "ab".repeat(32), jointMonero: { address: "4x" } };
    const r = await TP.runB(deps, party);
    ok(r && r.declined && !locked, "B declined before locking; xmrSend was NEVER called");
    ok(st.get("declined") && /unrealised loss/.test(st.get("declined").reason), "reason persisted: " + (st.get("declined") || {}).reason);
    ok((st.get("certs") || []).length >= 1, "certificate log written");
  }

  console.log("\n5. runA takes the REFUND when the market moved AGAINST the accepted deal");
  { const d = deal(10, Math.round(MID * 1.01 * 1e9));           // A sells XNO at +1%
    const st = mem();
    st.set("fund", { hash: "f" }); st.set("open", { hash: "ab".repeat(32), balance: d.xnoRaw });
    st.set("acceptCert", TP.certify(d, true, P(MID), { minBps: -1e9, feeAtomic: "0" }));   // A accepted here
    st.set("refund", { presig: "00".repeat(96), dest: "cd".repeat(32) }); st.set("lockseen", { block: 1, output: "x" });
    let presigned = false, refunded = false;
    const deps = { store: st, note: () => {}, feeAtomic: "0", maxUnrealizedLossBps: 50, maxStress: 2,
      price: async () => P(MID * 1.10),             // mid rose 10%: the XNO A gives away is worth far more
      wasm: { presig_complete: () => new Uint8Array(64), state_block_hash: () => new Uint8Array(32), nano_check: () => true,
              nano_address_encode: () => "nano_x" },
      beacon: { THRESH: { send: 0n }, _internals: { generateWork: async () => "w", processBlock: async () => { refunded = true; return "h"; } } },
      walletApi: { receive: async () => {} } };
    TP.buildBlock = () => ({ workRoot: "r", signedJson: "{}" });
    const party = { deal: d, roleIsA: true, jointNanoAccount: "ab".repeat(32), jointNanoAddress: "nano_j",
                    myXmrShare: new Uint8Array(32), _account: new Uint8Array(32), _wire: null,
                    _signer: { presign_commit: () => { presigned = true; throw new Error("must not presign"); } } };
    let r = null; try { r = await TP.runA(deps, party); } catch (e) { r = { threw: e.message }; }
    ok(!presigned, "adaptorPresignRole was NEVER reached");
    ok(r && r.refunded && refunded, "A broadcast the refund instead (B recovers via the revealed share)");
    ok(/unrealised loss/.test(r.reason || ""), "reason: " + r.reason);
  }

  console.log("\n6. makerPollTake declines an unprofitable take and reports it as stale-quote, not junk");
  { const te = new TextEncoder(); const m = new Map();
    const relay = { async post(b, s, v) { m.set(b + "/" + s, v); }, async fetch(b, s) { return m.get(b + "/" + s) || null; } };
    const OFFER = "ab".repeat(32); const intent = { side: 1, price_e9: Math.round(MID * 0.99 * 1e9), size_log2: 200 };
    const d = TP.dealFromOffer({ blockHash: OFFER, intent }, XNO(10));
    const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const pub = Buffer.from(await crypto.subtle.exportKey("raw", kp.publicKey)).toString("hex");
    await relay.post("take-v1:" + OFFER, 0, te.encode(JSON.stringify({ v: 1, pub, deal: d })));
    const M = { derive: async () => ({ send: 0, recv: 1, key: new Uint8Array(32) }), MailboxWire: function () {} };
    const r = await TP.makerPollTake(M, relay, OFFER, intent, (2n ** 200n).toString(),
      async (dl) => TP.certify(dl, false, P(MID * 0.95), { minBps: 30, feeAtomic: "0" }));   // mid fell 5%: B's quote is now a loss
    ok(r && r.declined && !r.wire, "declined (no handshake), reason: " + r.declined);
    { const r0 = m.get("resp-v1:" + OFFER + "/0"); const j = r0 ? JSON.parse(new TextDecoder().decode(r0)) : null;
      ok(j && j.decline && !j.pub, "no HANDSHAKE reply posted - only a typed decline so the taker stops waiting"); }
    const r2 = await TP.makerPollTake(M, relay, OFFER, intent, (2n ** 200n).toString(),
      async (dl) => TP.certify(dl, false, P(MID), { minBps: 30, feeAtomic: "0" }));
    ok(r2 && r2.wire && r2.cert && r2.cert.ok, "same take at a good market: accepted WITH its certificate (" + r2.cert.netBps + " bps)");
  }

  console.log("\n7. minimum viable size is derived from the fee, and it is exact");
  { const price = Math.round(MID * 0.99 * 1e9);          // B at 1% below mid
    const minRaw = TP.minViableXnoRaw(price, false, MID, undefined, 30);
    ok(minRaw !== null, "a positive-spread price has a viable minimum");
    const minXno = Number(BigInt(minRaw) / (10n ** 24n)) / 1e6;
    const at = (x) => TP.partyProfit({ xnoRaw: XNO(x), priceE9: String(price), xmrAtomic: ((BigInt(XNO(x)) * BigInt(price) * 1000n) / (10n ** 30n)).toString() }, false, MID).netBps;
    ok(at(minXno) >= 30 && at(minXno * 0.9) < 30, `min = ${minXno.toFixed(3)} XNO: at min ${at(minXno)} bps (>=30), at 90% of min ${at(minXno*0.9)} bps (<30)`);
    ok(TP.minViableXnoRaw(Math.round(MID * 1.01 * 1e9), false, MID, undefined, 30) === null, "a price that loses at ANY size returns null (B selling above mid)"); }

  console.log("\n8. peekTakes is READ-ONLY, and a decline reaches the taker in seconds");
  { const te = new TextEncoder(); const m = new Map();
    const relay = { async post(b, s, v) { m.set(b + "/" + s, v); }, async fetch(b, s) { return m.get(b + "/" + s) || null; } };
    const OFFER = "cd".repeat(32); const intent = { side: 1, price_e9: Math.round(MID * 0.99 * 1e9), size_log2: 200 };
    const d = TP.dealFromOffer({ blockHash: OFFER, intent }, XNO(40));
    const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const pub = Buffer.from(await crypto.subtle.exportKey("raw", kp.publicKey)).toString("hex");
    await relay.post("take-v1:" + OFFER, 0, te.encode("junk"));
    await relay.post("take-v1:" + OFFER, 1, te.encode(JSON.stringify({ v: 1, pub, deal: d })));
    const rows = await TP.peekTakes(relay, OFFER, intent, (2n ** 200n).toString(), async (dl) => TP.certify(dl, false, P(MID), { minBps: 30, feeAtomic: "0" }));
    ok(rows.length === 2 && rows[0].valid === false && rows[1].valid === true, "peek lists junk as invalid and the honest take as valid");
    ok(rows[1].cert && rows[1].cert.ok && rows[1].cert.netBps > 0, `honest take carries its certificate (${rows[1].cert.netBps} bps)`);
    ok(!m.get("resp-v1:" + OFFER + "/1"), "peek posted NO reply - nothing was committed");
    // Now the maker's gate declines it (market fell): the taker must learn fast.
    const M = { derive: async () => ({ send: 0, recv: 1, key: new Uint8Array(32) }), MailboxWire: function () {} };
    const r = await TP.makerPollTake(M, relay, OFFER, intent, (2n ** 200n).toString(), async (dl) => TP.certify(dl, false, P(MID * 0.95), { minBps: 30, feeAtomic: "0" }));
    ok(r && r.declined, "maker declined on price");
    const resp = m.get("resp-v1:" + OFFER + "/1");
    ok(resp && JSON.parse(new TextDecoder().decode(resp)).decline, "a typed DECLINE was posted on the taker's slot");
    // the taker side: takerHandshake reads that decline and fails in one poll instead of 10 minutes
    const relay2 = { async post(b, s, v) { m.set(b + "/" + s, v); }, async fetch(b, s) { return m.get(b + "/" + s) || null; } };
    m.delete("take-v1:" + OFFER + "/0"); m.delete("take-v1:" + OFFER + "/1");         // fresh slots for the taker
    m.set("resp-v1:" + OFFER + "/0", te.encode(JSON.stringify({ v: 1, decline: "net -404 bps is below the 30 bps required" })));
    const t0 = Date.now(); let err = null;
    try { await TP.takerHandshake(M, relay2, { blockHash: OFFER, intent }, d, () => {}); } catch (e) { err = e; }
    ok(err && err.declined && /maker declined/.test(err.message) && Date.now() - t0 < 5000, "taker fails FAST with the maker's reason: " + (err && err.message)); }

  console.log("\n9. the certify contract shipped with the Hermes skill matches the canonical doc");
  { const fs = require("fs"), path = require("path");
    const root = path.resolve(__dirname, "..");
    const canon = fs.readFileSync(path.join(root, "docs/CERTIFY-PROFIT.md"), "utf8");
    const bundled = fs.readFileSync(path.join(root, "integrations/hermes/references/certify-profit.md"), "utf8");
    ok(canon === bundled, "references/certify-profit.md is byte-identical to docs/CERTIFY-PROFIT.md (no drift)"); }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
function mem() { const m = new Map(); return { get: (k) => (m.has(k) ? m.get(k) : null), set: (k, v) => m.set(k, v) }; }
