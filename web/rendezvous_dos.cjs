// Regression: a squatter must not be able to DoS a maker by parking junk in the
// rendezvous. Uses the real makerPollTake against an in-memory relay.
const TP = require("./two_party.js");
const te = new TextEncoder();
const M = { derive: async () => ({ send: 0, recv: 1, key: new Uint8Array(32) }),
            MailboxWire: function () {} };
const mkRelay = () => { const m = new Map(); return {
  async post(box, seq, b) { m.set(box + "/" + seq, b); return true; },
  async fetch(box, seq) { return m.get(box + "/" + seq) || null; }, _m: m }; };

const OFFER = "ab".repeat(32);
const REQ = "take-v1:" + OFFER, RESP = "resp-v1:" + OFFER;
const intent = { side: 1, price_e9: 912257, size_log2: 100 };
const maxXno = (2n ** 100n).toString();
const xnoRaw = (10n ** 30n).toString();
const goodDeal = { offerHash: OFFER, side: 1, priceE9: "912257", xnoRaw,
  xmrAtomic: ((BigInt(xnoRaw) * 912257n * 1000n) / (10n ** 30n)).toString() };
// A REAL P-256 public key: the maker performs a genuine ECDH against it.
const hx = b => Buffer.from(b).toString("hex");
let takeReq, badPriceReq;
async function buildRequests() {
  const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const pub = hx(new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)));
  takeReq = te.encode(JSON.stringify({ v: 1, pub, deal: goodDeal }));
  badPriceReq = te.encode(JSON.stringify({ v: 1, pub, deal: { ...goodDeal, priceE9: "999999" } }));
}

let pass = 0, fail = 0;
const ok = (c, m) => { c ? (pass++, console.log("  PASS " + m)) : (fail++, console.log("  FAIL " + m)); };

(async () => {
  await buildRequests();
  console.log("THE ATTACK: junk parked in rendezvous slot 0\n");
  const r = mkRelay();
  await r.post(REQ, 0, te.encode("garbage-not-even-json"));
  let res = await TP.makerPollTake(M, r, OFFER, intent, maxXno);
  ok(res && res.junk === true, "maker reports junk instead of throwing");
  ok(!(res && res.wire), "no handshake produced from junk");

  console.log("\nan HONEST taker arrives while slot 0 is still squatted");
  await r.post(REQ, 1, takeReq);
  res = await TP.makerPollTake(M, r, OFFER, intent, maxXno);
  ok(res && !res.junk && !!res.deal, "maker finds the honest take in slot 1 (was: blocked forever)");
  ok(res && res.deal && res.deal.priceE9 === "912257", "the validated deal is the honest one");
  ok(!!r._m.get(RESP + "/1"), "maker replied on the SAME slot, so the taker sees it");
  ok(!r._m.get(RESP + "/0"), "no reply posted into the squatted slot");

  console.log("\nevery slot squatted");
  const r2 = mkRelay();
  for (let i = 0; i < 8; i++) await r2.post(REQ, i, te.encode("junk" + i));
  ok((await TP.makerPollTake(M, r2, OFFER, intent, maxXno))?.junk === true,
     "reports junk so the caller can rate-limit instead of re-posting forever");

  console.log("\nempty rendezvous");
  ok((await TP.makerPollTake(M, mkRelay(), OFFER, intent, maxXno)) === null,
     "returns null, not junk");

  console.log("\na WRONG-PRICE take is skipped, not fatal");
  const r3 = mkRelay();
  await r3.post(REQ, 0, badPriceReq);
  await r3.post(REQ, 1, takeReq);
  const res3 = await TP.makerPollTake(M, r3, OFFER, intent, maxXno);
  ok(res3 && !!res3.deal && res3.deal.priceE9 === "912257",
     "mispriced request in slot 0 ignored, honest one in slot 1 accepted");

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
