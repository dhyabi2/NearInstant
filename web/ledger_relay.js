// LedgerRelay — an ASYNC, trustless transport that uses the Nano ledger itself
// as the message bus, so the two parties never need to be online at the same
// time (unlike WebRTC). It exposes the SAME post(mailbox,seq,blob) /
// fetch(mailbox,seq) interface as the HTTP/WebRTC relays, so MailboxWire runs
// the existing ceremony over it unchanged. Nothing is stored off-chain: a
// message persists as ordinary (encrypted) on-chain sends until the peer next
// comes online and reads it.
//
// Encoding: a message's bytes are split into 32-byte chunks. Each chunk is one
// send from the poster's funded identity to a mailbox account (a hash of the
// mailbox id — no key needed, it only ever holds readable receivables). The
// 32-byte chunk rides in the block's REPRESENTATIVE field; a packed header
// (magic|seq|idx|total|blobLen) rides in the send AMOUNT — which is negligible
// dust because 1 XNO = 1e30 raw, so a full 64-bit header is < 2e-11 XNO.
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.XnoxmrLedgerRelay = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const MAGIC = 0x5An; // marks our sends in the mailbox account
  const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
  const fromHex = (h) => { const o = new Uint8Array(h.length / 2); for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(i * 2, 2), 16); return o; };

  async function sha256(bytes) {
    const c = (typeof crypto !== "undefined" && crypto.subtle) ? crypto : require("crypto").webcrypto;
    return new Uint8Array(await c.subtle.digest("SHA-256", bytes));
  }
  async function mailboxAccountHex(mailbox) {
    return hex(await sha256(new TextEncoder().encode("xnoxmr-ledger-mailbox-v1:" + mailbox)));
  }

  // header = MAGIC(8) | seq(16) | idx(12) | total(12) | blobLen(16)  → 64 bits
  function packHeader(seq, idx, total, blobLen) {
    return ((MAGIC << 56n) | (BigInt(seq & 0xffff) << 40n) | (BigInt(idx & 0xfff) << 28n)
      | (BigInt(total & 0xfff) << 16n) | BigInt(blobLen & 0xffff)).toString();
  }
  function unpackHeader(amountStr) {
    let v; try { v = BigInt(amountStr); } catch (e) { return null; }
    if ((v >> 56n) !== MAGIC) return null;
    return {
      seq: Number((v >> 40n) & 0xffffn),
      idx: Number((v >> 28n) & 0xfffn),
      total: Number((v >> 16n) & 0xfffn),
      blobLen: Number(v & 0xffffn),
    };
  }

  // makeLedgerRelay({ beacon, wasm, urls, seed })
  //   beacon = XnoxmrBeacon.makeBeacon(wasm,{})  (for _internals: rpc, generateWork,
  //            processBlock, pocketAll, accountInfoQuorum, THRESH)
  //   seed   = the poster's funded Nano identity (omit for a read-only party).
  function makeLedgerRelay(opts) {
    const { beacon, wasm, urls, seed } = opts;
    const I = beacon._internals;

    async function post(mailbox, seq, blob) {
      if (!seed) throw new Error("this LedgerRelay is read-only (no seed)");
      const mbHex = await mailboxAccountHex(mailbox);
      const total = Math.max(1, Math.ceil(blob.length / 32));
      // After a burst of posts the RPC endpoints can briefly disagree on the
      // frontier and the fail-closed quorum (correctly) refuses to sign. Wait
      // and retry a few times rather than failing the whole message.
      let st = null;
      for (let a = 0; a < 6; a++) {
        try { st = await I.pocketAll(urls, seed); break; }
        catch (e) { if (!/disagree|failed/i.test(String(e.message)) || a === 5) throw e; await new Promise(r => setTimeout(r, 4000)); }
      }
      let prev = st.frontier, bal = BigInt(st.balance);
      for (let idx = 0; idx < total; idx++) {
        const chunk = new Uint8Array(32);
        chunk.set(blob.subarray(idx * 32, idx * 32 + 32));
        const amount = BigInt(packHeader(seq, idx, total, blob.length));
        bal = bal - amount;
        if (bal < 0n) throw new Error("identity balance too low to post");
        const signed = wasm.sign_state_block(seed, prev, hex(chunk), bal.toString(), mbHex, "send");
        if (!signed) throw new Error("could not sign chunk " + idx);
        const work = await I.generateWork(urls, JSON.parse(signed).work_root, beacon.THRESH.send, null);
        prev = await I.processBlock(urls, signed, work);
      }
      return true;
    }

    // Return the reassembled blob for (mailbox, seq), or null if not all chunks
    // are visible yet (caller polls, exactly like the other relays' fetch).
    async function fetch(mailbox, seq) {
      const mbAddr = wasm.nano_address_encode(fromHex(await mailboxAccountHex(mailbox)));
      const j = await I.rpc(urls, { action: "receivable", account: mbAddr, count: "500", threshold: "1", source: "true" });
      const blocks = j && j.blocks && typeof j.blocks === "object" ? j.blocks : {};
      const want = [];
      for (const [hash, entry] of Object.entries(blocks)) {
        const amount = typeof entry === "object" ? entry.amount : entry;
        const h = unpackHeader(String(amount));
        if (h && h.seq === seq) want.push({ hash, ...h });
      }
      if (!want.length) return null;
      const total = want[0].total, blobLen = want[0].blobLen;
      if (want.length < total) return null;                 // still arriving
      const info = await I.rpc(urls, { action: "blocks_info", json_block: "true", hashes: want.map(w => w.hash) });
      const bi = info && info.blocks ? info.blocks : {};
      const out = new Uint8Array(total * 32);
      let have = 0;
      for (const w of want) {
        const b = bi[w.hash];
        if (!b || !b.contents || !b.contents.representative) continue;
        const chunk = wasm.nano_address_decode(b.contents.representative);
        if (chunk.length !== 32) continue;
        out.set(chunk, w.idx * 32); have++;
      }
      if (have < total) return null;
      return out.subarray(0, blobLen);
    }

    return { post, fetch, mailboxAccountHex };
  }

  return { makeLedgerRelay, _packHeader: packHeader, _unpackHeader: unpackHeader, _mailboxAccountHex: mailboxAccountHex };
});
