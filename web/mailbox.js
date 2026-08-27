// mailbox.js, browser MailboxWire client, WIRE-COMPATIBLE with the Rust
// transport::mailbox (AES-256-GCM + SHA-256), so a browser can run the swap
// ceremony over the same swappable dumb relays as the native helper, with no
// server of ours and no library beyond native WebCrypto. Works in the browser
// (globalThis.crypto.subtle) and in Node (require('crypto').webcrypto) for the
// interop test. See deploy/mailbox_interop_test.sh for the Rust<->JS proof.
"use strict";
(function () {
  const subtle = (globalThis.crypto && globalThis.crypto.subtle) ||
    require("crypto").webcrypto.subtle;
  const te = new TextEncoder();

  function cat(...arrs) {
    let n = 0; for (const a of arrs) n += a.length;
    const o = new Uint8Array(n); let i = 0;
    for (const a of arrs) { o.set(a, i); i += a.length; }
    return o;
  }
  // 8-byte little-endian, matching Rust's seq.to_le_bytes().
  function u64le(n) {
    const b = new Uint8Array(8); let v = BigInt(n);
    for (let i = 0; i < 8; i++) { b[i] = Number(v & 0xffn); v >>= 8n; }
    return b;
  }
  async function sha256(...parts) {
    return new Uint8Array(await subtle.digest("SHA-256", cat(...parts)));
  }
  function hex(u8) {
    return Array.from(u8).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  // derive(shared, i_am_initiator) -> {send, recv, key}, mirrors Rust derive().
  async function derive(shared, initiator) {
    const idA = hex(await sha256(te.encode("xnoxmr-mailbox-id-v1"), te.encode("A"), shared));
    const idB = hex(await sha256(te.encode("xnoxmr-mailbox-id-v1"), te.encode("B"), shared));
    const keyBytes = await sha256(te.encode("xnoxmr-mailbox-key-v1"), shared);
    const key = await subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
    return initiator ? { send: idA, recv: idB, key } : { send: idB, recv: idA, key };
  }
  async function slotNonce(mailbox, seq) {
    const d = await sha256(te.encode("xnoxmr-mailbox-nonce-v1"), te.encode(mailbox), u64le(seq));
    return d.slice(0, 12);
  }
  function aad(mailbox, seq) { return cat(te.encode(mailbox), u64le(seq)); }

  // Dumb HTTP relay: POST /m/{mailbox}/{seq} stores the blob; GET returns it.
  function HttpRelay(base) {
    base = base.replace(/\/+$/, "");
    return {
      async post(mailbox, seq, blob) {
        const r = await fetch(`${base}/m/${mailbox}/${seq}`, {
          method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: blob,
        });
        return r.ok;
      },
      async fetch(mailbox, seq) {
        const r = await fetch(`${base}/m/${mailbox}/${seq}`);
        if (r.status === 404) return null;
        if (!r.ok) throw new Error("relay " + r.status);
        return new Uint8Array(await r.arrayBuffer());
      },
    };
  }

  class MailboxWire {
    constructor(relays, sendBox, recvBox, key) {
      this.relays = relays; this.send_box = sendBox; this.recv_box = recvBox;
      this.key = key; this.sseq = 0; this.rseq = 0; this.pollMs = 500; this.timeoutMs = 120000;
    }
    async send(msg) {
      const seq = this.sseq, nonce = await slotNonce(this.send_box, seq);
      const ct = new Uint8Array(await subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad(this.send_box, seq) }, this.key, msg));
      // WIRE-LEVEL RESILIENCE (root cause of "recv timeout at confirming joint
      // accounts"): a ceremony message is a large multi-chunk on-chain post,
      // and ONE transient failure (stale frontier, node hiccup, PoW blip) used
      // to kill the sender's whole ceremony while the peer waited blind for
      // 240 s. Retrying here is safe by construction: the ciphertext for a
      // given (key, box, seq) is DETERMINISTIC — nonce and AAD derive from the
      // slot — so re-posting after a partial failure re-sends identical bytes.
      let ok = false, lastErr = "all relays failed";
      for (let round = 0; round < 4 && !ok; round++) {
        if (round) await new Promise((r) => setTimeout(r, 3000 * round));
        for (const r of this.relays) { try { if (await r.post(this.send_box, seq, ct)) { ok = true; break; } } catch (e) { lastErr = String(e && e.message || e); } }
      }
      if (!ok) throw new Error("could not deliver a protocol message after 4 rounds (" + lastErr + ")");
      this.sseq = seq + 1;
    }
    async recv() {
      const seq = this.rseq, nonce = await slotNonce(this.recv_box, seq);
      const deadline = Date.now() + this.timeoutMs;
      while (Date.now() < deadline) {
        for (const r of this.relays) {
          let blob = null;
          try { blob = await r.fetch(this.recv_box, seq); } catch (e) {}
          if (blob) {
            // AES-GCM auth binds mailbox+seq via the AAD: a tampered, reordered,
            // or misrouted blob throws (the browser mirror of BadContribution).
            const pt = new Uint8Array(await subtle.decrypt(
              { name: "AES-GCM", iv: nonce, additionalData: aad(this.recv_box, seq) }, this.key, blob));
            this.rseq = seq + 1;
            return pt;
          }
        }
        await new Promise(res => setTimeout(res, this.pollMs));
      }
      throw new Error("recv timeout");
    }
  }

  const API = { derive, HttpRelay, MailboxWire, sha256, slotNonce };
  if (typeof module !== "undefined" && module.exports) module.exports = API;
  if (typeof window !== "undefined") window.XnoxmrMailbox = API;
})();
