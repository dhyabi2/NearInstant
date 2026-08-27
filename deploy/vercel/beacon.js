// beacon.js, Stage 4: the Nano-block order beacon, in the browser.
//
// Serverless order discovery on the Nano ledger itself (mirrors
// dex_core::beacon via the wasm exports, the codec is the SAME Rust code,
// cross-checked bit-for-bit in wasm-bridge's native tests):
//
//   - everyone derives the same namespace burn account per (pair, side);
//   - publishing an order intent = one dust send to it (the send IS the
//     message; the amount IS the payload);
//   - scanning = the `receivable` RPC on that account, junk skipped by
//     checksum. No relay, no server, nothing to censor.
//
// Publishing needs real Nano proof-of-work: we first ask the user's own RPC
// list (`work_generate`, many nodes refuse it), then fall back to REAL
// in-browser PoW via the wasm engine, chunked so the UI stays alive. The
// browser identity seed doubles as a normal Nano account: fund its address
// with a little Nano and this module pockets it and publishes from it.
//
// Works in the browser and in Node (pass fetch + the pkg-node wasm) for the
// test in web/beacon_flow.cjs.
"use strict";
(function () {
  const THRESH = { send: 0xfffffff800000000n, receive: 0xfffffe0000000000n };

  function hex(u8) {
    return Array.from(u8).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  // Try each RPC endpoint in order; first well-formed answer wins.
  async function rpc(urls, body, fetchFn) {
    const f = fetchFn || fetch;
    let lastErr = "no Nano connection configured";
    for (const url of urls) {
      // Per-endpoint timeout so a node that connects then stalls doesn't hang
      // the whole app — abort and fail over to the next endpoint.
      const ctrl = (typeof AbortController !== "undefined") ? new AbortController() : null;
      const t = ctrl ? setTimeout(() => ctrl.abort(), 10000) : null;
      try {
        const r = await f(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
          signal: ctrl ? ctrl.signal : undefined,
        });
        if (!r.ok) { lastErr = "HTTP " + r.status; continue; }
      const j = await r.json();
        // Some public nodes (e.g. rpc.nano.to when rate-limited) answer HTTP 200
        // with an error BODY like {"error":429,"message":"IP banned…"}. Treat a
        // ban/overload body as a node failure and fail over, but let benign
        // query errors ("Account not found", "Bad account number") pass through.
        if (j && j.error !== undefined) {
          const em = String(j.message || j.error);
          if (typeof j.error === "number" || /ban|abuse|rate|too many|429|busy|overload|unavailable|penalty|limit/i.test(em)) {
            lastErr = "node busy/banned: " + em; continue;
          }
        }
        return j;
      } catch (e) { lastErr = (e && e.name === "AbortError") ? ("timeout " + url) : String(e && e.message || e); }
      finally { if (t) clearTimeout(t); }
    }
    throw new Error("all Nano connections failed: " + lastErr);
  }

  function makeBeacon(wasm, opts) {
    opts = opts || {};
    const fetchFn = opts.fetch;
    // Absolute base for the PoW proxy. In a browser this is "" (same origin).
    // Headless (Node) there IS no origin, so the relative "/api/work" is
    // unreachable and every block silently fell back to in-process wasm PoW —
    // measured at ~156 s per send block, which makes an unattended maker that
    // re-posts on a cadence completely unusable. Pass opts.workUrl (or set
    // XNOXMR_WORK_URL) to point at the deployed proxy instead.
    const workBase = opts.workUrl
      || (typeof process !== "undefined" && process.env && process.env.XNOXMR_WORK_URL)
      || null;
    const yieldFn = opts.yield || (() => new Promise(r => setTimeout(r, 0)));
    const rand64 = () => {
      const b = new Uint8Array(8);
      (globalThis.crypto || require("crypto").webcrypto).getRandomValues(b);
      return BigInt("0x" + hex(b));
    };

    // Real Nano PoW: RPC first, in-browser wasm fallback (chunked).
    async function generateWork(urls, rootHex, threshold, onProgress) {
      const diffHex = threshold.toString(16).padStart(16, "0");
      let localOnly = false;
      try { localOnly = (typeof localStorage !== "undefined") && localStorage.getItem("xnoxmr_pow_local") === "1"; } catch (e) {}
      // 1) Same-origin PoW proxy (/api/work) — a tiny Vercel function that holds
      //    the upstream key server-side and returns GPU work in ~1s. Only a
      //    block root hash leaves the browser (public, non-identifying).
      try {
        if (localOnly) throw new Error("local-only");
        const base = workBase
          || ((typeof self !== "undefined" && self.location && self.location.origin) || "");
        if (!base && typeof self === "undefined") throw new Error("no work proxy configured");
        const r = await (fetchFn || fetch)(base.replace(/\/+$/, "") + "/api/work", {
          method: "POST", headers: { "content-type": "application/json" },
          body: JSON.stringify({ hash: rootHex.toUpperCase(), difficulty: diffHex }),
        });
        if (r && r.ok) {
          const j = await r.json();
          if (j && j.work && wasm.work_check(fromHex(rootHex), BigInt("0x" + j.work), threshold)) return j.work;
        }
      } catch (e) { /* fall through */ }
      // 2) work_generate on the configured Nano nodes (most public ones deny it).
      try {
        const j = await rpc(urls, {
          action: "work_generate", hash: rootHex.toUpperCase(), difficulty: diffHex,
        }, fetchFn);
        if (j && j.work && wasm.work_check(fromHex(rootHex), BigInt("0x" + j.work), threshold)) {
          return j.work;
        }
      } catch (e) { /* fall through to in-browser PoW */ }
      const root = fromHex(rootHex);
      const CHUNK = 1n << 17n; // ~130k hashes per slice keeps the UI responsive
      let nonce = rand64(), tried = 0n;
      for (;;) {
        const found = wasm.work_search(root, threshold, nonce, CHUNK);
        if (found !== undefined && found !== null) {
          return found.toString(16).padStart(16, "0");
        }
        nonce = BigInt.asUintN(64, nonce + CHUNK);
        tried += CHUNK;
        if (onProgress) onProgress(Number(tried));
        await yieldFn();
      }
    }

    function fromHex(h) {
      const o = new Uint8Array(h.length / 2);
      for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(i * 2, 2), 16);
      return o;
    }

    // Broadcast to EVERY configured endpoint (idempotent, same block, same
    // hash), so one censoring or flaky node can't stop a publish.
    async function processBlock(urls, signedJson, work) {
      const body = JSON.parse(signedJson).process;
      body.block.work = work;
      let hash = null, lastErr = "no endpoints";
      for (const u of urls) {
        try {
          const j = await rpc([u], body, fetchFn);
          if (j && j.hash) hash = hash || j.hash;
          else lastErr = JSON.stringify(j);
        } catch (e) { lastErr = String(e && e.message || e); }
      }
      if (!hash) throw new Error("no node accepted the block: " + lastErr);
      return hash;
    }

    // Read the account head from up to three endpoints and require the
    // responders to AGREE. Without this a single lying endpoint could
    // under-report the balance and trick us into signing a send that burns
    // the difference into the unspendable namespace account. Disagreement
    // (including opened-vs-unopened) aborts instead of guessing.
    async function accountInfoQuorum(urls, address) {
      // Read the head from a WIDE set of nodes and require two to AGREE, so one
      // lying/under-reporting node can't set the head alone (which could burn
      // funds on a send). Crucially, a node that is rate-limited (HTTP 429,
      // "too many requests") or errored is NOT a vote — only a real frontier or
      // a genuine "account not found" (unopened) counts. Reading only the first
      // 3 nodes, and mis-counting a 429 as an "unopened" vote, is what broke the
      // balance read when the top nodes were rate-limited.
      const list = urls.slice(0, 6);
      const single = urls.length < 2;             // a 1-node config trusts its one answer
      const votes = [];                            // {frontier,balance,representative} | null (unopened)
      const key = (v) => (v ? v.frontier + ":" + v.balance : "__unopened__");
      const twoAgree = () => {
        const c = {};
        for (const v of votes) { const k = key(v); (c[k] = c[k] || []).push(v); if (c[k].length >= 2) return { v: c[k][0] }; }
        return null;
      };
      for (const u of list) {
        let j = null;
        try {
          j = await rpc([u], { action: "account_info", account: address, representative: "true" }, fetchFn);
        } catch (e) { continue; }                  // unreachable / timeout / bad response → no vote
        if (j && j.frontier) {
          votes.push({ frontier: j.frontier.toLowerCase(), balance: String(j.balance), representative: j.representative });
        } else if (j && j.error && /not\s*found|unopened|missing/i.test(String(j.error))) {
          votes.push(null);                        // genuinely unopened account
        } else {
          continue;                                // rate-limited / node error → NOT a vote, try the next node
        }
        if (single) return votes[0];               // one configured node: its single answer stands
        const win = twoAgree();
        if (win) return win.v;                      // reached a 2-node agreeing quorum → done (stops early)
      }
      // No agreeing pair.
      if (votes.length === 0) {
        throw new Error("no Nano node answered the balance read — every configured node is unreachable or rate-limited right now. Wait a moment and retry, or add nodes in Settings.");
      }
      if (new Set(votes.map(key)).size > 1) {
        throw new Error("your Nano connections disagree about this account, refusing to sign; check them and try again shortly");
      }
      // Everyone who answered agreed, but fewer than two did (the rest were
      // rate-limited or down) — we still refuse to trust a single reader.
      throw new Error("only one Nano node answered (need 2 agreeing to read safely); the others are rate-limited or down. Retry in a moment, or add more nodes in Settings.");
    }

    // Pocket everything receivable on the identity account (opens it if new).
    // Returns {frontier, balance, representative} ready for a send.
    async function pocketAll(urls, seedHex, onProgress) {
      const acct = JSON.parse(wasm.seed_account(seedHex));
      let frontier = "0".repeat(64), balance = 0n, rep = acct.pubkey;
      const info = await accountInfoQuorum(urls, acct.address);
      if (info) {
        frontier = info.frontier;
        balance = BigInt(info.balance);
        const repPk = wasm.nano_address_decode(info.representative);
        if (repPk.length === 32) rep = hex(repPk);
      }
      const rcv = await rpc(urls, {
        action: "receivable", account: acct.address, count: "20", threshold: "1",
      }, fetchFn);
      const blocks = rcv && rcv.blocks && typeof rcv.blocks === "object" ? rcv.blocks : {};
      for (const [sendHash, amount] of Object.entries(blocks)) {
        const amt = BigInt(typeof amount === "object" ? amount.amount : amount);
        const isOpen = frontier === "0".repeat(64);
        balance += amt;
        const signed = wasm.sign_state_block(
          seedHex, frontier, rep, balance.toString(), sendHash.toLowerCase(),
          isOpen ? "open" : "receive");
        if (!signed) throw new Error("could not sign receive block");
        const parsed = JSON.parse(signed);
        if (onProgress) onProgress("pocketing " + amt + " raw…");
        const work = await generateWork(urls, parsed.work_root, THRESH.receive, null);
        frontier = (await processBlock(urls, signed, work)).toLowerCase();
      }
      return { address: acct.address, pubkey: acct.pubkey, frontier, balance, rep };
    }

    return {
      THRESH,

      // Scan a market side for live order intents. Junk and wrong-side
      // entries are dropped by the codec, duplicates by block hash.
      async scan(urls, pair, side) {
        const account = wasm.beacon_address(pair, side);
        const j = await rpc(urls, {
          action: "receivable", account, count: "100", threshold: "1", source: "true",
        }, fetchFn);
        const blocks = j && j.blocks && typeof j.blocks === "object" ? j.blocks : {};
        const out = [], seen = new Set();
        for (const [blockHash, entry] of Object.entries(blocks)) {
          if (seen.has(blockHash)) continue;
          seen.add(blockHash);
          const amount = typeof entry === "object" ? entry.amount : entry;
          const dec = wasm.beacon_decode(String(amount));
          if (!dec) continue;
          const intent = JSON.parse(dec);
          if (intent.side !== side) continue;
          out.push({
            maker: typeof entry === "object" ? entry.source : null,
            intent, blockHash,
          });
        }
        return out;
      },

      // Live, lifecycle-correct view of a market side. On an account-based
      // ledger you cannot delete a post, so consumers must interpret the LATEST
      // state, exactly as this does:
      //   • keep only the NEWEST offer per maker (a re-post supersedes the old
      //     one) — this is auto-reprice/replace,
      //   • drop offers whose block is older than `ttlSecs` (auto-expiry, so a
      //     maker who vanished stops showing),
      //   • honor a CANCEL sentinel: a maker re-posts price_e9 === 0 to withdraw.
      // Block times come from blocks_info (one extra call). Returned cheapest
      // (lowest XMR/XNO) first. `now` is the JS wall clock in seconds.
      async scanLive(urls, pair, side, ttlSecs, now) {
        const raw = await this.scan(urls, pair, side);
        if (!raw.length) return [];
        // blocks_info gives each offer block its account `height` (a strict
        // per-maker sequence — every offer is a send from the same account, so
        // height only ever increases) and `local_timestamp` (for expiry).
        const meta = {};
        try {
          const j = await rpc(urls, { action: "blocks_info", json_block: "true",
            hashes: raw.map(r => r.blockHash) }, fetchFn);
          const b = j && j.blocks ? j.blocks : {};
          for (const h of Object.keys(b)) meta[h] = {
            height: parseInt(b[h].height || "0", 10) || 0,
            ts: parseInt(b[h].local_timestamp || "0", 10) || 0,
          };
        } catch (e) { /* no meta ⇒ order by height 0, cancel still wins ties */ }
        for (const r of raw) { const m = meta[r.blockHash] || {}; r.height = m.height || 0; r.ts = m.ts || 0; }
        // Newest offer per maker: higher account height wins; on a tie a cancel
        // sentinel (price 0) always wins, so a withdraw is never lost.
        const isCancel = (r) => !r.intent || r.intent.price_e9 === 0;
        const newer = (r, cur) => !cur || r.height > cur.height ||
          (r.height === cur.height && isCancel(r) && !isCancel(cur));
        const byMaker = new Map();
        // Require a maker (source) — without it we can't group offers, honor a
        // cancel, or supersede, so a node that omits `source` could resurrect a
        // withdrawn offer. Fail closed: drop entries with no maker.
        for (const r of raw) { if (!r.maker) continue; if (newer(r, byMaker.get(r.maker))) byMaker.set(r.maker, r); }
        const ttl = ttlSecs || 3600, nowS = now || Math.floor(Date.now() / 1000);
        const live = [];
        for (const r of byMaker.values()) {
          if (isCancel(r)) continue;                            // withdrawn
          // Missing timestamp ⇒ can't prove freshness ⇒ treat as expired (a
          // lying node can't keep a stale offer visible by omitting the time).
          if (!r.ts || (nowS - r.ts) > ttl) continue;           // stale / expired / unknown
          live.push(r);
        }
        // Rank by what the TAKER actually gets, which is side-dependent.
        // Price is XMR-per-XNO. side 0 = maker sells XNO: the taker pays
        // price x amount in XMR, so a LOWER price is better for them.
        // side 1 = maker sells XMR: the taker RECEIVES price x amount in XMR,
        // so a HIGHER price is better. Sorting ascending unconditionally put
        // the taker's WORST offer at row 0 on side 1 - where it was labelled
        // "best" and handed to auto-select.
        live.sort((a, b) => side === 1
          ? b.intent.price_e9 - a.intent.price_e9      // side 1: most XMR received first
          : a.intent.price_e9 - b.intent.price_e9);    // side 0: least XMR paid first
        return live;
      },

      // Publish an order intent: pocket any funding dust first, then send the
      // encoded amount to the namespace account. Returns the beacon block hash.
      async publish(urls, seedHex, pair, intent, onProgress) {
        const amountStr = wasm.beacon_encode(intent.side, BigInt(intent.price_e9), intent.size_log2);
        if (!amountStr) throw new Error("price out of range");
        const st = await pocketAll(urls, seedHex, onProgress);
        if (st.frontier === "0".repeat(64)) {
          throw new Error("fund " + st.address + " with a little Nano first (any tiny amount)");
        }
        const amount = BigInt(amountStr);
        if (st.balance <= amount) throw new Error("balance too low to publish");
        const nsAccount = hex(wasm.beacon_account(pair, intent.side));
        const signed = wasm.sign_state_block(
          seedHex, st.frontier, st.rep, (st.balance - amount).toString(), nsAccount, "send");
        if (!signed) throw new Error("could not sign beacon block");
        const parsed = JSON.parse(signed);
        if (onProgress) onProgress("computing proof-of-work…");
        const work = await generateWork(urls, parsed.work_root, THRESH.send,
          n => onProgress && onProgress("proof-of-work: " + (n / 1e6).toFixed(1) + "M hashes tried…"));
        if (onProgress) onProgress("broadcasting…");
        return processBlock(urls, signed, work);
      },

      // Read the account head with strict multi-endpoint agreement, a lying
      // endpoint that under-reports the balance can't trick a send into burning
      // the difference. Returns {frontier, balance, representative} or null
      // (consistently unopened); throws on disagreement or no answer.
      accountInfo: (urls, address) => accountInfoQuorum(urls, address),

      _internals: {
        rpc: (urls, body) => rpc(urls, body, fetchFn),
        generateWork, pocketAll, processBlock, accountInfoQuorum,
      },
    };
  }

  const API = { makeBeacon, THRESH };
  if (typeof module !== "undefined" && module.exports) module.exports = API;
  if (typeof window !== "undefined") window.XnoxmrBeacon = API;
})();
