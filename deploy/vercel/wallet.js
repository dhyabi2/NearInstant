// NearInstant secure Nano wallet, main-thread API.
//
// Keys live in wallet-worker.js and never reach this file. Here we orchestrate
// the public operations: read the balance with strict multi-endpoint agreement,
// auto-receive incoming payments, and send (with the block SIGNED in the worker
// and the destination + amount confirmed before signing). Chain access is the
// user's own RPC list; no server of ours is involved.

(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.XnoxmrWallet = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const RAW_PER_XNO = 10n ** 30n;
  const PICO_PER_XMR = 10n ** 12n;
  const XMR_UNLOCK = 10; // confirmations before an output is spendable
  const CIPHER_KEY = "nearinstant_wallet_v1";

  function fmtAtomic(raw, per, dp) {
    const r = BigInt(raw), whole = r / per;
    const frac = (r % per).toString().padStart(String(per).length - 1, "0").slice(0, dp).replace(/0+$/, "");
    return frac ? `${whole}.${frac}` : `${whole}`;
  }
  function parseAtomic(s, per) {
    const m = String(s).trim().match(/^(\d+)(?:\.(\d+))?$/);
    if (!m) throw new Error("enter a number");
    const digits = String(per).length - 1;
    const frac = (m[2] || "").padEnd(digits, "0").slice(0, digits);
    return BigInt(m[1]) * per + BigInt(frac || "0");
  }
  const fmtXmr = (pico) => fmtAtomic(pico, PICO_PER_XMR, 8);
  const parseXmr = (s) => parseAtomic(s, PICO_PER_XMR);

  const hx = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

  // Format raw → XNO string, trimming trailing zeros.
  function fmtXno(raw) {
    const r = BigInt(raw);
    const whole = r / RAW_PER_XNO;
    const frac = (r % RAW_PER_XNO).toString().padStart(30, "0").slice(0, 6).replace(/0+$/, "");
    return frac ? `${whole}.${frac}` : `${whole}`;
  }
  // Parse an XNO decimal string → raw BigInt (throws on garbage).
  function parseXno(s) {
    const m = String(s).trim().match(/^(\d+)(?:\.(\d+))?$/);
    if (!m) throw new Error("enter a number");
    const frac = (m[2] || "").padEnd(30, "0").slice(0, 30);
    return BigInt(m[1]) * RAW_PER_XNO + BigInt(frac || "0");
  }

  function makeWallet(opts) {
    const { wasm, beacon, getEndpoints, getMonero, getMoneroList, workerUrl } = opts;
    // Which node URLs this page may actually open a connection to.
    //
    // The browser will not let an https page talk raw http to a PUBLIC host
    // (mixed content), and it will not let us read ANY cross-origin response
    // that lacks Access-Control-Allow-Origin. Those are enforced by the fetch
    // stack; no page code can opt out, and raw TCP (WICG Direct Sockets) is
    // exposed only to Isolated Web Apps, not to a page served from a domain.
    //
    // Loopback is the exception that matters: Chrome treats http://localhost
    // and http://127.0.0.1 as potentially trustworthy, so they are NOT blocked
    // as mixed content even from the hosted https page. So your OWN monerod,
    // started with --rpc-access-control-origins, is reachable raw over plain
    // http — the fully self-sovereign path, no third-party node at all.
    // Verified in Chrome 151 from https://www.nearinstant.xyz on 2026-08-26.
    const isLoopback = h => h === "localhost" || h === "127.0.0.1" || h === "[::1]" ||
      /^127\./.test(h) || h.endsWith(".localhost");
    const usableNode = u => {
      let x; try { x = new URL(String(u || "")); } catch (e) { return false; }
      if (x.protocol === "https:") return true;
      if (x.protocol !== "http:") return false;
      // Raw http is fine to loopback, or when this page is itself plain http
      // (running locally), where there is no mixed-content rule to violate.
      return isLoopback(x.hostname) || location.protocol === "http:";
    };
    const moneroNodes = () => {
      const list = getMoneroList ? getMoneroList() : [getMonero && getMonero()];
      return (list || []).filter(usableNode);
    };
    const B = beacon._internals; // rpc, generateWork, processBlock, accountInfoQuorum
    const worker = new Worker(workerUrl || "./wallet-worker.js");
    let seq = 0;
    const pending = new Map();
    worker.onmessage = (e) => {
      const { id, ok, data } = e.data || {};
      const p = pending.get(id);
      if (!p) return;
      pending.delete(id);
      ok ? p.resolve(data) : p.reject(new Error(data && data.error));
    };
    const call = (type, payload) =>
      new Promise((resolve, reject) => {
        const id = ++seq;
        pending.set(id, { resolve, reject });
        worker.postMessage({ id, type, payload });
      });

    let account = null, address = null, ws = null, idleTimer = null;

    // ---- user-gesture gate for secret egress (defense-in-depth) ----
    // The seed / spend-key backup is the only path that hands a private key to
    // the page. `lastGesture` lives in THIS closure (an injected same-realm
    // script cannot write it) and is bumped only by *trusted* user input, so a
    // silent script cannot trigger a backup with no interaction. (A complete fix
    // also keeps walletApi out of global reach; this raises the bar meanwhile.)
    let lastGesture = 0;
    try {
      const bump = (e) => { if (e && e.isTrusted) lastGesture = Date.now(); };
      ["pointerdown", "mousedown", "keydown", "touchstart"].forEach(
        ev => self.addEventListener(ev, bump, true));
    } catch (e) {}
    function requireGesture() {
      if (Date.now() - lastGesture > 3000)
        throw new Error("for your safety, a backup must be triggered by tapping the button yourself");
    }

    // ---- at-rest cipher (public: it's useless without the passphrase) ----
    function loadCipher() {
      try { const v = localStorage.getItem(CIPHER_KEY); return v ? JSON.parse(v) : null; }
      catch (e) { return null; }
    }
    function saveCipher(c) { try { localStorage.setItem(CIPHER_KEY, JSON.stringify(c)); } catch (e) {} }

    // ---- idle auto-lock ----
    // keepAlive suspends the idle auto-lock so an unattended "keep earning" run
    // (Smart Offer) can keep the wallet unlocked for long periods. It is opt-in
    // and only meant for a device the owner controls; turning it off restores
    // the normal 15-minute idle lock.
    let keepAlive = false;
    function armIdle(ms) {
      clearTimeout(idleTimer);
      if (keepAlive) return;                       // suspended while keep-earning
      idleTimer = setTimeout(() => api.lock(), ms || 15 * 60 * 1000);
    }

    // ---- receive: pocket every receivable, signing each block in the worker ----
    async function receive(onProgress) {
      const urls = getEndpoints();
      const info = await beacon.accountInfo(urls, address); // quorum read
      let frontier = info ? info.frontier : "0".repeat(64);
      let balance = info ? BigInt(info.balance) : 0n;
      let rep = account;
      if (info && info.representative) {
        const pk = wasm.nano_address_decode(info.representative);
        if (pk.length === 32) rep = hx(pk);
      }
      const rcv = await B.rpc(urls, { action: "receivable", account: address, count: "20", threshold: "1" });
      const blocks = rcv && rcv.blocks && typeof rcv.blocks === "object" ? rcv.blocks : {};
      let pocketed = 0n;
      for (const [sendHash, amount] of Object.entries(blocks)) {
        const amt = BigInt(typeof amount === "object" ? amount.amount : amount);
        const isOpen = frontier === "0".repeat(64);
        balance += amt;
        const { signed } = await call("sign", {
          block: { previous: frontier, representative: rep, balance: balance.toString(),
            link: sendHash.toLowerCase(), subtype: isOpen ? "open" : "receive" },
        });
        if (onProgress) onProgress(`receiving ${fmtXno(amt)} XNO…`);
        const work = await B.generateWork(urls, signed.work_root, beacon.THRESH.receive, null);
        frontier = String(await B.processBlock(urls, JSON.stringify(signed), work)).toLowerCase();
        pocketed += amt;
      }
      return { frontier, balance, pocketed };
    }

    const api = {
      hasWallet: () => !!loadCipher(),
      account: () => account,
      address: () => address,

      async create(passphrase) {
        const r = await call("create", { passphrase });
        saveCipher(r.cipher);
        account = r.account; address = r.address; armIdle();
        return { account, address };
      },
      async importSeed(seed, passphrase) {
        const r = await call("import", { seed, passphrase });
        // Safety net: if a different wallet already exists on this device, keep
        // its encrypted blob under a backup key before overwriting, so restoring
        // over the wrong wallet by mistake is recoverable. The backup is still
        // only openable with its own passphrase; erase-all clears it too.
        try {
          const prev = localStorage.getItem(CIPHER_KEY);
          if (prev && prev !== JSON.stringify(r.cipher)) localStorage.setItem(CIPHER_KEY + "_prev", prev);
        } catch (e) {}
        saveCipher(r.cipher);
        account = r.account; address = r.address; armIdle();
        return { account, address };
      },
      async unlock(passphrase) {
        const cipher = loadCipher();
        if (!cipher) throw new Error("no wallet on this device yet, create one");
        const r = await call("unlock", { cipher, passphrase });
        account = r.account; address = r.address; armIdle();
        return { account, address };
      },
      // Suspend/restore the idle auto-lock for unattended keep-earning runs.
      keepAlive(on) { keepAlive = !!on; if (keepAlive) clearTimeout(idleTimer); else armIdle(); },
      async lock() {
        await call("lock", {});
        account = null; address = null;
        clearTimeout(idleTimer);
        // Also drop any remembered passphrase so idle-lock (and manual lock)
        // truly re-locks — not just the in-worker seed.
        try { sessionStorage.removeItem("nearinstant_unlock_sess"); } catch (e) {}
        if (ws) { try { ws.close(); } catch (e) {} ws = null; }
      },
      // Explicit, user-initiated backup, the ONLY path that exposes the seed.
      // Gated on a fresh real gesture so an injected script can't exfiltrate it.
      async revealSeed() { requireGesture(); return (await call("reveal", {})).seed; },

      // Live balance via strict quorum; null balance = unopened (fund it first).
      async balance() {
        const info = await beacon.accountInfo(getEndpoints(), address);
        return info ? { raw: info.balance, xno: fmtXno(info.balance), opened: true }
                    : { raw: "0", xno: "0", opened: false };
      },

      receive,

      // Send: read the balance under quorum, validate the destination and
      // amount, sign in the worker, prove work, broadcast. `amountXno` is a
      // decimal string. Returns the block hash.
      async send(destAddress, amountXno, onProgress) {
        armIdle();
        const urls = getEndpoints();
        const destPk = wasm.nano_address_decode(String(destAddress).trim());
        if (destPk.length !== 32) throw new Error("that is not a valid Nano address");
        const amount = parseXno(amountXno);
        if (amount <= 0n) throw new Error("amount must be more than zero");

        if (onProgress) onProgress(`account_info via quorum of ${urls.length} node(s)…`);
        const info = await beacon.accountInfo(urls, address); // fail-closed on disagreement
        if (!info) throw new Error("this wallet has no funds yet");
        const balance = BigInt(info.balance);
        if (amount > balance) throw new Error(`you only have ${fmtXno(balance)} XNO`);
        if (onProgress) onProgress(`frontier ${String(info.frontier).slice(0, 10)}… · bal ${fmtXno(balance)} XNO · signing send block (ed25519-blake2b)…`);
        let rep = account;
        if (info.representative) {
          const pk = wasm.nano_address_decode(info.representative);
          if (pk.length === 32) rep = hx(pk);
        }
        const newBalance = balance - amount;
        const { signed } = await call("sign", {
          block: { previous: info.frontier, representative: rep, balance: newBalance.toString(),
            link: hx(destPk), subtype: "send" },
        });
        if (onProgress) onProgress(`work_generate: threshold ${beacon.THRESH.send.toString(16)} (RPC/local PoW)…`);
        const work = await B.generateWork(urls, signed.work_root, beacon.THRESH.send,
          (n) => onProgress && onProgress(`work_generate (local PoW): ${(n / 1e6).toFixed(1)}M hashes…`));
        if (onProgress) onProgress(`process (state/send) → broadcasting to ${urls.length} node(s)…`);
        const hash = await B.processBlock(urls, JSON.stringify(signed), work);
        if (onProgress) onProgress(`nano send confirmed ✓ block ${String(hash).slice(0, 12)}…`);
        return String(hash);
      },

      // Auto-receive the instant a deposit confirms (no polling). Best-effort:
      // if the websocket is unreachable, callers still have receive()/refresh.
      liveReceive(onIncoming) {
        if (!address) return;
        try { ws = new WebSocket("wss://ws.nano.to"); } catch (e) { return; }
        const pk = account.toLowerCase();
        ws.onopen = () => ws.send(JSON.stringify({
          action: "subscribe", topic: "confirmation", options: { accounts: [address] } }));
        ws.onmessage = async (ev) => {
          try {
            const raw = ev.data instanceof Blob ? await ev.data.text() : ev.data;
            const d = JSON.parse(raw);
            if (d && d.topic === "confirmation" &&
                String(d.message?.block?.link || "").toLowerCase() === pk &&
                BigInt(d.message?.amount || "0") > 0n) {
              await receive();
              if (onIncoming) onIncoming();
            }
          } catch (e) { /* ignore malformed */ }
        };
      },

      // ===================== MONERO (same wallet, same seed) =====================
      async xmrConfigure(network) { await call("xmr_config", { network: network || "mainnet" }); },
      async xmrAddress() { return (await call("xmr_account", {})).address; },
      // Explicit backup: the Monero spend key (importable into Cake etc.).
      // Gated on a fresh real gesture (see requireGesture) like revealSeed.
      async xmrReveal() { requireGesture(); return call("xmr_reveal", {}); },

      // Incremental view-key scan → spendable balance. Persists found outputs,
      // a scanned-to checkpoint and a spent-set per address in localStorage
      // (none of it secret). onProgress reports catch-up scanning.
      // opts.maxChunks bounds how much a single call scans, so a background
      // tick can make steady progress without blocking the UI for minutes.
      async xmrRefresh(onProgress, opts) {
        const addr = await this.xmrAddress();
        const nodes = moneroNodes();
        if (!nodes.length) throw new Error("no Monero connection set (Settings)");
        // Try each Monero node in turn; if one stalls/times out, move to the next
        // so a single bad node can't freeze the scan.
        let ni = 0;
        const host = (u) => { try { return new URL(u).host; } catch (e) { return String(u); } };
        const scan = async (payload) => {
          let lastErr = "no Monero node answered";
          for (let tries = 0; tries < nodes.length; tries++) {
            try { return await call("xmr_scan", Object.assign({ node: nodes[ni] }, payload)); }
            catch (e) {
              lastErr = e && e.message || String(e);
              if (onProgress) onProgress(`xmr node ${host(nodes[ni])} failed: ${lastErr} → failover`);
              ni = (ni + 1) % nodes.length;
            }
          }
          throw new Error(lastErr);
        };
        const KEY = "nearinstant_xmr_" + addr;
        let st;
        try { st = JSON.parse(localStorage.getItem(KEY)) || null; } catch (e) { st = null; }
        if (!st) st = { restore: null, scannedTo: null, outputs: [], spent: [] };
        const save = () => { try { localStorage.setItem(KEY, JSON.stringify(st)); } catch (e) {} };

        if (st.scannedTo == null) {
          if (onProgress) onProgress(`get_info/get_height via ${host(nodes[ni])}…`);
          const r = await scan({ from: null });   // returns the chain tip
          // Start ~6 days back so a recently-funded deposit is found without a
          // manual rescan; older deposits still use "Rescan from block".
          const LOOKBACK = 4320;
          st.restore = Math.max(0, r.tip - LOOKBACK); st.scannedTo = st.restore; save();
        }
        let tip = st.scannedTo;
        const start = st.restore != null ? st.restore : st.scannedTo;   // for a % that means something
        let found0 = st.outputs.length;
        const maxChunks = (opts && opts.maxChunks) || 5000;
        for (let guard = 0; guard < maxChunks; guard++) {
          const from0 = st.scannedTo;
          const r = await scan({ from: st.scannedTo, maxBlocks: 20 });
          tip = r.tip;
          for (const o of r.outputs) if (!st.outputs.some(x => x.index === o.index)) st.outputs.push(o);
          st.scannedTo = r.scannedTo; save();
          if (onProgress) {
            const total = Math.max(1, r.tip - start), done = Math.max(0, r.scannedTo - start);
            const pct = Math.min(100, Math.round(done / total * 100));
            const left = Math.max(0, r.tip - r.scannedTo);
            const got = st.outputs.length ? ` · ${st.outputs.length} output(s)` : "";
            onProgress(left > 0
              ? `scan_all [${from0.toLocaleString()}→${r.scannedTo.toLocaleString()}] via ${host(nodes[ni])} · ${pct}% · ${left.toLocaleString()} blk left${got}`
              : `scan done · tip ${r.tip.toLocaleString()} · ${st.outputs.length} output(s)${got}`);
          }
          if (r.scannedTo >= r.tip) break;
        }
        st.caughtUp = st.scannedTo >= tip;
        const spent = new Set(st.spent);
        let total = 0n, spendable = 0n;
        for (const o of st.outputs) {
          if (spent.has(o.index)) continue;
          const amt = BigInt(o.amount);
          total += amt;
          if (tip - o.block >= XMR_UNLOCK) spendable += amt;
        }
        return { total: fmtXmr(total), spendable: fmtXmr(spendable),
          pending: total > spendable, tip, state: st,
          caughtUp: st.scannedTo >= tip, behind: Math.max(0, tip - st.scannedTo) };
      },

      // Reset the Monero scan to start at `height` (e.g. the block the wallet
      // was funded at) and rescan, so a deposit that landed before the first
      // scan is picked up. Clears the cached outputs/spent-set for this address.
      async xmrRescanFrom(height, onProgress) {
        const addr = await this.xmrAddress();
        const h = Math.max(0, parseInt(height, 10) || 0);
        try {
          localStorage.setItem("nearinstant_xmr_" + addr,
            JSON.stringify({ restore: h, scannedTo: h, outputs: [], spent: [] }));
        } catch (e) {}
        return this.xmrRefresh(onProgress);
      },

      // Send Monero: pick a spendable (unlocked, unspent) output that can cover
      // the amount, sign + broadcast in the worker (change returns to self),
      // and mark the input spent. `amountXmr` is a decimal string.
      async xmrSend(destAddress, amountXmr, onProgress) {
        const dest = String(destAddress).trim();
        // Monero base58 alphabet (no 0 O I l); the worker is authoritative on
        // network + checksum, this is just an early sanity check.
        if (!/^[1-9A-HJ-NP-Za-km-z]{95,106}$/.test(dest)) throw new Error("that is not a valid Monero address");
        const amount = parseXmr(amountXmr);
        if (amount <= 0n) throw new Error("amount must be more than zero");

        const bal = await this.xmrRefresh(onProgress);
        const st = bal.state, nodes = moneroNodes();
        const spent = new Set(st.spent);
        // Multi-input selection. This used to demand ONE output covering the
        // whole amount, so a wallet funded by two deposits could not spend its
        // balance at all. Now we accumulate.
        //
        // Smallest-first: it consolidates dust over time and avoids the
        // privacy anti-pattern of always spending the largest output. The fee
        // reserve grows with the input count because each input adds weight;
        // the builder is still authoritative and fails closed if we undershoot.
        const FEE_BASE = 100000000n;       // ~0.0001 XMR
        const FEE_PER_INPUT = 30000000n;   // ~0.00003 XMR per additional input
        const MAX_INPUTS = 16;             // must match wasm-monero MAX_INPUTS
        const spendable = st.outputs
          .filter(o => !spent.has(o.index) && bal.tip - o.block >= XMR_UNLOCK)
          .sort((a, b) => (BigInt(a.amount) > BigInt(b.amount) ? 1 : -1));   // ascending
        const chosen = [];
        let sum = 0n;
        for (const o of spendable) {
          chosen.push(o); sum += BigInt(o.amount);
          if (sum >= amount + FEE_BASE + FEE_PER_INPUT * BigInt(chosen.length)) break;
          if (chosen.length >= MAX_INPUTS) break;
        }
        const need = amount + FEE_BASE + FEE_PER_INPUT * BigInt(Math.max(1, chosen.length));
        if (!chosen.length || sum < need) {
          const have = fmtXmr(spendable.reduce((a, o) => a + BigInt(o.amount), 0n));
          throw new Error(chosen.length >= MAX_INPUTS
            ? `your balance is split across too many small outputs (max ${MAX_INPUTS} per send) — send a smaller amount first to consolidate`
            : `not enough spendable XMR: need about ${fmtXmr(need)} including fee, ${have} is unlocked and unspent`);
        }
        const pick = chosen[0];   // representative, for progress messages
        const host2 = (u) => { try { return new URL(u).host; } catch (e) { return String(u); } };

        // PHASE 1 — build and sign EXACTLY ONCE. Failing over here is safe
        // because nothing has been broadcast yet.
        let signed = null, lastErr = "no Monero node answered";
        for (let i = 0; i < nodes.length; i++) {
          if (onProgress) onProgress(`building via ${host2(nodes[i])}: ${chosen.length} input${chosen.length > 1 ? "s" : ""} (from block ${pick.block}), CLSAG+BP+ with real decoys…`);
          try { signed = await call("xmr_build", { node: nodes[i], inputs: chosen.map(o => ({ output: o.output, block: o.block })), dest, amount: amount.toString() }); break; }
          catch (e) { lastErr = e && e.message || String(e); if (onProgress) onProgress(`xmr node ${host2(nodes[i])} failed: ${lastErr} → failover`); }
        }
        if (!signed) throw new Error(lastErr);

        // PHASE 2 — mark the input spent BEFORE broadcasting. If we crash
        // between relay and write, the alternative is re-spending a key image
        // we already published. A false positive only hides an output until
        // the next rescan (Wallet → rescan clears the spent set); a false
        // negative produces a double-spend attempt. Fail safe, not sorry.
        if (signed.fee && onProgress) onProgress(`network fee for this send: ${fmtXmr(BigInt(signed.fee))} XMR (${signed.inputs} input${signed.inputs > 1 ? "s" : ""})`);
        for (const o of chosen) st.spent.push(o.index);
        try { localStorage.setItem("nearinstant_xmr_" + (await this.xmrAddress()), JSON.stringify(st)); } catch (e) {}

        // PHASE 3 — broadcast the SAME signed bytes. Relaying one transaction
        // to several nodes is a no-op on the network, so this retry is safe.
        let hash = null;
        for (let i = 0; i < nodes.length; i++) {
          if (onProgress) onProgress(`broadcasting via ${host2(nodes[i])}…`);
          try { const p = await call("xmr_publish", { node: nodes[i], tx: signed.tx }); hash = p.tx_hash; break; }
          catch (e) { lastErr = e && e.message || String(e); if (onProgress) onProgress(`broadcast via ${host2(nodes[i])} failed: ${lastErr} → next node`); }
        }
        if (!hash) {
          // The transaction is signed and the input is marked spent. It may or
          // may not have reached the network — never re-sign it; rescan instead.
          throw new Error("signed the transaction but no node accepted the broadcast (" + lastErr
            + "). Tx " + String(signed.tx_hash).slice(0, 12) + "… — check an explorer before retrying, and rescan if it never lands.");
        }
        if (onProgress) onProgress(`xmr broadcast ✓ tx ${String(hash).slice(0, 12)}…`);
        return hash;
      },

      _fmt: fmtXno, _parse: parseXno, _fmtXmr: fmtXmr, _parseXmr: parseXmr,
    };
    return api;
  }

  return { makeWallet, fmtXno, parseXno };
});
