// Stage 6 custody, main-thread API. Wraps the custody Web Worker so the page
// can unlock a passphrase wallet, read its public account, and get blocks
// signed, WITHOUT the seed ever entering the DOM's reach: everything secret
// stays inside the worker. A stable per-account salt is kept in localStorage
// (the salt is not secret; the passphrase is, and it is never stored).

(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.XnoxmrCustodyMain = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  function makeCustody(workerUrl) {
    const worker = new Worker(workerUrl || "./custody-worker.js");
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

    // A non-secret, stable per-page salt (16 random bytes), persisted so the
    // same passphrase always yields the same account on this device.
    function salt() {
      const KEY = "xnoxmr_custody_salt";
      let hexStr = null;
      try { hexStr = localStorage.getItem(KEY); } catch (e) {}
      if (!hexStr) {
        const b = new Uint8Array(16);
        (self.crypto || window.crypto).getRandomValues(b);
        hexStr = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
        try { localStorage.setItem(KEY, hexStr); } catch (e) {}
      }
      const out = new Uint8Array(hexStr.length / 2);
      for (let i = 0; i < out.length; i++) out[i] = parseInt(hexStr.substr(i * 2, 2), 16);
      return out;
    }

    return {
      // Returns the PUBLIC account. The passphrase goes straight to the worker
      // and is never retained here.
      async unlock(passphrase, memKib) {
        const d = await call("unlock", { passphrase, salt: Array.from(salt()), memKib });
        return d.account;
      },
      async account() { return call("account", {}); },
      async sign(block) { return (await call("sign", { block })).signed; },
      async lock() { return call("lock", {}); },
      terminate() { worker.terminate(); },
    };
  }

  return { makeCustody };
});
