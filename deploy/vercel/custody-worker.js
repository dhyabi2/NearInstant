// Stage 6 custody Web Worker. The wallet seed is derived and used ONLY in this
// worker's scope, the page's DOM/scripts cannot read a Worker's variables, and
// this worker never postMessages the seed back. The main thread gets only the
// public account and finished signatures. Load with:
//   new Worker("custody-worker.js", { type: "module" })  // if using ES import
// This build uses importScripts so it works as a classic worker too.

let vault = null;

async function ensureVault() {
  if (vault) return vault;
  // wasm-bridge (web target) + the shared custody logic.
  importScripts("./custody_core.js");
  const wasm = await import("./pkg/wasm_bridge.js");
  await wasm.default();
  vault = self.XnoxmrCustody.makeVault(wasm);
  return vault;
}

self.onmessage = async (e) => {
  const { id, type, payload } = e.data || {};
  const reply = (ok, data) => self.postMessage({ id, ok, data });
  try {
    const v = await ensureVault();
    switch (type) {
      case "unlock": {
        // salt arrives as a plain array/Uint8Array; never echo the passphrase.
        const salt = Uint8Array.from(payload.salt);
        const account = v.unlock(payload.passphrase, salt, payload.memKib);
        reply(true, { account }); // PUBLIC only, no seed ever crosses back
        break;
      }
      case "account":
        reply(true, { account: v.account(), locked: v.locked() });
        break;
      case "sign":
        reply(true, { signed: v.signBlock(payload.block) });
        break;
      case "lock":
        v.lock();
        reply(true, {});
        break;
      default:
        reply(false, { error: "unknown message type " + type });
    }
  } catch (err) {
    reply(false, { error: String((err && err.message) || err) });
  }
};
