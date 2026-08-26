// Stage 6 custody, the pure logic, shared by the Web Worker (custody-worker.js)
// and node tests. Given the wasm-bridge module it turns a passphrase into a
// wallet and signs blocks, WITHOUT ever exposing the seed: the seed lives only
// inside the closure this returns. Nothing here posts the seed anywhere; the
// only outputs are the public account and signatures.

(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.XnoxmrCustody = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // Create a locked vault bound to a wasm-bridge module. The returned object
  // never returns or emits the seed, only `account()` (public) and `sign()`.
  function makeVault(wasm) {
    let seed = null;      // Uint8Array, held ONLY in this closure
    let account = null;   // hex string, public
    let address = null;   // nano_… address, public

    return {
      // Derive the seed from the passphrase (Argon2id) and remember it in
      // closure scope. Returns the PUBLIC account only. `salt` ≥ 8 bytes,
      // stable per account. `memKib` optionally raises the memory cost.
      unlock(passphrase, salt, memKib) {
        const s = wasm.argon2id_seed(passphrase, salt, memKib || 0);
        if (!s || s.length !== 32) throw new Error("could not derive a seed (check the passphrase/salt)");
        seed = s;
        const info = JSON.parse(wasm.seed_account(hx(seed)));
        account = info.pubkey; // 32-byte account public key (hex)
        address = info.address; // nano_… form of the same key
        return account;
      },

      // The public account / address, or null while locked. Never the seed.
      account() { return account; },
      addr() { return address; },
      locked() { return seed === null; },

      // Sign a Nano block. The caller passes ONLY block fields (no key) and a
      // human-checkable manifest describing what is being signed; the vault
      // signs the exact block and returns the process-ready JSON. This is where
      // a per-chunk consent/manifest check belongs, the vault will only ever
      // sign the block it is handed, and the seed never leaves.
      signBlock(block) {
        if (seed === null) throw new Error("vault is locked");
        const out = wasm.sign_state_block(
          hx(seed), block.previous, block.representative, block.balance, block.link, block.subtype);
        if (!out) throw new Error("refused to sign (invalid block fields)");
        return JSON.parse(out);
      },

      // Wipe the seed from memory.
      lock() {
        if (seed) seed.fill(0);
        seed = null;
        account = null;
        address = null;
      },
    };
  }

  function hx(b) {
    let s = "";
    for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
    return s;
  }

  return { makeVault };
});
