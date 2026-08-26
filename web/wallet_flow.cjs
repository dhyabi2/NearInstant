// Proof for the secure-wallet core (the exact crypto wallet-worker.js runs):
// random seed → Argon2id → AES-256-GCM encrypt → decrypt round-trips; the seed
// opens a valid account and signs a valid Nano send; and the at-rest cipher
// blob never contains the seed.
//
//   node web/wallet_flow.cjs
const assert = require("assert");
const { webcrypto } = require("crypto");
const subtle = webcrypto.subtle;
const wasm = require("../swap-core/wasm-bridge/pkg-node/wasm_bridge.js");

const hexToBytes = (h) => Uint8Array.from(Buffer.from(h, "hex"));
const MEM = 64 * 1024;

async function aesKey(pass, salt) {
  const raw = wasm.argon2id_raw(pass, salt, MEM);
  assert.strictEqual(raw.length, 32, "argon2id_raw is 32 bytes");
  return subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

(async () => {
  const PASS = "a strong wallet passphrase 2026!";

  // 1. Create: fresh random account key, encrypted at rest.
  const gen = JSON.parse(wasm.gen_identity());
  assert(/^[0-9a-f]{64}$/.test(gen.seed), "seed is 64 hex");
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const key = await aesKey(PASS, salt);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, hexToBytes(gen.seed)));
  console.log("1) created wallet — seed encrypted at rest (AES-256-GCM, Argon2id key)");

  // 2. The cipher blob must NOT contain the seed.
  const cipher = { v: 1, mem: MEM, salt: Buffer.from(salt).toString("base64"),
    iv: Buffer.from(iv).toString("base64"), ct: Buffer.from(ct).toString("base64") };
  const blob = JSON.stringify(cipher);
  assert(!blob.includes(gen.seed), "seed must not appear in the stored cipher");
  assert(!Buffer.from(cipher.ct, "base64").equals(hexToBytes(gen.seed)), "ciphertext != plaintext seed");
  console.log("2) at-rest blob carries no seed ✓ (only salt/iv/ciphertext)");

  // 3. Unlock: wrong passphrase fails (GCM auth), right one round-trips exactly.
  const wrongKey = await aesKey(PASS + "x", salt);
  await assert.rejects(subtle.decrypt({ name: "AES-GCM", iv }, wrongKey, ct), "wrong passphrase must fail");
  const rightKey = await aesKey(PASS, salt);
  const pt = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv }, rightKey, ct));
  const back = Buffer.from(pt).toString("hex");
  assert.strictEqual(back, gen.seed, "decrypt returns the exact seed");
  console.log("3) wrong passphrase rejected (GCM auth); correct one recovers the exact seed ✓");

  // 4. The seed opens a valid account and signs a valid Nano send block.
  const acct = JSON.parse(wasm.seed_account(back));
  assert(acct.address.startsWith("nano_"), "derives a nano_ address");
  const signed = JSON.parse(wasm.sign_state_block(
    back, "0".repeat(64), acct.pubkey, "1000000000000000000000000000000",
    "1".repeat(64), "open"));
  const sig = hexToBytes(signed.process.block.signature);
  assert(wasm.nano_check(hexToBytes(acct.pubkey), hexToBytes(signed.hash), sig), "signature verifies");
  console.log("4) seed opens", acct.address.slice(0, 16) + "… and signs a valid block ✓");

  console.log("\nOK: secure-wallet core proven — random seed, Argon2id+AES-GCM at rest,");
  console.log("    exact round-trip, valid signing, and no seed in the stored blob.");
})().catch((e) => { console.error("FAIL:", e); process.exit(1); });
