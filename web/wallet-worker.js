// NearInstant secure wallet, the key lives ONLY here.
//
// The account's 32-byte seed is a fresh CSPRNG value (unbruteforceable), held
// as a closure variable inside this Web Worker. The DOM cannot read a worker's
// scope, and this worker never postMessages the seed back except on an explicit
// user-initiated "reveal" for backup. At rest the seed is encrypted with an
// Argon2id-derived AES-256-GCM key (memory-hard; a stolen localStorage blob is
// useless without the passphrase). All block signing happens here; the page
// only ever receives the public account and finished, verified signatures.

let seedHex = null; // the account private scalar (hex), worker scope only
let account = null; // public key hex
let address = null; // nano_ address
let wasm = null;    // wasm-bridge (Nano)
let xmr = null;     // wasm-monero (Monero), loaded on demand

// Version the engine imports with the SAME ?v the page gave this worker.
// Without it the browser can cache an old glue JS against a new .wasm binary
// (or vice versa) across deploys — init then throws and everything Monero
// reads "unavailable" until a hard refresh. Passing the versioned binary URL
// into default() versions the .wasm fetch too.
const ENGINE_V = (self.location && self.location.search) || "";
async function ensureWasm() {
  if (wasm) return wasm;
  const m = await import("./pkg/wasm_bridge.js" + ENGINE_V);
  await m.default("./pkg/wasm_bridge_bg.wasm" + ENGINE_V);
  wasm = m;
  return wasm;
}
async function ensureXmr() {
  if (xmr) return xmr;
  const m = await import("./pkg-xmr/wasm_monero.js" + ENGINE_V);
  await m.default("./pkg-xmr/wasm_monero_bg.wasm" + ENGINE_V);
  xmr = m;
  return xmr;
}
// The Monero network chosen by the page ("mainnet" | "stagenet" | "testnet").
let xmrNet = "mainnet";
// The SAME wallet seed derives the Monero identity, one wallet, two coins.
// Keys stay in this worker; only the address is handed to the page.
async function xmrIdentity() {
  if (seedHex === null) throw new Error("wallet is locked");
  const x = await ensureXmr();
  return JSON.parse(x.xmr_personal(hexToBytes(seedHex), xmrNet));
}
// A fetch-backed transport for the wasm Monero daemon client (worker has fetch).
function xmrRouteTimeout(route) {
  // get_output_distribution.bin (decoy selection) returns a large payload public
  // nodes are slow to serve — a flat 12 s timeout made ALL nodes "fail" and the
  // whole lock build die (observed: 2 timeouts + a gateway 502). Give the heavy
  // routes the time they actually need; keep the default snappy.
  if (/get_output_distribution/.test(route)) return 90000;
  if (/get_blocks/.test(route)) return 45000;
  return 12000;
}
function xmrPost(node) {
  const base = String(node).replace(/\/+$/, "");
  return async (route, body) => {
    const isJson = body.length && (body[0] === 0x7b || body[0] === 0x5b);
    // Time out a stalled node instead of deadlocking the worker forever.
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), xmrRouteTimeout(route));
    try {
      const r = await fetch(base + "/" + route, {
        method: "POST", body, signal: ctrl.signal,
        headers: { "content-type": isJson ? "application/json" : "application/octet-stream" },
      });
      if (!r.ok) throw new Error("HTTP " + r.status);
      return new Uint8Array(await r.arrayBuffer());
    } catch (e) {
      throw new Error(e && e.name === "AbortError" ? "Monero node timed out (" + base + ")" : (e && e.message || String(e)));
    } finally { clearTimeout(t); }
  };
}

// --- base64 helpers (worker has atob/btoa) ---
function b64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function unb64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function hexToBytes(h) {
  const a = new Uint8Array(h.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
  return a;
}

const MEM_KIB = 64 * 1024; // 64 MiB Argon2id, above the OWASP floor, for at-rest key

async function aesKeyFrom(passphrase, saltBytes) {
  const w = await ensureWasm();
  const raw = w.argon2id_raw(passphrase, saltBytes, MEM_KIB);
  if (!raw || raw.length !== 32) throw new Error("key derivation failed");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function setSeed(hex) {
  const w = await ensureWasm();
  const info = JSON.parse(w.seed_account(hex));
  if (!info || !info.pubkey) throw new Error("invalid seed");
  seedHex = hex;
  account = info.pubkey;
  address = info.address;
  return { account, address };
}

async function createWallet(passphrase) {
  const w = await ensureWasm();
  // Fresh account key = a canonical ed25519 scalar from the CSPRNG.
  const gen = JSON.parse(w.gen_identity());
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await aesKeyFrom(passphrase, salt);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, hexToBytes(gen.seed))
  );
  const pub = await setSeed(gen.seed);
  return {
    cipher: { v: 1, mem: MEM_KIB, salt: b64(salt), iv: b64(iv), ct: b64(ct) },
    ...pub,
  };
}

async function unlockWallet(cipher, passphrase) {
  const key = await aesKeyFrom(passphrase, unb64(cipher.salt));
  let pt;
  try {
    pt = new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(cipher.iv) }, key, unb64(cipher.ct))
    );
  } catch (e) {
    throw new Error("wrong passphrase");
  }
  let hex = "";
  for (let i = 0; i < pt.length; i++) hex += pt[i].toString(16).padStart(2, "0");
  return setSeed(hex);
}

// Import an existing NearInstant seed (64 hex). Re-encrypts under the passphrase.
async function importWallet(seedIn, passphrase) {
  const hex = String(seedIn || "").trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error("seed must be 64 hex characters");
  const w = await ensureWasm();
  // seed_account returns "" for a hex string that is not a valid account seed
  // (e.g. a canonical-scalar range failure) — guard so the user gets a clear
  // message instead of a cryptic JSON parse error.
  const acctJson = w.seed_account(hex);
  if (!acctJson || !JSON.parse(acctJson).pubkey) throw new Error("not a valid account seed");
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await aesKeyFrom(passphrase, salt);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, hexToBytes(hex))
  );
  const pub = await setSeed(hex);
  return { cipher: { v: 1, mem: MEM_KIB, salt: b64(salt), iv: b64(iv), ct: b64(ct) }, ...pub };
}

function signBlock(block) {
  if (seedHex === null) throw new Error("wallet is locked");
  const out = wasm.sign_state_block(
    seedHex, block.previous, block.representative, block.balance, block.link, block.subtype);
  if (!out) throw new Error("refused to sign (invalid block fields)");
  return JSON.parse(out);
}

function lock() {
  seedHex = null;
  account = null;
  address = null;
}

self.onmessage = async (e) => {
  const { id, type, payload } = e.data || {};
  const reply = (ok, data) => self.postMessage({ id, ok, data });
  try {
    switch (type) {
      case "create": reply(true, await createWallet(payload.passphrase)); break;
      case "unlock": reply(true, await unlockWallet(payload.cipher, payload.passphrase)); break;
      case "import": reply(true, await importWallet(payload.seed, payload.passphrase)); break;
      case "sign": reply(true, { signed: signBlock(payload.block) }); break;
      case "account": reply(true, { account, address, locked: seedHex === null }); break;
      case "reveal": // explicit, user-initiated backup ONLY
        if (seedHex === null) throw new Error("wallet is locked");
        reply(true, { seed: seedHex });
        break;
      case "lock": lock(); reply(true, {}); break;

      // ---- Monero (same seed, keys confined here) ----
      case "xmr_config": xmrNet = payload.network || "mainnet"; reply(true, { network: xmrNet }); break;
      case "xmr_account": {
        const id = await xmrIdentity();
        reply(true, { address: id.address }); // public address only
        break;
      }
      case "xmr_reveal": { // explicit backup: the Monero spend key (Cake-importable)
        const id = await xmrIdentity();
        reply(true, { spend_secret: id.spend_secret, view_key: id.view_key, address: id.address });
        break;
      }
      case "xmr_scan": {
        const x = await ensureXmr();
        const id = await xmrIdentity();
        const node = await x.XmrNode.connect(xmrPost(payload.node));
        const tip = await node.height();
        if (payload.from == null) { reply(true, { outputs: [], scannedTo: tip, tip }); break; }
        const from = Math.max(0, payload.from | 0);
        const to = Math.min(tip - 1, from + (payload.maxBlocks || 500) - 1);
        const outs = from > to ? [] : JSON.parse(await node.scan_all(
          hexToBytes(id.spend_pub), hexToBytes(id.view_key), from, to, null));
        reply(true, { outputs: outs, scannedTo: (from > to ? tip : to + 1), tip });
        break;
      }
      // Build+sign ONLY. Deliberately split from broadcast: the old combined
      // xmr_send was retried against the next node on any failure, which
      // re-signed a SECOND transaction spending the same key image. If the
      // first node had actually relayed but the reply was lost, that is a
      // double-spend attempt. Sign once, then broadcast the same bytes.
      case "xmr_build": {
        const x = await ensureXmr();
        if (seedHex === null) throw new Error("wallet is locked");
        const id = await xmrIdentity();
        const node = await x.XmrNode.connect(xmrPost(payload.node));
        // payload.inputs = [{output, block}, ...] — multi-input since the
        // wallet's balance is routinely spread across several outputs.
        const signed = JSON.parse(await node.send(
          JSON.stringify(payload.inputs), hexToBytes(id.spend_secret),
          payload.dest, payload.amount, id.address, xmrNet));
        reply(true, { tx: signed.tx, tx_hash: signed.tx_hash, fee: signed.fee, inputs: signed.inputs });
        break;
      }
      // Broadcast already-signed bytes. Safe to retry across nodes: relaying
      // the same transaction twice is a no-op, not a double spend.
      case "xmr_publish": {
        const x = await ensureXmr();
        const node = await x.XmrNode.connect(xmrPost(payload.node));
        const hash = await node.publish(payload.tx);
        reply(true, { tx_hash: hash });
        break;
      }
      default: reply(false, { error: "unknown message type " + type });
    }
  } catch (err) {
    reply(false, { error: String((err && err.message) || err) });
  }
};
