// Server-side Nano proof-of-work proxy — the ONLY backend function.
//
// It exists so the browser never has to grind PoW locally (slow) and never
// sees the upstream API key. It forwards a single, tightly-validated
// `work_generate` request to the upstream Nano RPC using a key kept in a
// Vercel environment variable. It does nothing else: no account reads, no
// broadcast, no key material, no personal data — the only input is a block
// ROOT HASH (public, non-identifying) and an optional difficulty.
//
// Env: NANO_WORK_KEY (secret, set in Vercel — never in git),
//      NANO_WORK_UPSTREAM (optional, defaults to https://rpc.nano.to).
const UPSTREAM = process.env.NANO_WORK_UPSTREAM || "https://rpc.nano.to";
const HEX64 = /^[0-9a-fA-F]{64}$/;
const HEX16 = /^[0-9a-fA-F]{16}$/;

function readBody(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => { data += c; if (data.length > 4096) req.destroy(); });
    req.on("end", () => resolve(data));
    req.on("error", () => resolve(""));
  });
}

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "content-type");
  if (req.method === "OPTIONS") { res.statusCode = 204; return res.end(); }
  if (req.method !== "POST") { res.statusCode = 405; return res.end(JSON.stringify({ error: "POST only" })); }

  const key = process.env.NANO_WORK_KEY;
  if (!key) { res.statusCode = 503; return res.end(JSON.stringify({ error: "work proxy not configured" })); }

  let body;
  try { body = JSON.parse((await readBody(req)) || "{}"); } catch (e) { body = {}; }
  const hash = String(body.hash || "").trim();
  if (!HEX64.test(hash)) { res.statusCode = 400; return res.end(JSON.stringify({ error: "hash must be 64 hex chars" })); }
  const payload = { action: "work_generate", hash: hash.toUpperCase() };
  if (body.difficulty && HEX16.test(String(body.difficulty))) payload.difficulty = String(body.difficulty);

  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 20000);
    const r = await fetch(UPSTREAM, {
      method: "POST",
      headers: { "content-type": "application/json", key },
      body: JSON.stringify(payload),
      signal: ctrl.signal,
    }).finally(() => clearTimeout(t));
    const j = await r.json();
    if (!j || !j.work) { res.statusCode = 502; return res.end(JSON.stringify({ error: "upstream returned no work", detail: j && j.error })); }
    res.statusCode = 200;
    return res.end(JSON.stringify({ work: j.work, difficulty: j.difficulty }));
  } catch (e) {
    res.statusCode = 502;
    return res.end(JSON.stringify({ error: "work proxy failed: " + (e && e.message || String(e)) }));
  }
};
