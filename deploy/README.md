# Deployment

The product is a single self-contained static page (`web/index.html`) plus the
browser engine files it lazy-loads (`web/*.js`, `web/pkg*/`). There is **no
backend**: no server of ours, no functions, no environment variables. Matching,
messaging and settlement run in the two users' browsers against the public
Nano and Monero networks.

## Ship to production (Vercel, static hosting only)

```
bash deploy/vercel_deploy.sh
```

This rebuilds the content-addressed bundle (`dist/swap.html` + `MANIFEST.txt`
with sha256 / IPFS CID), syncs `deploy/vercel/`, and runs
`vercel deploy --prod` for the linked project (alias: www.nearinstant.xyz).
Commit `dist/` and `deploy/vercel/` afterwards.

`deploy/vercel/vercel.json` only sets headers (no-cache for HTML/JS, CSP,
frame/referrer policy). Anything that would add server-side code there is
out of scope by design.

## Local verification scripts

- `build_bundle.sh` — build `dist/` and print its hashes.
- `browser_ceremony_test.sh` — two independent parties run the real FROST DKG,
  joint signing and adaptor flow over the MailboxWire, in Node.
- `mailbox_interop_test.sh` — the browser MailboxWire is byte-compatible with
  the Rust `transport::mailbox`.
