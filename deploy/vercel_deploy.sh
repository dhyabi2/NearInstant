#!/usr/bin/env bash
# Ship the static, content-addressed frontend to Vercel production.
# The frontend is a single self-contained HTML file (dist/swap.html) — no
# server, no build step, no secrets. Only the frontend goes here; the relay
# and maker never do.
set -euo pipefail
cd "$(dirname "$0")/.."

# 1. Rebuild the content-addressed bundle so dist/swap.html is current.
bash deploy/build_bundle.sh

# 2. Sync it into the Vercel publish dir (index.html at the root), plus the
#    optional experimental engine files the page lazy-loads behind its flag
#    (pkg/ wasm engine, mailbox.js transport, beacon.js order beacon). The
#    core page stays fully self-contained without them.
cp dist/swap.html deploy/vercel/index.html
# PWA + SEO static assets (manifest, service worker, icons, social share image).
# These are real files (not inlined) so the hosted app is installable and link
# previews resolve; the single-file bundle still works standalone without them.
cp web/manifest.webmanifest web/sw.js web/favicon.svg web/favicon.ico \
   web/favicon-16.png web/favicon-32.png web/apple-touch-icon.png \
   web/icon-192.png web/icon-512.png web/icon-maskable-512.png web/og-image.png \
   deploy/vercel/
cp web/mailbox.js web/beacon.js deploy/vercel/
# Stage 5 swap driver + Stage 6 custody (page + worker + shared core).
cp web/swap_driver.js web/custody.js web/custody_core.js web/custody-worker.js deploy/vercel/
# Secure in-browser Nano wallet (page API + key-holding worker).
cp web/wallet.js web/wallet-worker.js deploy/vercel/
# Funded self-swap orchestrator (test our trustless swap with real funds).
cp web/funded_swap.js web/ledger_relay.js web/two_party.js web/swap_machine.js web/swap_responder.js deploy/vercel/
mkdir -p deploy/vercel/pkg
cp web/pkg/wasm_bridge.js web/pkg/wasm_bridge_bg.wasm deploy/vercel/pkg/
# Stage 5 Monero engine (separate, lazy-loaded package).
if [ -f web/pkg-xmr/wasm_monero.js ]; then
  mkdir -p deploy/vercel/pkg-xmr
  cp web/pkg-xmr/wasm_monero.js web/pkg-xmr/wasm_monero_bg.wasm deploy/vercel/pkg-xmr/
fi
echo "synced dist/swap.html + experimental engine -> deploy/vercel/"

# 3. Deploy to production (requires: vercel login, already linked).
vercel deploy --prod --yes deploy/vercel
