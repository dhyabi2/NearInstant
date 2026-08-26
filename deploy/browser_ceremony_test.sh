#!/usr/bin/env bash
# Prove the pure-in-browser swap ceremony end to end: build the WASM package,
# then run (in Node, the same JS a browser runs) two independent parties over
# the MailboxWire performing the REAL FROST 2-of-2 DKG, joint block signing,
# and the adaptor pre-signature / completion / secret-extraction flow — each
# party holding only its own share, no helper and no trusted dealer.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== building wasm-bridge (nodejs target) =="
( cd swap-core/wasm-bridge && wasm-pack build --target nodejs --out-dir pkg-node >/dev/null 2>&1 )

echo "== 1/3 DKG over MailboxWire =="
node web/dkg_over_mailbox.cjs

echo "== 2/3 signing + adaptor ceremony over MailboxWire =="
node web/swap_ceremony_over_mailbox.cjs

echo "== 3/3 order beacon publish->scan + lifecycle (LIVE ledger, no mock) =="
# Real on-chain post + supersede + cancel. Skips cleanly if no funded wallet is
# configured (BEACON_WALLET=/path.json); there is no mock node fallback.
node web/beacon_live_test.cjs

echo "== 4 full cross-chain atomic swap (both engines, one secret unlocks both legs) =="
( cd swap-core/wasm-monero && wasm-pack build --target nodejs --out-dir pkg-node >/dev/null 2>&1 )
node web/atomic_swap_full.cjs

echo "== 5 passphrase custody (Stage 6: Argon2id seed, seed never leaves the vault) =="
node web/custody_flow.cjs

echo "== 6 funded swap orchestrator (self) + two-party swap mechanism =="
node web/funded_swap_check.cjs
node web/two_party_swap.cjs

echo "OK: pure-in-browser ceremony core + order beacon + full swap + custody + two-party proven."

# Stage 5 (Monero leg in wasm) proof — LIVE: talks to a public stagenet node.
# Scans the real funded block, builds+signs a real CLSAG/BP+ sweep in wasm,
# and expects the node to reject the broadcast ONLY as a double spend (the
# output was already swept on chain). Skip with XMR_STAGE5=0.
if [ "${XMR_STAGE5:-1}" = "1" ]; then
  echo "== stage 5: Monero leg in wasm over live stagenet =="
  ( cd swap-core/wasm-monero && wasm-pack build --target nodejs --out-dir pkg-node >/dev/null 2>&1 )
  node web/xmr_stage5.cjs
  # The GOLD proof (an ACCEPTED broadcast) needs a fresh, spendable joint output
  # from the stagenet faucet — opt in with XMR_GOLD=1 once funded (see
  # web/xmr_gold_proof.cjs). Proven live once: tx c736e7dea3b2dccce… relayed.
  if [ "${XMR_GOLD:-0}" = "1" ]; then
    echo "== stage 5 GOLD: accepted broadcast of a wasm-built sweep =="
    node web/xmr_gold_proof.cjs
  fi
fi
