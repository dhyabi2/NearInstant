# Hermes skill — XNO⇄XMR DEX

**Requirements:** Node.js ≥ 18 and a clone of this repo. The wasm engines are
committed (`swap-core/*/pkg-node`), so there is **no build step** — clone and
run. The CLI must run from inside the repo checkout (it resolves the engines and
protocol code relative to the repo root).


```bash
mkdir -p ~/.hermes/skills/trading/xno-xmr-dex
cp -r integrations/hermes/SKILL.md integrations/hermes/scripts integrations/hermes/references ~/.hermes/skills/trading/xno-xmr-dex/
export XNOXMR_MAKER_SEED=...        # or WALLET_A_SEED in the repo's .env
node /path/to/NearInstant/integrations/hermes/scripts/xnoxmr.cjs health
```

Cron the loop (Hermes `cron_mode: approve` for unattended runs):

```bash
node /path/to/NearInstant/integrations/hermes/scripts/xnoxmr.cjs tick --side 1 --live
```

It quotes, posts, monitors, re-certifies, declines losers, and reports a
`HANDOFF` when a certified take appears. It **never settles** — a human does
that from the page. See `SKILL.md`.
