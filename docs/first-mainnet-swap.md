# First mainnet XNO ⇄ XMR swap — runbook

This is the checklist and exact commands for the **first real-value** swap on
mainnet. It uses the **native helper (`swapper`)** — the settlement path that is
proven on-chain (Nano dev-net + Monero stagenet, Stages 2–5). The hosted page /
pure-browser flow is **not** wired for real funds yet (its "Full swap" is a
key-only demo), so the first transaction runs from the native helper.

> ⚠️ Honest status before you fund anything:
> - **No third-party audit.** Internal review only. Treat the first swap as an
>   at-risk experiment, not production.
> - Do it as **maker and taker yourself** (both sides, your own wallets) first,
>   with a **tiny amount**. That bounds loss to fees + the one-chunk abort bound.
> - Mainnet Monero requires a **≥2-node quorum** (single node can lie about
>   confirmations). Pass `--monero` twice.

## 0. Prerequisites
- `cargo build --release -p swapper` (workspace compiles clean).
- **Funded mainnet wallets you control:**
  - a Nano account with a little real XNO (the XNO-seller funds the joint Nano account),
  - a Monero wallet with a little real XMR (the XMR-seller locks it).
- **A Monero `monero-wallet-rpc`** open on your funded mainnet wallet (the
  XMR-seller side builds the lock tx through it). Point it at a mainnet daemon.
- **Endpoints (verified live):**
  - Nano: `https://rpc.nano.to` (+ a 2nd, e.g. `https://rainstorm.city/api`)
  - Monero: `https://xmr-node.cakewallet.com:18081`, `https://xmr.triplebit.org`

## 1. Start `monero-wallet-rpc` (XMR-seller side)
```
monero-wallet-rpc --mainnet \
  --daemon-address xmr-node.cakewallet.com:18081 --trusted-daemon \
  --wallet-file <your-mainnet-wallet> --password-file <pwfile> \
  --rpc-bind-port 38083 --disable-rpc-login
```

## 2. Maker — sells XMR (locks Monero, receives Nano)
```
swapper --role maker --listen 0.0.0.0:47999 --net main --live \
  --sell xmr \
  --nano https://rpc.nano.to --nano https://rainstorm.city/api \
  --monero https://xmr-node.cakewallet.com:18081 --monero https://xmr.triplebit.org \
  --wallet-rpc http://127.0.0.1:38083/json_rpc \
  --chunk <small-raw-amount> \
  --checkpoint ~/.xnoxmr/swap.chkpt.json \
  --transcript ~/.xnoxmr/swap.transcript.jsonl
```

## 3. Taker — sells XNO (funds joint Nano, sweeps Monero)
```
swapper --role taker --connect 127.0.0.1:47999 --net main --live \
  --sell xno \
  --nano https://rpc.nano.to --nano https://rainstorm.city/api \
  --monero https://xmr-node.cakewallet.com:18081 --monero https://xmr.triplebit.org \
  --sweep-dest <your-mainnet-XMR-address> \
  --chunk <same-small-raw-amount> \
  --checkpoint ~/.xnoxmr/swap-taker.chkpt.json \
  --transcript ~/.xnoxmr/swap-taker.transcript.jsonl
```
`--live` refuses to run mainnet Monero with fewer than 2 `--monero` nodes
(fail-closed quorum). If interrupted, re-run with `--resume <checkpoint>`.

## 4. Verify
- Watch both transcripts; confirm the Nano claim and the Monero sweep land
  on-chain (check the tx hashes on a mainnet explorer).
- `swap-verify <transcript.jsonl>` re-checks the hash-chained event log.

## Still-open blockers (not code — do these before real size)
1. **Third-party audit** — the one thing that can't be self-cleared.
2. A **stranger counterparty** flow (beacon discovery + two independent parties)
   for a real other-party swap; the self-swap above proves the mechanism first.
3. **Pure-browser real-funds flow** — integrate BrowserSigner + beacon + the
   Monero engine into a single funded flow in the Swap panel (today: native
   helper only for real funds; browser is component-proven + a key-only demo).
