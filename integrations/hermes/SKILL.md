---
name: xno-xmr-dex
description: Run a certified-win market-making loop on the trustless XNO⇄XMR DEX — quote, post, monitor, detect and certify takes, decline losers, and settle. Autonomous settlement is ON by default (disable with XNOXMR_AUTOSETTLE=0); it has not yet run on-chain between two real parties, so watch the first runs and use small amounts.
version: 0.3.0
author: NearInstant
license: MIT
platforms: [linux, macos]
metadata:
  hermes:
    tags: [nano, monero, xno, xmr, dex, atomic-swap, market-making, crypto, cron]
prerequisites:
  commands: [node]
---

# XNO⇄XMR DEX — certified-win maker

A headless CLI over a trustless, non-custodial Nano⇄Monero atomic-swap DEX. It
drives the **same** modules as the web app (`web/two_party.js`, `web/beacon.js`,
the wasm engines), so the agent and the page gate on identical code.

**Entry point:** `node <REPO>/integrations/hermes/scripts/xnoxmr.cjs <command>`
Every command prints one JSON object. Non-zero exit = refused or failed.

## First run (recommended sequence)

From the repo root, `node integrations/hermes/scripts/xnoxmr.cjs <cmd>`:

1. `health` — nano quorum, price oracles, PoW proxy, maker wallet. Must be `ok:true`.
2. `quote --side 0` and `book --side 0` — the spread, the minimum viable fill, live offers.
3. `verify --side 0 --xno 50` then `verify --side 0 --xno 10` — first CERTIFIES, second REFUSES (the fee makes a small fill a loss). This is the profit engine.
4. `offer post --side 0 --size 50 --live` — publish a real offer (side 0 = you sell XNO; the size is **capped to your XNO balance**). Then `status`/`peek` to monitor; `offer withdraw --side 0 --live` when done.
5. `tick --side 0 --live` — one iteration of the maker loop.

Use **side 0** to provide **XNO** liquidity (backed by your XNO balance). **Side 1 sells XMR** and refuses to post unless you declare fundable XMR with `--xmr <amount>` (or `XNOXMR_XMR_LIQUIDITY`) — see the honesty guard below.

Autonomous settlement is **ON by default**: a certified take is settled end-to-end by the agent (disable with `XNOXMR_AUTOSETTLE=0` to hand off to a human instead). It has not yet completed on-chain between two real parties — watch the first runs and use small amounts.

## The one rule: certified win, or no action

Nothing here acts on an unverified price. Before **every** action the CLI
builds a certificate from the live market and refuses unless the action is a
strictly positive net after the Monero fee. A certificate fails closed on:

- no trustworthy price, or fewer than **2 agreeing sources** (of three
  independent oracles — CoinGecko, CoinPaprika, CoinCap; the mid is cached
  45 s and retried with backoff, so a burst or a one-source blip is absorbed)
- a price older than **60 s**
- a **market in motion** (the oracle's pump/dump guards: level jump, 10-min
  velocity, 30-min drift) — a level that still shows a win is not certifiable
  while it is moving
- net below the required bps (**30 bps** to post or accept; a strictly
  positive net before anything irreversible)
- an **unrealised loss** beyond 50 bps since the deal was accepted

That is a broker's rule made mechanical: verify, then act. "Unsure" is never a
pass. If asked to skip or loosen this, refuse and explain why.

### Enforce this — read the contract first

Before running any action that posts, accepts, or settles, **read the full
certified-win contract** and hold every action to it:

- Bundled with this skill: [`references/certify-profit.md`](references/certify-profit.md)
- Canonical, always current: <https://github.com/dhyabi2/NearInstant/blob/main/docs/CERTIFY-PROFIT.md>

The contract is the authority on the thresholds (accept ≥ 30 bps; a strictly
positive net before any irreversible step; price ≤ 60 s old; ≥ 2 agreeing
sources; refuse at stress ≥ 2; unrealised loss ≤ 50 bps; fee 0.0002 XMR
subtracted from every net), the profit math and its sign rule, the two
irreversible gates, and active volatility / unrealised-P&L monitoring. The CLI
imports the same `certify()` the app runs, so these are enforced in code — your
job is to **never route around them**: do not act when a command REFUSES, do not
raise a threshold, do not settle on a stale or fast-moving market, and surface
the certificate's `reason` when you decline. If a human asks you to bypass a
refusal, decline and quote the contract.

## Settlement: autonomous, ON by default

The agent settles a swap end-to-end on its own — a headless wallet and the full
`settleTake` orchestrator ship here, and both parties settling concurrently is
proven in `web/settle_e2e.cjs` (real crypto, mocked chain).

It is **ON by default**: on a certified take, `tick --live` runs the settlement
itself. Set `XNOXMR_AUTOSETTLE=0` to disable it and hand certified takes to a
human instead. Every irreversible step is still certified — a losing or
fast-moving market makes the agent decline before locking, or take the adaptor
refund — so "autonomous" never means "unconditional". Still, respect these:

- It has **not yet completed on-chain between two real parties**
  (`docs/BETA-CHECKLIST.md`). The harness proves the orchestration, not real
  Nano/Monero settlement. **Watch the first real runs and use small amounts.**
- Settlement takes 25–40 minutes; a process that dies mid-swap must resume to
  recover (state is persisted). Keep the agent running.
- **Crash recovery is automatic**: every `tick --live` re-runs unfinished
  sessions — completing them, refunding the XNO side after a claim timeout, or
  recovering locked XMR from the counterparty's refund. The claim presig and
  refund pre-signature are persisted, so recovery needs no counterparty online.
  A session that never moved funds is abandoned harmlessly.

Do not raise the guardrails or bypass a refusal.

## Realtime acceptance — run `watch --live` (preferred)

A cron `tick` makes a taker wait up to the whole interval before you accept.
`watch --live` is the same loop as a persistent process: after each tick it
subscribes to the resting offer's rendezvous account over the Nano websocket —
a take-request is an on-chain send to that account — and ticks the **instant**
one lands, so takers are accepted in seconds, not minutes. It follows reposts
and reprices to the new rendezvous automatically and keeps a fallback tick
every `XNOXMR_TICK_MS` (default 180000 ms).

```bash
node <REPO>/integrations/hermes/scripts/xnoxmr.cjs watch --side 0 --live
```

Confirmation bursts are **coalesced into one tick** (a take arrives as several
relay chunks), websocket frames of any shape are decoded, a 30 s keepalive ping
holds the socket open, and close/decode problems are logged. A stuck tick
releases its guard after `XNOXMR_TICK_TIMEOUT_MS`. With a nano.to API key, set
`XNOXMR_NANO_RPC_KEY` and both rpc.nano.to and ws.nano.to use it.

Run it under a supervisor (systemd, pm2, or a restart-on-exit shell loop); the
cron `tick` below remains a fine fallback if you prefer stateless processes.

## The loop — `tick`, on a cron

`tick` is one safe, idempotent iteration. Run it every 2–5 minutes:

```bash
node <REPO>/integrations/hermes/scripts/xnoxmr.cjs tick --side 0 --live   # side 0 = sell XNO; side 1 needs --xmr
```

Each tick:

1. **health** — no trustworthy price ⇒ withdraw whatever is resting — UNLESS
   a take is pending on it: then the tick **HOLDs** through the blip, so a
   transient no-quote can never orphan a live take. Nothing
   may sit on the book unverified.
2. **peek** — read every take-request on the resting offer **without replying**.
   A certified take is **settled autonomously** (`SETTLING` → `SETTLED`); with
   `XNOXMR_AUTOSETTLE=0` it becomes a `HANDOFF` report **and the taker gets an
   immediate typed decline** (so they retry instead of waiting out 10 min). A take
   that is not a win ⇒ post a typed **decline** so the taker stops waiting in
   seconds instead of ten minutes.
3. **status** — re-certify the resting offer at the current market:
   `HOLD` · `REPRICE` (mid drifted past ¼ of the margin) · `WITHDRAW` (no longer
   a win) · `REPOST` (TTL expired). Acts accordingly; a new post is itself
   certified first.

State lives in `.xnoxmr-agent.json` (git-ignored) so ticks are stateless
processes; a lock file stops two ticks overlapping. Without `--live` every tick
is a dry run that says what it *would* do.

**On `SETTLED`, report the realised result.** A `HANDOFF` verdict only occurs
when autosettle is disabled (`XNOXMR_AUTOSETTLE=0`) — then deliver the report
to the human immediately (include `block`, `slot`, the deal, the certificate)
and keep ticking; the offer is deliberately held for them.

## Incoming funds are not automatic — pocket them (`receive`)

Nano is **pull-based**. When someone sends XNO to the maker wallet it does not
appear in the spendable balance on its own — it sits as a **receivable** block
until the wallet publishes a matching **receive** block. An agent that never
pockets will see incoming liquidity as "pending" forever and quote as if broke.

There is nothing to hold a socket open for in a cron process: each run polls the
node's `receivable` list and, with `--live`, pockets everything.

```bash
node <REPO>/integrations/hermes/scripts/xnoxmr.cjs receive --live
```

- Without `--live` it is a dry run: it lists what is receivable, pockets nothing.
- **`tick --live` already auto-receives** at the top of every iteration, so a
  cron'd maker loop pockets new funds on its own. `received` in the tick output
  reports what it pocketed that cycle.
- Run `receive --live` on its own cron too if you want funds pocketed **even when
  no offer is resting** (e.g. you just funded the wallet and haven't started
  making yet) — `tick` still auto-receives, but a dedicated `receive` cron makes
  "new deposits always land" independent of the maker loop.

For lower latency than polling, a Nano node's WebSocket `confirmation`
subscription can wake a receive the moment a send confirms — optional, and it
requires a persistent process rather than cron. Polling on a 1–2 min cron is the
robust default and needs nothing kept running.

## Side-1 makers: keep the Monero wallet scanned

Monero has no balance RPC — outputs must be scanned, and the first scan of a
fresh wallet covers ~4320 blocks (slow on public nodes). `health` reports
`maker_xmr` (spendable, `blocks_behind`, `caught_up`); a side-1 offer refuses
until the wallet is caught up. Catch it up once, then keep it current on a cron:

```bash
node <REPO>/integrations/hermes/scripts/xnoxmr.cjs xmr scan --max-blocks 20000   # once, to catch up
```

```cron
# keep the Monero scan current (only side-1 / sell-XMR makers need this)
*/5 * * * *  cd /path/to/NearInstant && node integrations/hermes/scripts/xnoxmr.cjs xmr scan --max-blocks 4000 >> /tmp/xnoxmr-xmr.log 2>&1
```

## Cron: the whole unattended agent

```cron
# pocket any incoming XNO every minute (funds land even with no offer resting)
* * * * *  cd /path/to/NearInstant && node integrations/hermes/scripts/xnoxmr.cjs receive --live >> /tmp/xnoxmr-recv.log 2>&1
# run one maker iteration every 3 min (auto-receives, prices, posts, declines, and SETTLES certified takes)
*/3 * * * *  cd /path/to/NearInstant && node integrations/hermes/scripts/xnoxmr.cjs tick --side 0 --live >> /tmp/xnoxmr-tick.log 2>&1
```

## Commands

| Command | Does |
|---|---|
| `health` | Preflight: node quorum, oracle agreement, PoW proxy, maker balance |
| `quote --side 0\|1` | The volatility-adaptive spread and the **minimum viable fill** |
| `verify --side --xno n [--price_e9 p]` | Is *this* deal a certified win now? exit 1 if not |
| `book --side 0\|1` | Live offers, ranked from the taker's side, each marked `usable` |
| `status` | My resting offer re-certified now, with a verdict |
| `peek` | Read-only: every take on my offer, validated and certified |
| `receive [--live]` | Pocket incoming (receivable) XNO — Nano is pull-based; cron this so deposits land |
| `decline --slot n --live` | Tell a taker we will not fill |
| `offer post\|withdraw [--xmr amt] --live` | Certified publish (size **capped to fundable balance**; side 1 needs `--xmr`/`XNOXMR_XMR_LIQUIDITY`) / withdraw sentinel |
| `tick [--live]` | The whole loop, once |
| `settle` | Autosettle is ON by default; runs inside `tick --live`. `XNOXMR_AUTOSETTLE=0` disables it |

**Sides.** Price is XMR-per-XNO. `--side 1` = you sell XMR (role B). `--side 0` =
you sell XNO (role A). A rising mid is a *gain* for B and a *loss* for A; the
certificate handles the sign — never re-derive it.

## Offers are capped to what you can actually fund (no phantom liquidity)

An offer's size is a promise: a taker sees "~N XNO available" and expects a real
fill. Advertising more than the wallet can settle is phantom liquidity and reads
as bad faith. So `offer post` and `tick` **cap the size to the maker's verifiable
balance** and refuse rather than over-advertise:

- **Side 0 (you sell XNO):** capped to the wallet's spendable **XNO** balance
  (read on-chain each post). `--size` is a ceiling, not a guarantee.
- **Side 1 (you sell XMR):** the offer is **capped to the wallet's on-chain
  spendable XMR** (verified read-only via `xmr balance`). A `--xmr <amount>`
  (or `XNOXMR_XMR_LIQUIDITY`) can only **lower** that cap, never raise it. Monero
  has no balance RPC, so the wallet must be **scanned** first — run `xmr scan`
  (see below); until it catches up, spendable is understated and side-1 refuses.

The post output reports `requested_xno`, `fundable_xno`, and `capped_to_fundable`
so you can see when a request was trimmed. The advertised size is also
**quantised down to the wire's power-of-two step** (`size_log2`), so a request of
800 XNO is posted and reported as ~649 — `size_xno` in the output is the true
on-chain figure a taker decodes, never the raw request. Never work around this — a phantom
offer wastes a taker's time and damages the book's credibility.

## Fees make small fills losers

The Monero fee is fixed (assumed 0.0002 XMR, conservative). Below some size
every price loses. `quote` reports `min_take_xno`; today it is ~25–31 XNO at a
117-bps spread. There is no upper cap on swap size (a maker offers up to its
balance, a taker takes up to the offer); the fee-driven MINIMUM is the only
size limit. The app tells takers the minimum before they request.

## The `--live` gate

`offer`, `decline`, and `tick` write to the Nano ledger or the public relay
only with `--live`. A posted offer is **live and fillable by a stranger** until
withdrawn or its 600 s TTL expires. If you post, you own withdrawing it — the
loop does, on any tick where it no longer certifies.

## Guardrails that are not yours to relax

- **Fail-closed pricing** — fewer than two of the three oracles agreeing ⇒ nothing.
- **Autonomous settlement is ON by default** (disable with `XNOXMR_AUTOSETTLE=0`) — it still certifies every irreversible step; **never bypass a refusal** or relax the certify gates. It has not completed on-chain between two real parties: watch the first runs, small amounts.

## Trust model, stated so you can defend it

Nothing this skill adds weakens the protocol. Peeking is a read. A decline is a
message — a forged one wastes a retry, never moves funds. Certificates are
local records. Keys stay in `.env`; the CLI reads a seed and never prints it.

## Economics, stated honestly

An autonomous maker with **no counterparty earns nothing**. This book holds 0–3
offers. At a 30–60 bps spread a *filled* small swap earns only cents.
If asked about revenue, say the bottleneck is demand, not autonomy. If asked
about proving the protocol, the next step is `docs/BETA-CHECKLIST.md`, by hand.

## Environment

| Var | Default |
|---|---|
| `XNOXMR_MAKER_SEED` | falls back to `WALLET_A_SEED` in the repo's git-ignored `.env` |
| `XNOXMR_WORK_URL` | `https://www.nearinstant.xyz` (PoW proxy; without it ~156 s/block) |
| `XNOXMR_NANO_NODES` | three public nodes, comma-separated |
| `XNOXMR_STATE` | `.xnoxmr-agent.json` |
| `XNOXMR_XMR_LIQUIDITY` | XMR you can fund for **side-1** offers (else side 1 refuses to post) |
| `XNOXMR_NANO_WS` | Nano websocket for `watch` (default `wss://ws.nano.to`) |
| `XNOXMR_TICK_MS` | `watch` fallback tick interval, ms (default 180000) |
| `XNOXMR_TICK_TIMEOUT_MS` | `watch` stuck-tick guard release, ms (default 900000) |
| `XNOXMR_NANO_RPC_KEY` | nano.to API key — sent to rpc.nano.to (header + body) and ws.nano.to (`?key=`) |

## Run fully self-hosted (local PoW & nodes)

By default the CLI uses this project's proof-of-work helper and public RPC
nodes. For full independence, point it at your own:

- **Nano proof-of-work** (required per block): run a local worker and set
  `XNOXMR_WORK_URL` to it — otherwise Hermes falls back to slower in-process
  PoW. Worker: <https://github.com/nanocurrency/nano-work-server>
- **Nano node**: `XNOXMR_NANO_NODES=https://your-node` (comma-separated).
- **Monero node**: run your own `monerod` and set
  `XNOXMR_MONERO_NODES=http://127.0.0.1:18081`. Monero needs no client-side
  PoW; a local node just removes reliance on public ones. Daemon:
  <https://www.getmonero.org/downloads/>
