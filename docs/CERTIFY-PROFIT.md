# Certified-Win Reference

The rule this system enforces: **no action on an unverified price, and no
irreversible step that is not a certified win.** Every offer, every accepted
take, and every step that cannot be undone is checked against the live market —
after fees, with active volatility monitoring and an unrealised-loss limit — or
it is refused. "Unsure" is never a pass.

This document is the exact contract. All values below are the ones in the
running code (`web/two_party.js` for the engine, `web/index.html` for the app
policy, `integrations/hermes/scripts/xnoxmr.cjs` for the agent). A parity check
in the build confirms the agent and the app compute identical numbers.

---

## Where the money is at risk

A swap has exactly two irreversible commitments. Everything before them is a
free abort window; everything is gated at these points and re-checked in the
waits leading up to them.

| Party | Irreversible step | Gate before it |
|---|---|---|
| **B** (sells XMR, offer side 1) | locks XMR into the 2-of-2 joint address | `gate("before locking XMR")` — declines cost B nothing; A refunds |
| **A** (sells XNO, offer side 0) | pre-signs the claim (commits its XNO) | `gate("before committing the claim")` — if it fails, A takes the adaptor refund instead |

Order is enforced so the recoverable leg (XNO) always moves first and the
irreversible leg (XMR) last. **A swap has ONE price and the two parties sit on
opposite sides of it** — the taker pays the maker's spread — so these gates do
not re-demand an absolute win (that would abort every taker). They check the
deal has not moved *materially worse than when it was accepted*
(`MAX_UNREALIZED_LOSS_BPS`), on a fresh, calm, agreed price. A genuine adverse
move unwinds the swap safely; nobody loses more than one network fee. The
absolute-win requirement lives at ACCEPT and OFFER time, where the maker sets
the spread.

## The certificate

`certify(deal, roleIsA, price, opts)` returns a record. `ok: true` is the only
pass. It refuses — `ok: false` with a `reason` — on any of:

| Refusal | Rule |
|---|---|
| no trustworthy price | `price.ok` is false |
| too few sources | fewer than **2** agreeing price sources |
| stale price | price older than **60 s** (`MAX_MID_AGE_MS`) |
| below threshold | net **< the required bps** (see below) |
| market in motion | oracle **stress ≥ 2** — a level that still shows a win is not certifiable while it is moving |
| unrealised loss | in-flight deal has bled **> 50 bps** against the accept baseline |

A passing certificate carries: `mid`, `sources`, `ageMs`, `stress`,
`grossAtomic`, `feeAtomic`, `netAtomic`, `netBps`, `outlayAtomic`, and — once a
deal is accepted — `unrealizedBps` and `midDriftPct` marked against the
certificate the deal was accepted on.

## Thresholds (verified identical in app and agent)

| Name | Value | Meaning |
|---|---|---|
| `MIN_ACCEPT_BPS` | **30 bps** | to post an offer or accept a take |
| pre-irreversible gate | **no absolute floor** | before B locks / A commits, the deal must not have moved *worse than when accepted* (see `MAX_UNREALIZED_LOSS_BPS`) — it does **not** re-demand a fresh win, because the taker knowingly pays the maker's spread |
| `MAX_MID_AGE_MS` | **60 000** | a price older than this certifies nothing |
| `MAX_UNREALIZED_LOSS_BPS` | **50 bps** | how far an accepted deal may drift adversely before a later gate refuses |
| `MAX_STRESS` | **2** | pump/dump guard level at which nothing certifies |
| `XMR_TX_FEE_ATOMIC_DEFAULT` | **200 000 000** piconero (0.0002 XMR) | conservative fee subtracted from every net |

## The profit math

Amounts are integers end to end: `xnoRaw` (1e30 per XNO), `xmrAtomic` (1e12 per
XMR). Price is XMR per XNO.

```
midE18        = round(mid * 1e18)
xnoValueAtomic = xnoRaw * midE18 / 1e36          # the XNO leg valued in piconero
gross          = A ? (xmrAtomic - xnoValueAtomic)   # A receives XMR, gives XNO-value
                   : (xnoValueAtomic - xmrAtomic)   # B receives XNO-value, gives XMR
net            = gross - fee
netBps         = net * 10000 / outlay            # outlay = what this side puts in
```

A rising mid is a **gain for B and a loss for A**; the sign is handled by
`roleIsA`. Never re-derive it.

**Fees dominate at small sizes.** The fee is fixed, so below some size every
price is a loss. `minViableXnoRaw()` solves the smallest fill that still clears
the threshold. At a ~117 bps spread today that floor is ~25–31 XNO — below it a fill
is a certified loss. There is no upper cap: a maker offers up to its balance and
a taker takes up to the offer. The app and the CLI both refuse a take that is too
small and say the minimum.

## Active monitoring and unrealised P&L

The certificate is not a snapshot. `price.stress` comes from the oracle's
pump/dump guards (a jump vs the recent median, velocity over 10 min, drift over
30 min). Once a deal is accepted, the certificate it was accepted on becomes the
**baseline**; every later gate marks the deal to market against it and refuses
if the unrealised loss exceeds 50 bps — the trend is information, and a deal
bleeding toward the line is stopped before it crosses.

## What the agent calls

The Hermes CLI imports `certify`/`gate`/`minViableXnoRaw` directly from
`web/two_party.js` — the same functions the app runs, one source of truth.

| Command | Certified-win behaviour |
|---|---|
| `verify --side S --xno N` | `CERTIFIED WIN` or `REFUSE` for a specific deal now; exit 1 on refuse |
| `quote --side S` | the volatility-adaptive ask, plus `min_take_xno` |
| `offer post --side S --live` | refuses to publish unless a full fill certifies |
| `tick --live` | posts only certified offers; accepts only certified takes; declines the rest so the taker stops waiting |

Example — the exact live behaviour, today's mainnet prices:

```
$ verify --side 1 --xno 50   →  CERTIFIED WIN   net +74 bps
$ verify --side 1 --xno 10   →  REFUSE          net -98 bps (the fee alone is a loss)
```

## Honest limits

- The **fee is a conservative constant**, not a live per-tx estimate; the real
  fee is usually lower, so the gate is slightly stricter than necessary.
- Certification governs **price risk**, not settlement mechanics. The
  person-to-person swap has not yet completed on-chain between two browsers
  ([BETA-CHECKLIST.md](BETA-CHECKLIST.md)); the gates are proven in the test
  harness (`web/profit_gates.cjs`, 35 assertions), not yet on a live two-party
  mainnet swap.
- With no counterparty a maker earns nothing. Certification makes each fill
  safe; it does not create demand.

---

*Values here are asserted against the code by the build. If a threshold changes
in `web/two_party.js` or `web/index.html`, update this file in the same commit.*
