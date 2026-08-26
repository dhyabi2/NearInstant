# How it works — and how you earn

A technical explainer for the trustless XNO⇄XMR DEX: what the system does, how a
cross-chain swap settles without a custodian, and — in detail — **how a liquidity
provider earns**, including the economics, the fairness of the early-adopter
edge, and the honest limits.

For the full process model (every task, gateway, and message flow) see
[ARCHITECTURE-BPMN.md](./ARCHITECTURE-BPMN.md). This document is the narrative
companion.

---

## 1. What this is

A **non-custodial, backend-less** atomic-swap exchange between **Nano (XNO)** and
**Monero (XMR)**, running entirely in the browser. There is no server, no
account, no deposit into a company wallet. Your keys never leave your device
(they live in an isolated Web Worker; the page's DOM cannot read them). The only
network calls are to public chain RPC nodes and two read-only price oracles.

Two things happen here:

- **Swap** — trade XNO for XMR (or back) directly with another user, settled by
  cryptography so neither side can cheat.
- **Earn** — provide liquidity (post offers) and collect the spread that
  *swappers* pay. This is the "Earn" feature, and the rest of this document is
  mostly about it.

---

## 2. How a swap settles (the 60-second version)

A swap is bound together by a single secret, `x`:

- `x` is the XMR-seller's Monero spend-key share, **and** it is the adaptor
  secret behind a point `T = x·G` used in the Nano side.
- The two parties build a **2-of-2 joint Nano account** (FROST threshold
  signatures) and a **2-of-2 joint Monero address** (MuSig).
- The XMR-seller **locks XMR** into the joint Monero address. The XNO-seller
  **funds XNO** into the joint Nano account.
- The Nano claim is pre-signed as an **adaptor signature**: it is provably
  useless on its own, and the *only* way to make it broadcastable is to fold in
  `x`.
- When the XMR-seller broadcasts the claim to take the XNO, that broadcast
  **publishes `x`**. The XNO-seller reads `x` off the chain, reconstructs the
  joint Monero key, and **sweeps the XMR**.

Result: either **both** legs settle or **neither** party's counterpart-value
moves. No custodian ever holds both sides. (See BPMN §4 for the full ceremony,
and §4.4 there for the current no-refund/timelock limitation.)

---

## 3. How you earn — the mechanism

You earn by being a **liquidity provider (LP)**: you post an offer to swap at a
price, and when a **swapper (taker)** accepts it, they pay a small **spread** on
top of the mid-market price. That spread is your income.

- **Spread (`MARGIN`) = 0.8%.** When you post via Smart Offer, your ask is set to
  `mid × (1 + 0.8%)` when selling XNO, or `mid × (1 − 0.8%)` when selling XMR —
  always in your favour. The taker accepts because they want the swap.
- **You collect the 0.8%; the taker pays it.** Your earnings are funded entirely
  by the customer who wants the swap, not by other providers and not by later
  joiners.
- **Your only cost is the Monero network fee** (~0.00012 XMR for the two on-chain
  legs of a swap you serve). The Nano side is feeless.
- **The price is fail-closed.** Smart Offer will not post an offer it cannot
  price safely: it requires **≥2 agreeing price sources**, within a **6%
  agreement band**, and within **10% of a trailing median** (a circuit breaker).
  If any check fails, it posts nothing. This protects you from quoting against a
  wrong or unknown market price.

Your offer is published **on-chain** (packed into a tiny Nano send), so it is a
real, censorship-resistant, publicly-verifiable order — not an entry in a company
database. Your **earnings are read straight from your account's public history**
and are never a stored number; anyone can verify them against a block explorer.

---

## 4. The economics — how the earnings work

This section explains the *mechanism* by which a provider earns. (Detailed
sensitivity modelling is kept separately and is not part of this document.)

### 4.1 The one equation that governs everything

A provider's monthly profit is:

```
net = 0.8% × (volume routed through you) − MoneroFee × (swaps you served)
```

Both terms scale with your volume. There is **no term for the number of
providers** and **no term for anyone else's deposit**. That single fact drives
every conclusion below.

### 4.2 It is positive-sum and NOT a Ponzi (proven)

Every payout traces to a fee a **taker** paid for a service they received. Map
the money flow of one swap:

```
   TAKER ──(asset + 0.8% spread)──► PROVIDER ──(Monero network fee)──► miners
     ▲                                  │
     └──────(receives the swap)─────────┘
   platform fee = 0 · Nano fee = 0
```

- **No arrow ever runs from one provider to another**, or from a later
  provider's deposit back to an earlier one. Deposits stay in the owner's wallet,
  withdrawable at any time.
- The system is **positive-sum**: it delivers a service that did not otherwise
  exist, and the only value leaving the system is the tiny Monero miner fee.
- The all-win condition is a set of **independent** inequalities
  (`0.8% × volume_i > cost_i`) — all satisfiable at once. There is no regime where
  one provider must lose so another can win. Competition is over *who fills an
  order* (you earn less if a rival fills it), never over *each other's capital*
  (a rival can never make you go negative).

**Ponzi check: clean.** No earning requires inflows from later participants. A
provider who joins and gets no fills simply earns 0 and withdraws their deposit
intact — the signature *absence* of Ponzi dynamics.

### 4.3 The Monero fee is almost irrelevant; swap size is the real floor

The fee eats only ~1.5% of the spread. The number that matters is the
**break-even swap size**:

```
break-even = fee / margin = 0.00012 / 0.008 = 0.015 XMR (≈ $2–3)
```

Any swap **larger** than 0.015 XMR is profitable; any smaller one loses money
regardless of volume. **Recommendation: enforce a minimum swap size (~0.05 XMR,
3.3× break-even)** so every served swap is structurally profitable.

### 4.4 What determines whether everyone stays positive

Adding providers only shrinks each slice of the fee pot — it never, by itself,
flips a provider from profit to loss. The two things that *can* create a loser
are (a) each provider's own **fixed cost** (a node, opportunity cost on locked
capital), which sets a minimum viable volume per provider, and (b) how flow is
**routed** — pure price-priority concentrates volume on a few providers and
starves the tail. The fee pot is finite (`0.8% × total taker volume`) and grows
with **swapper demand**, not with how many providers show up: the market is
demand-limited, so beyond a point new providers only dilute.

### 4.5 Keeping "everyone wins" true — recommended parameters

All of these are fee-funded and non-Ponzi:

- **Minimum swap size ≥ 0.05 XMR** — guarantees every swap profits.
- **Demand-gated onboarding** — admit provider #(N+1) only if projected volume
  keeps the newest seat above the viability floor (`seats ≈ volume / V_min`). This
  keeps late joiners *out of a losing seat* rather than selling them one.
- **Near-proportional / rationed routing** instead of pure price-priority — the
  single biggest lever against tail starvation.
- **Dynamic spread backstop** — widen the spread modestly (cap ~1.2%) only when
  volume-per-provider is starved; relax to 0.8% in healthy conditions.

---

## 5. Why joining early is better (and why that's fair)

Early providers legitimately earn more, from **two fee-derived mechanisms**:

1. **Less competition early.** When few providers are online, each captures a
   larger share of the same taker-fee pot. Provider #1 at N=1 earns 100% of the
   fees; that share decays roughly as `1/N` as others join.
2. **Priority / tenure weighting.** Earlier, longer-serving providers can be
   routed a larger slice of the *same* real fee pot — e.g. a weight
   `w(rank) = 1 + e^(−(rank−1)/25)` makes provider #1 out-earn #50 by ~1.75× at
   equal capital, **decaying smoothly to 1× by ~rank 100**.

Both are just **reweightings of real taker fees** — no minting, no subsidy, no
later-joiner's deposit. That makes the early edge real *and* fair: it compensates
the higher risk and thinner volume that early providers bear, and it fades as the
market matures.

---

## 6. The honest caveats

We hold ourselves to honest copy. Three things you should know:

- **Returns are demand-capped, not guaranteed.** The fee pot is finite. "Everyone
  can be net-positive" is provably true given enough volume; "everyone earns a
  lot" is **not** — it depends on real swapper demand. No fixed %/mo, no APY, no
  "guaranteed" or "passive" return is promised.
- **The tier calculator currently overstates it.** The in-app estimator computes
  a percentage of *your capital* with no volume term — a yield-on-capital framing.
  The engine underneath is 100% fee-derived and clean, but that framing is
  misleading and is being reframed as **"share of real trading fees / turnover
  scenarios,"** driven by a volume input so earnings visibly go to zero when
  volume is zero. Tenure should **decay**, not be permanent.
- **This is early software with known gaps** — most importantly, the two-party
  settlement path has **no refund/timelock yet** (the live self-swap harness caps
  each leg at a token 0.0001). See [ARCHITECTURE-BPMN.md §8](./ARCHITECTURE-BPMN.md#8-known-gaps--honest-notes)
  for the complete list.

---

## 7. What you may and may not rely on

**True today:**

- Non-custodial: your keys never leave your device; no server holds funds.
- Offers are real, on-chain, publicly verifiable, and lifecycle-correct
  (cancel + expiry work).
- Pricing is fail-closed: no offer is posted at an unsafe/unknown price.
- Earnings are read from the public ledger, never stored.
- The earn model is positive-sum and non-Ponzi.

**Not yet / in progress:**

- Selecting a specific offer in the order book does not yet drive settlement
  (`swSelected` is display-only).
- Two-party swaps need a refund/timelock before more than token amounts are safe.
- The tier estimator's framing is being corrected as described in §6.

---

*This document reflects the code and the economic modelling as of the latest
commit. Figures in §4 are parametric (stated assumptions inline in the modelling
notes); the qualitative conclusions — positive-sum, non-Ponzi, demand-limited,
fair fee-derived early edge — are robust to the assumptions.*
