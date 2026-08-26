# NearInstant

**A trustless, non-custodial Nano ⇄ Monero atomic-swap DEX that runs entirely in your browser.**

Swap XNO for XMR (and back) directly with another person — no server holding
your funds, no account, no deposit into anyone's wallet, no token, no oracle in
the settlement path. The swap is enforced by cryptography: 2-of-2 joint accounts
and adaptor signatures link the two legs so a single secret unlocks both. Either
the swap completes for both sides, or it unwinds and both sides recover.

**Live:** [www.nearinstant.xyz](https://www.nearinstant.xyz)

---

## How it works

A swap binds a Nano leg and a Monero leg with an **adaptor signature**. The
XMR-seller can only claim the Nano by completing a pre-signature with a secret
`x`, and doing so publishes `x` on-chain, which the XNO-seller extracts to sweep
the Monero. One secret, both legs — that is the atomicity.

- **Keys never leave your device.** They are generated in the browser, held in
  an isolated Web Worker the page's DOM cannot read, and encrypted at rest with
  Argon2id + AES-256-GCM.
- **No custody, no backend.** The only network calls are to public Nano/Monero
  RPC nodes and two read-only price oracles. (One optional serverless function,
  `/api/work`, does Nano proof-of-work; it sees only a public block hash and can
  be turned off.)
- **Recoverable aborts.** The Monero leg is locked last, after the Nano is
  funded and a pre-signed **adaptor refund** exists. If a counterparty walks
  away, both sides recover; nobody loses more than a network fee.

Full narrative: [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md) ·
Full process model: [docs/ARCHITECTURE-BPMN.md](docs/ARCHITECTURE-BPMN.md)

## Earn by providing liquidity

Post an offer and get paid the spread each time someone swaps against it. Pricing
is **certified-win**: every offer, every accepted take, and every irreversible
step is checked to be profitable at the live market — after fees, with active
volatility monitoring and unrealised-loss limits — or it is refused. The spread
adapts to volatility; it is never a promise of yield, and with no counterparty a
maker earns nothing. The exact rules — thresholds, profit
math, the two irreversible gates, volatility monitoring — are in
[docs/CERTIFY-PROFIT.md](docs/CERTIFY-PROFIT.md). The honest economics are in
[docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md).

## Automate it (Hermes agent skill)

[`integrations/hermes/`](integrations/hermes) ships a headless CLI — the same
pricing and protocol code as the web app — that reads the order book, quotes,
posts and monitors offers, and detects certified takes, with no browser. It
installs as a skill for the [Hermes agent](https://github.com/NousResearch/hermes-agent)
and works standalone.

Autonomous settlement is included: the orchestrator is proven end-to-end in a
test harness (`web/settle_e2e.cjs` — two parties, real crypto, mocked chain) and
is enabled with `XNOXMR_AUTOSETTLE=1`. It has not yet run on-chain between two
real parties ([docs/BETA-CHECKLIST.md](docs/BETA-CHECKLIST.md)); until it does,
running it under supervision is wise.
See [`integrations/hermes/SKILL.md`](integrations/hermes/SKILL.md).

## Repository layout

| Path | What |
|---|---|
| `web/` | The app: `index.html` (single self-contained page), the in-browser wallet, `two_party.js` (the swap ceremony), and the wasm engines |
| `swap-core/` | Rust → wasm: FROST signing, adaptor signatures, the Nano ceremony, Monero joint keys, transport |
| `integrations/hermes/` | The headless CLI and the Hermes agent skill |
| `docs/` | How-it-works, the BPMN process model, the beta checklist, the first-swap runbook |
| `deploy/` | The static-frontend deploy tooling |

## Build & test

```bash
# Rust workspace (protocol core)
cd swap-core && cargo test --workspace

# Browser-side proofs (run against real mainnet read paths / in-process peers)
node web/two_party_swap.cjs        # the full two-party ceremony
node web/refund_recovery.cjs       # adaptor-refund recovery, 11 assertions
node web/profit_gates.cjs          # certified-win gates, 35 assertions
node web/rendezvous_dos.cjs        # relay DoS resistance

# The agent CLI (read-only preflight)
node integrations/hermes/scripts/xnoxmr.cjs health
```

The wasm engines are built with [`wasm-pack`](https://rustwasm.github.io/wasm-pack/)
(`--target web` for the browser, `--target nodejs` for the CLI and tests).

## Status & honesty

This project states its limits plainly, in the app and here:

- The person-to-person swap has **not** completed on-chain between two browsers yet.
- No independent audit.
- Deep Monero restore scans are impractical in a browser (no balance RPC exists
  in Monero by design); running your own node is the strongest configuration.
- Swept Monero currently returns to the wallet's primary address (reused),
  which weakens unlinkability; fresh subaddresses per sweep are planned.

## License

MIT — see [LICENSE](LICENSE).
