# swap-core

Implementation of the trustless XNO⇄XMR DEX, following the settled solutions
register (27 issues: I1–I10 protocol, N1–N8 hardening, U experience, B1–B9
Binance-parity). Register artifact:
https://claude.ai/code/artifact/be090cad-b68d-4f41-90e3-cf1e6ffd375a

## Build order

| Block | Crate / scope | Status |
|---|---|---|
| 1 | `signing` — frost-core ed25519-blake2b ciphersuite + I2 adaptor module | **done** |
| 2 | `nano-ceremony` — joint account, guard ladder (I3), block builder, broadcast | **done** |
| 3 | `monero-side` — I10 isolation layer + MuSig joint key + 2-of-2 CLSAG co-signing | **done** |
| 4 | `swap-engine` — chunk schedules, premium pricing, swap state machine | **done** |
| 5 | `puzzle-escrow` — RSW verifiable escrow + N3 horizon rule | **done** |
| 6 | `channels` — one-way monotone channels, N1 journal anchoring | **done** |
| 7 | `dex-core` — orders, book, market data, matching, triggers, earn, ledger, privacy | **done** |
| 8 | `pledge` — bilateral commitment bonds + provable drip (H-series) | **done** |
| 9a | `transport` — wire-driven two-party ceremonies (framed bytes, loopback) | **done** |
| 9b | `wasm-bridge` — real engine compiled to WASM, live in the web app | **done** |
| 10 | `transport::tcp` + `dexd` — real TCP wire & relay daemon (B4) | **done** |
| 11 | `transport::socks` (Tor) + live-network validator | **done** |
| 12 | Real Nano-node settlement (dev network) — **done** | proven |
| 13+ | Monero stagenet settlement (needs stagenet node + faucet) | supervised |
| 14 | `swap-executor` — settlement driver + full session (DKG over wire, guard-confirm-then-reveal, secret sweep) + `swapper` binary | **done** |

## `signing` (Block 1)

- `ciphersuite`: FROST(Ed25519, Blake2b-512) over unmodified `frost-core`.
  `H2` is the raw `Blake2b-512(R‖A‖M) mod ℓ` challenge, so aggregated 2-of-2
  signatures verify as ordinary Nano block signatures.
- `adaptor`: pre-signature generation via a doctored signing package (lowest
  identifier's hiding commitment offset by the adaptor point `T`), share
  verification against the true commitments, aggregation, public pre-signature
  verification, completion with `x`, and extraction of `x` from the broadcast
  signature. No FROST math reimplemented; built entirely on `frost-core`'s
  `internals` API.
- `nano_verify`: independent ed25519-blake2b verifier (Nano node semantics).

## `nano-ceremony` (Block 2)

- `address`: Nano account encoding/decoding (verified against the mainnet
  genesis account).
- `block`: state-block construction and Blake2b-256 hashing (verified against
  a real confirmed mainnet block, including its live network signature and
  era-correct proof-of-work).
- `work`: PoW validation and generation; the next block's work root is known
  at signing time, so work pipelines ahead of the chunk stream (N4).
- `ceremony`: joint 2-of-2 and adaptor signing of block hashes over `signing`.
- `guard`: the I3 guard ladder — chained pre-signed representative-change
  blocks; broadcasting the next rung advances the frontier and kills every
  stale-frontier signature before a secret-revealing claim. Rung hashes are
  deterministic, so the claim is adaptor-pre-signed against the post-guard
  frontier at setup.
- `broadcast`: `NanoNode` trait, saturation broadcast, and an RPC node client
  (feature `rpc`).

Tests: a mock ledger enforcing one-block-per-frontier and signature/work
rules runs the I3 scenarios end to end — the guard kills a stale co-signed
refund and the adaptor-completed claim settles and reveals the secret
(S05), and losing the guard race is a clean abort with nothing revealed
(S05b) — plus ladder chain/tamper rejection and a Python hash differential.

## `monero-side` (Block 3)

- `isolation` (I10): pure bytes-in/out boundary for every CLSAG/CARROT-coupled
  derivation — MuSig spend-key aggregation (rogue-key safe), order-independent
  shared view key, joint primary address, sender/receiver one-time-key
  derivation, key-image generator, Pedersen commitments. When FCMP++/CARROT
  lands, this module is the only file that changes.
- `cosign`: 2-of-2 CLSAG co-signing of channel-state spends over
  `monero-clsag`'s FROST multisig (`modular-frost` + `dkg-musig`), with keys
  offset by the output's key offset. Joint key image assembled from public
  per-party interpolated shares.

Tests: aggregation determinism/binding (joint ≠ naive sum), joint address +
mainnet donation-address spec anchor, one-time key round trip with wrong-view
rejection, full 2-of-2 CLSAG over an 11-ring verifying against the assembled
key image (with message/ring/pseudo-out tamper rejection), the I5 channel
invariant — two states spending one output carry the SAME key image across
independent ceremonies — and corrupted-share/wrong-message ceremony aborts.

## `swap-engine` (Block 4)

- `schedule`: I1 chunk schedules — loss per abort bounded at one chunk by
  construction, dust tails folded, chunk-count caps.
- `premium`: N6 exponential-decay VWAP + volatility from settled trades only;
  the I4 option premium, explicit and time-decaying to a floor.
- `machine`: deterministic transport-agnostic state machine (events in,
  actions out); enforces the one-chunk-in-flight invariant on every
  transition; routes aborts to the backstop (Bob) or the unilateral sweep
  (Alice).

Tests: the S06 re-run — abort at every event boundary of a 3-chunk swap with
worst-case loss ≤ one chunk everywhere; happy-path action choreography for
both roles; out-of-order/terminal rejection; pricing decay. Plus the
**atomic-chunk integration test**: one full chunk driven across all three
crates with real cryptography — FROST ed25519-blake2b joint Nano account on a
frontier-enforcing ledger, guard rung, adaptor-pre-signed claim (T = Bob's
XMR MuSig contribution), Bob's broadcast reveals x, Alice reconstructs the
joint XMR secret from public MuSig binding constants and her share, and her
single-party CLSAG sweep verifies. The pre-signature alone is proven
non-broadcastable and non-extractable.

## `puzzle-escrow` (Block 5)

- `puzzle`: RSW time-lock puzzles — trapdoor fast path (φ(N)) for the
  generator, T sequential squarings for everyone else, plus a squaring-rate
  calibrator for horizon sizing.
- `escrow`: cut-and-choose verifiable escrow of an ed25519 share. Per-instance
  self-generated moduli (a weak modulus only hurts its generator); audited
  instances reveal r and the modulus factors (millisecond verification);
  kept instances bind algebraically via `d·G = R + K`; recovery solves one
  puzzle and checks the result against K.
- `horizon`: the strict N3 rule `deadline < T_target/(2·S_max)` with T-sizing
  helpers.

Tests: full lifecycle recovering the exact share from every kept instance;
tamper detection on all four surfaces (unbound d, dishonest audited puzzle,
fake factorization, corrupted kept puzzle caught at recovery); the S10
modulus-vs-curve-order rejection; trapdoor/sequential solve agreement; and
strict horizon boundary failure (S08's catch).

## `channels` (Block 6)

- `channel`: the one-way channel state machine — taker-held monotone states
  over real 2-of-2 CLSAG co-signing, one key image per channel (only one
  state can ever confirm), client-enforced lifetime caps strictly before the
  puzzle horizon T2, and the S09 no-cross-channel-credit rule.
- `journal`: N1 anchoring as 1-raw sends whose destination is the state
  hash; replay recovers the ordered anchor list, and a counterparty serving
  a stale state is convicted by position.

Tests: full channel session (3 states, one key image, correct splits),
monotonicity/capacity/lifetime enforcement incl. the open-time T2 check,
cross-channel credit refusal, journal stale-serve conviction, and forged
state rejection.

## `dex-core` (Block 7)

Transport-agnostic DEX layers, one module per settled issue:

- `order` (I7): ed25519-blake2b signed orders, canonical hashing,
  deterministic tie-breaking, expiry + proof-of-funds hooks.
- `book` (B1/I7): staleness-aware PoF-weighted consolidated book, identical
  on every client, Merkle-rooted for Nano link anchoring with inclusion
  proofs.
- `market` (B2/N6): candles/ticker/volume from settled trades only, each
  candle carrying an integrity hash of its constituent trades.
- `matching` (B8): best-execution walk, commit-reveal taking, single-use
  tickets, maker-signed FCFS receipts with a reorder-conviction audit.
- `triggers` (B3): local stop/stop-limit/OCO/trailing against the VWAP,
  atomic OCO cancellation, no delegation.
- `earn` (G1/G4): VWAP-anchored quoting with inventory skew/lean,
  volatility widening and pull, a latching drawdown breaker, and a
  realized-only yield band (no fabricated APY code path exists).
- `ledger` (G2): deterministic replay of the signed event log — decay-
  accrued premium, cost netting, bond opportunity cost, per-strategy
  attribution, mark-to-VWAP.
- `privacy` (I9): swap-chaining planner — fixed denominations, batch
  windows, distinct-counterparty hop assignment, honest round-trip cost.

## `pledge` (Block 8 — H-series)

- `terms`: pledge terms with validation, H3 linear penalty decay (full at
  start, zero at maturity — everyone holds a clean exit date), and N3-strict
  escrow-puzzle sizing.
- `bond`: pre-signed early-exit chains (stayer gets principal + the
  leaver's penalty; leaver gets the rest), the deliberately-unsigned clean
  maturity split (co-signed at maturity or executed unilaterally after
  solving the counterparty's share escrow), joint-key reconstruction from a
  recovered share, and honest BondState labels for the G2 ledger.

Tests: early exit pays the stayer and kills every other pre-signed path
(frontier rule); cooperative maturity close pays clean; a vanished
counterparty is recovered via the Block 5 escrow and the clean split
executes unilaterally with the reconstructed joint key; the penalty-free
early door provably does not exist; terms validate and the penalty decays
to zero.

The `stream` module is the H5 provable drip: after a streamed exit the
penalty stays in the joint account and its pre-signed installment
signatures are sealed under a sequential RSW chain — only the first link's
starting point is public, each next start derives from the previous
solution, so not even parallel hardware can unseal ahead of schedule. The
leaver seals; the stayer audits by cut-and-choose (revealed trapdoors make
verification instant); the frontier rule forces on-chain settlement in
order, making the pacing publicly provable.

## `dexd` + `transport::tcp` (Block 10)

- `transport::tcp::TcpWire`: the `Wire` trait over real length-prefixed TCP —
  the adaptor ceremony runs across an actual localhost socket in the battery.
- `dexd`: a minimal honest relay (B4) — a de-duplicating gossip node holding
  the deterministic consolidated book, forwarding only verified orders,
  never holding funds. `Relay` is transport-agnostic; the `dexd` binary
  wraps it in a TCP listener + peer dialer.
- `dex_core::order` gained wire (de)serialization with a round-trip guard.

Tests: relay dedup/verify/drop logic, order wire round-trips, and a real
three-node `dexd` mesh on localhost where an injected order propagates
across the network intact (run the ignored `three_node_gossip_propagates`
with `--ignored`).

## Block 11 — Tor backend + live validation

- `transport::socks`: a SOCKS5 client so the `Wire` trait can ride a Tor
  circuit to a `.onion` — domain addresses are proxy-resolved (no DNS leak).
  Verified against a local mock proxy; an ignored `live_tor` test dials a
  real .onion when a Tor daemon is present.
- `nano-ceremony/tests/live_network.rs`: fetches real confirmed Nano blocks
  over public RPC and confirms our hashing, address codec, and signature
  verifier agree with the network on every one — 12/12 matched live.
  Read-only (no funds, no broadcast); run with `--features rpc -- --ignored`.

The only remaining work needs funded testnet accounts and live broadcasting
(Nano testnet + Monero stagenet), best done under supervision.

## `signing` test battery

Tests (`cargo test`): plain joint signing verified by both frost-core and the
independent Nano verifier; full adaptor lifecycle (invalid alone → complete →
extract); tamper rejection (wrong secret, foreign signature, cross-transcript
shares, tampered pre-signature); identity/small-order adaptor points refused;
edge secrets `1` and `ℓ−1`; a FROST-SHA512 signature failing Nano verification
(proving the Blake2b challenge is load-bearing); and a differential run of all
vectors (positive and negative) through a pure-Python ed25519-blake2b
reference (`signing/tests/nano_ref.py`).
