# Async maker-precommit swap (one party online at a time)

Goal: a maker posts an offer and goes **offline**; a taker shows up later,
**offline from the maker**, and the two complete a trustless XNO⇄XMR atomic swap
with the fewest possible on-chain round-trips, over `LedgerRelay` (the ledger as
an async message bus — nothing stored off-chain). This document is the protocol;
the crypto-dependency section is honest about what is reusable vs. new work.

## Why there is a floor of 3 messages

The swap's setup is an interactive 2-party protocol: the joint 2-of-2 key and the
adaptor pre-signature each depend on **both** parties' secret contributions.
Whatever one side commits, the other's response depends on it, and the first
side's finalization depends on that response. That mutual dependency cannot be
compressed below **three messages**: `maker → taker → maker`. WebRTC hides this
behind a live socket; async makes each message a separate on-chain post, so the
win is entirely in getting to exactly three (vs. the ~7 round-trips of the naive
interactive ceremony).

## The three posts

**Post 1 — maker precommit (published with the offer).** Everything the maker can
fix without seeing the taker:
- `P_M` — the maker's 2-of-2 public share (key aggregation is additive:
  `P = P_M + P_T`, computable by either side once both shares are known — no
  interactive DKG round).
- `T` — the adaptor point (the maker's Monero spend pubkey; revealing its secret
  `x` later is what makes the legs atomic).
- `R_M[]` — a batch of **message-independent** signing nonces (FROST round-1
  commitments are generated with no message, so they precompute cleanly; today's
  wasm couples a message in at `*_commit` — see crypto deps).
- `refund_terms` — the timelocks `T1` (taker-claim deadline) and `T2` (maker
  refund), and the maker's Nano payout address.
- `sig_M` — the maker signs the whole blob under `P_M` so the taker knows it is
  authentic and un-substituted.

Maker goes **offline**.

**Post 2 — taker response (one online session).** The taker reads Post 1 and can
now compute its entire half:
- `P_T`, and the joint account `P = P_M + P_T` (so it can verify where funds go).
- `R_T[]` — the taker's nonces, so the aggregate nonce `R = R_M + b·R_T` is fixed.
- `taker_payout` — the taker's own Nano address (this fixes the "pay-taker"
  message `m`).
- `s_T` — the taker's **partial adaptor signature** on `m`, locked to `T`. The
  taker has everything it needs (`R_M`, `R_T`, `m`, `P_M`) to produce it now.
- Optionally the taker funds/locks its leg here, referencing `T` and the timelocks.

Taker goes **offline**.

**Post 3 — maker finalize (one online session).** The maker reads Post 2 and:
- computes its own partial adaptor signature `s_M` and combines → the **complete
  adaptor pre-signature** on the pay-taker block, locked to `T`;
- funds/locks its Nano leg into the joint account (or publishes the pre-sig so the
  taker can).

From here **execution is on-chain and async, guarded by timelocks**:
- The taker completes the adaptor signature to claim the XNO; **completing reveals
  `x` on-chain**.
- The maker (whenever next online) reads `x` and sweeps the joint Monero.
- If the taker never claims by `T1`, the maker refunds; if the maker never sweeps,
  that is only the maker's loss (it already holds `x`). No counterparty can steal;
  worst case is a bounded, refundable timeout.

Net: **each party is online exactly once for setup, never together**, then normal
on-chain claim/sweep on their own schedule.

## Crypto dependencies (honest)

- **Additive key aggregation** (`P = P_M + P_T`) and **message-independent nonce
  precommit** are how MuSig2/FROST are meant to work, but the *current* wasm
  (`BrowserDkg` 2-round DKG; `sign_commit(message)` / `presign_commit(message,T)`
  couple the message into round 1) does not expose them in precommit-friendly
  form. Reaching the true 3-post minimum needs small, careful additions to
  `swap-core/wasm-bridge` (expose `commit()` without a message; expose additive
  share aggregation) plus a security review. This is real cryptographic work and
  must not be rushed — it handles funds.
- **What is reusable today, unchanged:** the whole ceremony already runs over an
  abstract relay (`MailboxWire`), and `LedgerRelay` provides that relay
  asynchronously over the ledger (proven on mainnet). So the *interactive*
  ceremony can run async **right now** at the cost of ~7 round-trips instead of 3
  — correct and trustless, just slower. The precommit redesign is a latency
  optimization, not a correctness prerequisite.

## Latency reality (measured)

On-chain posting is proof-of-work-bound: a ~200-byte message (7 Nano blocks) took
~491s when free-node work generation was rate-limited and fell back to in-browser
PoW (~70s/block). Levers, in priority order:
1. **Fewer messages** — the 3-post precommit flow above (biggest win).
2. **Fewer blocks per message** — carry large blobs in one **Monero `tx_extra`**
   (~1 KB/tx) instead of Nano's 32-bytes-per-block chaining.
3. **Reliable work generation** (a work peer / DPoW-style) so each Nano post is
   ~4s, not ~70s.

## Status

- `LedgerRelay` (async transport, ledger as bus): **built, verified on mainnet.**
- This 3-post protocol: **designed (this doc).**
- **Safe round reduction 7 → 4, IMPLEMENTED.** `runCeremonyBatched` runs two
  signer instances from one DKG key so the sign and adaptor rounds ride together:
  4 wire exchanges (DKG r1, DKG r2, batched commits, batched shares) instead of 7.
  It uses the **exact same vetted FROST calls** — no new cryptography — and passes
  a solo correctness self-test (`testBatchedCeremony`): joint sig verifies, pre-sig
  verifies and is invalid alone, the secret is revealed and extracted. The async
  ledger path now uses it, so an async swap needs ~4 on-chain message rounds.
- Precommit-friendly crypto (additive agg + bare nonce commit) for the theoretical
  3-post minimum: **still scoped, deliberately NOT implemented.** It requires a new
  cryptographic scheme (MuSig2-style) rolled by hand — the one thing that must be
  built and independently reviewed before it ever moves real funds. Reducing below
  4 rounds is a latency optimization, not a correctness requirement.
