# Architecture & BPMN — trustless XNO⇄XMR DEX

This document is the **full technical process model** of the app: every pool
(actor), lane, task, gateway, timer, and message flow, drawn as BPMN-style
diagrams (Mermaid, rendered natively by GitHub) plus a written specification.

It is generated from the **actual code**, not an idealised design. Where the
implementation differs from what you might expect, that is called out inline and
collected in [§9 Known gaps](#9-known-gaps--honest-notes). Read that section
before trusting any single flow.

**Regenerated 2026-08-26** against `a050c5e`. Changes folded in since the previous
revision (`5f4cd08`, 2026-08-25 22:50): the self-test UI was deleted, the taker
flow now actually consumes the selected offer, the earn calculator was reframed
from rank tiers to turnover scenarios, a **server-side Nano PoW proxy** was added
(the first and only backend function — see §1), Nano RPC gained HTTP-200
ban-body failover, the Monero node list was re-verified from a browser, and
wallet unlock now resumes a saved Monero scan.

**Source of truth (files referenced throughout):**

| Area | Files |
|---|---|
| Wallet | `web/wallet.js`, `web/wallet-worker.js`, `web/index.html` (wallet UI) |
| Earn / Smart Offer / beacon | `web/beacon.js`, `web/index.html` (`smart*`, `earn*`), `swap-core/dex-core/src/beacon.rs`, `swap-core/wasm-bridge/src/lib.rs` |
| Swap core (crypto) | `web/funded_swap.js`, `web/two_party.js`, `swap-core/signing/src/{lib,adaptor}.rs`, `swap-core/nano-ceremony/src/ceremony.rs`, `swap-core/monero-side/src/{isolation,cosign}.rs`, `swap-core/wasm-monero/src/lib.rs` |
| Taker / transport / RPC | `web/index.html` (`swOffers*`, `tpRelay`, `RPC_DEFAULTS`), `web/mailbox.js`, `web/ledger_relay.js` |
| Chunked responder (shipped, not wired) | `web/swap_machine.js`, `web/swap_responder.js` |
| Backend (the only one) | `deploy/vercel/api/work.js` |

---

## Legend

```mermaid
flowchart LR
  s((Start)):::ev --> t[Task]:::task --> g{Gateway}:::gw
  g -->|yes| e((End)):::ev
  g -.->|"message / async"| e2((End)):::ev
  x[["Sub-process"]]:::sub --> e
  classDef ev fill:#dff0d8,stroke:#3c763d
  classDef task fill:#eef,stroke:#3355aa
  classDef gw fill:#fcf8e3,stroke:#8a6d3b
  classDef sub fill:#f5e8ff,stroke:#7a3fbf
```

- **Solid arrow** = sequence flow. **Dashed arrow** = message flow / async / on-chain persistence.
- **Lanes** are drawn as `subgraph` boxes; the actor owning a task is the lane it sits in.

---

## 1. System context (pools)

```mermaid
flowchart TB
  subgraph Browser["Browser (single origin)"]
    UI[UI thread — index.html DOM + JS]:::task
    WK[Web Worker — wallet-worker.js<br/>holds seed & keys]:::task
    WASM[WASM engines<br/>wasm-bridge Nano · wasm-monero]:::task
  end
  subgraph Origin["Own origin (Vercel static + 1 function)"]
    PW[["/api/work — Nano PoW proxy<br/>input: block root hash only"]]:::sub
  end
  subgraph Chains["Public chains (censorship-resistant)"]
    NANO[(Nano RPC nodes)]:::db
    XMR[(Monero daemons — public https, or YOUR node on loopback)]:::db
  end
  subgraph Oracles["Price oracles (read-only HTTP)"]
    CG[(CoinGecko)]:::db
    CP[(Coinpaprika)]:::db
  end

  UI <-->|postMessage| WK
  WK --> WASM
  UI --> WASM
  WK -.->|fetch| NANO
  WK -.->|fetch| XMR
  UI -.->|fetch| CG
  UI -.->|fetch| CP
  UI -.->|"POST {hash}"| PW
  PW -.->|work_generate + API key| NANO
  classDef task fill:#eef,stroke:#3355aa
  classDef db fill:#e8f4ff,stroke:#2a6db0
  classDef sub fill:#f5e8ff,stroke:#7a3fbf
```

**Custody invariant (unchanged, absolute):** no server of ours ever sees key
material, a seed, a passphrase, a view key, or a balance. Secret key material
lives **only inside the Web Worker**; the DOM cannot read the Worker's closure
scope (§2.5). Every signature is produced in the browser.

**Revised "no server" claim — read this.** The previous revision said *"there is
no server."* That is no longer literally true. One serverless function now
exists: **`/api/work`** (`deploy/vercel/api/work.js`), a Nano proof-of-work
proxy. Its honest scope:

- **Input:** a block **root hash** (64 hex) and optional difficulty. Nothing else;
  the body is capped at 4 KiB and both fields are regex-validated.
- **Output:** `{work, difficulty}`.
- **It never** sees a seed, key, passphrase, address, balance, or amount, and it
  **cannot broadcast** anything. A root hash is public and non-identifying.
- **Why it exists:** it holds the upstream `work_generate` API key server-side
  (browsers cannot hold a secret) and returns GPU work in ~1 s, where in-browser
  PoW takes far longer.
- **It is optional and defeatable.** Settings → *Proof-of-work* has a
  **local-only** toggle (`localStorage["xnoxmr_pow_local"] === "1"`), which skips
  the proxy entirely and grinds PoW in wasm. With it on, the app is once again
  fully serverless. The proxy is the *default* because it is dramatically faster,
  not because anything depends on it.

The only other network calls are to public chain RPC nodes and two read-only
price oracles. **The retired Hostinger relay VPS and the native wallet-helper
(`ws://127.0.0.1:47999`) are both gone** — deleted in `f3c7c67` and the earlier
F4 cleanup. Settlement is now browser-only; there is no local helper path.

---

## 2. Wallet lifecycle

Lanes: **User**, **UI thread**, **Web Worker**, **WASM**, **localStorage /
sessionStorage**. The Worker is the only lane that ever holds `seedHex` at
runtime.

Recurring data objects:
`cipher = {v:1, mem:65536, salt, iv, ct}` at `localStorage["nearinstant_wallet_v1"]`;
`pass` (plaintext passphrase) transiently at `sessionStorage["nearinstant_unlock_sess"]`;
`{account, address}` (public) is the only normal output crossing back to the UI.

### 2.1 Create new wallet

```mermaid
flowchart TB
  s((User clicks Create)):::ev --> g1{pass.length ≥ 8?}:::gw
  g1 -->|no| e1((Reject: too short)):::ev
  g1 -->|yes| boot[UI: walletBoot — load WASM + spawn Worker]:::task
  boot --> gen["Worker/WASM: gen_identity() — seed via OsRng CSPRNG"]:::task
  gen --> kdf["Worker/WASM: argon2id_raw pass+salt, 64 MiB → AES-256 key"]:::task
  kdf --> enc[Worker: AES-GCM encrypt seed → ct]:::task
  enc --> der["WASM: seed_account → Nano {account,address}"]:::task
  der --> g2{pubkey valid?}:::gw
  g2 -->|no| e2((Error: invalid seed)):::ev
  g2 -->|yes| back["Worker→UI: {cipher, account, address} ONLY (seed stays in Worker)"]:::task
  back --> save[UI: saveCipher → localStorage; armIdle 15 min]:::task
  save --> rem[UI: rememberUnlock pass → sessionStorage]:::task
  rem --> e((Wallet open + unlocked — prompt to back up seed)):::ev
  classDef ev fill:#dff0d8,stroke:#3c763d
  classDef task fill:#eef,stroke:#3355aa
  classDef gw fill:#fcf8e3,stroke:#8a6d3b
```

At-rest custody: `passphrase → Argon2id (m = 64 MiB, t = 2, p = 1, v0x13, 32-byte
tag) → AES-256-GCM`, salt 16 random bytes, IV 12 random bytes, both stored beside
the ciphertext. The seed is generated with `OsRng` (`gen_identity`,
`wasm-bridge/src/lib.rs`). `argon2id_raw` clamps memory to a floor of 19 MiB
(`mem_kib.max(19 * 1024)`), so a caller cannot weaken it below the OWASP minimum.

**Verified 2026-08-26** (Chrome 151, live origin): the create→lock→unlock
round-trip is deterministic and correct — same passphrase reopens the wallet
from a cold Worker and across a reload; a wrong passphrase fails the GCM tag and
surfaces as `wrong passphrase`. The KDF parameters have never changed since the
feature landed (`f8247ad`), so no wallet can have been orphaned by a parameter
drift. **A "wrong passphrase" on a wallet you believe is correct therefore means
the stored blob was re-encrypted under a different passphrase** — i.e. a later
*Create* or *Restore & set password* overwrote it (§2.2).

### 2.2 Restore from backup seed

```mermaid
flowchart TB
  s((User pastes 64-hex seed + new password)):::ev --> g1{pass ≥ 8 chars?}:::gw
  g1 -->|no| e1((Reject)):::ev
  g1 -->|yes| imp["Worker: importWallet(seed, pass) — fresh salt+iv, re-encrypt"]:::task
  imp --> g2{seed valid 64-hex → pubkey?}:::gw
  g2 -->|no| e2((Error: invalid seed)):::ev
  g2 -->|yes| bk{"a DIFFERENT cipher already stored?"}:::gw
  bk -->|yes| prev["UI: copy old blob → localStorage nearinstant_wallet_v1_prev"]:::task --> save
  bk -->|no| save[UI: saveCipher — OVERWRITES the active wallet]:::task
  save --> e((Restored — unlocked under the NEW password)):::ev
  classDef ev fill:#dff0d8,stroke:#3c763d
  classDef task fill:#eef,stroke:#3355aa
  classDef gw fill:#fcf8e3,stroke:#8a6d3b
```

Restore **sets a new password** for this device (the `wImportPass` field) — it
does not reuse the previous one. This is the most common way a device ends up
with a wallet whose passphrase is not the one the user remembers.

The `_prev` safety net (`a0a13d7`) keeps the previous encrypted blob before an
overwrite, but it is **still only openable with its own passphrase** and it was
added late — wallets overwritten before that commit have no backup. Restore is
**64-hex only** (no BIP39 mnemonic).

### 2.3 Unlock (manual + auto-on-load) — now resumes the Monero scan

```mermaid
flowchart TB
  s((Page load)):::ev --> a{"sessionStorage pass AND cipher present?"}:::gw
  a -->|no| idle((Show locked shell — Unlock or Create)):::ev
  a -->|yes| auto[walletAutoUnlock: unlock silently]:::task
  idle --> u((User enters passphrase → Unlock)):::ev
  u --> kdf
  auto --> kdf["Worker/WASM: argon2id_raw pass + cipher.salt (64 MiB)"]:::task
  kdf --> dec[Worker: AES-GCM decrypt ct]:::task
  dec --> g{GCM tag verifies?}:::gw
  g -->|no| bad["throw 'wrong passphrase' — UI: 'Wrong passphrase.'<br/>auto-path: forgetUnlock and stay locked"]:::task --> idle
  g -->|yes| set[Worker: setSeed → derive account+address; armIdle 15 min]:::task
  set --> after[[walletAfterOpen]]:::sub
  after --> scan{"saved Monero scan position?<br/>nearinstant_xmr_&lt;addr&gt;.scannedTo"}:::gw
  scan -->|yes| res["show 'scanned to block N — resuming…' and auto-run walletXmrRefresh()"]:::task --> e
  scan -->|no| e((Wallet open)):::ev
  classDef ev fill:#dff0d8,stroke:#3c763d
  classDef task fill:#eef,stroke:#3355aa
  classDef gw fill:#fcf8e3,stroke:#8a6d3b
  classDef sub fill:#f5e8ff,stroke:#7a3fbf
```

**New in `8196b4b`.** Previously an unlocked wallet showed a bare Monero balance
with no hint that a multi-thousand-block scan had ever run; the user had to know
to tap *Refresh & scan*. `walletAfterOpen` now reads the persisted scan record
(`{restore, scannedTo, outputs, spent}` per Monero address, checkpointed every
20 blocks), displays the block it reached, and **auto-resumes** the scan.
`walletAfterOpen` is also the hook that restarts a running Smart Offer, so an
offer never sits live on the beacon while the wallet that backs it is locked.

### 2.4 Lock / idle-lock

Explicit lock (`walletCta`), idle timeout (15 min, `armIdle`), and Smart Offer's
`keepAlive(true)` suspension are unchanged. Lock clears `seedHex` in the Worker
**and** `sessionStorage["nearinstant_unlock_sess"]`, so a lock is a real lock and
not just a UI state — `walletAutoUnlock` cannot silently reopen it afterwards.

### 2.5 Key isolation (cross-cutting invariant)

The seed exists only as `seedHex` inside the Worker closure. The UI thread can
request `sign`, `account`, `xmr_*` operations by `postMessage`, and receives only
results. The **single** path that returns the seed is `reveal`, which is gated on
`requireGesture()` — a fresh, real user gesture — so injected script cannot
exfiltrate it headlessly. `/api/work` (§1) receives a block root hash and nothing
else, so adding it did not widen this boundary.

---

## 3. Earn / Smart Offer + beacon

### 3.1 Start → poll/reprice loop

```mermaid
flowchart TB
  s((User: Start earning)):::ev --> w{wallet unlocked?}:::gw
  w -->|no| jump[jump to Wallet view]:::ev
  w -->|yes| bal[read balances; pick the coin you hold more of]:::task
  bal --> px[[marketPrice — fail-closed §3.5]]:::sub
  px --> pub[publish offer on the beacon §3.2]:::task
  pub --> poll["makerPollTake — poll OUR OWN offer for a taker"]:::task
  poll --> t{taker handshake?}:::gw
  t -->|no| age{price moved / offer stale?}:::gw
  age -->|yes| pub
  age -->|no| poll
  t -->|yes| run[[settle: ceremony → runA/runB §4]]:::sub
  run --> rec[record fill in nearinstant_history; grow next offer]:::task --> pub
  classDef ev fill:#dff0d8,stroke:#3c763d
  classDef task fill:#eef,stroke:#3355aa
  classDef gw fill:#fcf8e3,stroke:#8a6d3b
  classDef sub fill:#f5e8ff,stroke:#7a3fbf
```

The provider loop is real: post → `makerPollTake` on the maker's own offer →
ceremony → `runA`/`runB` → record → re-post with earnings folded in. It runs
unattended while the page is open, with `keepAlive` suspending the idle lock and
a `beforeunload` warning if a settlement is mid-flight.

### 3.2–3.4 Offer encoding, read side, cancel

Unchanged from the previous revision: intents are packed into the **amount field
of a Nano send** (price, side, size, expiry), published on-chain, decoded by
`scan`/`scanLive`, and cancelled with a sentinel. On-chain publication is what
makes the order book censorship-resistant and asynchronous — an offer persists
without any server holding it.

### 3.5 Fail-closed pricing (`marketPrice`) — the safety spine

`marketPrice()` (`web/index.html:1009`) reads CoinGecko and Coinpaprika. If the
oracles disagree beyond tolerance, or none answers, it **throws** and no offer is
published or repriced. Nothing is ever quoted from a single unchecked source.
This is the guard that stops a poisoned price from writing a bad offer on-chain.

### 3.6 Earn accounting + the calculator (REFRAMED)

Earnings are **taker-fee-derived**: a maker captures the ~0.8 % spread each time
their liquidity is traded through. There is no yield on idle capital, no
inflation, no token.

**Changed in `37b7207`.** The calculator previously presented **rank tiers**
(Bronze/Silver/Gold/Founder) with an implied %/month on *capital*, plus claims
that a higher tier gets "picked first" and "carries bigger trades". Both the
capital framing and the priority claim were unsupported by the engine, which has
no tenure or rank input at all. The calculator now exposes the **only** variable
that actually drives earnings — **monthly turnover** (how many times your coins
are traded through per month, each pass paying the spread) — presented as
user-chosen **scenarios**, labelled `SCENARIO`, not levels and not a promise.
Tenure- and priority-based language is gone.

> **Honest note.** `fills` and "earned" are still read from the device-local
> `nearinstant_history` record (spread ≈ MARGIN × received), **not** recomputed
> from the public ledger. Two devices show two different totals for the same
> wallet. See §9.

---

## 4. Atomic swap core (two-pool collaboration)

### 4.1 Collaboration overview

```mermaid
flowchart TB
  subgraph A["Pool A — XNO-seller browser"]
    a1[DKG share → joint Nano account]:::task
    a2[adaptor pre-sign the Nano claim]:::task
    a3[co-sign open + refund]:::task
    a4[extract x from B's claim → sweep XMR]:::task
  end
  subgraph B["Pool B — XMR-seller browser"]
    b1[DKG share → joint Monero spend/view]:::task
    b2[generate adaptor secret x, publish T]:::task
    b3[lock XMR to the joint address]:::task
    b4[complete pre-sig with x → claim XNO]:::task
  end
  b2 -.->|T| a2
  a1 <-.->|DKG blobs over MailboxWire| b1
  b3 -.->|on-chain XMR lock, 10 confs| a3
  a3 -.->|joint Nano funded + refund pre-signed| b4
  b4 -.->|claim sig published on Nano| a4
  classDef task fill:#eef,stroke:#3355aa
```

The link is an **adaptor signature**: B can only claim the Nano by completing a
pre-signature with the secret `x`, and doing so publishes `x` on-chain, which A
extracts to sweep the Monero. One secret unlocks both legs — that is the
atomicity.

### 4.2 Cryptographic sub-processes

Unchanged. 2-of-2 FROST DKG and signing (`swap-core/signing`), adaptor
pre-signature / complete / extract (`signing/src/adaptor.rs`), joint Monero
spend key and `shared_view_key` (`monero-side`), all exposed to the browser
through `wasm-bridge` (`BrowserDkg`, `BrowserSigner`) and `wasm-monero`.

### 4.3 Settlement driver — Monero side now fully narrated

**Changed in `c46caa8`.** Monero is the slow leg (a 10-confirmation wait is
~20 min) and previously a silent minute was indistinguishable from a hang.
`web/two_party.js` now emits a line for every phase:

| Phase | Narration |
|---|---|
| connect | `Monero: connecting to a node…` |
| scan | `scanning blocks N–M for the X XMR lock (chain at T) · P%` |
| lock broadcast | `lock tx abc123… broadcast ✓ — taker waits ~20 min for 10 confirmations` |
| confirming | `lock found at block N · c/10 confirmations · ~m min left · checking again in 45 s` |
| not yet seen | `no X XMR lock on the joint address yet · re-scanning in 45 s (check n)` |
| confirmed | `lock of X XMR confirmed ✓ (block N, c confirmations)` |
| sweep | `building the sweep (ring signature with real decoys + fee)` → `broadcasting` → `sweep tx abc123… broadcast ✓` |

`waitJointXmrLock` scans in 10-block windows from `sinceHeight − 5` (or
`tip − 720` cold), polls every 45 s, and requires `XMR_CONF = 10`.

Logs are rendered by `logTo(id, m)`: timestamped, newest at the bottom,
auto-scrolling, with the **latest line repeated in bold at the top** so the
current state is one glance away.

### 4.4 Atomicity & the counterparty-abort gap

Unchanged and still the sharpest edge: there is a **refund/timelock path
pre-signed for the Nano leg**, but a counterparty who aborts at the wrong moment
can still strand the Monero leg pending manual recovery. The `pledge` crate
(bilateral grief bonds) and `puzzle-escrow` (I1 time-lock refund backstop) are
built and exposed to wasm, but the **browser executor that would drive them is
not wired** (§9). Use small amounts.

---

## 5. Taker order book — the selected offer now drives settlement

```mermaid
flowchart TB
  s((Swap tab)):::ev --> side[user picks the coin they SELL — swSide]:::task
  side --> fetch["scanLive: read live offers for the OTHER side (swWantSide)"]:::task
  fetch --> rank[rank by price; render rows]:::task
  rank --> pick["user clicks a row → swSelected = offer"]:::task
  pick --> amt[user enters amount]:::task
  amt --> deal[["tpDealFromInput → TP.dealFromOffer(swSelected, xnoRaw)"]]:::sub
  deal --> g{amount ≤ offer max?}:::gw
  g -->|no| tb((show 'too big for this offer')):::ev
  g -->|yes| q[render quote]:::task
  q --> go((user confirms → TP.takerHandshake with swSelected)):::ev
  go --> run[[settle §4]]:::sub
  classDef ev fill:#dff0d8,stroke:#3c763d
  classDef task fill:#eef,stroke:#3355aa
  classDef gw fill:#fcf8e3,stroke:#8a6d3b
  classDef sub fill:#f5e8ff,stroke:#7a3fbf
```

**Gap 1 of the previous revision is CLOSED.** `swSelected` was cosmetic — ranked
and displayed, but never read by any settlement back-end, which ran hard-coded
0.0001↔0.0001 amounts. It now drives the real path: `tpDealFromInput`
(`index.html:2207`) reads `swSelected.intent.price_e9`, converts the typed
amount to `xnoRaw` in the direction implied by `swSide`, rejects an amount above
`offerMaxXnoRaw(swSelected.intent)`, and builds the deal via
`TP.dealFromOffer(swSelected, xnoRaw)`. `takerHandshake(M, tpRelay(), swSelected,
deal, tpLog)` (`index.html:2256`) carries that exact offer into settlement.

Roles follow the offer's side: side 1 (maker sells XMR) ⇒ taker is **A**
(XNO-seller); side 0 ⇒ taker is **B** (XMR-seller).

**The self-test UI is gone entirely** (`e495862`). There is no mode selector, no
`?twoparty=1` URL flag, and no `xnoxmr_swmode` state: `TWO_PARTY = false` and
`swMode = "peer"` are constants, and the Swap tab is only ever
swap-with-someone. The underlying engine paths remain for automated tests.
Direction buttons can no longer be locked by leftover self-test state
(`01b47d7`).

---

## 6. Async transport / signaling

All transports expose the same `post(mailbox,seq,blob)` / `fetch(mailbox,seq)`
interface consumed by **`MailboxWire`**, which wraps every message in AES-GCM
with the sequence number bound as additional-authenticated-data (so tamper,
reorder, or misroute makes decrypt throw). The ceremony code is
transport-agnostic.

```mermaid
flowchart LR
  subgraph Wire["MailboxWire (crypto envelope)"]
    snd["send: AES-GCM encrypt, AAD = box‖seq → post to every relay"]:::task
    rcv["recv: poll fetch(box,seq) every 500ms until timeout → decrypt (AAD-checked)"]:::task
  end
  Wire --> B1
  Wire --> B2
  Wire --> B3
  subgraph B1["B1 · Beacon (on-chain intents)"]
    x1[intent packed in Nano send amount — persists on-chain, async]:::task
  end
  subgraph B2["B2 · LedgerRelay (arbitrary blobs) — the live path"]
    x2["32-byte chunks in representative field; header in amount; retry ×6 / 4s — async"]:::task
  end
  subgraph B3["B3 · WebRTC DataChannel"]
    x3["manual copy/paste SDP signaling; STUN only — requires BOTH online"]:::task
  end
  classDef task fill:#eef,stroke:#3355aa
```

`tpRelay()` (`index.html:2201`) builds the live transport:
`makeLedgerRelay({beacon, wasm, urls: rpcState.nano, seed})` — **B2**, riding the
user's own configured Nano nodes. There is no relay server.

**Async property (works if only one party is online at a time):** B1 and B2 write
to the public ledger, so a blob persists as an on-chain receivable until the peer
next comes online and fetches it. **B3 (WebRTC) is the exception** — it needs
both browsers connected simultaneously.

---

## 7. RPC reliability / failover

### 7.1 Nano — failover, HTTP-200 ban bodies, and the read quorum

```mermaid
flowchart TB
  s((Nano rpc call)):::ev --> loop[Iterate endpoints in config order; 10s AbortController each]:::task
  loop --> g1{r.ok?}:::gw
  g1 -->|no / timeout| next[record lastErr; try next]:::task --> loop
  g1 -->|yes| body{"HTTP 200 but body has .error?"}:::gw
  body -->|"ban/rate/429/busy/overload"| next
  body -->|"benign (Account not found)"| done((Return JSON)):::ev
  body -->|no error| done
  next --> gall{all failed?}:::gw
  gall -->|yes| eall((Throw: all connections failed)):::ev

  s2((accountInfoQuorum — reads that gate signing)):::ev --> q[Query first 3 endpoints]:::task
  q --> q0{≥1 answered?}:::gw
  q0 -->|no| qe0((Throw)):::ev
  q0 -->|yes| q2{"≥2 configured but <2 answered?"}:::gw
  q2 -->|yes| qe2((Throw: need ≥2 agreeing)):::ev
  q2 -->|no| qd{all answers agree on frontier+balance?}:::gw
  qd -->|no| qed((Throw: nodes disagree — refuse to sign — FAIL-CLOSED)):::ev
  qd -->|yes| qok((Return agreed head)):::ev
  classDef ev fill:#dff0d8,stroke:#3c763d
  classDef task fill:#eef,stroke:#3355aa
  classDef gw fill:#fcf8e3,stroke:#8a6d3b
```

**New in `91937de`.** Some public nodes answer a rate-limit with **HTTP 200 and
an error body** (`rpc.nano.to` returns `{"error":429,"message":"IP banned…"}`).
The old code treated any 200 as success and returned that object as data.
`beacon.js` now inspects the body: a **numeric** `error`, or a message matching
`/ban|abuse|rate|too many|429|busy|overload|unavailable|penalty|limit/i`, is
treated as a node failure and fails over. Benign query errors ("Account not
found", "Bad account number") still pass through as legitimate answers — the
distinction matters, because a fresh account legitimately reports not-found.

Node order (`RPC_DEFAULTS.nano`): `rpc.nano-gpt.com` (added in `a9fbfa2` — open
CORS, serves both `process` and reads, no 200-ban behaviour), then
`rainstorm.city`, `node.somenano.com`, `nanoslo.0x.no`, `rpc.nano.to`.

`processBlock` broadcasts the **same** signed block to **every** node
(idempotent, censorship-resistant). The quorum's disagreement check is the key
anti-manipulation guard: a lying node cannot under-report balance to trick a send.

### 7.2 Nano proof-of-work — three-step chain with a local-only escape

```mermaid
flowchart TB
  s((generateWork root, threshold)):::ev --> t{"localStorage xnoxmr_pow_local = 1?"}:::gw
  t -->|yes| rpc
  t -->|no| px["POST same-origin /api/work {hash, difficulty}"]:::task
  px --> pv{"work returned AND work_check passes locally?"}:::gw
  pv -->|yes| ok((Return work)):::ev
  pv -->|no / error| rpc["RPC work_generate on configured nodes<br/>(most public nodes deny it)"]:::task
  rpc --> rv{valid?}:::gw
  rv -->|yes| ok
  rv -->|no| wasm["in-browser wasm work_search<br/>~130k hashes/slice, yields to keep UI alive"]:::task --> ok
  classDef ev fill:#dff0d8,stroke:#3c763d
  classDef task fill:#eef,stroke:#3355aa
  classDef gw fill:#fcf8e3,stroke:#8a6d3b
```

**Every returned work value is re-verified locally** with
`wasm.work_check(root, work, threshold)` before use — the proxy and the RPC nodes
are **untrusted**. A malicious proxy can at worst deny service; it cannot make
the browser accept invalid work, and it never learns anything but a public root
hash. The **local-only** toggle (Settings → Proof-of-work) skips step 1 entirely.

### 7.3 Monero — rotation, no quorum, and what the browser will actually connect to

`xmrPost` uses a 12 s timeout; `xmrRefresh`/`xmrSend` iterate the node list and
**rotate to the next node on any error** (the round-robin index persists across a
chunked scan, so a bad node is skipped for the whole scan). Scans checkpoint to
localStorage every 20 blocks and are resumable (§2.3). **Monero has no
cross-node quorum** — the first working node wins.

**Node reachability is a hard browser constraint, not a preference.** Re-verified
in Chrome 151 on 2026-08-26 against every node in the wallet's default list and
the Unstoppable Wallet node list:

```mermaid
flowchart TB
  s((candidate node URL)):::ev --> p{scheme}:::gw
  p -->|https| c{"sends Access-Control-Allow-Origin?"}:::gw
  c -->|yes| ok((USABLE)):::ev
  c -->|no| x1((BLOCKED — CORS: response unreadable)):::ev
  p -->|http| l{"host is loopback?<br/>localhost · 127.0.0.0/8 · [::1]"}:::gw
  l -->|yes| c2{"node sends ACAO?<br/>monerod --rpc-access-control-origins"}:::gw
  c2 -->|yes| ok2((USABLE — even from the https page)):::ev
  c2 -->|no| x2((BLOCKED — CORS)):::ev
  l -->|no| pg{"is THIS page also plain http?"}:::gw
  pg -->|no| x3((BLOCKED — mixed content)):::ev
  pg -->|yes| c2
  classDef ev fill:#dff0d8,stroke:#3c763d
  classDef gw fill:#fcf8e3,stroke:#8a6d3b
```

Two independent gates, both enforced by the browser's fetch stack and
**not overridable from page code**:

1. **Mixed content** — an `https` page may not open plain `http` to a *public*
   host. **Loopback is exempt**: Chrome treats `http://localhost` and
   `http://127.0.0.1` as potentially trustworthy, so they connect fine from the
   hosted https page (verified against a local daemon on 2026-08-26).
2. **CORS** — any cross-origin response without `Access-Control-Allow-Origin` is
   unreadable, regardless of scheme. There is no way around this: the
   preflight-avoiding "simple request" trick (`content-type: text/plain`, which
   monerod accepts) removes the preflight but the *response* still needs ACAO, and
   `mode:"no-cors"` yields an opaque body. Tested and confirmed failing.

**Raw TCP is not available to this page.** The WICG Direct Sockets API
(`TCPSocket`/`UDPSocket`/`TCPServerSocket`) is real, but exposed only to
**Isolated Web Apps** — and IWAs reach end users only on ChromeOS. Confirmed
empirically: `typeof TCPSocket === "undefined"` on the live origin in Chrome 151.
This is why a node list that works for a **native** wallet (Unstoppable, Cake,
Monerujo — all speaking raw HTTP on 18081/18089) is largely unusable here; the
nodes are healthy, the browser simply refuses the connection.

| Node | Alive | Browser-usable | Why |
|---|---|---|---|
| `https://xmr.hexide.com:443` | ✅ | ✅ **default** | https + CORS |
| `https://node.sethforprivacy.com:443` | ✅ | ✅ **default** (added `a050c5e`) | https + CORS; `json_rpc`, `get_outs`, `get_blocks.bin` all verified |
| `https://xmr-node.cakewallet.com:18081` | ✅ | ✅ **default** | https + CORS |
| `http://127.0.0.1:18081` (your own) | — | ✅ **best** | loopback exempt from mixed content; needs `--rpc-access-control-origins` |
| `xmr.unstoppable.money:443` | ✅ | ❌ | https but **no ACAO**; preflight → 405 |
| `node.xmr.rocks:18089` | ✅ | ❌ | http-only + no ACAO |
| `opennode.xmr-tw.org:18089` | ✅ | ❌ | http-only + no ACAO |
| `nodex.monerujo.io:18081` | ✅ | ❌ | http-only + no ACAO |
| `monero.stackwallet.com:18081` | ✅ | ❌ | http-only + no ACAO |
| `xmr.cryptostorm.is:18081` | ❌ | ❌ | retired `a050c5e` — no longer answers |
| `xmr.triplebit.org` | ❌ | ❌ | retired `a050c5e` — no longer answers |

**Run your own node — the intended path.** `wallet.js`'s `usableNode()` now
accepts loopback `http://` URLs (previously every non-`https://` entry was
silently dropped, so a user could add their own node in Settings and it would
never be used). Settings documents the one-line daemon flag. This is the only
configuration in which no third party learns which addresses you query.

**List maintenance.** `rpcLoad` merges: a saved user list keeps the user's own
entries, drops URLs listed in `RPC_RETIRED`, and gains any new verified default
the user does not yet have — so a browser with a stale saved list self-heals
without discarding custom nodes.

> **Honest note.** `rpcCheck` probes each node's health and latency but is used
> **only to paint the settings panel** — it does **not** reorder the active node
> list at runtime. Node order is user-config order, seeded healthy-first.

---

## 8. Monero wallet maturity — measured against a reference implementation

A full audit of **Unstoppable Wallet (Android)** + `monero-kit` was run on
2026-08-26 and compared against our wallet. The reference delegates essentially
everything to native `wallet2`; we reimplement it in Rust/wasm, so it is a fair
mirror for what a mature Monero wallet does that we do not. **Every item below
was re-verified directly in our source** before being recorded here.

### 8.1 Scanning cost — the dominant performance problem

`scan_all` walks `scannable_block_by_number(n)` **one block at a time**
(`wasm-monero/src/lib.rs:381-423`), 20 blocks per worker message, with a fresh
`XmrNode::connect` + `height()` per chunk (`wallet-worker.js:192-204`). Each
block fans out to roughly 3–5 HTTP round trips (block hash → get_block →
get_transactions → get_o_indexes.bin), so a 20-block chunk costs ~60–100
requests and a cold 4320-block scan costs **~20,000 requests**.

The dependency we already ship exposes the batched form:
`contiguous_scannable_blocks(range)` in `monero-daemon-rpc` issues **one** epee
`get_blocks.bin` POST for the whole range, with an automatic JSON-batch
fallback. Our JS transport already handles binary bodies (`get_blocks.bin` was
verified working against the default nodes). This is the single largest available
speed win and it is a call-the-existing-API change, not new cryptography.

### 8.2 Verified correctness defects in `xmrSend`

| # | Defect | Evidence | Consequence |
|---|---|---|---|
| 1 | **Single-input sends only** | `wallet.js:385-390` filters for one output covering the amount, sorts descending, takes `usable[0]`; throws `no single spendable output covers …` | A wallet holding the amount across several outputs **cannot spend it at all**. Also always spends the largest output — a consolidation/privacy anti-pattern. |
| 2 | **Fee is a hardcoded guess** | `wallet.js:388` — `BigInt(o.amount) > amount + 200000000n` (0.0002 XMR headroom) | No fee is ever queried, computed, or shown to the user before they commit. |
| 3 | **Fee rate sanity check disabled** | `lib.rs:462,519` — `fee_rate(FeePriority::Normal, u64::MAX)`; the crate documents `max_per_weight` as a MUST sanity-check | A hostile node can quote an absurd fee rate and we build, sign and publish in the same call with no confirmation step. |
| 4 | **Failover re-signs the transaction** | `wallet.js:394-399` — the whole `xmr_send` (build + sign + relay) is retried against the next node | If node 1 actually relayed but the reply was lost, node 2 gets a **second signature spending the same key image**. |
| 5 | **Spent-set written after broadcast** | `wallet.js:403-404` — `st.spent.push` runs after `call("xmr_send")` resolves | A crash between relay and write leaves a spent output marked spendable. |
| 6 | **Ring size hardcoded to 16** | `lib.rs:457,514` — `OutputWithDecoys::new(…, 16, …)` | Silently breaks at the next consensus ring-size change; the reference passes `mixin=0` to inherit the consensus default. |
| 7 | **No send-max / sweep** | no `Change::None` path | The wallet can never be emptied. |
| 8 | **Send permitted mid-scan** | `xmrSend` calls `xmrRefresh` but does not require `scannedTo >= tip` | Spending against a stale output set. |
| 9 | **Address validated by regex only** | `index.html:1494`, `wallet.js:379` — `/^[1-9A-HJ-NP-Za-km-z]{95,106}$/`; real parse happens in Rust at build time | Typos surface after a multi-minute scan rather than at entry. |
| 10 | **Health data collected then discarded** | `rpcCheck` (`index.html:631`) measures height + latency for the Settings panel only; scan/send walk `rpcState.monero` in list order | A node hundreds of blocks behind is used if it is first, corrupting confirmation counts and swap timelocks. |

The reference ranks nodes by **height descending, then latency ascending**
(`BestNodeComparator`), pinged 10-wide with a hard 5 s cap. Adopting that
ordering is cheap — we already collect both numbers.

### 8.3 Privacy gaps vs. the reference

- The reference **never reuses an address**: every receive is a fresh unused
  subaddress (index 0 explicitly excluded), and change goes to a new subaddress.
  We use **one static primary address forever**, for every deposit, every swap
  sweep, and every change output (§9.9).
- Our per-address scan cache (`nearinstant_xmr_<addr>`) is written to
  localStorage in **plaintext** — outputs, amounts, block heights, spent set.
  The seed is Argon2id+AES-GCM protected; the transaction graph derived from it
  is not. Anything with DOM access reads a full history.

---

## 9. Known gaps & honest notes

True of the code as it stands, so the diagrams above are not read as more than
they are. **Closed since the last revision:** old gap 1 (`swSelected` cosmetic —
now drives settlement, §5) and old gap 7 (earn tier calculator framing — reframed
to turnover scenarios, §3.6).

1. **No refund/timelock in live two-party settlement** (§4.4). `pledge` (grief
   bonds) and `puzzle-escrow` (I1 time-lock refund) are built and exposed to
   wasm, but the browser executor that drives them does not exist. A
   counterparty who aborts at the wrong moment can strand the Monero leg pending
   manual recovery. **Use small amounts.**
2. **Chunked auto-responder not wired to chain.** `swap_machine.js` /
   `swap_responder.js` ship, but with no browser executor for bonds/guard/chunks
   a person-to-person swap is **one chunk = the whole amount**.
3. **Mid-ceremony resume needs both browsers.** Snapshots and per-step markers
   persist (`nearinstant_2p_*`, indexed in `nearinstant_2p_index`) and appear
   under *Unfinished swaps*, but only the post-co-sign tail (A after `x`, B after
   `claim`) resumes unattended. The co-sign middle is not resumable across a
   reload — the mailbox wire and signer nonces are in memory. A re-handshake
   protocol is needed.
4. **Monero send is single-input, unpriced, and re-signs on failover** — see
   §8.2, items 1–5. These are the most consequential open defects in the wallet.
5. **Monero scanning is ~20,000 requests cold** (§8.1) because the batched
   `get_blocks.bin` path in a dependency we already ship is unused.
6. **Monero has no read quorum** — timeout + node rotation only. Nano's
   fail-closed quorum has no Monero equivalent.
7. **No dynamic health-first RPC ordering.** `rpcCheck` paints the settings panel
   and nothing else (§7.3, §8.2 item 10).
8. **Restore is 64-hex only** (no BIP39) and **overwrites** the active wallet.
   The `_prev` backup exists only for overwrites after `a0a13d7`, and is itself
   only openable with its own passphrase (§2.2). This is the usual cause of a
   "wrong passphrase" on a wallet the user believes is correct.
9. **On-chain linkability (Monero privacy).** The sweep sends received XMR to the
   wallet's **primary address**, reused on every swap, and the Nano claim goes to
   the main Nano account; change also returns to the primary address. An observer
   can link swaps to each other and to the user's main Monero identity. The fix —
   a **fresh subaddress per sweep/change** (and fresh Nano account per claim) —
   needs new derivation plus subaddress-aware scanning in
   `wasm-monero`/`wasm-bridge` (`xmr_personal`/`scan_all` are primary-address
   only), so it is a Rust/wasm change, not a frontend edit. Documented to users
   in the FAQ; deferred until it can be verified on-chain, because an untested
   sweep to an unscanned subaddress would strand funds.
10. **Scan cache is plaintext** in localStorage (§8.3).
11. **Fills / earnings are device-local.** They come from `nearinstant_history`
    on this device (spread ≈ MARGIN × received), not recomputed from the public
    ledger, so two devices disagree for the same wallet.
12. **One backend function now exists** (`/api/work`, §1). It is minimal,
    untrusted (its output is re-verified locally), and defeatable via the
    local-only PoW toggle — but the literal "zero servers" claim no longer holds
    and should not be repeated in user-facing copy without that qualifier.
13. **Most public Monero nodes are unusable from a browser** and this is not
    fixable in page code (§7.3). Running your own node on loopback is the
    intended and strongest configuration.
14. **No two-browser on-chain swap has been completed end-to-end.** The
    person-to-person flow is verified against mocks and in unit/integration
    tests; a real mainnet run with two independent browsers is still outstanding.

---

*Generated from the codebase. When code changes, regenerate the affected
section rather than editing the diagram in isolation.*
