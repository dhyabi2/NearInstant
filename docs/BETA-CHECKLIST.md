# Beta checklist — run this BEFORE announcing

The person-to-person swap has been verified offline (mocked engine calls) but
**has not yet completed end-to-end on-chain between two browsers.** Do this
once in each direction with tiny amounts. Nothing below can be automated: it
needs two funded wallets you control.

## Setup
- Device A and device B (two browsers/profiles — separate localStorage).
- Each: Wallet → Create → **Back up seed**. Fund A with ~0.5 XNO + ~0.002 XMR,
  B likewise. Wait until the Monero shows as spendable (10 confirmations).
- Both on https://www.nearinstant.xyz, hard-refreshed.

## Test 1 — maker sells Monero, taker sells Nano
1. Device A → Earn → **Start smart offering** (A's larger balance should be
   XMR; if not, adjust funding). Status must reach `live on the ledger ✓` and
   show `Your offer …abcdef · listening for takers`.
2. Device B → Swap → **Nano → get Monero** → the offer appears (marked fair) →
   enter a small XNO amount → **Review swap** → **Confirm**.
3. Watch both logs. Expected phases:
   - B: `posting take-request` → `running the joint ceremony` → `Monero: scanning…`
     → `lock found … c/10 · ~m min` (≈20 min) → `funding X XNO` → `co-signing the
     joint open` → `waiting for the counterparty to claim` → `Monero: sweep tx …
     broadcast ✓` → `swap complete`.
   - A: `a taker took your offer` → ceremony → `locking … XMR` → `Monero: lock tx …
     broadcast ✓` → `co-signing` → `broadcasting the claim` → `swap settled ✓ —
     re-posting`, Fills = 1.
4. Verify: A's Nano balance rose by the XNO amount; B's Monero shows the swept
   amount after a scan (spendable after 10 confirmations). Earn → Earned so far
   shows ≈0.8 % of the received amount.

## Test 2 — maker sells Nano, taker sells Monero
Same with roles flipped: A must hold more XNO than XMR when starting Smart
Offer; B chooses **Monero → get Nano** and enters an XMR amount.

## Failure handling to rehearse once
- Close the taker tab after `funding X XNO` and reopen: the swap must appear
  under **Unfinished swaps** with the joint addresses and last step. Only the
  final sweep resumes unattended; anything earlier needs both browsers back —
  note the exact behaviour for the announcement.
- Stop Smart Offer while idle: status must say `offer withdrawn ✓`, and the
  offer must disappear from the taker's list on Refresh.

## Announcement draft (public beta)

> **NearInstant — trustless Nano ⇄ Monero swaps, in the browser. Public beta.**
>
> No account, no custodian, no server: your keys are generated in your browser,
> offers live on the Nano ledger, and a swap is a 2-of-2 joint account settled
> with adaptor signatures. Nobody — not us — can hold or freeze your coins.
>
> Earn: post one coin you already hold and keep a 0.8 % spread each time a
> swapper trades through it. You stay in your own wallet.
>
> Honest limits, please read:
> - **Beta, no third-party audit yet.** Use small amounts.
> - The maker's browser tab must stay open for their offer to fill.
> - Keep the page open during a swap; only the final step resumes after a reload.
> - Received Monero currently sweeps to your primary address (linkable); forward
>   it onward if unlinkability matters to you.
> - Earnings depend entirely on swap volume; there are no levels, ranks or
>   guaranteed returns.
>
> Source and verification hashes: <repo link> · dist/MANIFEST.txt
>
> https://www.nearinstant.xyz
