# Trustless transport — peer-to-peer, nothing stored

The two-party ceremony needs the two browsers to exchange a handful of encrypted
messages. It must do this **without any server storing anything** and without a
party you have to trust. That rules out a hosted key-value "relay" (even a blind,
TTL'd one is still a stored, trusted box). The transport is therefore **direct
browser-to-browser (WebRTC DataChannel)**, and the only bootstrap uses the medium
we already trust for everything else: **the Nano ledger**.

## How it works (no stored server anywhere)

1. **Discovery** — makers already publish offers on the Nano ledger (the beacon).
   That is the meeting point; no server involved.
2. **Signaling over the ledger** — to connect, the two sides exchange a compact,
   encrypted WebRTC handshake (SDP + ICE) as beacon-style on-chain messages,
   addressed to a mailbox id derived from the order + a shared secret. Small,
   one-time, and it rides the same trustless rail as the offers themselves —
   nothing is stored off-chain.
3. **Direct P2P** — once the DataChannel is up, the entire FROST 2-of-2 + adaptor
   ceremony runs **browser-to-browser**, end-to-end encrypted, ephemeral. When the
   tab closes, it is gone. No third party ever holds a byte.

## NAT traversal — what touches the network, and its trust level

- **STUN** (public, stateless): only reflects your own public IP:port back to you
  so the two browsers can find each other. It stores nothing and relays no
  content. A malicious STUN sees an IP, never content, and cannot MITM (WebRTC
  DTLS + our own AES-GCM sit on top).
- **Symmetric-NAT fallback**: the ~10–20% of networks where direct P2P fails
  normally need a TURN relay, which *does* forward bytes. Rather than trust a
  hosted TURN, the fallback here is to **retry via a different network path or
  wait** — and, if needed, let a user run their own TURN. The ceremony is
  crash-safe and resumable, so a failed connect never risks funds; you simply
  reconnect and continue.

## Security model

- The transport is **untrusted by design**. Every ceremony message is AES-GCM
  sealed with the mailbox+sequence bound into the AAD (already how `mailbox.js`
  works), so tampering, reordering, replay, or misrouting fail to decrypt in the
  browser. The worst any network element can do is **withhold** (a liveness
  failure you retry), never forge or read.
- No custody, no settlement, no oracle: funds move only on-chain between the two
  parties' own keys. There is nothing to store and nothing to trust.

## What changes in code (drop-in)

`mailbox.js` already speaks an abstract relay with `post(mailbox, seq, blob)` /
`fetch(mailbox, seq)` and an AES-GCM `MailboxWire`. We add a **`WebRTCWire`**
(same `send`/`recv` interface) so the existing ceremony code is unchanged — only
the transport swaps from "HTTP relay" to "direct DataChannel", with on-chain
signaling to establish it. No hosted server, no stored state.

## Honest tradeoffs vs a stored relay

- **+** Fully trustless, nothing persisted, no infra to run or pay for.
- **−** Connection setup is a few seconds slower (on-chain signaling + ICE), and
  symmetric-NAT peers may need a retry or a self-run TURN. The ceremony itself,
  once connected, is instant.
