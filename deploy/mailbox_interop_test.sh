#!/usr/bin/env bash
# Prove the browser MailboxWire (web/mailbox.js, WebCrypto) is wire-compatible
# with the native one (transport::mailbox, Rust) — so a browser can run the
# swap ceremony over the same swappable relays as the helper. Rust encrypts,
# JS decrypts, and vice versa, through a shared file-backed dumb relay.
set -euo pipefail
cd "$(dirname "$0")/.."

SHARED=$(head -c32 /dev/urandom | xxd -p -c32)
D1=$(mktemp -d); D2=$(mktemp -d)
MF="--manifest-path swap-core/Cargo.toml"
RUST="cargo run -q $MF -p transport --example mailbox_file --"

echo "building example…"; cargo build -q $MF -p transport --example mailbox_file

# Rust (initiator) encrypts -> Node (responder) decrypts.
$RUST enc "$SHARED" 1 "$D1" "hello from rust" 2>/dev/null
OUT1=$(node web/mailbox_interop.cjs dec "$SHARED" 0 "$D1")
[ "$OUT1" = "hello from rust" ] && echo "PASS rust->js: '$OUT1'" || { echo "FAIL rust->js: '$OUT1'"; exit 1; }

# Node (initiator) encrypts -> Rust (responder) decrypts.
node web/mailbox_interop.cjs enc "$SHARED" 1 "$D2" "hello from browser" 2>/dev/null
OUT2=$($RUST dec "$SHARED" 0 "$D2" 2>/dev/null)
[ "$OUT2" = "hello from browser" ] && echo "PASS js->rust: '$OUT2'" || { echo "FAIL js->rust: '$OUT2'"; exit 1; }

echo "=== MailboxWire is wire-compatible across Rust (helper) and JS (browser) ==="
rm -rf "$D1" "$D2"
