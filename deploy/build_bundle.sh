#!/usr/bin/env bash
# Build the content-addressed single-file app bundle.
#
# The web app (web/index.html) is fully self-contained — inline CSS + JS, no
# external fonts/CDN/analytics, no baked-in network calls (RPC endpoints are
# user-supplied at runtime). So the file itself IS the deliverable: a user can
# save it and open it locally, and it can be pinned to IPFS/Arweave and mirrored
# anywhere. Its content hash is its identity — no host to trust or take down.
#
# This script copies it to dist/, computes its SHA-256 (universal, verify
# out-of-band) and its IPFS CIDv1-raw (resolves on any IPFS gateway), and writes
# a MANIFEST. The hashes are published OUTSIDE the file (here, git tags, a
# pinned post) so the file stays byte-clean — embedding the CID would change the
# file and thus the CID (circular). Reproducible: same input → same hashes.
set -euo pipefail
cd "$(dirname "$0")/.."

SRC="web/index.html"
OUT="dist"
mkdir -p "$OUT"
cp "$SRC" "$OUT/swap.html"

# Cache-bust the lazy-loaded assets. index.html requests them as `<file>?v=$ASSET_V`;
# if ASSET_V never changes, a browser serves a STALE cached copy after a deploy
# even though swap.html itself is content-addressed (the bug that hid new
# two_party.js/wasm from users). Derive ASSET_V from the actual asset bytes so it
# changes iff an asset changes — same input, same version (reproducible).
ASSETS="web/two_party.js web/mailbox.js web/beacon.js web/ledger_relay.js \
  web/wallet.js web/wallet-worker.js web/swap_machine.js web/swap_responder.js \
  web/swap_driver.js web/custody.js web/custody_core.js web/custody-worker.js \
  web/funded_swap.js web/pkg/wasm_bridge_bg.wasm web/pkg-xmr/wasm_monero_bg.wasm"
ASSET_V=$(cat $ASSETS 2>/dev/null | shasum -a 256 | cut -c1-12)
# Replace the placeholder ASSET_V in the bundled copy (source keeps its literal).
sed -i.bak "s/const ASSET_V = \"[^\"]*\";/const ASSET_V = \"$ASSET_V\";/" "$OUT/swap.html"
rm -f "$OUT/swap.html.bak"
echo "asset version: $ASSET_V"

SHA=$(shasum -a 256 "$OUT/swap.html" | awk '{print $1}')

# CIDv1, raw codec, sha2-256: multibase-base32( 0x01 0x55 0x12 0x20 <digest> ).
# Any IPFS gateway resolves this for a single-block (<256KB) raw file.
CID=$(python3 - "$SHA" <<'PY'
import sys
digest = bytes.fromhex(sys.argv[1])
blob = bytes([0x01, 0x55, 0x12, 0x20]) + digest   # ver=1, raw, sha2-256, len=32
# RFC4648 base32 lowercase, no padding; multibase prefix 'b'.
ALPHA = "abcdefghijklmnopqrstuvwxyz234567"
bits = 0; val = 0; out = []
for byte in blob:
    val = (val << 8) | byte; bits += 8
    while bits >= 5:
        bits -= 5; out.append(ALPHA[(val >> bits) & 31])
if bits: out.append(ALPHA[(val << (5 - bits)) & 31])
print("b" + "".join(out))
PY
)

SIZE=$(wc -c < "$OUT/swap.html" | tr -d ' ')
cat > "$OUT/MANIFEST.txt" <<EOF
trustless XNO<->XMR swap — content-addressed single-file bundle
================================================================
file:        swap.html   ($SIZE bytes, fully self-contained)
sha256:      $SHA
ipfs cidv1:  $CID

VERIFY (no server needed):
  shasum -a 256 swap.html   # must equal the sha256 above

PUBLISH (pick any / all — content hash is identical everywhere):
  ipfs add --cid-version=1 --raw-leaves dist/swap.html
  # or drag into web3.storage / Pinata; or host the file anywhere
  # (GitHub Pages, Codeberg, a VPS, Arweave). It is the SAME file/hash.

REACH IT (any of these resolve the same bytes):
  https://<cid>.ipfs.dweb.link
  https://ipfs.io/ipfs/$CID
  or open the saved swap.html directly (file://).

The hash is published OUTSIDE this file (here, git tags, pinned posts) so
the file stays byte-clean. If two sources disagree on the bytes, the hash
mismatch exposes it — the file cannot be tampered at one host without
changing its address.
EOF

echo "built $OUT/swap.html"
echo "sha256: $SHA"
echo "cidv1:  $CID"
