#!/usr/bin/env python3
"""Independent Nano state-block hash: blake2b-256 over
preamble(0x…06) | account | previous | representative | balance_be16 | link.
Reads JSON lines {account, previous, representative, balance, link, expect}
(hex fields, balance decimal string) and exits non-zero on any mismatch."""
import hashlib
import json
import sys

n = 0
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    v = json.loads(line)
    h = hashlib.blake2b(digest_size=32)
    h.update(bytes(31) + b"\x06")
    h.update(bytes.fromhex(v["account"]))
    h.update(bytes.fromhex(v["previous"]))
    h.update(bytes.fromhex(v["representative"]))
    h.update(int(v["balance"]).to_bytes(16, "big"))
    h.update(bytes.fromhex(v["link"]))
    got = h.hexdigest()
    if got != v["expect"].lower():
        print(f"MISMATCH at vector {n}: {got} != {v['expect']}")
        sys.exit(1)
    n += 1
print(f"OK {n}")
