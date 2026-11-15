#!/usr/bin/env python3
# scan_calls.py <snapshot.bin> <target_rva> [target2...] — find direct-call sites
# (e8 rel32) to RVA targets in a .text snapshot (offset 0 == RVA 0x1000).
import sys, struct

snap = open(sys.argv[1], "rb").read()
targets = {int(t, 16) for t in sys.argv[2:]}
SEC_RVA, BASE = 0x1000, 0x140000000

hits = {t: [] for t in targets}
for off in range(len(snap) - 5):
    if snap[off] != 0xE8:
        continue
    rel = struct.unpack_from("<i", snap, off + 1)[0]
    src_rva = off + SEC_RVA
    dst = (BASE + src_rva + 5 + rel) - BASE
    if dst in targets:
        hits[dst].append(src_rva)

for t in sorted(hits):
    print(f"target {t:#x}: {len(hits[t])} call sites")
    for s in hits[t]:
        print(f"  call at RVA {s:#x}")
