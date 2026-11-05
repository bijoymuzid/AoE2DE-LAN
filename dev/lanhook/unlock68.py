"""For every call through [vtbl+0x68](widget, bool) in the exe, group by enclosing
function and list the strings that function references (plus the arg hint).

Usage: python unlock68.py [--arg0]
  --arg0  only sites where edx looks like 0 within the preceding instructions
"""
import sys

import capstone
import numpy as np

import aoe2re as A
import fn

d = A.dump()
B = 0x140001000
p = A.pe
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

PATS = ["4c8b4968", "4c8b4868", "4c8b5168", "4c8b5068", "488b4168", "488b4868"]

sites = []
for hexp in PATS:
    pat = bytes.fromhex(hexp)
    i = d.find(pat)
    while i >= 0:
        va = B + i
        ins = list(md.disasm(d[i:i + 40], va))
        if ins and "+ 0x68]" in ins[0].op_str:
            reg = ins[0].op_str.split(",")[0]
            for nxt in ins[1:6]:
                if nxt.mnemonic == "call" and nxt.op_str.strip() == reg:
                    sites.append(va)
                    break
        i = d.find(pat, i + 1)


def strings_in(lo, hi):
    out = []
    a = lo
    while a < hi:
        got = False
        for i in md.disasm(d[a - B:hi - B], a, count=1):
            got = True
            for op in i.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    s = fn.s_at(i.address + i.size + op.mem.disp)
                    if s and len(s) > 3:
                        out.append(s)
            a = i.address + i.size
        if not got:
            a += 1
    seen, uniq = set(), []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


want_arg0 = "--arg0" in sys.argv
groups = {}
for s in sites:
    b = fn.bounds(s)
    if not b:
        continue
    groups.setdefault(b, []).append(s)

for (lo, hi), ss in sorted(groups.items()):
    if want_arg0:
        keep = False
        for s in ss:
            blk = d[s - B - 60:s - B]
            ins = list(md.disasm(blk, s - 60))
            txt = [(i.mnemonic, i.op_str) for i in ins[-8:]]
            if any(t == ("xor", "edx, edx") for t in txt) or any(
                    t[0] == "mov" and t[1].startswith("edx, 0") for t in txt):
                keep = True
        if not keep:
            continue
    print(f"== {lo:#x}..{hi:#x}  sites={[hex(x) for x in ss]}")
    for st in strings_in(lo, hi)[:14]:
        print("     ", st)