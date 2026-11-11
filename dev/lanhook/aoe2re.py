"""AoE2DE static-analysis toolkit.

  gametext.bin = decrypted .text of AoE2DE_s.exe, VA = 0x140001000 + offset
  AoE2DE_s.exe = the shipped image (readable .rdata strings)

Usage (from dev/lanhook):
  python -c "import re as R; ..."   <- name clash; import via 'import importlib'
  python re.py <cmd> ...
"""
import struct
import sys

import capstone
import numpy as np

import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_PFX = os.environ.get("AOE2LAN_PFX", os.path.join(_HERE, "..", "..", "..", "winepfx"))
# paths are host-local: the wine prefix layout on Linux, the old W1 layout as fallback
_EXE_L = os.path.join(_PFX, "pfx", "drive_c", "Games", "AoE2DE", "AoE2DE_s.exe")
_EXE_W = r"D:\Age of Empires II Definitive Edition\AoE2DE_s.exe"
_DUMP_L = os.path.join(_HERE, "gametext.bin")
_DUMP_W = r"D:\Age of Empires II Definitive Edition\dev\lanhook\gametext.bin"
EXE = os.environ.get("AOE2DE_EXE") or (_EXE_L if os.path.exists(_EXE_L) else _EXE_W)
DUMP = os.environ.get("AOE2DE_DUMP") or (_DUMP_L if os.path.exists(_DUMP_L) else _DUMP_W)
DUMP_BASE = 0x140001000

_md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
_md.detail = True


class PE:
    def __init__(self, path=EXE):
        self.data = open(path, "rb").read()
        d = self.data
        lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        self.imagebase = struct.unpack_from("<Q", d, lfanew + 0x30)[0]
        nsec = struct.unpack_from("<H", d, lfanew + 6)[0]
        optsz = struct.unpack_from("<H", d, lfanew + 0x14)[0]
        self.sections = []
        off = lfanew + 0x18 + optsz
        for i in range(nsec):
            name = d[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
            vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", d, off + 8)
            self.sections.append((name, va, vsize, rawptr, rawsize))
            off += 40

    def rva2off(self, rva):
        for name, va, vsize, rawptr, rawsize in self.sections:
            if va <= rva < va + max(vsize, rawsize):
                return rawptr + (rva - va)
        return None

    def va2off(self, va):
        return self.rva2off(va - self.imagebase)

    def off2va(self, off):
        for name, va, vsize, rawptr, rawsize in self.sections:
            if rawptr <= off < rawptr + rawsize:
                return self.imagebase + va + (off - rawptr)
        return None

    def find_string(self, s, utf16=False):
        pat = s.encode("utf-16le") if utf16 else (s.encode() if isinstance(s, str) else s)
        out, i = [], self.data.find(pat)
        while i >= 0:
            out.append((i, self.off2va(i)))
            i = self.data.find(pat, i + 1)
        return out


pe = PE()
_dump = None


def dump():
    global _dump
    if _dump is None:
        _dump = open(DUMP, "rb").read()
    return _dump


def off2va(off):
    return DUMP_BASE + off


def va2off(va):
    return va - DUMP_BASE


def read(va, n):
    o = va2off(va)
    return dump()[o:o + n]


def u8(va):
    return dump()[va2off(va)]


def u32(va):
    return struct.unpack_from("<I", dump(), va2off(va))[0]


def i32(va):
    return struct.unpack_from("<i", dump(), va2off(va))[0]


def u64(va):
    return struct.unpack_from("<Q", dump(), va2off(va))[0]


def cstr(va):
    off = pe.va2off(va)
    if off is None:
        return None
    d = pe.data
    e = d.find(b"\0", off, off + 400)
    if e < 0:
        return None
    return d[off:e].decode("utf-8", "replace")


def dis(va, n=40, stop_ret=True):
    out = []
    o = va2off(va)
    d = dump()
    for ins in _md.disasm(d[o:o + n * 15], va):
        out.append((ins.address, ins.size, f"{ins.mnemonic} {ins.op_str}"))
        if stop_ret and ins.mnemonic == "ret":
            break
    return out


def show(va, n=40):
    for a, sz, t in dis(va, n):
        print(f"{a:#x}: {t}")


_idx_full = None


def xrefs(va, limit=40):
    """Positions (instruction VAs) whose RIP-relative operand resolves to va."""
    global _idx_full
    d = dump()
    if _idx_full is None:
        arr = np.frombuffer(d[: len(d) // 4 * 4], dtype="<i4").astype(np.int64)
        arr += np.arange(len(arr), dtype=np.int64)
        _idx_full = arr
    target = va - DUMP_BASE - 4
    idx = np.nonzero(_idx_full == target)[0]
    res = []
    for i in idx:
        # disp stored at byte i..i+3, next insn starts at file offset i+4 => VA
        cand_va = DUMP_BASE + i + 4
        # back off a few bytes and disassemble to confirm the instruction is
        # RIP-relative and ends exactly at cand_va
        for back in range(3, 11):
            start = cand_va - back
            for ins in _md.disasm(d[va2off(start):va2off(start) + 15], start):
                if ins.address + ins.size == cand_va and "rip" in ins.op_str:
                    res.append((ins.address, f"{ins.mnemonic} {ins.op_str}"))
                    break
            else:
                continue
            break
        else:
            res.append((cand_va - 4, "<unconfirmed>"))
        if len(res) >= limit:
            break
    return res


def find_calls(target, limit=200):
    d = dump()
    out = []
    i = 0
    while True:
        i = d.find(b"\xe8", i)
        if i < 0 or len(out) >= limit:
            break
        rel = struct.unpack_from("<i", d, i + 1)[0]
        if DUMP_BASE + i + 5 + rel == target:
            out.append(DUMP_BASE + i)
        i += 1
    return out


def func_start(va, max_back=0x2000):
    """Heuristic: walk back to the nearest int3/ret-aligned padding block."""
    o = va2off(va)
    d = dump()
    for k in range(1, max_back):
        if d[o - k:o - k + 1] == b"\xcc":
            j = o - k + 1
            while d[j:j + 1] == b"\xcc":
                j += 1
            return DUMP_BASE + j
    return None


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    if cmd == "sec":
        for s in pe.sections:
            print(s[0], hex(s[1]), hex(s[2]), hex(s[3]), hex(s[4]))
        print("imagebase", hex(pe.imagebase), "dumpsize", hex(len(dump())))
    elif cmd == "str":
        for off, va in pe.find_string(sys.argv[2]):
            print(hex(off), hex(va), "->", cstr(va))
    elif cmd == "xref":
        for a, t in xrefs(int(sys.argv[2], 16)):
            print(hex(a), t)
    elif cmd == "dis":
        show(int(sys.argv[2], 16), int(sys.argv[3]) if len(sys.argv) > 3 else 40)
    elif cmd == "cstr":
        print(cstr(int(sys.argv[2], 16)))
    else:
        print("cmds: sec str xref dis cstr")