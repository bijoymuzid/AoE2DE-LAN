"""M0.1: raw REX/lea RIP-relative scan — no linear disassembly needed."""
import sys, re, pefile, struct

BIN = 'BattleServer/BattleServer.exe'
pe = pefile.PE(BIN, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
secs = [(s.Name.rstrip(b'\x00').decode(), s.PointerToRawData, s.SizeOfRawData, s.VirtualAddress, s.Misc_VirtualSize) for s in pe.sections]
def foff2va(fo):
    for name, pr, sr, va, vs in secs:
        if pr <= fo < pr + sr:
            return base + va + (fo - pr), name
    return None, None

blob = open(BIN, 'rb').read()

targets = sys.argv[1:]
hits = {}
for m in re.finditer(rb'[\x20-\x7e]{5,}', blob):
    s = m.group().decode()
    for t in targets:
        if t in s:
            va, secname = foff2va(m.start())
            if va:
                hits[va] = s

for va, s in hits.items():
    print(f'str {va:#x} ({foff2va(0)[0]}) :: {s[:140]}')

print('\n=== code refs ===')
text = next(s for s in secs if s[0] == '.text')
tpr, tsr, tva = text[1], text[2], base + text[3]
# scan for REX(0x48-0x4F) 8D modrm(mod=00,rm=101) disp32
o = tpr
end = tpr + tsr
refs = {}
while o < end - 7:
    if 0x48 <= blob[o] <= 0x4F and blob[o+1] == 0x8D and (blob[o+2] & 0xC7) == 0x05:
        disp = struct.unpack('<i', blob[o+3:o+7])[0]
        insva = tva + (o - tpr)
        tgt = insva + 7 + disp
        if tgt in hits:
            refs.setdefault(tgt, []).append(insva)
    o += 1

for va, rlist in refs.items():
    print(f'\n{va:#x} :: {hits[va][:110]}')
    for a in rlist[:30]:
        print(f'  ref at {a:#x} (file off {0x400 + a - tva:#x})')
