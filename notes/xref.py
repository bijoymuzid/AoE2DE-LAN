"""Section-aware REX-lea xref scanner. Usage: xref.py <substring> [<substring2> ...]"""
import re, sys, pefile, struct

BIN = 'AoE2DE_s.exe'
pe = pefile.PE(BIN, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
blob = open(BIN, 'rb').read()

def fo2va(fo):
    for s in pe.sections:
        if s.PointerToRawData <= fo < s.PointerToRawData + s.SizeOfRawData:
            return base + s.VirtualAddress + (fo - s.PointerToRawData)
    return None

targets = {}
for m in re.finditer(rb'[\x20-\x7e]{5,}', blob):
    s = m.group().decode()
    if any(t in s for t in sys.argv[1:]):
        va = fo2va(m.start())
        if va:
            targets[va] = s
print(f'{len(targets)} candidate strings')
for va, s in list(targets.items())[:40]:
    print(f'  {va:#x} :: {s[:120]}')

text = [s for s in pe.sections if s.Name.rstrip(b'\x00') == b'.text'][0]
TPR, TSZ, TVA = text.PointerToRawData, text.SizeOfRawData, base + text.VirtualAddress
o = TPR; end = TPR + TSZ; refs = {}; n = 0
while o < end - 7:
    b = blob[o]
    if 0x40 <= b <= 0x4F and blob[o+1] == 0x8D and (blob[o+2] & 0xC7) == 0x05:
        disp = struct.unpack('<i', blob[o+3:o+7])[0]
        insva = TVA + (o - TPR)
        tgt = insva + 7 + disp
        if tgt in targets:
            refs.setdefault(tgt, []).append(insva); n += 1
    o += 1
print(f'--- {n} refs ---')
for va, r in refs.items():
    print(f'\n{va:#x} :: {targets[va][:110]}')
    for a in r[:20]:
        print(f'  ref {a:#x} (file off {a - TVA + TPR:#x})')
