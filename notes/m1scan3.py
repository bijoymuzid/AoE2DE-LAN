# m1scan3.py — verify the login-fn region state: runtime-executed (ret 0x140674542,
# 0x140670062, 0x14061C20C, 0x1405FE49F) vs dump bytes vs disk bytes; and survey the
# string-neighborhood of "NON XBOX" (0x143285EC8) + fn 0x140F0F990-0x140F10514.
import pefile, struct, sys
sys.path.insert(0, r'C:\Python314\Lib\site-packages')
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE = 'AoE2DE_s.exe'
DUMP = 'dev/lanhook/gametext.bin'
IB = 0x140000000
BT = 0x140001000
ex = open(EXE, 'rb').read()
d = open(DUMP, 'rb').read()
pe = pefile.PE(EXE, fast_load=True)
secs = pe.sections
def rva2off(r):
    for s in secs:
        if s.VirtualAddress <= r < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.PointerToRawData + (r - s.VirtualAddress)
    return None
def vdisk(va, n):
    o = rva2off(va - IB); return ex[o:o+n] if o is not None else None
def vdump(va, n):
    o = va - BT; return d[o:o+n] if 0 <= o <= len(d)-n else None
md = Cs(CS_ARCH_X86, CS_MODE_64)

print('--- runtime-executed login sites: dump vs disk ---')
for name, ret in [('profiles', 0x140674542), ('init', 0x140670062),
                  ('XalBrowser', 0x14061C20C), ('abort', 0x1405FE49F)]:
    call = ret - 5
    vd = vdump(call, 16); dk = vdisk(call, 16)
    enc_dump = b'\x00' * 16
    print('%-10s call 0x%X dump=%s disk=%s' % (name, call, vd.hex(' '), dk.hex(' ')))
    ins = next(md.disasm(vd, call), None)
    if ins:
        print('           dump decodes as: %s %s' % (ins.mnemonic, ins.op_str))

print('\n--- NON XBOX neighborhood (0x143285EC8; PLAN cites 0x3284abc/0x3284ac8) ---')
for va in (0x143284ABC, 0x143284AC8, 0x143285EC8):
    o = rva2off(va - IB)
    if o is not None:
        print('0x%X disk: %r' % (va, ex[o:o+64].split(b'\x00')[0]))
print('\n--- lea site 0x140F0FBA5 context (fn 0x140F0F990-0x140F10514, encrypted) ---')
code = vdump(0x140F0FB60, 128)
for ins in md.disasm(code, 0x140F0FB60):
    mark = ' <<<' if ins.address == 0x140F0FBA5 else ''
    print('  0x%x  %-22s %s %s%s' % (ins.address, ins.bytes.hex(' '), ins.mnemonic, ins.op_str, mark))
