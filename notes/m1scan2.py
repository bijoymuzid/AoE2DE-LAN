# m1scan2.py — disassemble the CLEAN LogHelper callers from m1scan.py:
# which strings they pass, the call arg pattern, and prologue bytes.
import pefile, struct, sys
sys.path.insert(0, r'C:\Python314\Lib\site-packages')
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE = 'AoE2DE_s.exe'
DUMP = 'dev/lanhook/gametext.bin'
IB = 0x140000000
BASE_TEXT = 0x140001000
ex = open(EXE, 'rb').read()
d = open(DUMP, 'rb').read()
pe = pefile.PE(EXE, fast_load=True)
secs = pe.sections
def rva2off(r):
    for s in secs:
        if s.VirtualAddress <= r < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.PointerToRawData + (r - s.VirtualAddress)
    return None
def va_str(va, n=90):
    o = rva2off(va - IB)
    if o is None: return None
    s = ex[o:o+n].split(b'\x00')[0]
    try: return s.decode()
    except: return repr(s)
def dd(b, n):
    o = b - BASE_TEXT
    return d[o:o+n]

md = Cs(CS_ARCH_X86, CS_MODE_64)

TARGETS = [(0x140505DE0, 0x14050691F),
           (0x1405FED30, 0x1405FF7ED),
           (0x1405FF7F0, 0x1405FFF93),
           (0x140600AF0, 0x14060111E),
           (0x140601E10, 0x140602449),
           (0x14077DB90, 0x14077DFED)]
LOG = 0x1402BCB30
for b, e in TARGETS:
    code = dd(b, e - b)
    print('=== fn 0x%X-0x%X (prologue %s)' % (b, e, code[:8].hex(' ')))
    for i in range(len(code) - 5):
        if code[i] == 0xE8:
            disp = struct.unpack_from('<i', code, i+1)[0]
            if b + i + 5 + disp == LOG:
                site = b + i
                print('  LogHelper call at 0x%X (ret 0x%X)' % (site, site+5))
                # look back up to 60 bytes for rdx loads (lea rdx / mov rdx)
                seg = code[max(0,i-64):i]
                base = b + max(0,i-64)
                for ins in md.disasm(seg, base):
                    tgt = None
                    if ins.mnemonic == 'lea' and ins.op_str.startswith('rdx,') :
                        # rip-relative?
                        if 'rip' in ins.op_str:
                            tgt = ins.address + ins.size + int(ins.op_str.split('rip')[-1].strip().lstrip('+').rstrip(']') or '0', 16) if '0x' in ins.op_str else None
                    if tgt:
                        s = va_str(tgt)
                        print('    rdx lea at 0x%X -> 0x%X: %r' % (ins.address, tgt, (s[:100] if s else None)))
    # also print all leas to .rdata strings in the first 120 bytes (purpose hint)
    print('  first strings referenced:')
    shown = 0
    for i in range(min(200, len(code)-7)):
        if code[i] in (0x48,0x4C,0x4D,0x49) and code[i+1] == 0x8D and code[i+2] in {0x05,0x0D,0x15,0x1D,0x25,0x2D,0x35,0x3D}:
            disp = struct.unpack_from('<i', code, i+3)[0]
            tgt = b + i + 7 + disp
            if 0x143000000 <= tgt < 0x144000000:
                s = va_str(tgt)
                if s and len(s) > 4:
                    print('    0x%X: %r' % (tgt, s[:110])); shown += 1
                    if shown > 8: break
