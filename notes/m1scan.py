# m1scan.py — M1 hook-site discovery (session 11).
# Strategy: the rlink login state machine CALLS the log helper 0x1402BCB30.
# Enumerate every E8/E9 call site to it in the decrypted dump, group by
# enclosing pdata function, and classify clean-on-disk (dump==disk => the
# ONLY functions Arxan tolerates being E9-patched; session-10 rule 10b).
# Also: lea xrefs to the key login strings, same classification.
import pefile, struct, sys
sys.path.insert(0, r'C:\Python314\Lib\site-packages')
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE = 'AoE2DE_s.exe'
DUMP = 'dev/lanhook/gametext.bin'
IB = 0x140000000
BASE_TEXT = 0x140001000   # dump file offset 0 == VA 0x140001000

ex = open(EXE, 'rb').read()
d = open(DUMP, 'rb').read()
pe = pefile.PE(EXE, fast_load=True)

secs = pe.sections
def rva2off(r):
    for s in secs:
        if s.VirtualAddress <= r < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.PointerToRawData + (r - s.VirtualAddress)
    return None
def off2rva(off):
    for s in secs:
        if s.PointerToRawData <= off < s.PointerToRawData + s.SizeOfRawData:
            return s.VirtualAddress + (off - s.PointerToRawData)
    return None
def va_disk(va, n):
    o = rva2off(va - IB)
    return ex[o:o+n] if o is not None else None
def va_dump(va, n):
    o = va - BASE_TEXT
    return d[o:o+n] if 0 <= o <= len(d)-n else None

# pdata function table
pdata_sec = [s for s in secs if s.Name.rstrip(b'\0') == b'.pdata'][0]
pdata = pdata_sec.get_data()
funcs = []
for i in range(0, len(pdata)-11, 12):
    b, e, u = struct.unpack_from('<III', pdata, i)
    if b:
        funcs.append((b, e))
funcs.sort()
import bisect
begins = [f[0] for f in funcs]
def enclosing(va):
    rva = va - IB
    i = bisect.bisect_right(begins, rva) - 1
    while i >= 0:
        b, e = funcs[i]
        if b <= rva < e:
            return (IB+b, IB+e)
        if i-1 >= 0 and funcs[i-1][0] == b:
            i -= 1; continue
        break
    return None

def is_clean(va, n=16):
    dd = va_dump(va, n); dk = va_disk(va, n)
    return dd is not None and dk is not None and dd == dk

md = Cs(CS_ARCH_X86, CS_MODE_64)

# 1) all E8 call sites to 0x1402BCB30 in the dump
LOGHELPER = 0x1402BCB30
cs = []
for i in range(len(d)-5):
    if d[i] == 0xE8:
        disp = struct.unpack_from('<i', d, i+1)[0]
        tgt = BASE_TEXT + i + 5 + disp
        if tgt == LOGHELPER:
            cs.append(BASE_TEXT + i)
print('E8 call sites to LogHelper 0x%X: %d' % (LOGHELPER, len(cs)))
fns = {}
for site in cs:
    en = enclosing(site)
    if not en:
        print('  call at 0x%X: NO pdata fn' % site); continue
    fns.setdefault(en, []).append(site)
print('distinct enclosing fns: %d' % len(fns))
clean_fns = []
for (b, e), sites in sorted(fns.items()):
    cl = is_clean(b)
    if cl: clean_fns.append((b, e))
    print('  fn 0x%X-0x%X size %5d  calls %2d  clean=%d' % (b, e, e-b, len(sites), cl))
print('CLEAN fns calling LogHelper: %d' % len(clean_fns))

# 2) login strings -> lea xrefs
def find_str(s):
    o = ex.find(s + b'\x00')
    return (IB + off2rva(o)) if o >= 0 else None
MODRM = {0x05,0x0D,0x15,0x1D,0x25,0x2D,0x35,0x3D}
def lea_hits(va):
    hits = []
    for i in range(len(d)-7):
        if d[i] in (0x48,0x4C,0x4D,0x49) and d[i+1] == 0x8D and d[i+2] in MODRM:
            disp = struct.unpack_from('<i', d, i+3)[0]
            if BASE_TEXT + i + 7 + disp == va:
                hits.append(BASE_TEXT + i)
    return hits

STRS = [b'Found %zd profiles for account %s',
        b'WorldwideLoginService::WorldwideLoginService - initializing',
        b'XalSignInAsync, sign in aborted',
        b'XalBrowserHandles: commandLine: %s',
        b'Requesting ticket',
        b'SteamAuth received ticket at t=%I64u',
        b'Cannot connect to Multiplayer Services.',
        b'Signing into Multiplayer Services',
        b'NON XBOX',
        b'OnAccountEvent']
print('\n--- login string lea xrefs ---')
for s in STRS:
    va = find_str(s)
    if va is None:
        print('%-50s NOT FOUND' % s.decode()[:50]); continue
    hits = lea_hits(va)
    print('%-50s VA 0x%X leas: %d' % (s.decode()[:50], va, len(hits)))
    for h in hits[:6]:
        en = enclosing(h)
        cl = is_clean(en[0]) if en else False
        print('    lea 0x%X -> fn %s clean=%s' % (h, '0x%X-0x%X' % en if en else 'NONE', cl))
