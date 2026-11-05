import sys; sys.path.insert(0,".")
import struct, capstone, aoe2re as A

pe = A.pe
def u64f(va):
    o = pe.va2off(va)
    if o is None: return None
    return struct.unpack_from('<Q', pe.data, o)[0]

head = 0x144c9e3e0
node = u64f(head)
print('head ptr', hex(node) if node else node)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=True
d = A.dump()

def strs_in(fn, n=0x180):
    off = A.va2off(fn)
    out=[]
    for ins in md.disasm(d[off:off+n], fn):
        if 'rip' in ins.op_str:
            for op in ins.operands:
                if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
                    t=(ins.address+ins.size+op.mem.disp)&0xffffffffffffffff
                    s=A.cstr(t)
                    if s and len(s)<80: out.append((hex(ins.address),s))
    return out

for i in range(80):
    if not node: break
    fn = u64f(node)
    nxt = u64f(node+8)
    print(f'#{i:2d} node={hex(node)} fn={hex(fn) if fn else None}', strs_in(fn)[:6])
    node = nxt