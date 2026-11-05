import sys; sys.path.insert(0,".")
import struct, capstone, aoe2re as A
pe=A.pe
def q(va):
    o=pe.va2off(va)
    if o is None or o+8>len(pe.data): return 0
    return struct.unpack_from('<Q',pe.data,o)[0]
d=A.dump()
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64); md.detail=True
def xstr(va):
    o=pe.va2off(va)
    if o is None: return None
    e=pe.data.find(b'\0',o,o+120)
    if e<0: return None
    s=pe.data[o:e]
    try: s=s.decode()
    except: return None
    return s if all(32<=ord(c)<127 for c in s) else None
def strs(fn,n=0x140):
    o=A.va2off(fn)
    if o<0 or o>len(d): return []
    out=[]
    for ins in md.disasm(d[o:o+n],fn):
        if 'rip' in ins.op_str:
            for op in ins.operands:
                if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
                    t=(ins.address+ins.size+op.mem.disp)&0xffffffffffffffff
                    s=xstr(t)
                    if s: out.append((hex(ins.address),s))
        if ins.mnemonic=='ret' and len(out)>0: break
    return out
start=0x144116af0
node=start
for i in range(60):
    fn=q(node); nxt=q(node+8)
    print(f'#{i:2d} node={node:x} fn={fn:x} next={nxt:x} {strs(fn)[:5]}')
    if not nxt or nxt==node: break
    node=nxt