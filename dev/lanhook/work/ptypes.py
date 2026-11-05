import sys; sys.path.insert(0,".")
import struct, capstone, aoe2re as A
pe=A.pe; d=A.dump()
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64); md.detail=True
def q(va):
    o=pe.va2off(va); return struct.unpack_from('<Q',pe.data,o)[0]
def xstr(va):
    o=pe.va2off(va)
    if o is None: return None
    e=pe.data.find(b'\0',o,o+200)
    s=pe.data[o:e]
    try: s=s.decode()
    except: return None
    return s if len(s)>1 and all(32<=ord(c)<127 for c in s) else None
base=0x144116af0
for i in range(46):
    fn=q(base+i*16)
    o=A.va2off(fn)
    insns=list(md.disasm(d[o:o+0x40],fn))
    callee=None
    for ins in insns:
        if ins.mnemonic=='call' and ins.op_str.startswith('0x'):
            callee=int(ins.op_str,16); break
    if not callee:
        print(i,hex(fn),'nocall'); continue
    o2=A.va2off(callee)
    tstr=[]; mstr=[]
    for ins in md.disasm(d[o2:o2+0x100],callee):
        if 'rip' in ins.op_str:
            for op in ins.operands:
                if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
                    t=(ins.address+ins.size+op.mem.disp)&0xffffffffffffffff
                    s=xstr(t)
                    if s: tstr.append((ins.mnemonic,ins.op_str,s))
        if ins.mnemonic in ('ret',): break
    # the type name is usually loaded with lea rdx/r8/[rip] near a strcmp
    names=[s for mn,op,s in tstr if s[0].isupper() and len(s)>8]
    print(f'#{i:2d} {hex(fn)} -> {hex(callee)}  {names[:3]}  all={[s for _,_,s in tstr][:4]}')
