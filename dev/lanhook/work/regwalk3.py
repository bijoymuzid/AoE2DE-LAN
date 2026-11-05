import sys; sys.path.insert(0,".")
import struct, capstone, aoe2re as A
pe=A.pe
def q(va):
    o=pe.va2off(va); return struct.unpack_from('<Q',pe.data,o)[0]
d=A.dump()
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64); md.detail=True
def xstr(va):
    o=pe.va2off(va)
    if o is None: return None
    e=pe.data.find(b'\0',o,o+200)
    if e<0: return None
    s=pe.data[o:e]
    try: s=s.decode()
    except: return None
    return s if len(s)>1 and all(32<=ord(c)<127 for c in s) else None
base=0x144116af0
for i in range(56):
    fn=q(base+i*16)
    o=A.va2off(fn)
    strs=[]; calls=[]; n=0
    for ins in md.disasm(d[o:o+0x300],fn):
        n+=1
        if 'rip' in ins.op_str:
            for op in ins.operands:
                if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
                    t=(ins.address+ins.size+op.mem.disp)&0xffffffffffffffff
                    s=xstr(t)
                    if s: strs.append(s)
        if ins.mnemonic=='call' and ins.op_str.startswith('0x'):
            t=int(ins.op_str,16)
            # ignore thunk/helper region 0x14039xxxx
            if not (0x14039a000 <= t < 0x1403a0000): calls.append(hex(t))
        if n>90: break
    print(f'#{i:2d} {fn:x} strs={strs[:5]} calls={calls[:4]}')