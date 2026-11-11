import sys,capstone,aoe2re,fn
p=aoe2re.PE(); d=open('gametext.bin','rb').read(); B=0x140001000
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64); md.detail=True
def strAt(va):
    off=p.va2off(va)
    if off is None: return None
    e=p.data.find(b'\0',off); s=p.data[off:e]
    if 2<len(s)<160 and all(32<=c<127 for c in s): return s.decode()
    return None
lo=int(sys.argv[1],16); hi=int(sys.argv[2],16)
for i in md.disasm(d[lo-B:hi-B],lo):
    line=f"{i.address:x}  {i.mnemonic:8s} {i.op_str}"
    if 'rip' in i.op_str:
        for op in i.operands:
            if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RIP:
                tgt=(i.address+i.size+op.mem.disp)&0xffffffffffffffff
                s=strAt(tgt); line+=f"  ; {hex(tgt)}"+(f' "{s}"' if s else '')
    if i.mnemonic=='call' and i.operands and i.operands[0].type==capstone.x86.X86_OP_IMM:
        b=fn.bounds(i.operands[0].imm)
        if b: line+=f"  ; fn {b[0]:#x}..{b[1]:#x} ({b[1]-b[0]}B)"
    print(line)
