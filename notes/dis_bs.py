"""M0.1/M0.4: disassemble around BattleServer ProcessPacket/PeerMessage functions."""
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BIN = 'BattleServer/BattleServer.exe'
blob = open(BIN, 'rb').read()
pe = pefile.PE(BIN, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
text = [s for s in pe.sections if s.Name.rstrip(b'\x00') == b'.text'][0]
tva, tpr = base + text.VirtualAddress, text.PointerToRawData
tdata = text.get_data()

def va2fo(va):
    return tpr + (va - tva)

md = Cs(CS_ARCH_X86, CS_MODE_64)

def show(start_va, n=140, name=''):
    print(f'===== {name} @ {start_va:#x} =====')
    code = blob[va2fo(start_va):va2fo(start_va)+n*15]
    for i, ins in enumerate(md.disasm(code, start_va)):
        if i >= n:
            break
        print(f'{ins.address:#x}: {ins.mnemonic:10s} {ins.op_str}')
    print()

import sys
# functions found by string xrefs:
# ProcessPeerMessage region ~0x1400dadab-ish; ProcessPacket region ~0x1400de1cd-ish
# find function starts: scan backwards for push rbx / sub rsp pattern? Just show from a bit before the first ref.
show(0x1400daaf0, 400, 'ProcessPeerMessage')
show(0x1400de050, 500, 'ProcessPacket')
