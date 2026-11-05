import sys, struct
EXE = r"D:/Age of Empires II Definitive Edition/AoE2DE_s.exe"
d = open(EXE, 'rb').read()
# section map (RVA->file offset)
import pefile  # may not exist
