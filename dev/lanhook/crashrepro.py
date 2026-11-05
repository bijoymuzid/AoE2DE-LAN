import ctypes, time, sys
k = ctypes.WinDLL('kernel32', use_last_error=True)
class SI(ctypes.Structure):
    _fields_=[('cb',ctypes.c_ulong),('a',ctypes.c_byte*128)]
class PI(ctypes.Structure):
    _fields_=[('hProcess',ctypes.c_void_p),('hThread',ctypes.c_void_p),
              ('pid',ctypes.c_ulong),('tid',ctypes.c_ulong)]
exe = sys.argv[1]
wait = int(sys.argv[2]) if len(sys.argv)>2 else 8
sus = 0x4 if len(sys.argv)>3 and sys.argv[3]=='susp' else 0
si=SI(); si.cb=ctypes.sizeof(SI); pi=PI()
ok = k.CreateProcessW(None, ctypes.create_unicode_buffer(exe), None, None, False,
                      sus, None, None, ctypes.byref(si), ctypes.byref(pi))
print('created',ok,'pid',pi.pid if ok else ctypes.get_last_error())
if not ok: sys.exit(1)
if sus:
    print('suspended; press on with resume in separate step')
    # read a pointer: enum modules via psapi? keep simple: resume after short manual delay
    time.sleep(2)
    k.ResumeThread(pi.hThread)
    print('resumed')
time.sleep(wait)
code = ctypes.c_ulong(0xFFFFFFFF)
alive = k.WaitForSingleObject(pi.hThread, 0) != 0
k.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
print('alive' if alive else 'dead', 'exit=%08lx'%code.value)
if not alive:
    k.CloseHandle(pi.hThread); k.CloseHandle(pi.hProcess)
