# armcatch.py — runs inside `gdb -p <pid> -batch -x armcatch.py` with env
# PEER=0x... TARGET_PID=...  Arms h/w write-watchpoints on peer+0x18 (reason
# dword) and peer+0x40 (flag byte), continues, dumps on hit, then DETACHES
# cleanly (never leave a stopped tracee behind).
import gdb, os, time

PEER = int(os.environ["PEER"], 16)

gdb.execute("set pagination off")
gdb.execute("set confirm off")
for sig in ("SIGILL", "SIGSYS", "SIGPWR", "SIGXCPU", "SIGWINCH", "SIG34", "SIG35", "SIG32", "SIG33"):
    try:
        gdb.execute(f"handle {sig} nostop noprint pass")
    except gdb.error:
        pass
gdb.execute("handle SIGTRAP nostop noprint nopass")

hit = {"n": 0}

class ReasonWP(gdb.Breakpoint):
    def __init__(self, off):
        expr = f"*({'int' if off == 0x18 else 'char'}*)({PEER}+{off})"
        super().__init__(expr, gdb.BP_WATCHPOINT, gdb.WP_WRITE)
        self.off = off

def on_stop(ev):
    if isinstance(ev, gdb.SignalEvent):
        return
    for b in gdb.breakpoints():
        if isinstance(b, ReasonWP) and b.hit_count > 0:
            hit["n"] += 1
            print(f"\n=== WRITE peer={PEER:#x} off={b.off:#x} hit#{b.hit_count} ===", flush=True)
            print(gdb.execute(f"x/48gx {PEER}", to_string=True), flush=True)
            print(gdb.execute("info registers rip rax rbx rcx rdx rsi rdi r8 r9 r14 r15", to_string=True), flush=True)
            print(gdb.execute("bt 40", to_string=True), flush=True)

gdb.events.stop.connect(on_stop)
w1 = ReasonWP(0x18)
w2 = ReasonWP(0x40)
print(f"armcatch: peer={PEER:#x} watchpoints armed", flush=True)

t_end = time.time() + 45
while time.time() < t_end and hit["n"] == 0:
    try:
        gdb.execute("continue")
    except gdb.error as e:
        print("continue err:", e, flush=True)
        break

print(f"armcatch: done hits={hit['n']}, detaching", flush=True)
gdb.execute("detach")
gdb.execute("quit")
