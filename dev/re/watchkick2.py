# watchkick2.py <pid> — async-run the game, poll the peer array via
# /proc/<pid>/mem (no stop needed), and the moment a NEW peer appears:
# interrupt -> arm h/w watchpoints on peer+0x18 (reason dword) and peer+0x40
# (flag byte) -> blocking continue -> on write: dump peer + backtrace.
import gdb, os, struct, time

PID = int(gdb.parse_and_eval("$_pid")) if False else int(os.environ["TARGET_PID"])

gdb.execute("set pagination off")
gdb.execute("set confirm off")
for sig in ("SIGILL", "SIGSYS", "SIGPWR", "SIGXCPU", "SIG34", "SIG35"):
    gdb.execute(f"handle {sig} nostop noprint pass")
gdb.execute("handle SIGTRAP nostop noprint nopass")

def read_u64_mem(addr):
    with open(f"/proc/{PID}/mem", "rb", buffering=0) as m:
        m.seek(addr)
        return struct.unpack("<Q", m.read(8))[0]

def peer_list():
    g = read_u64_mem(0x144C9E5F0)
    if not g:
        return []
    mgr = read_u64_mem(g + 0x1880)
    if not mgr:
        return []
    beg, end = read_u64_mem(mgr + 0x70), read_u64_mem(mgr + 0x78)
    if not (0 < end - beg <= 0x1000):
        return []
    return [read_u64_mem(beg + i * 16) for i in range((end - beg) // 16)]

def wait_stopped():
    for _ in range(200):
        try:
            gdb.execute("x/i $pc", to_string=True)
            return True
        except gdb.error:
            time.sleep(0.01)
    return False

known = set()
wps = []

class ReasonWP(gdb.Breakpoint):
    def __init__(self, peer, off):
        expr = f"*({'int' if off == 0x18 else 'char'}*)({peer}+{off})"
        super().__init__(expr, gdb.BP_WATCHPOINT, gdb.WP_WRITE)
        self.peer, self.off = peer, off

def on_stop(ev):
    if isinstance(ev, gdb.SignalEvent):
        return
    for w in wps:
        if w.hit_count > 0 and not getattr(w, "_dumped", False):
            w._dumped = True
            print(f"\n=== WATCHPOINT peer={w.peer:#x} off={w.off:#x} hit ===", flush=True)
            print(gdb.execute(f"x/48gx {w.peer}", to_string=True), flush=True)
            print(gdb.execute("info registers rip rdx rsi rdi r8 r9", to_string=True), flush=True)
            print(gdb.execute("bt 30", to_string=True), flush=True)

gdb.events.stop.connect(on_stop)

print(f"watchkick2 on pid {PID}: async continue + external poll", flush=True)
gdb.execute("continue &")
t_end = time.time() + 3600
while time.time() < t_end:
    try:
        peers = peer_list()
    except OSError:
        peers = []
    new = [p for p in peers if p and p not in known]
    if new:
        gdb.execute("interrupt")
        if wait_stopped():
            for p in new:
                known.add(p)
                print(f"NEW PEER {p:#x} — arming watchpoints", flush=True)
                wps.append(ReasonWP(p, 0x18))
                wps.append(ReasonWP(p, 0x40))
            print(gdb.execute("continue", to_string=True), flush=True)  # blocks until WP hit / signal
            print("--- continue returned (WP or stop); resuming async poll", flush=True)
            gdb.execute("continue &")
    time.sleep(0.005)
