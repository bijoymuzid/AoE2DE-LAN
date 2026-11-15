# probelocal.py — is GetLocalRelayServerInfo (0x140ee9420) called, what returns?
# gdb -p <pid> -batch -x probelocal.py ; detaches cleanly at the end.
import gdb, time

gdb.execute("set pagination off")
gdb.execute("set confirm off")
for sig in ("SIGILL", "SIGSYS", "SIGPWR", "SIGXCPU", "SIGWINCH"):
    try:
        gdb.execute(f"handle {sig} nostop noprint pass")
    except gdb.error:
        pass

calls = {"n": 0}

class Entry(gdb.Breakpoint):
    def stop(self):
        calls["n"] += 1
        Fin()
        return False

class Fin(gdb.FinishBreakpoint):
    def stop(self):
        v = self.return_value
        print(f"GetLocalRelayServerInfo #{calls['n']} -> {v}", flush=True)
        return False

Entry("*0x140ee9420")
print("probe armed, 30s window", flush=True)
t_end = time.time() + 30
while time.time() < t_end:
    try:
        gdb.execute("continue")
    except gdb.error as e:
        print("continue err:", e, flush=True)
        break
print(f"probe done, calls={calls['n']}", flush=True)
gdb.execute("detach")
gdb.execute("quit")
