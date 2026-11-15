# gdb watchpoint harness: poll peer array each event-pump call; arm h/w
# watchpoints on peer+0x18 (reason dword) and peer+0x40 (flag byte) for any
# NEW peer; on write, dump backtrace + peer object.
import gdb

gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("handle SIGILL nostop noprint pass")
gdb.execute("handle SIGTRAP nostop noprint nopass")
gdb.execute("handle SIGPWR nostop noprint pass")
gdb.execute("handle SIGXCPU nostop noprint pass")

STATE = {"count": 0, "hits": 0}

def read_u64(addr):
    return int.from_bytes(gdb.selected_inferior().read_memory(addr, 8), "little")

class ReasonWP(gdb.Breakpoint):
    def __init__(self, expr, peer, off):
        super().__init__(expr, gdb.BP_WATCHPOINT, gdb.WP_WRITE)
        self.peer = peer
        self.off = off
    def stop(self):
        print(f"\n=== WATCHPOINT peer={self.peer:#x} off={self.off:#x} ===", flush=True)
        gdb.execute(f"x/48gx {self.peer}")
        gdb.execute("info registers rip rdx rsi rdi r8 r9")
        gdb.execute("bt 30")
        return True

class PollBP(gdb.Breakpoint):
    def stop(self):
        STATE["hits"] += 1
        try:
            g = read_u64(0x144C9E5F0)
            if not g:
                return False
            mgr = read_u64(g + 0x1880)
            if not mgr:
                return False
            beg = read_u64(mgr + 0x70)
            end = read_u64(mgr + 0x78)
            if not (0 < end - beg < 0x1000):
                return False
            n = (end - beg) // 16
            if n > STATE["count"]:
                for i in range(STATE["count"], n):
                    peer = read_u64(beg + i * 16)
                    print(f"NEW PEER[{i}] = {peer:#x}", flush=True)
                    ReasonWP(f"*(int*)({peer}+0x18)", peer, 0x18)
                    ReasonWP(f"*(char*)({peer}+0x40)", peer, 0x40)
                STATE["count"] = n
        except Exception as e:
            print("poll err", e, flush=True)
        return False

PollBP("*0x14041c960")
print("poll bp armed at 0x14041c960", flush=True)
gdb.execute("continue")
print(f"session ended, poll hits={STATE['hits']}", flush=True)
