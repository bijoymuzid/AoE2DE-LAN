#!/usr/bin/env python3
# supervise.py — launches AoE2DE_s.exe under Proton and stays as its ancestor so
# /proc/<pid>/mem stays readable under yama ptrace_scope=1. Dumps .text on SIGUSR1
# (pkill -USR1 -f supervise.py), exit when the game exits.
import os, re, signal, subprocess, sys, time

AOE = "/home/hexal/Games/aoe"
GAMEDIR = f"{AOE}/winepfx/pfx/drive_c/Games/AoE2DE"
PROTON = f"{AOE}/Proton-CachyOS Latest-x86_64_v3/proton"

env = os.environ.copy()
PFX = f"{AOE}/winepfx"
env.update({
    "WINEPREFIX": f"{PFX}/pfx",
    "AOE2LAN_STAGE": "8", "AOE2LAN_NOHOOKS": "1", "AOE2LAN_HOOKS": "4,5,13,14",
    "AOE2LAN_WSETVT": "0", "AOE2LAN_NOKW": os.environ.get("SUPERVISE_NOKW", "1"), "AOE2LAN_AIGATE": "0", "AOE2LAN_LOGVT": "1", "AOE2LAN_GLOG": "1",
    "STEAM_COMPAT_DATA_PATH": PFX,
    "STEAM_COMPAT_CLIENT_INSTALL_PATH": os.path.expanduser("~/.steam/steam"),
    "WINEDLLOVERRIDES": "dbghelp,winmm=n,b", "PROTON_NO_NTSYNC": "1", "PROTON_USE_XALIA": "0",
    "AOE2LAN_RELAY_IP": subprocess.run(["tailscale", "ip", "-4"], capture_output=True, text=True).stdout.strip(),
})

def find_game_pid():
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/maps") as f:
                if "AoE2DE_s.exe" in f.read():
                    return int(pid)
        except OSError:
            pass
    return None

def dump(sig=None, frame=None):
    try:
        _dump_inner()
    except Exception as e:
        # never die from a signal handler: losing supervise means losing the
        # ancestor that keeps /proc/<pid>/mem readable (yama scope=1)
        print(f"supervise: dump failed: {e!r}", flush=True)

def _dump_inner():
    pid = find_game_pid()
    if not pid:
        print("supervise: game pid not found", flush=True)
        return
    base, maps = None, []
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \S+\s*(.*)", line)
            if not m:
                continue
            lo, hi, perm, path = int(m[1], 16), int(m[2], 16), m[3], m[4]
            if "AoE2DE_s.exe" in path and base is None:
                base = lo
            if base and "x" in perm and base + 0x1000 <= lo < base + 0x3197000:
                maps.append((lo, hi))
    if not maps:
        print("supervise: no .text mappings yet", flush=True)
        return
    out = f"/tmp/aoe_text_{int(time.time())}.bin"
    PAGE, unread, buf = 0x1000, [], bytearray()
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
        for lo, hi in maps:
            for page in range(lo, hi, PAGE):
                try:
                    mem.seek(page)
                    data = mem.read(min(PAGE, hi - page))
                except OSError:
                    unread.append(page)
                    data = b"\x00" * min(PAGE, hi - page)
                buf += data
    with open(out, "wb") as f:
        f.write(buf)
    print(f"supervise: pid={pid} base={base:#x} wrote {out} ({len(buf):#x}B, {len(unread)} unread pages)", flush=True)

signal.signal(signal.SIGUSR1, dump)
os.chdir(GAMEDIR)
# wineserver -f stays in the foreground (no daemonize), so the wine processes it
# forks remain our descendants and yama lets us read their /proc/<pid>/mem.
WINESERVER = f"{AOE}/Proton-CachyOS Latest-x86_64_v3/files/bin/wineserver"
ws = subprocess.Popen([WINESERVER, "-f", "-p"], env=env)
time.sleep(1)
print(f"supervise: wineserver pid={ws.pid}; launching, pid={os.getpid()}, SIGUSR1 to dump", flush=True)
p = subprocess.Popen([PROTON, "runinprefix", "AoE2DE_s.exe"], env=env)
p.wait()
ws.terminate()
