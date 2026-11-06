#!/usr/bin/env python3
"""L3 relay regression harness (PLAN §17.2): prove stock BattleServer.exe relays a
two-peer synthetic session under Proton, PASS/FAIL.

Modes:
  local    spawn the relay inside the Proton prefix, run BOTH peers from here,
           print PASS/FAIL, exit 0/1. (default)
  host     cross-tailnet: peer A side (admits B). Start AFTER joiner, within ~8 s.
  joiner   cross-tailnet: peer B side. Start FIRST.

Frame builders + WSClient come from notes/bs_live_test.py (read-only import).
Session-5/6 rules baked in: same sessionID, different LC secrets, different
pidents; B's LOBBYCONNECT must be processed BEFORE the session exists (host RJ);
admit B exactly once; peers must send GAMEDATA (not just LOBBYPING) to beat the
60 s silence timeout.

Env overrides: AOE2LAN_PFX (default ~/Games/aoe/winepfx),
AOE2LAN_PROTON (default <pfx-parent>/Proton-GE Latest/proton).
"""
import os, socket, struct, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "notes"))
import bs_live_test as bs  # read-only: builders + WSClient + constants

PFX = os.environ.get("AOE2LAN_PFX", os.path.expanduser("~/Games/aoe/winepfx"))
PROTON = os.environ.get("AOE2LAN_PROTON",
                        os.path.expanduser("~/Games/aoe/Proton-GE Latest/proton"))
RELAY_EXE = os.path.join(PFX, "pfx", "drive_c", "Games", "AoE2DE",
                         "BattleServer", "BattleServer.exe")
WS_PORT = 47111
LOG = os.path.join(HERE, "bs_relay_linux.log")


def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def spawn_relay():
    env = dict(os.environ,
               STEAM_COMPAT_DATA_PATH=PFX,
               STEAM_COMPAT_CLIENT_INSTALL_PATH=os.path.expanduser("~/.steam/steam"))
    args = [PROTON, "run", RELAY_EXE,
            "-bsPort", "47110", "-webSocketPort", "47111", "-outOfBandPort", "47112",
            "-lobbyPort", "47114", "-relayBroadcastPort", "47113", "-logLevel", "debug"]
    f = open(LOG, "wb")
    p = subprocess.Popen(args, stdout=f, stderr=subprocess.STDOUT, env=env,
                         start_new_session=True)
    t0 = time.time()
    while time.time() - t0 < 60:
        if p.poll() is not None:
            raise SystemExit(f"relay exited early rc={p.returncode}, see {LOG}")
        try:
            socket.create_connection(("127.0.0.1", WS_PORT), timeout=1).close()
            log(f"relay up on :{WS_PORT} after {time.time()-t0:.1f}s (pid {p.pid})")
            return p
        except OSError:
            time.sleep(0.5)
    raise SystemExit(f"relay never listened on :{WS_PORT}, see {LOG}")


def kill_relay(p):
    try:
        os.killpg(p.pid, 15)
    except ProcessLookupError:
        pass
    time.sleep(1)
    subprocess.run([os.path.join(os.path.dirname(PROTON), "files", "bin", "wineserver"),
                    "-k"],
                   env=dict(os.environ, WINEPREFIX=os.path.join(PFX, "pfx")),
                   capture_output=True)


def peer_attach(host, secret):
    ws = bs.WSClient(host, WS_PORT)
    ws.send_bin(bs.build_lobbyconnect(secret=secret))
    return ws


def is_intro(frame, pid):
    return (len(frame) >= 25 and frame[0] == 0x0F and frame[16] == 0x02
            and frame[-8:] == struct.pack("<Q", pid))


def funnel_has(frame, needle):
    return len(frame) >= 2 and frame[0] == 0x0A and frame[1] == 0xFE and needle in frame


def session_flow(host, joiner_already_attached, rj_wait):
    """Host-side flow shared by local + cross modes. Returns (saw_other, stats)."""
    a = peer_attach(host, bs.A_SECRET)
    log(f"A: LC sent (secret=0x{bs.A_SECRET:016x}); waiting {rj_wait}s (B LC must land first)")
    t0 = time.time()
    while time.time() - t0 < rj_wait:  # keep the socket warm, eat echoes
        a.drain(0.5)
    a.send_bin(a.ph(bs.build_requestjoin(peerIdentifier=bs.A_PID)))
    log("A: RJ sent (creates session)")
    a.drain(1.0)
    a.send_bin(a.ph(bs.build_addpeer(0, bs.A_PID, isHost=1)))
    log("A: self-ADDPEER(0, host) sent")
    admitted = saw_b = False
    funnels = 0
    t0, last_gd, last_ping = time.time(), 0, 0
    while time.time() - t0 < 30:
        for f in a.drain(0.5):
            if is_intro(f, bs.B_PID):
                log(f"A: B intro relay seen ({len(f)}B)")
                if not admitted:
                    a.send_bin(a.ph(bs.build_addpeer(2, bs.B_PID)))
                    admitted = True
                    log("A: ADDPEER(B,2) sent (on intro)")
            elif funnel_has(f, bs.B_PING) and not saw_b:
                saw_b = True
                log(f"A: *** B-GD-PING inside 0x0A funnel: {f.hex()}")
            elif len(f) >= 2 and f[0] == 0x0A:
                funnels += 1
        now = time.time() - t0
        if not admitted and joiner_already_attached and now >= 5:
            a.send_bin(a.ph(bs.build_addpeer(2, bs.B_PID)))
            admitted = True
            log("A: ADDPEER(B,2) sent (backstop)")
        if now - last_gd >= 2:
            a.send_bin(bs.build_gamedata(bs.A_PING))
            last_gd = now
        if now - last_ping >= 15:
            a.send_bin(bs.build_lobbyping())
            last_ping = now
        if saw_b and admitted and now >= 8:
            break
    return saw_b, funnels


def joiner_flow(host, rj_wait):
    b = peer_attach(host, bs.B_SECRET)
    log(f"B: LC sent (secret=0x{bs.B_SECRET:016x}); RJ in {rj_wait}s (after host session)")
    t0 = time.time()
    while time.time() - t0 < rj_wait:
        b.drain(0.5)
    b.send_bin(b.ph(bs.build_requestjoin(peerIdentifier=bs.B_PID)))
    log("B: RJ sent")
    admitted = saw_a = False
    funnels = 0
    t0, last_gd, last_ping = time.time(), 0, 0
    while time.time() - t0 < 30:
        for f in b.drain(0.5):
            if len(f) >= 2 and f[0] == 0x0A and f[1] == 0xFE:
                funnels += 1
                if not admitted:
                    admitted = True
                    log(f"B: admission signal: first 0x0A funnel ({len(f)}B)")
                if bs.A_PING in f and not saw_a:
                    saw_a = True
                    log(f"B: *** A-GD-PING inside 0x0A funnel: {f.hex()}")
        now = time.time() - t0
        if now - last_gd >= 2:
            b.send_bin(bs.build_gamedata(bs.B_PING))
            last_gd = now
        if now - last_ping >= 15:
            b.send_bin(bs.build_lobbyping())
            last_ping = now
        if saw_a and now >= 8:
            break
    return saw_a, funnels


def run_local():
    log(f"local mode: relay={RELAY_EXE}")
    p = spawn_relay()
    try:
        # B attaches first (its LC must precede session creation), A right after;
        # A's RJ waits 2 s so both LCs are processed pre-session.
        b = peer_attach("127.0.0.1", bs.B_SECRET)
        log("B: LC sent")
        a = peer_attach("127.0.0.1", bs.A_SECRET)
        log("A: LC sent")
        time.sleep(2)
        a.send_bin(a.ph(bs.build_requestjoin(peerIdentifier=bs.A_PID)))
        a.send_bin(a.ph(bs.build_addpeer(0, bs.A_PID, isHost=1)))
        log("A: RJ + self-ADDPEER sent")
        time.sleep(1)
        b.send_bin(b.ph(bs.build_requestjoin(peerIdentifier=bs.B_PID)))
        log("B: RJ sent")
        saw_a = saw_b = admitted = False
        funnels = 0
        t0, last_gd, last_ping = time.time(), 0, 0
        while time.time() - t0 < 30:
            for f in a.drain(0.25):
                if is_intro(f, bs.B_PID) and not admitted:
                    a.send_bin(a.ph(bs.build_addpeer(2, bs.B_PID)))
                    admitted = True
                    log("A: ADDPEER(B,2) sent (on intro)")
                elif funnel_has(f, bs.B_PING) and not saw_b:
                    saw_b = True
                    log(f"A: *** B-GD-PING in 0x0A funnel: {f.hex()}")
            for f in b.drain(0.25):
                if funnel_has(f, bs.A_PING) and not saw_a:
                    saw_a = True
                    log(f"B: *** A-GD-PING in 0x0A funnel: {f.hex()}")
            now = time.time() - t0
            if not admitted and now >= 5:
                a.send_bin(a.ph(bs.build_addpeer(2, bs.B_PID)))
                admitted = True
                log("A: ADDPEER(B,2) sent (backstop)")
            if now - last_gd >= 2:
                a.send_bin(bs.build_gamedata(bs.A_PING))
                b.send_bin(bs.build_gamedata(bs.B_PING))
                last_gd = now
            if now - last_ping >= 15:
                a.send_bin(bs.build_lobbyping())
                b.send_bin(bs.build_lobbyping())
                last_ping = now
            if saw_a and saw_b and now >= 8:
                break
            funnels += 0  # counts kept per-side in the log lines above
        ok = saw_a and saw_b
        log(f"local done in {time.time()-t0:.1f}s: A_saw_B={saw_b} B_saw_A={saw_a} admitted={admitted}")
        print("PASS" if ok else "FAIL")
        return 0 if ok else 1
    finally:
        kill_relay(p)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "local"
    host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    if mode == "local":
        sys.exit(run_local())
    if mode == "host":
        # run joiner on the other machine first, then this within ~8 s
        saw, funnels = session_flow(host, joiner_already_attached=True, rj_wait=8)
        log(f"host done: saw_b={saw} funnels={funnels}")
        print("PASS" if saw else "FAIL")
        sys.exit(0 if saw else 1)
    if mode == "joiner":
        # host must finish its LC+RJ within this window
        saw, funnels = joiner_flow(host, rj_wait=16)
        log(f"joiner done: saw_a={saw} funnels={funnels}")
        print("PASS" if saw else "FAIL")
        sys.exit(0 if saw else 1)
    raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
