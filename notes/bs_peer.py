"""M0.1 two-machine tailnet test — ONE peer per machine, no game needed.

Proven ordering (see notes/m0-findings.md "Session-3.5"): both peers must attach
(LOBBYCONNECT) BEFORE the first REQUESTJOIN creates the session, or the later
client's messages get swallowed by the server. This script encodes that:

  role A (HOST side, runs on the relay machine):
     connect -> LOBBYCONNECT -> WAIT for operator Enter (B must attach first)
     -> REQUESTJOIN (creates session) -> wait for B's intro (B's REQUESTJOIN
     relayed to us) -> ADDPEER for B -> GAMEDATA ping -> keep listening.
     You press Enter only AFTER the friend confirms their script is past
     "attached" — their LOBBYCONNECT must be processed before your REQUESTJOIN
     creates the session, or their later messages are swallowed server-side.
  role B (JOINER side, friend's machine):
     connect -> LOBBYCONNECT -> wait 12s (host creates session by then)
     -> REQUESTJOIN (registers as PendingPeer) -> keep listening for GAMEDATA,
     with a LOBBYPING every 25s (peers idle >60s get silence-timeout dropped).

Usage:
  A (this machine):    python notes/bs_peer.py A 127.0.0.1
  B (friend's box):    python notes/bs_peer.py B 100.79.215.72

Requires: python3 (stdlib only), Tailscale up. The relay must already be running
on the A machine with -logLevel debug.
"""
import sys, socket, struct, time, threading

sys.path.insert(0, __file__.rsplit('\\', 1)[0] if '\\' in __file__ else '.')
try:
    import bs_client as m
except ImportError:
    sys.path.insert(0, 'notes')
    import bs_client as m

SID = 0x1122334455667788
A_PID = 0xAABBCCDDEEFF0001
B_PID = 0xBBCCDDEEFF0002
B_PEERID = 2  # peerID the host assigns to B in its ADDPEER

def recv_frames(s, tag, wait, want=None):
    """Receive ws frames (reassembled); if `want` bytes appear in any payload,
    print and keep going. Returns list of payloads."""
    s.settimeout(wait)
    buf = b''
    try:
        while True:
            d = s.recv(8192)
            if not d:
                print('[%s] closed by server' % tag, flush=True)
                break
            buf += d
    except socket.timeout:
        pass
    frames, i = [], 0
    while i + 2 <= len(buf):
        ln = buf[i + 1] & 0x7F
        j = i + 2
        if ln == 126:
            if j + 2 > len(buf): break
            ln = struct.unpack('>H', buf[j:j + 2])[0]; j += 2
        elif ln == 127:
            if j + 8 > len(buf): break
            ln = struct.unpack('>Q', buf[j:j + 8])[0]; j += 8
        if j + ln > len(buf): break
        frames.append(buf[j:j + ln]); i = j + ln
    for f in frames:
        note = ''
        if f[:1] == b'\x09': note = '   <<< GAMEDATA!'
        elif f[:1] == b'\x0f': note = '   (peerheader)'
        elif f[:1] == b'\x15': note = '   (lobbyconnect echo)'
        print('[%s] frame %dB %s%s' % (tag, len(f), f[:60].hex(), note), flush=True)
    if not frames:
        print('[%s] quiet' % tag, flush=True)
    return frames

def peer_A(host):
    s = socket.create_connection((host, m.WS_PORT), timeout=8)
    m.ws_handshake(s)
    m.ws_send_bin(s, m.build_lobbyconnect(sessionID=SID, marker=0, version=5))
    print('[A] attached (LC sent).', flush=True)
    try:
        input('[A] Start the friend\'s B script now; press Enter here once B '
              'prints "attached" (before that, do NOT proceed): ')
    except EOFError:
        print('[A] no TTY; waiting 20s instead', flush=True)
        time.sleep(20)
    m.ws_send_bin(s, m.build_peerheader(m.build_requestjoin(sessionID=SID, peerIdentifier=A_PID)))
    print('[A] REQUESTJOIN sent (session created; we are host)', flush=True)
    print('[A] waiting up to 20s for B join intro...', flush=True)
    recv_frames(s, 'A', 20)
    m.ws_send_bin(s, m.build_peerheader(m.build_addpeer(B_PEERID, B_PID)))
    print('[A] ADDPEER(B) sent', flush=True)
    time.sleep(1)
    m.ws_send_bin(s, m.build_gamedata(b'A-GD-PING'))
    print('[A] GAMEDATA ping sent', flush=True)
    # keep alive under the 60s silent timeout + keep listening
    for round_ in range(3):
        time.sleep(15)
        m.ws_send_bin(s, m.build_gamedata(b'A-GD-PING-%d' % round_))
        print('[A] GAMEDATA ping %d sent' % round_, flush=True)
        recv_frames(s, 'A', 10)
    s.close()

def peer_B(host):
    s = socket.create_connection((host, m.WS_PORT), timeout=8)
    m.ws_handshake(s)
    m.ws_send_bin(s, m.build_lobbyconnect(sessionID=SID, marker=0, version=5))
    print('[B] attached (LC sent); waiting 12s for host to create session...', flush=True)
    time.sleep(12)
    m.ws_send_bin(s, m.build_peerheader(m.build_requestjoin(sessionID=SID, peerIdentifier=B_PID)))
    print('[B] REQUESTJOIN sent', flush=True)
    # keepalive: silence-timeout drops idle peers after ~60s
    for round_ in range(5):
        recv_frames(s, 'B', 15)
        try:
            m.ws_send_bin(s, m.build_lobbyping())
            print('[B] keepalive LOBBYPING sent', flush=True)
        except OSError:
            print('[B] send failed (closed)', flush=True)
            break
    s.close()

if __name__ == '__main__':
    role = sys.argv[1].upper() if len(sys.argv) > 1 else 'A'
    host = sys.argv[2] if len(sys.argv) > 2 else m.HOST
    print('role %s relay %s:%d  (Ctrl-C to stop)' % (role, host, m.WS_PORT), flush=True)
    (peer_A if role == 'A' else peer_B)(host)
