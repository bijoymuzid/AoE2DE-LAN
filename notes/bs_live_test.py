#!/usr/bin/env python3
"""M0.1 tailnet repeat — two-machine live relay test.

A (host: this Windows box, relay machine) and B (joiner: friend's Arch box
over the tailnet) run this against the stock BattleServer relay started with
-logLevel debug on the M0 ports (bs 47110 / ws 47111 / oob 47112, lobby 47114).

Sequence:
  A: ws + LC(secret_A) + RJ(pid_A)        -> session created server-side
  B: ws + LC(secret_B) + RJ(pid_B)        -> pending peer; A gets B's intro
  A: PEERHEADER+ADDPEER(0, pid_A, isHost=1)  (self-admit, right after A's RJ)
  A: PEERHEADER+ADDPEER(2, pid_B)            (auto, on seeing B's intro relay)
  both: GAMEDATA ping every 5 s + LOBBYPING every 15 s (60 s silence timeout)

Success: each side sees the OTHER side's ping inside a type-0x0A
(MultiGameData, flag 0xFE) funnel frame and prints the frame hex.

Rules per session-5 delta: SAME sessionID, DIFFERENT LC secrets, DIFFERENT
pidents. (Same secret re-triggers the FUN_1400eb5f0 marker-0 socket-replacement
swallow for the second attacher.)

Usage:
  host:   python bs_live_test.py host [--host 127.0.0.1] [--port 47111]
  joiner: python bs_live_test.py joiner --host 100.79.215.72
Only stdlib is used; works on Windows python and Arch python3.
"""
import argparse, base64, os, socket, struct, sys, time

SESSION = 0x1122334455667788
TITLE_ID = 2064168993 & 0xFFFF        # 0xB821, matches notes/relay-capture.txt
A_PID = 0xAABBCCDDEEFF0001
B_PID = 0xBBCCDDEEFF0002
A_SECRET = 0x0BADF00DCAFEF00D
B_SECRET = 0x0BADC0DE5AFEBABE         # MUST differ from A_SECRET
A_PING = b'A-GD-PING'
B_PING = b'B-GD-PING'


def build_lobbyconnect(titleID=TITLE_ID, sessionID=SESSION, secret=0,
                       marker=0, version=5):
    out = bytearray()
    out += bytes([0x15])
    out += struct.pack('<Q', ((titleID & 0xFFFF) << 48) |
                      (sessionID & 0xFFFFFFFFFFFF))
    out += struct.pack('<Q', sessionID)
    out += bytes([marker])
    if marker == 2:
        out += struct.pack('<I', 60)
    out += struct.pack('<H', version)
    out += struct.pack('<I', 0)          # dataReceivedCount, unconditional
    if version > 4:
        out += struct.pack('<Q', secret)
    assert len(out) in (24, 28, 32, 36)
    return bytes(out)


def build_requestjoin(sessionID=SESSION, peerIdentifier=0,
                      addrList=b'', customData=b''):
    out = bytearray()
    out += bytes([0x02])
    out += struct.pack('<H', len(addrList)) + addrList
    out += struct.pack('<H', len(customData)) + customData
    out += struct.pack('<Q', ((TITLE_ID & 0xFFFF) << 48) |
                      (sessionID & 0xFFFFFFFFFFFF))
    out += struct.pack('<Q', peerIdentifier)
    return bytes(out)


def build_peerheader(inner, packetNumber=1):
    hdr = bytearray(15)
    hdr[0] = 0
    struct.pack_into('<I', hdr, 1, 0)
    struct.pack_into('<H', hdr, 5, packetNumber & 0xFFFF)
    struct.pack_into('<I', hdr, 7, 0)
    struct.pack_into('<H', hdr, 11, 0)
    return bytes([0x0F]) + bytes(hdr) + inner


def build_addpeer(peerID, globalID, isHost=0, isLocal=0):
    out = bytearray()
    out += bytes([0x06])
    out += struct.pack('<H', 0)          # addressList string 1 (empty)
    out += struct.pack('<H', 0)          # addressList string 2 (empty)
    out += bytes([peerID & 0xFF, isHost & 0xFF, isLocal & 0xFF])
    out += struct.pack('<Q', globalID)
    return bytes(out)


def build_gamedata(payload):
    if len(payload) > 0xFFFF:
        raise ValueError('payload too long')
    return bytes([0x09, 0xFE]) + struct.pack('<H', len(payload)) + payload


def build_lobbyping():
    return bytes([0x14])


class WSClient:
    """Minimal RFC6455 client: sends masked binary frames, reads with a
    reassembly buffer (server coalesces/splits frames across TCP segments)."""

    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=10)
        key = base64.b64encode(os.urandom(16)).decode()
        req = ('GET /chat HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n'
               'Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n'
               'Sec-WebSocket-Version: 13\r\n\r\n' % (host, port, key))
        self.sock.sendall(req.encode())
        self.sock.settimeout(10)
        buf = b''
        while b'\r\n\r\n' not in buf:
            d = self.sock.recv(4096)
            if not d:
                raise RuntimeError('closed during ws handshake')
            buf += d
        head, rest = buf.split(b'\r\n\r\n', 1)
        if b' 101 ' not in head.split(b'\r\n')[0]:
            raise RuntimeError('ws handshake refused: %r' % head[:120])
        self.buf = rest                 # frames may piggyback the 101
        self.pn = 1

    def ph(self, inner):
        m = build_peerheader(inner, packetNumber=self.pn)
        self.pn += 1
        return m

    def send_bin(self, payload):
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        n = len(payload)
        if n < 126:
            hdr = bytes([0x82, 0x80 | n])
        elif n < 65536:
            hdr = bytes([0x82, 0x80 | 126]) + struct.pack('>H', n)
        else:
            hdr = bytes([0x82, 0x80 | 127]) + struct.pack('>Q', n)
        self.sock.sendall(hdr + mask + masked)

    def _need(self, n, timeout):
        self.sock.settimeout(timeout)
        while len(self.buf) < n:
            try:
                d = self.sock.recv(8192)
            except socket.timeout:
                return False
            if not d:
                raise EOFError('server closed connection')
            self.buf += d
        return True

    def recv_frame(self, timeout=2.0):
        """One ws payload, or None on timeout."""
        if not self._need(2, timeout):
            return None
        ln = self.buf[1] & 0x7F
        hdrlen = 2
        if ln == 126:
            if not self._need(4, timeout):
                return None
            ln = struct.unpack('>H', self.buf[2:4])[0]
            hdrlen = 4
        elif ln == 127:
            if not self._need(10, timeout):
                return None
            ln = struct.unpack('>Q', self.buf[2:10])[0]
            hdrlen = 10
        if ln == 0:
            self.buf = self.buf[hdrlen:]
            return b''
        if not self._need(hdrlen + ln, timeout):
            return None  # incomplete tail: treat as quiet
        out = self.buf[hdrlen:hdrlen + ln]
        self.buf = self.buf[hdrlen + ln:]
        return bytes(out)

    def drain(self, wait=2.0):
        frames, t0 = [], time.time()
        while time.time() - t0 < wait:
            f = self.recv_frame(timeout=0.5)
            if f is None:
                continue
            if f == b'':
                continue
            frames.append(f)
        return frames


def stamp(msg):
    print('[%s] %s' % (time.strftime('%H:%M:%S'), msg), flush=True)


def countdown(secs, label, ws=None):
    t0 = time.time()
    last_ping = 0.0
    while True:
        el = time.time() - t0
        if el >= secs:
            break
        stamp('%s %ds' % (label, int(secs - el)))
        if ws is not None and el - last_ping >= 15:
            ws.send_bin(build_lobbyping())
            last_ping = el
            for f in ws.drain(1.0):
                if f:
                    stamp('wait-phase frame (%dB): %s'
                          % (len(f), f[:40].hex()))
        time.sleep(min(15, max(0.5, secs - el)))


def run_host(ws_host, ws_port, duration, rj_delay=180, admit_backstop=480):
    stamp('HOST A: session=0x%016x pid=0x%016x' % (SESSION, A_PID))
    ws = WSClient(ws_host, ws_port)
    stamp('ws connected to %s:%d' % (ws_host, ws_port))
    ws.send_bin(build_lobbyconnect(secret=A_SECRET))
    echo = ws.drain(2.0)
    stamp('LC sent (secret=0x%016x); echo frames=%d %s'
          % (A_SECRET, len(echo), [f[:4].hex() for f in echo]))
    stamp('PHASE 1: LC done pre-session. Waiting %ds for B to attach '
          '(B LC must be processed BEFORE this session exists)' % rj_delay)
    countdown(rj_delay, 'waiting for B attach; RJ in', ws)
    ws.send_bin(ws.ph(build_requestjoin(peerIdentifier=A_PID)))
    stamp('RJ sent (creates session)')
    stamp('RJ drain: %s' % [('%dB:%s' % (len(f), f[:40].hex()))
                            for f in ws.drain(3.0)])
    ws.send_bin(ws.ph(build_addpeer(0, A_PID, isHost=1)))
    stamp('self-ADDPEER(0, host) sent')
    stamp('AP drain: %s' % [('%dB:%s' % (len(f), f[:40].hex()))
                            for f in ws.drain(3.0)])
    admitted_b = False
    saw_b_ping = False
    admit_sends = 0
    t0, last_gd, last_ping, last_hb = time.time(), 0, 0, 0
    hb = 0
    # NOTE (session-6, run 5): admit B EXACTLY ONCE, ~5 s after our RJ (B's RJ
    # is already pending by then in our rj-delay ordering). DO NOT re-send
    # ADDPEER: a repeat while the peer already exists re-runs the fill path
    # (FUN_1400e5670) and the funnel broadcast to B stops dead (observed
    # 07:39:43 -> 07:40:14: B's writes went from 7-9 per tick to zero).
    while time.time() - t0 < duration:
        for f in ws.drain(2.0):
            if len(f) >= 2 and f[0] == 0x0A and f[1] == 0xFE:
                hb += 1
                if B_PING in f and not saw_b_ping:
                    saw_b_ping = True
                    stamp('*** SUCCESS(A): B-GD-PING inside 0x0A funnel: %s'
                          % f.hex())
            elif (len(f) >= 17 and f[0] == 0x0F and f[16] == 0x02
                    and len(f) >= 8 and f[-8:] == struct.pack('<Q', B_PID)):
                stamp('B intro (PEERHEADER+RJ pid_B) seen, len=%d' % len(f))
                if not admitted_b:
                    ws.send_bin(ws.ph(build_addpeer(2, B_PID)))
                    admit_sends += 1
                    admitted_b = True
                    stamp('ADDPEER(B,2) sent (on intro, single #%d)'
                          % admit_sends)
        now = time.time() - t0
        if not admitted_b and now >= 5:
            ws.send_bin(ws.ph(build_addpeer(2, B_PID)))
            admit_sends += 1
            admitted_b = True
            stamp('ADDPEER(B,2) sent (single, 5s post-RJ #%d)' % admit_sends)
        now = time.time() - t0
        if now - last_gd >= 5:
            ws.send_bin(build_gamedata(A_PING))
            last_gd = now
            stamp('GD A-GD-PING sent')
        if now - last_ping >= 15:
            ws.send_bin(build_lobbyping())
            last_ping = now
            stamp('LOBBYPING sent (hb=%d)' % hb)
        if now - last_hb >= 60:
            last_hb = now
            stamp('alive %ds: admitted_b=%s saw_b_ping=%s funnels=%d'
                  % (now, admitted_b, saw_b_ping, hb))
    stamp('HOST done: admitted_b=%s saw_b_ping=%s funnels=%d -> %s'
          % (admitted_b, saw_b_ping, hb,
             'PASS' if admitted_b and saw_b_ping else 'FAIL (see notes/bs_server.log)'))


def run_joiner(ws_host, ws_port, duration, rj_delay=240):
    stamp('JOINER B: session=0x%016x pid=0x%016x host=%s:%d'
          % (SESSION, B_PID, ws_host, ws_port))
    ws = WSClient(ws_host, ws_port)
    stamp('ws connected')
    ws.send_bin(build_lobbyconnect(secret=B_SECRET))
    echo = ws.drain(2.0)
    stamp('LC sent (secret=0x%016x); echo frames=%d %s'
          % (B_SECRET, len(echo), [f[:4].hex() for f in echo]))
    if not echo:
        stamp('WARNING: no LC echo (attach may be swallowed); leaving '
              'script running, but likely FAIL')
    stamp('PHASE 1: LC attached pre-session. Waiting %ds for host RJ, '
          'then sending our RJ' % rj_delay)
    countdown(rj_delay, 'waiting for host session; RJ in', ws)
    ws.send_bin(ws.ph(build_requestjoin(peerIdentifier=B_PID)))
    stamp('RJ sent')
    stamp('RJ drain: %s' % [('%dB:%s' % (len(f), f[:40].hex()))
                            for f in ws.drain(3.0)])
    # Session-6 finding: an admitted peer that sends only LOBBYPING is dropped
    # by the 60 s 'Peer silent timeout' (peer timer counts GAMEDATA, not pings).
    # So ping on our own clock regardless of admission; early pings are dropped
    # server-side until our peer record exists, then they flow.
    admitted, saw_a_ping = False, False
    t0, last_gd, last_ping, last_hb = time.time(), -3, 0, 0
    hb = 0
    while time.time() - t0 < duration:
        for f in ws.drain(2.0):
            if len(f) >= 2 and f[0] == 0x0A and f[1] == 0xFE:
                hb += 1
                if not admitted:
                    admitted = True
                    stamp('admission signal: first 0x0A funnel (%dB)' % len(f))
                if A_PING in f and not saw_a_ping:
                    saw_a_ping = True
                    stamp('*** SUCCESS(B): A-GD-PING inside 0x0A funnel: %s'
                          % f.hex())
            elif (len(f) >= 17 and f[0] == 0x0F and f[16] == 0x02
                    and len(f) >= 8
                    and f[-8:] == struct.pack('<Q', A_PID)):
                stamp('A intro relay seen (host RJ echo, %dB)' % len(f))
        now = time.time() - t0
        if now - last_gd >= 5:
            ws.send_bin(build_gamedata(B_PING))
            last_gd = now
            stamp('GD B-GD-PING sent')
        if now - last_ping >= 15:
            ws.send_bin(build_lobbyping())
            last_ping = now
            stamp('LOBBYPING sent (hb=%d)' % hb)
        if now - last_hb >= 60:
            last_hb = now
            stamp('alive %ds: admitted=%s saw_a_ping=%s funnels=%d'
                  % (now, admitted, saw_a_ping, hb))
    stamp('JOINER done: admitted=%s saw_a_ping=%s funnels=%d -> %s'
          % (admitted, saw_a_ping, hb,
             'PASS' if admitted and saw_a_ping else 'FAIL'))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('role', choices=['host', 'joiner'])
    ap.add_argument('--host', default=None)
    ap.add_argument('--port', type=int, default=47111)
    ap.add_argument('--duration', type=int, default=900)
    ap.add_argument('--rj-delay', type=int, default=None)
    a = ap.parse_args()
    host = a.host or ('127.0.0.1' if a.role == 'host' else '100.79.215.72')
    try:
        if a.role == 'host':
            run_host(host, a.port, a.duration,
                     rj_delay=a.rj_delay or 180)
        else:
            run_joiner(host, a.port, a.duration,
                       rj_delay=a.rj_delay or 240)
    except (EOFError, ConnectionError) as e:
        stamp('connection lost: %s' % e)
    except KeyboardInterrupt:
        stamp('stopped by operator')


if __name__ == '__main__':
    main()
