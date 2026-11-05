"""M0.1 client: connect to BattleServer websocket port, speak RLink packets.

Wire format (derived from BattleServer.exe 2.58.0, Ghidra; session-3 decoded JOIN):
  Transports: raw TCP (-bsPort, TLS 1.2 server side, handshake uncooperative) and
  websocket (-webSocketPort, RFC6455 binary frames; PROVEN 2026-11-01).
  Payloads are bare RLink SessionMessages (no length prefix needed over ws;
  the relay reads one message per frame).
  u16/u32/u64 integer fields serialize LITTLE-ENDIAN (unpacks read them with
  native casts, memory dword compare e.g. '?? == 0x15'; confirmed by framing.c).

  LOBBYCONNECT (0x15, LobbyConnectMessage::unpack FUN_1400efe50, pack slot4):
    u8  0x15
    u64 LE (titleID<<48 | sessionID&0xFFFFFFFFFFFF)      '16-bit title / 48-bit session'
    u64 LE sessionID                                      (yes, AGAIN at offset 9; unpack stores msg+0x38)
    u8  marker (0x02 = v2-style reconnect; 0x00 = plain connect)
    u32 LE timeoutOverride   (ONLY when marker==2; else absent entirely)
    u16 LE clientMessageVersion
    u32 LE dataReceivedCount (ALWAYS present, read unconditionally)
    if version>4: u64 LE secret
    Valid totals: 24/32 (marker 0, v4/v5) and 28/36 (marker 2, v4/v5).
    CORRECTION vs session 2: timeoutOverride is conditional; yesterday's "36-byte
    marker=0 attach" could not have parsed (32 is correct for marker 0 + v5) — the
    silent-accept observations were parse failures, not attaches.

  REQUESTJOIN (0x02, RLink::SessionMessage::RequestJoinMessage; server vtable
  0x140243c30, unpack FUN_1400f3370, pack FUN_1400f4b80, count FUN_1400f4200):
    u8  0x02
    u16 LE addrLen; u8[addrLen] addrList        (AddressList blob; pack via FUN_1400dd040)
    u16 LE customLen; u8[customLen] customData  (player customization; FUN_1400dd110)
    u64 LE (titleID<<48 | sessionID&0xFFFFFFFFFFFF)  'Identifiers' — SAME composite as
          LOBBYCONNECT (pack: (short)m[0xd]<<0x30 | m[0xe]; unpack splits qword >>48/48)
    u64 LE peerIdentifier                          (PIdent; joiner's unique global ID)
    No trailer; unpack requires exact consumption. Server: ProcessPacket case 0x0F ->
    Server::ProcessPeerMessage FUN_1400daaf0 case 2 -> SessionManager::OnPeerRequestJoin
    FUN_1400ea680 -> CREATES the WWBS::Session (0x938 bytes) keyed (titleID u16, sessionID
    u64), binds client+0x28=session, registers joiner by PIdent in session+0x820 map.

  PEERHEADER (0x0F, PeerMessage::unpack FUN_1400f1160) — REQUESTJOIN rides INSIDE this:
    u8  0x0F
    15 raw bytes: flagBits(1) ackBits(4) packetNumber(2) startACKReliableNonSequential(4)
                  lastReliableSequentialID(3+1)  [sub-field split provisional; zeros work]
    nested message (full SessionMessage incl. its own type byte)
    NOTE: flagBits bit 0x04 = introduction path; keep clear for the join flow.

  ADDPEER (0x06, AddPeerMessage; server factory case 6, handlers FUN_1400eae60 ->
  FUN_1400e5670): host admits a joiner; object has TWO strings (0x30, 0x48) then
  peerID u8, isHost u8, isLocal u8, globalID u64 (live-verified 2026-11-02).
  This is what populates session+0x890, the vector FUN_1400e2e00 (GAMEDATA relay)
  walks.

  GAMEDATA (0x09, GameDataMessage): u8 0x09, u8 0xFE flag, u16 LE len, payload.
  Sent top-level after peers are admitted; FUN_1400e2e00 relays to session peers.

  LOBBYRELAY (0x13, LobbyRelayMessage::unpack FUN_1400ef5e0 / pack FUN_1400ef4a0):
    u8 0x13; u8 fromPeerID; u8 toPeerID; nested message
    (u8 ids, NOT u16 — earlier guess in this file was wrong; server recurses
    ProcessPacket on the nested message, so LOBBYRELAY can carry any inner type.)
"""
import socket, struct, sys, time, threading

HOST = '127.0.0.1'
PORT = 47110
WS_PORT = 47111  # websocket: proven path for now

TITLE_ID = 2064168993 & 0xFFFF  # AoE2 titleID low16 as used in prior probes

def recv_exact(s, n):
    buf = b''
    while len(buf) < n:
        d = s.recv(n - len(buf))
        if not d:
            raise EOFError('closed')
        buf += d
    return buf

def recv_packet(s, timeout=5.0):
    s.settimeout(timeout)
    hdr = recv_exact(s, 4)
    n = struct.unpack('<I', hdr)[0]
    return recv_exact(s, n)

def send_packet(s, payload):
    s.sendall(struct.pack('<I', len(payload)) + payload)

# ---------------------------------------------------------------- message builders

def build_lobbyconnect(titleID=TITLE_ID, sessionID=0x1122334455667788, profileID=999,
                       secret=0x0BADF00DCAFEF00D, marker=0, timeoutOverride=60, version=5):
    out = bytearray()
    out += bytes([0x15])
    out += struct.pack('<Q', ((titleID & 0xFFFF) << 48) | (sessionID & 0xFFFFFFFFFFFF))
    out += struct.pack('<Q', sessionID)
    out += bytes([marker])
    if marker == 2:
        out += struct.pack('<I', timeoutOverride)
    out += struct.pack('<H', version)
    out += struct.pack('<I', 0)              # dataReceivedCount (unconditional)
    if version > 4:
        out += struct.pack('<Q', secret)
    assert len(out) in (24, 28, 32, 36)
    return bytes(out)

def build_requestjoin(titleID=TITLE_ID, sessionID=0x1122334455667788,
                      peerIdentifier=0xAABBCCDDEEFF0001,
                      addrList=b'', customData=b''):
    """RLink::SessionMessage::RequestJoinMessage (type 0x02) — exact pack layout.
    Fields: AddressList blob, Customization blob, Identifiers (title<<48|session48),
    PIdent. All ints little-endian; blobs are u16 LE len + raw bytes."""
    if len(addrList) > 0xFFFF or len(customData) > 0xFFFF:
        raise ValueError('blob too long')
    out = bytearray()
    out += bytes([0x02])
    out += struct.pack('<H', len(addrList)) + addrList
    out += struct.pack('<H', len(customData)) + customData
    out += struct.pack('<Q', ((titleID & 0xFFFF) << 48) | (sessionID & 0xFFFFFFFFFFFF))
    out += struct.pack('<Q', peerIdentifier)
    return bytes(out)

def build_peerheader(inner, flagBits=0, ackBits=0, packetNumber=1,
                     startACKReliableNonSequential=0, lastReliableSequentialID=0):
    """RLink::SessionMessage::PeerMessage (type 0x0F): 15 raw header bytes + nested
    message. Keep flagBits bit 0x04 clear for the normal join path (FUN_1400daaf0)."""
    hdr = bytearray(15)
    hdr[0] = flagBits & 0xFF
    struct.pack_into('<I', hdr, 1, ackBits & 0xFFFFFFFF)
    struct.pack_into('<H', hdr, 5, packetNumber & 0xFFFF)
    struct.pack_into('<I', hdr, 7, startACKReliableNonSequential & 0xFFFFFFFF)
    struct.pack_into('<H', hdr, 11, lastReliableSequentialID & 0xFFFF)
    # byte 14: trailing flag byte (provisional; 0 observed)
    return bytes([0x0F]) + bytes(hdr) + inner

def build_addpeer(peerID, globalID, isHost=0, isLocal=0, addressList=b'', addressList2=b''):
    """RLink::SessionMessage::AddPeerMessage (type 0x06). TWO strings (object has
    two std::string members at 0x30 and 0x48), then peerID/isHost/isLocal bytes,
    then globalID. Layout verified live 2026-11-02: server log printed
    'ADDPEER peerID=.. isHost=.. isLocal=.. globalID=..' from this packing."""
    out = bytearray()
    out += bytes([0x06])
    out += struct.pack('<H', len(addressList)) + addressList
    out += struct.pack('<H', len(addressList2)) + addressList2
    out += bytes([peerID & 0xFF, isHost & 0xFF, isLocal & 0xFF])
    out += struct.pack('<Q', globalID)
    return bytes(out)

def build_gamedata(payload, flag=0xFE):
    """RLink::SessionMessage::GameDataMessage (type 0x09): flag byte must be 0xFE."""
    if len(payload) > 0xFFFF:
        raise ValueError('payload too long')
    return bytes([0x09, flag]) + struct.pack('<H', len(payload)) + payload

def build_lobbyrelay(fromPeerID, toPeerID, inner):
    """RLink::SessionMessage::LobbyRelayMessage (type 0x13): u8 ids + nested message.
    Server recurses ProcessPacket on the nested bytes (FUN_1400de050 case 0x13)."""
    return bytes([0x13, fromPeerID & 0xFF, toPeerID & 0xFF]) + inner

def build_lobbyping():
    return bytes([0x14])

# ---------------------------------------------------------------- websocket plumbing

def ws_handshake(s, host='127.0.0.1', port=47111, resource='/chat'):
    import base64, hashlib
    key = base64.b64encode(b'0123456789abcdef').decode()
    s.sendall(('GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n'
               'Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n'
               'Sec-WebSocket-Version: 13\r\n\r\n' % (resource, host, port, key)).encode())
    s.settimeout(6)
    resp = s.recv(1024)
    if b'101' not in resp:
        raise RuntimeError('ws handshake failed: %r' % resp[:80])
    return resp

def ws_send_bin(s, payload, mask=b'\xde\xad\xbe\xef'):
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    n = len(payload)
    if n < 126:
        hdr = bytes([0x82, 0x80 | n])
    elif n < 65536:
        hdr = bytes([0x82, 0x80 | 126]) + struct.pack('<H', n)
    else:
        hdr = bytes([0x82, 0x80 | 127]) + struct.pack('<Q', n)
    s.sendall(hdr + mask + masked)

def ws_drain(s, tag, wait=5.0, max_frames=20):
    """Recv whole ws frames; returns list of PAYLOAD bytes (frame headers stripped).
    NOTE: must reassemble: server sends multi-frame responses split across TCP
    segments; naive s.recv(4096) returns 1.5 frames (proved 2026-11-02)."""
    s.settimeout(wait)
    buf = b''
    try:
        for _ in range(max_frames):
            try:
                d = s.recv(8192)
            except socket.timeout:
                break
            if not d:
                print(tag, 'closed by server')
                break
            buf += d
    except socket.timeout:
        pass
    frames = []
    i = 0
    while i + 2 <= len(buf):
        ln = buf[i + 1] & 0x7F
        j = i + 2
        if ln == 126:
            if j + 2 > len(buf):
                break
            ln = struct.unpack('>H', buf[j:j + 2])[0]
            j += 2
        elif ln == 127:
            if j + 8 > len(buf):
                break
            ln = struct.unpack('>Q', buf[j:j + 8])[0]
            j += 8
        if j + ln > len(buf):
            break  # incomplete tail: server still sending
        frames.append(buf[j:j + ln])
        print(tag, 'recv frame', len(buf[j:j + ln]), buf[j:j + 40].hex())
        i = j + ln
    if not frames:
        print(tag, 'quiet (connection kept open)')
        if buf:
            print(tag, 'leftover', len(buf), 'unparsed bytes')
    return frames

# ---------------------------------------------------------------- join flow

def join_and_relay(host=HOST, ws_port=WS_PORT, sessionID=0x1122334455667788,
                   pident=0xAABBCCDDEEFF0001, send_gamedata=True,
                   secret=0x0BADF00DCAFEF00D, self_peerID=None):
    """Full JOIN handshake: LOBBYCONNECT attach, PEERHEADER+REQUESTJOIN (creates
    the session server-side), then optional GAMEDATA ping. Run as A on one
    tailnet box and as B (different pident) on the other with the SAME sessionID.
    If GAMEDATA is not relayed, the host must first send ADDPEER for the joiner
    (see build_addpeer + 'admit' subcommand) — the relay target list (session
    +0x890) is filled by ADDPEER, not by REQUESTJOIN.
    Check notes/bs_server.log for 'ProcessPeerMessage: ... REQUESTJOIN' lines."""
    s = socket.create_connection((host, ws_port), timeout=8)
    ws_handshake(s, host, ws_port)

    lc = build_lobbyconnect(sessionID=sessionID, secret=secret, marker=0, version=5)
    ws_send_bin(s, lc)
    print('sent LOBBYCONNECT (%d B): %s' % (len(lc), lc.hex()))
    ws_drain(s, 'LC', wait=2.0)

    rj = build_requestjoin(sessionID=sessionID, peerIdentifier=pident)
    ph = build_peerheader(rj)
    ws_send_bin(s, ph)
    print('sent PEERHEADER/REQUESTJOIN (%d B): %s' % (len(ph), ph.hex()))
    ws_drain(s, 'RJ', wait=3.0)

    if self_peerID is not None:
        ap = build_peerheader(build_addpeer(self_peerID, pident, isHost=1 if self_peerID == 0 else 0))
        ws_send_bin(s, ap)
        print('sent self-ADDPEER peerID=%d gid=%x' % (self_peerID, pident))
        ws_drain(s, 'AP', wait=3.0)

    if send_gamedata:
        gd = build_gamedata(b'M0JOIN-ping-%08x' % (pident & 0xFFFFFFFF))
        ws_send_bin(s, gd)
        print('sent GAMEDATA (%d B): %s' % (len(gd), gd.hex()))
        ws_drain(s, 'GD', wait=5.0)

    return s

def main():
    s = socket.create_connection((HOST, PORT), timeout=5)
    print('connected to', HOST, PORT)
    pkt = build_lobbyconnect()
    print('sending LOBBYCONNECT:', pkt.hex())
    send_packet(s, pkt)
    try:
        while True:
            r = recv_packet(s, timeout=6.0)
            print('recv:', r.hex(), repr(r[:120]))
    except (socket.timeout, EOFError) as e:
        print('end:', e)
    s.close()

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'ws':
        marker = int(sys.argv[2]) if len(sys.argv) > 2 else 0
        sid = 0xAAAABBBBCCCCDDDD
        s = socket.create_connection((HOST, WS_PORT), timeout=8)
        ws_handshake(s)
        lc = build_lobbyconnect(sessionID=sid, secret=0xdeadbeef, marker=marker)
        ws_send_bin(s, lc)
        print('sent LOBBYCONNECT marker=%d len=%d' % (marker, len(lc)))
        ws_drain(s, 'LC')
        ws_send_bin(s, build_lobbyrelay(0, 0, lc))
        print('sent LOBBYRELAY-encapsulated LOBBYCONNECT (now correct u8 ids)')
        ws_drain(s, 'LR')
        s.close()
    elif len(sys.argv) > 1 and sys.argv[1] == 'join':
        # usage: join [pident-hex] [selfpeerID]  (A: 'join'; B: 'join bbccddeeff0002')
        # selfpeerID: also admit OURSELVES via ADDPEER so FUN_1400e2e00's
        # sender-slot gate (session+0x18+fromPeerID*8) passes (proved 2026-11-02).
        _sp = int(sys.argv[3]) if len(sys.argv) > 3 else None
        pident = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0xAABBCCDDEEFF0001
        s = join_and_relay(pident=pident, self_peerID=_sp)
        try:
            s.settimeout(15)
            while True:
                d = s.recv(4096)
                if not d:
                    print('server closed')
                    break
                print('JOIN recv', len(d), d[:200].hex())
        except socket.timeout:
            print('join: no more frames (see notes/bs_server.log for relay lines)')
        s.close()
    elif len(sys.argv) > 1 and sys.argv[1] == 'livejoin':
        # Long-lived peer: attach+RJ, then WAIT listening while the operator runs
        # the other peer / admit from a second shell. Usage:
        #   shell 1: python notes/bs_client.py livejoin [pident-hex]
        #   shell 2: python notes/bs_client.py admit 2 <pident-of-B>
        pident = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0xAABBCCDDEEFF0001
        s = join_and_relay(pident=pident, send_gamedata=False)
        try:
            s.settimeout(120)
            while True:
                for f in ws_drain(s, 'LIVE', wait=4.0):
                    if b'M0' in f or f[:1] in (b'	', b'', b''):
                        print('LIVE payload:', f.hex())
                print('LIVE: still attached (Ctrl-C to stop)', flush=True)
        except KeyboardInterrupt:
            pass
        except socket.timeout:
            pass
        s.close()
    elif len(sys.argv) > 1 and sys.argv[1] == 'admit':
        # host-side admission: admit <peerID> <globalID-hex> [sessionID-hex]
        # Sequence matters: LOBBYCONNECT -> REQUESTJOIN (binds our session, client+0x28)
        # -> PEERHEADER+ADDPEER (server fills relay list session+0x890).
        # Without our own REQUESTJOIN first, the server logs
        # "OnAddPeerMessage - session doesn't exist ... wrong order" and drops it.
        peerID = int(sys.argv[2])
        gid = int(sys.argv[3], 16)
        sid = int(sys.argv[4], 16) if len(sys.argv) > 4 else 0x1122334455667788
        s = socket.create_connection((HOST, WS_PORT), timeout=8)
        ws_handshake(s)
        lc = build_lobbyconnect(sessionID=sid, marker=0, version=5)
        ws_send_bin(s, lc); ws_drain(s, 'LC', wait=2.0)
        rj = build_requestjoin(sessionID=sid, peerIdentifier=0xAABBCCDDEEFF0001)
        ws_send_bin(s, build_peerheader(rj))
        print('sent our REQUESTJOIN (bind session)')
        ws_drain(s, 'RJ', wait=2.0)
        ap = build_addpeer(peerID, gid, isHost=0, isLocal=0)
        ws_send_bin(s, build_peerheader(ap))
        print('sent PEERHEADER/ADDPEER peerID=%d gid=%x: %s' % (peerID, gid, ap.hex()))
        ws_drain(s, 'AP', wait=3.0)
        gd = build_gamedata(b'M0ADMIT-ping-%08x' % gid)
        ws_send_bin(s, gd)
        print('sent GAMEDATA:', gd.hex())
        ws_drain(s, 'GD', wait=5.0)
        s.close()
    elif len(sys.argv) > 1 and sys.argv[1] == 'probe':
        pre = bytes([0x15]) + struct.pack('<Q', ((TITLE_ID) << 48) | 0x334455667788) + struct.pack('<Q', 0x1122334455667788)
        versions = [
            ('v2-toff0-ver4', pre + bytes([2]) + struct.pack('<I', 0) + struct.pack('<H', 4)),
            ('v2-toffpair', pre + bytes([2]) + struct.pack('<I', 0x12345678)),
            ('raw-22bytes', pre),
            ('v2-toffonly', pre + bytes([2]) + struct.pack('<I', 0)),
        ]
        for name, p in versions:
            try:
                s = socket.create_connection((HOST, PORT), timeout=5)
                send_packet(s, p)
                time.sleep(1.0)
                s.close()
                print('sent', name, len(p), 'bytes')
            except Exception as e:
                print('fail', name, e)
        print('done; check notes/bs_server.log for SessionManager lines')
    else:
        main()
