import sys, socket, time, threading
sys.path.insert(0, 'notes')
import bs_client as m
SID = 0x1122334455667788
A_PID, B_PID = 0xAABBCCDDEEFF0001, 0xBBCCDDEEFF0002

# 1. BOTH sockets connect + attach (LC) BEFORE any REQUESTJOIN => both stay
#    on the normal websocket dispatch path (session doesn't exist yet).
sa = socket.create_connection((m.HOST, m.WS_PORT), timeout=8); m.ws_handshake(sa)
sb = socket.create_connection((m.HOST, m.WS_PORT), timeout=8); m.ws_handshake(sb)
m.ws_send_bin(sa, m.build_lobbyconnect(sessionID=SID, marker=0, version=5))
m.ws_send_bin(sb, m.build_lobbyconnect(sessionID=SID, marker=0, version=5))
print('both LC sent', flush=True); time.sleep(1.0)

# 2. Both REQUESTJOINs (A first = session creator/host)
m.ws_send_bin(sa, m.build_peerheader(m.build_requestjoin(sessionID=SID, peerIdentifier=A_PID)))
time.sleep(0.2)
m.ws_send_bin(sb, m.build_peerheader(m.build_requestjoin(sessionID=SID, peerIdentifier=B_PID)))
print('both RJ sent', flush=True); time.sleep(1.5)

def drain(tag, s, wait=3.0):
    s.settimeout(wait)
    try:
        while True:
            d = s.recv(8192)
            if not d: print('[%s] closed' % tag, flush=True); break
            print('[%s] recv %dB %s' % (tag, len(d), d[:120].hex()), flush=True)
    except socket.timeout: pass

# 3. Host admits B (ADDPEER), then GAMEDATA ping
m.ws_send_bin(sa, m.build_peerheader(m.build_addpeer(2, B_PID)))
print('A sent ADDPEER(B)', flush=True)
time.sleep(0.5)
m.ws_send_bin(sa, m.build_gamedata(b'A-GD-PING'))
print('A sent GAMEDATA', flush=True)
ta = threading.Thread(target=drain, args=('A', sa, 6.0))
tb = threading.Thread(target=drain, args=('B', sb, 6.0))
ta.start(); tb.start(); ta.join(); tb.join()
print('DONE', flush=True)
