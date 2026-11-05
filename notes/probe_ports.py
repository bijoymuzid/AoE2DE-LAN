"""M0.1: probe BattleServer wire ports. Tries TCP connect + capture banner/response."""
import socket, sys, time

def try_tcp(port, payload=None, timeout=3.0):
    try:
        s = socket.create_connection(('127.0.0.1', port), timeout=timeout)
        s.settimeout(timeout)
        if payload:
            s.sendall(payload)
        try:
            data = s.recv(4096)
        except socket.timeout:
            data = b'<no data before timeout>'
        s.close()
        return data
    except Exception as e:
        return f'<connect failed: {e}>'.encode()

for port in (47110, 47111, 47112, 47114, 47115):
    print(port, 'empty ->', try_tcp(port)[:200])

# HTTP-ish probe on raw port?
print('47110 http ->', try_tcp(47110, b'GET / HTTP/1.0\r\n\r\n')[:200])
# websocket-ish probe on 47111
print('47111 ws ->', try_tcp(47111, b'GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n')[:300])
