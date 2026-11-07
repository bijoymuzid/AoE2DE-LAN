# linux/ — Linux-side launch path (W2)

- `launch.sh` — the L4 launcher: stages W1's `dbghelp.dll` next to the game exe in the
  prefix, starts the native `lanhub`, sets `WINEDLLOVERRIDES="dbghelp=n,b"` +
  `AOE2LAN_STAGE=8`, launches `AoE2DE_s.exe` under the workspace GE-Proton.
  Expects the DLL at `AoE2DE-LAN/dbghelp.dll` (override: `AOE2LAN_DLL`).
- `relay_test.py` — the L3 relay harness. `python3 relay_test.py local` spawns stock
  BattleServer.exe in the prefix and PASS/FAILs a synthetic two-peer relay session.
  `host` / `joiner` modes run the same session across the tailnet (joiner first,
  host within ~8 s): `python3 relay_test.py joiner 100.79.215.72`.

## Prefix layout (this machine)

- Prefix: `~/Games/aoe/winepfx` (`STEAM_COMPAT_DATA_PATH`; real prefix at `…/pfx`)
- Game: `C:\Games\AoE2DE` = `~/Games/aoe/winepfx/pfx/drive_c/Games/AoE2DE`
- Proton: `~/Games/aoe/Proton-GE Latest` (GE-Proton11-12) — no other Proton/Wine used

## Privileged port (required, one time)

The in-DLL login server binds `127.0.0.1:443`; on Linux that is privileged, so it fails
with `srv: bind 127.0.0.1:443 FAILED` (really EACCES). Allow unprivileged binds:

    echo 'net.ipv4.ip_unprivileged_port_start=0' | sudo tee /etc/sysctl.d/99-aoe2lan.conf
    sudo sysctl --system

Alternative if that is unacceptable: listen on 4443 and rewrite the port in the
`getaddrinfo` hook (`dev/lanhook/iathook.c`) — not done, the sysctl is one line.

## Firewall / tailnet checklist (PLAN §3.6, §8)

- Tailscale up: `sudo tailscale up` — self is `100.109.201.126` on `tail9ccab8`.
- Default tailnet ACL (`* -> *:*`) already permits everything below; restrictive
  policies need an explicit allow for `47101/tcp` and `47110-47114`.
- ufw (if enabled — check `sudo ufw status`; it is inactive by default on Arch):
  `sudo ufw allow in on tailscale0 to any port 47101 proto tcp`
  `sudo ufw allow in on tailscale0 to any port 47110:47114`
- MTU: tailscale0 is 1280; do not raise `[net] mtu` past 1200 in `aoe2lan.ini`.
- Path quality: `lanhub peers` — anything `derp` means +100–200 ms relayed traffic.
