# linux/ — Linux-side launch path (W2)

- `launch.sh` — the L4 launcher: stages W1's `dbghelp.dll` next to the game exe in the
  prefix, starts the native `lanhub`, sets `WINEDLLOVERRIDES="dbghelp,winmm=n,b"` +
  `AOE2LAN_STAGE=8` + `PROTON_NO_NTSYNC=1`, and launches `AoE2DE_s.exe` under the workspace
  Proton-CachyOS with `proton runinprefix` (direct wine — `proton run` goes through Proton's
  `steam.exe` stub, which delegated to the real Steam client and hung; see
  `notes/linux-session2.md` 2b).
  Expects the DLL at `AoE2DE-LAN/dbghelp.dll` (override: `AOE2LAN_DLL`).
- `relay_test.py` — the L3 relay harness. `python3 relay_test.py local` spawns stock
  BattleServer.exe in the prefix and PASS/FAILs a synthetic two-peer relay session.
  `host` / `joiner` modes run the same session across the tailnet (joiner first,
  host within ~8 s): `python3 relay_test.py joiner 100.79.215.72`.

## Prefix layout (this machine)

- Prefix: `~/Games/aoe/winepfx` (`STEAM_COMPAT_DATA_PATH`; real prefix at `…/pfx`)
- Game: `C:\Games\AoE2DE` = `~/Games/aoe/winepfx/pfx/drive_c/Games/AoE2DE`
- Proton: `~/Games/aoe/Proton-CachyOS Latest-x86_64_v3` (`cachyos-11.0-20261015-slr`) — default;
  `~/Games/aoe/Proton-GE Latest` (GE-Proton11-12) also works via `AOE2LAN_PROTON`. No other
  Proton/Wine used.

## Privileged port (required, one time)

The in-DLL login server binds `127.0.0.1:443`; on Linux that is privileged, so it fails
with `srv: bind 127.0.0.1:443 FAILED` (really EACCES). Allow unprivileged binds:

    echo 'net.ipv4.ip_unprivileged_port_start=0' | sudo tee /etc/sysctl.d/99-aoe2lan.conf
    sudo sysctl --system

Alternative if that is unacceptable: listen on 4443 and rewrite the port in the
`getaddrinfo` hook (`dev/lanhook/iathook.c`) — not done, the sysctl is one line.

## Host block (required, one time)

The game must *not* reach the real `api.ageofempires.com`: a genuine HTTP 401 from it ends the
login flow, while a transport failure is tolerated (that is what the Windows reference box sees).
This Wine build ignores the prefix's `drivers\etc\hosts`, so it has to be the real resolver:

    echo '127.0.0.2 api.ageofempires.com cdn.ageofempires.com' | sudo tee -a /etc/hosts

`127.0.0.2` is loopback with nothing on :443 (our server binds `127.0.0.1` exactly), so the connect
is refused instantly and the game gets the same `-47` failure Windows does. Undo with
`sudo sed -i '/ageofempires\.com/d' /etc/hosts`. Evidence: `notes/linux-session2.md` 2c.

## Firewall / tailnet checklist (PLAN §3.6, §8)

- Tailscale up: `sudo tailscale up` — self is `100.109.201.126` on `tail9ccab8`.
- Default tailnet ACL (`* -> *:*`) already permits everything below; restrictive
  policies need an explicit allow for `47101/tcp` and `47110-47114`.
- ufw (if enabled — check `sudo ufw status`; it is inactive by default on Arch):
  `sudo ufw allow in on tailscale0 to any port 47101 proto tcp`
  `sudo ufw allow in on tailscale0 to any port 47110:47114`
- MTU: tailscale0 is 1280; do not raise `[net] mtu` past 1200 in `aoe2lan.ini`.
- Path quality: `lanhub peers` — anything `derp` means +100–200 ms relayed traffic.

## Session-3 findings (2026-11-10) — read notes/linux-session3.md

- The game **does** launch on wine 10. `AOE2LAN_STAGE=8` (the login shim) deadlocks the boot at
  `Main.txt` line 18 on wine: with the grp2/grp3 detours a game thread spins inside wine's
  `RtlWakeAddressAll`; with the server up a game thread busy-polls `fsync_msgwait` at ~4k/s
  (wineserver ~35% CPU) and everything else parks. Details, stacks and the bisect ladder in
  `notes/linux-session3.md` 3a–3e; W1 asks in 3h.
- Interim boot without login: `AOE2LAN_STAGE=1` (DLL inert) or `AOE2LAN_STAGE=7` (IAT only)
  reach the main menu in under a minute on `pfx-wine10`; Multiplayer stays greyed because no
  login server runs. Use these to test anything menu-side on Linux.
- Ops traps: `pgrep -f 'AoE2DE_s.exe'` matches the python launcher — use `pgrep -x`; there is no
  `xwininfo`/`xdotool` here (use `import` + `identify`); the shim's 900/1400-line log caps are
  burned by t≈3.6 s on Linux, so post-boot visibility needs strace or `WINEDEBUG=+server`.
