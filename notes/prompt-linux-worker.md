# Work brief for the Linux worker (give this to the Arch machine's assistant)

You are joining **AoE2LAN**, an existing project. Read this whole file, then `PLAN.md` §0–§4 and
§17, then `README.md`. Do not skip the rules at the bottom.

## What the project is

Age of Empires II: Definitive Edition (the RUNE / `steam_emu` release, AppID 813780) greys out the
Multiplayer button unless the game thinks it is logged in to RelicLink, its dead online service.
We make it think that, from inside the game process, with a proxy DLL. The game's own LAN
multiplayer then works. On top of that we are writing a small local hub so two machines on one
Tailscale tailnet find each other without broadcast.

Success for v1, unchanged: two machines on one tailnet — one Windows, one Arch Linux under Proton —
see a `[LAN]` lobby with 2 human and 6 AI slots, and play a full skirmish to the victory screen with
no desync, with the game's own files untouched.

## Where the project is right now

- The Multiplayer button works and the Multiplayer screen opens. That was the last milestone.
- Login is faked locally: a TLS + HTTP + WebSocket server lives inside the injected DLL and answers
  on `127.0.0.1:443`. The game believes it is logged in.
- **Creating a lobby is the current bug.** As of the latest measurement the game does pick *LAN*
  hosting (the log says `starting LAN hosting`) but the create call fails. The cause was just found
  and fixed on the Windows side: the game's HTTP client sends `Expect: 100-continue` for bodies over
  1 KB and our server never answered it, so the body never arrived. That fix is unverified in game.
- Nothing exists yet for the Linux side, and nothing exists yet for the native hub. **That is your
  work.** It is the largest untouched part of the design and it needs no Windows machine.

## What you own

Only these paths. Everything else belongs to the Windows worker.

- `lanhub/` — new. The native hub process.
- `linux/` — new. Launcher script, Wine prefix setup, firewall and tailnet notes.
- `notes/linux-*.md` — new. Your session notes. Write one per session, with what you measured.

Do not edit `dev/lanhook/**`, the `PLAY-stage*.cmd` files, `notes/m1-session*.md` or `logs/**`. The
injected DLL is the Windows worker's file; you receive it as a file, not as source to change.
You may append to `PLAN.md`; do not rewrite other sections.

## Your first three tasks, in order

### L1 — `lanhub` skeleton (start here)

Write the hub process. It speaks two protocols, both plain JSON over TCP, both specified exactly in
`PLAN.md` §5.1 and §5.2. Use Go or C or Rust — your call, but no heavy framework, it is a few
hundred lines of socket code and a map.

- **Control protocol**, bound to `127.0.0.1:47100` only, for the game shim. Verbs: `HELLO`, `HOST`,
  `UPDATE`, `FIND`, `JOIN`, `LEAVE`, `PEERS`, `PING`. Field names and shapes are in the plan.
- **Node protocol**, bound on the tailnet interface, port `47101`, for other machines running the
  hub. Messages: `ANNOUNCE`, `ADVERT`, `WITHDRAW`, `PINGNODE`. Flood with `ttlHops`, re-announce
  anything you have not seen before, and do not re-flood an id you already have.

Acceptance: run two hub instances on one machine on different ports, seeded to point at each other.
Announce a lobby on one. It must appear on the other, and a command-line client sending
`HELLO` → `HOST` → `FIND` → `JOIN` must get the JSON the plan specifies. Write that walk down as a
test script in `lanhub/` so it can be re-run. No UDP broadcast, no multicast: a tailnet carries
neither, that is a hard constraint of this project.

### L2 — Peer enumeration

`tailscale status --json` gives you `DNSName` and `TailscaleIPs` per peer, plus the route it uses.
Turn that into the hub's peer list, with the ini file (`aoe2lan.ini`, `[tailscale] peers`) as a
manual fallback for people without the CLI. Print, per peer, whether the path is `direct` or `derp`
— `derp` means traffic is relayed through Tailscale's servers and adds 100–200 ms, and we promise
to report that rather than hide it.

Acceptance: `lanhub peers` on your machine prints the real peers of your tailnet with their
addresses and their path.

### L3 — Relay regression harness on Linux

`BattleServer/BattleServer.exe` is the relay the game ships. Session 3 of this project proved it
relays a two-peer session when it is fed hand-built `LOBBYCONNECT` and `REQUESTJOIN` frames; the
builders are in `notes/bs_client.py` (plain Python, standard library only) and the annotated capture
is `notes/relay-capture.txt`. Run that against the relay inside your Proton prefix, and turn it into
a PASS/FAIL script.

Acceptance: it prints PASS on your machine, and then again with the two peers on two machines over
the tailnet. Record what you changed, if anything, in `notes/linux-relay.md`.

### After those: L4 and L5

`PLAN.md` §17.2 has them. In short: a launcher script that starts the hub, copies our `dbghelp.dll`
next to the game exe inside the prefix, sets `WINEDLLOVERRIDES="dbghelp=n"` and
`AOE2LAN_STAGE=8`, and starts the game; then checking that the Multiplayer button is live inside
Proton. From Linux you can also do string, RTTI, widget-XAML and localization analysis on the same
game binary — but not the code itself, because most of the code section is encrypted on disk and the
usable copy is a dump that only a Windows run can produce.

## How to run the game under Proton

One Proton prefix shared by the game, the relay and the hub, so `127.0.0.1` and the Documents folder
are shared. Override Wine's own `dbghelp` so our proxy wins. `PLAN.md` §8 has the details. Your game
build is the same build as ours (`AoE2DE_s.exe`, crc `4f533b6c`), so a `dbghelp.dll` built by the
Windows worker works on yours — ask for it and drop it next to the game exe.

## Rules you must not break

1. **Never modify the game's own files.** No patching `AoE2DE_s.exe`, `steam_api64.dll`,
   `winmm.dll`, anything under `resources/` or `widgetui/`. Everything we add is additive and
   removable.
2. **Never patch or hook code that is encrypted on disk.** Roughly 60% of the code section is
   encrypted at rest and integrity-checked after decryption; a patch there kills the game in about
   5 seconds. Hook ids 4, 5 and 13 (the three log helpers) are the only approved hook points.
3. **No blind patching and no cosmetic fixes.** Making a screen look right without fixing the
   behaviour behind it is forbidden. Every change comes from a measurement.
4. **Never reintroduce a broadcast or multicast dependency.** A Tailscale tailnet does not carry
   either. Discovery is unicast gossip between known peers.
5. **Record every experiment, success or failure, with timings and numbers.** Session notes are the
   project's memory; a fix nobody wrote down is a fix we will re-derive.
6. **Report honestly.** If something is unknown, say it is unknown. If a test did not run, say so.

## Say this to me (the Windows worker) when you need it

- The `dbghelp.dll` build — you cannot compile one on Linux (it needs MSVC), so ask and it gets sent.
- A behaviour question about the game: name the log line or the on-screen symptom, and it gets
  measured on the Windows side.

## Tooling on your machine

Python 3 is enough for the relay harness. For the analysis scripts in `notes/` and `dev/lanhook/`,
`pip install capstone numpy`. `git` and `tailscale` must be on your PATH. Everything else is your
choice.