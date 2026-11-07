# Prompt for the next Windows session (paste this into a new chat)

Continue AoE2LAN (AoE2:DE LAN mod). Session 35 is finished — it was analysis only, **no code change,
and the lobby settings block is still not fixed**. Read `notes/m1-session35.md` in full before
touching anything; it supersedes the settings-block parts of s32 and s33. Then `PLAN.md` §0–§2, §6.1
and §17.

Say everything to me in plain English: short sentences, no jargon, no code dumps, no leaps. If
something is unknown, say it is unknown.

Working dir: `D:\Age of Empires II Definitive Edition`. Repo: `D:\aoe2lan-repo` →
https://github.com/bijoymuzid/AoE2DE-LAN. `git pull` first. At the end run
`cmd /c D:\aoe2lan-repo\sync.cmd "session 36 - <one line, no parentheses, no colon after NN>"`
(in this shell `cmd /c` must be written as `/c/WINDOWS/system32/cmd.exe //c`).

**You cannot launch the game** and you cannot see the screen. I double-click `PLAY-stage*.cmd`. Ask me
what is on screen. If a launch dies at ~3 s, wait ~45 s and ask for a relaunch. A running game locks
the staged `dbghelp.dll`, so rebuild only after I close it, and confirm the copy actually landed.

## WHERE WE ARE (do not re-derive)

- **The Linux login bug is fixed, built, staged and committed** (session 34, `bbc7acb`):
  `tls_encrypt_send()` in `dev/lanhook/loginsrv.c` ~L912 now sends `bufs[0..2].cbBuffer` as adjusted by
  `EncryptMessage`, with a `total <= 0 || total > sizeof(rec)` guard. Wine 11.0 shrinks `cbTrailer`
  (256 → 24 for GCM); Windows leaves it alone, so the old pre-call total shipped the zero tail of `rec`
  and broke TLS record framing. Staged `dbghelp.dll` = 240,128 B, md5
  `42868034f7cb57276e7d3a6de3b203bc`, and it contains the new `TLS: bad record size` string, so the
  binary does carry the fix. Handoff copy exists: `D:\dbghelp-session34-latest.dll`.
- **Verification on Linux is the Linux worker's job, not ours.** `srvtest.exe` cannot verify it — it
  runs Windows SChannel, which never resizes the buffers, so it passes either way. Do not call the
  framing bug closed on a green `srvtest`. Also already landed in s34: `WINEDLLOVERRIDES="dbghelp=n,b"`
  (`n` alone broke the proxy's `LoadLibraryExW`) and the privileged-port sysctl
  (`net.ipv4.ip_unprivileged_port_start=0`) in `linux/README.md` + `linux/launch.sh`. The server still
  binds `127.0.0.1:443`; no 4443 fallback was written.
- Gates: `hooktest.exe` PASS, `srvtest.exe` + `srvclient.py` PASS. Game exe MD5
  `affb19f03ca96965abf9e56775cab688`, untouched. LAN hosting works. Skirmish works.
- **The one blocker:** in the host lobby only Location (map) and Map Size work. Difficulty, Resources,
  Population, Game Speed, Reveal Map, Starting/Ending Age, Treaty Length, Victory, Teams, the Advanced
  checkboxes and the add-AI offer are all dead.

## WHAT SESSION 35 SETTLED (all static, all in `notes/m1-session35.md`)

- **Enable polarity is no longer unknown.** `0x140a74ca0` writes `[rcx+0xa5] = dl`; `dl != 0` sets
  `[+0x22] = 1` and returns; `dl == 0` runs a teardown (walks the parent chain, clears `+0x400`,
  clears `+0x3e0` unless `+0x140 == 2`, clears `+0x22`). So **`dl` = enabled, 1 = live**.
  `0x140a74cf0` is the bare field write. Both are virtual — zero direct `E8` callers, 2 and 7+ vtables
  respectively, so it is a base-class setter and any detour on it will be noisy.
- **s33's getter/setter pair on vtable `0x1433fe100` is wrong.** Slot `+0x68` = `0x141f40420` reads
  `[rcx+0x45]`; slot `+0x70` (not `+0x74`) = `0x141f40430` writes `[rcx+0x46]`. Different fields, not
  a pair. Both are clean on disk. Do not hook `0x141f40430` as "SetEnabled".
- **The `rbx` gate in `UpdateLobbySettings` (`0x141abc6c0`) is traced and demoted.** `rbx` comes from
  the accessor `0x1413d3c70` via `0x140daaf10`; if it is NULL the apply call `0x141aab4a0` at
  `0x141abe0e5` is skipped. Since a real lobby with slots appears, that object almost certainly
  exists. Unlikely to be the cause.
- **Not a data problem:** `widgetui/screenmultiplayerlobbyhost.json` defines all the dead rows and has
  no `IsEnabled`/`enabled`/`visible` property anywhere.
- **`q0` in the `wpo:` logs is static, not state.** Across every log, dead rows are always `0x2f` and
  working rows always `0x3f` (differing bit `0x10`), never varying. It correlates with works/dead,
  which is exactly why it is a trap. Caveat: no Skirmish log was identified, so s33's "same values
  while every row works in Skirmish" is still unverified — if you are tempted by `0x10`, find a
  Skirmish log first.
- **Static analysis is exhausted.** The row-path string pool at `0x14334c148` (0x38 stride) has zero
  pointers to it in `.rdata`/`.data` and zero `lea rip` sites in `.text`; RTTI type descriptors read
  back as garbage. The protector means on-disk `.data` ≠ runtime `.data`. **Nothing more can be
  learned from the files. The next step must be a runtime measurement in the host lobby.**

## THIS SESSION, IN ORDER

1. `git pull`. Confirm the staged DLL is still 240,128 B / `42868034…`.
2. **Cheapest measurement first, and it needs no new hook:** run the existing read-only
   `AOE2LAN_RULES=1` probe (`PLAY-stage8-RULES.cmd`) while I sit in the **host lobby**, and check
   whether the settings rows are governed by the same twin-rule table that decides the Multiplayer
   button (`0x141b126f0` registers the (enabled, disabled) pair, `0x141b12d60` fills one status per
   rule id, `0x141b12a00` evaluates, `0x141b12410` applies visibility + SetEnabled). If a rule record
   names those rows, the fix has the same shape as the MP-unlock fix and needs no detour.
   **Read this before launching:** that probe fires at 25/40/70 s and scans at 75 s, i.e. at the main
   menu, before a lobby exists. So either tell me to reach the host lobby inside ~75 s, or change the
   probe to re-scan periodically — that is a change to our own DLL, not a game patch, and it is the
   smallest thing that makes the measurement possible.
3. Only if step 2 shows nothing: propose a logging detour on `0x140a74ca0` (clean on disk, polarity
   known), behind a new env var, logging `rcx`, `dl`, the caller and the widget name if reachable,
   deduped by (name, dl) and line-capped. Ask me first — it is a new hook id, so bring exact bytes and
   a revert story (revert = rebuild without it; ids 4, 5 and 13 stay the only ones installed).
4. Still open from s32, lower priority: relay answers `relayIP 127.0.0.1` while the game uses
   `192.168.0.104:27012`; cross-machine join untested; `matchTypeID` is `-1`; party plane answers
   `[0,[]]`.

## RULES THAT STILL APPLY

Never patch or hook code encrypted on disk (`0x141aab4a0`, `0x141abc6c0`, `0x140ac4090` and friends) —
read those from `dev/lanhook/gametext.bin` only. **No whole-memory sweeps and never set
`AOE2LAN_UIW=1`** — that is what crashed the game in s33 (Event 1000, `0x40010006` in
`KERNELBASE.dll`); read only addresses reached through a pointer you already trust. Hook ids 4, 5 and
13 only unless I approve a new one. No blind patching, no cosmetic fixes. Any new detour or game-file
edit is my call and needs exact bytes plus a revert story. Do not edit `lanhub/**`, `linux/**` or
`notes/linux-*.md` — that is the Linux worker (PLAN §17.1); hand him `dbghelp.dll` as a file. Edit the
game-dir tree (`D:\Age of Empires II Definitive Edition\dev\lanhook`), not the repo mirror. Ask me
what is on screen — you cannot see it.
