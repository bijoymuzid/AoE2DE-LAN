# Session-32 — the lobby settings block is off, and it is one switch

Supersedes `notes/m1-session31.md` for state. Everything below is MEASURED unless the line says
INFERRED or UNKNOWN. No game file, no `.text` byte, no XAML was changed. Code changes this session
are in `dev/lanhook/loginsrv.c` and `dev/lanhook/srvclient.py` (ours).

## 32a. Offline gates (re-run after every change, all pass)

- `hooktest.exe` **68/68** (`game-image iat walk: swapped 68 of 68`).
- `srvtest.exe` + `srvclient.py` **PASS**, now seven checks: the s31 six plus the new
  `updateTags` check in 32e.
- `AoE2DE_s.exe` MD5 **`affb19f03ca96965abf9e56775cab688`** — untouched.
- Staged `dbghelp.dll` at session end: **240,128 B**, MD5 **`d32910972f7d221842607cf37144174e`**.

## 32b. Two trees, and which one builds

`D:\Age of Empires II Definitive Edition\dev\lanhook` is the working tree that builds: its
`build.cmd` stages `dbghelp.dll` into the game dir, and `hooktest.exe` there finds `..\..\AoE2DE_s.exe`.
`D:\aoe2lan-repo\dev\lanhook` is a mirror of it, byte-identical except line endings, refreshed by
`sync.cmd`. Edit the game-dir copy. Running `build.cmd` in the repo copy stages the DLL to `D:\`,
which is harmless but not the game.

A rebuild is not bit-reproducible: the s32 DLL vs the s31 DLL differed in exactly 4 bytes
(`0x110/0x111` = PE TimeDateStamp, `0x2dcf4` = debug timestamp). Compare size + those offsets, not
just the MD5, when the code is supposed to be unchanged.

## 32c. MEASURED (operator, live host lobby): the panel is switched off, not empty

With hosting working (s31c), in the host lobby:

| row | state |
|---|---|
| Location (map), Map Size | **work** |
| Difficulty, Resources, Population, Game Speed, Reveal Map, Starting Age, Ending Age, Treaty Length, Victory | dead — clicking opens **no list at all** |
| Team settings and Advanced settings (Lock Teams, Team Together, Team Position, Shared Exploration, Player Assist, Lock Speed, Allow Cheats, Turbo, All Techs, Solid Farms, Record Game) | dead — no tick appears |
| every row still shows its current value (e.g. Resources = Standard) | yes |
| "I am ready" ticked or unticked | no difference |
| add-AI on the empty slots | not offered |
| Start Game | not pressable (only one player) |

So the widgets hold data and are drawn, but they are **disabled** (a disabled widget in this UI opens
nothing). It is not an empty list and not a rejected value.

## 32d. MEASURED: single-player Skirmish is innocent

The operator opened Single Player → Skirmish on the same launch and every one of those rows works
there (opens, changes). The widget code, the option tables and the data files are therefore fine.
The lock is specific to the multiplayer host lobby.

## 32e. FOUND AND FIXED: `updateTags` was answering with an empty lobby, once a second

`route()` matches with `contains(path, "/game/advertisement/update")`, which also matches
`/game/advertisement/updateTags` and `/game/advertisement/updateState`. Those two bodies are tiny
(`advertisementid`, `callNum`, `connect_id`, `sessionID`, or the numeric tag arrays) — no `hostid`,
no `mapname`, no `options`. `emit_advertisement()` therefore produced a full advertisement saying
**hostProfileID 0, options "", encodedSlots "", matchState -1**, stored it, and returned it as
`updatedAvertisement` every second (log `lanhook-12548.log` t=48.485 / 49.547).

Fix: those calls now echo the lobby already stored in `g_AdvBody` and never overwrite it. Pinned in
`srvclient.py` (`updateTags reply: hostProfileID=3842241165083521967` fails the gate if it is 0 or if
the slot blob is lost).

MEASURED after the fix, in game (`logs/lanhook-18928.log` t=55.157 … 59.438): every `updateTags`
reply now carries `hostProfileID 3842241165083521967` and the real blobs — **and the settings panel is
still locked**. So this defect was real but it was **not** the cause of 32c.

## 32f. Static: the one function that flips the whole block

`0x141aab4a0` is the switch. It takes `(screen, flag)` and for a fixed list of widgets does
`GetWidget(0x140ac4090)` then `[vtable+0x68](widget, flag, 0)`:

- the settings dropdowns **Resources, Population, Reveal Map, Starting Age, Ending Age,
  Treaty Length, Time**,
- **LockTeams, SharedExploration, PlayerAssist, SolidFarms** and the
  Reset / Randomize / Lobby Settings buttons.

That list is almost exactly the s32c dead set. Map, Map Size and the Game-mode row are **not** in it;
they are handled elsewhere, which is why they still work. (Difficulty, Game Speed, Victory are not in
this list either — UNKNOWN whether a second list covers them or their own code disables them.)

`vtable+0x68` is **SetEnabled**, `vtable+0x60` is SetVisible: measured, `ButtonReadyStart` (a button
you can always press) is called with `edx = 1` at `0x141a40a99`, and hidden icons are driven with
`+0x60` and `edx = 0`. So in `0x141aab4a0`, `flag = 1` means enabled.

Its only two callers:

| caller | inside | passes |
|---|---|---|
| `0x141aacd03` | the 19 KB per-slot refresh `0x141aac3d0` | **0** (would mean: disable) |
| `0x141abe0e5` | `UpdateLobbySettings` `0x141abc6c0` | `IsEventScenario(...)` |

`IsEventScenario` = `0x1413d4210` → thunk `0x140f6a260` → `0x140f69fe0`, which takes the selected
scenario name and looks it up in a 4-record table in `.data` at `0x1442eb050` (stride `0xc8`, keys are
the event scenario file names built by `0x140182010`: June 2020, September 2020, Mangudai Madness,
March 2024). Returns `id != -1`.

**The contradiction that has to be settled by measurement:** if `0` = disabled, then the per-slot
refresh `0x141aac3d0` disables the block on every run, and the host lobby could never be editable.
If `0` = enabled, nothing in either caller explains 32c. One of the two readings is wrong, and only a
live read of a widget's flag will say which.

Also measured: the host-lobby refresh calls at `0x141abe0e5` are guarded by `test rbx,rbx` — when
`rbx` (a lobby object) is null the enable call is **skipped entirely**, leaving the block in whatever
state it was created with. `rbx` is set earlier in `0x141abc6c0`; its identity is UNKNOWN.

## 32g. Static: widget paths are directly xref-able (corrects §31k)

§31k said `xr.py` gives nothing for these widget names. That is wrong — the earlier attempt matched
bare names (`GameDropDown`) and landed on other screens' strings. The **full paths** xref cleanly
from `gametext.bin`:

| widget path (`.rdata`) | VA |
|---|---|
| `Background/Data/GameSettings/Data/GameDropDown` | `0x14334c148` |
| `.../MapSizeDropDown` | `0x14334c1b8` |
| `.../DifficultyDropDown` | `0x14334c1f0` |
| `.../ResourcesDropDown` | `0x14334c228` |
| `.../PopulationDropDown` | `0x14334c260` |
| `.../GameSpeedDropDown` | `0x14334c298` |
| `.../RevealMapDropDown` | `0x14334c2d0` |
| `.../StartingAgeDropDown` | `0x14334c308` |
| `.../EndingAgeDropDown` | `0x14334c340` |
| `.../TreatyLengthDropDown`, `.../VictoryDropDown`, `.../TimeDropDown`, `.../DataModDropDown` | next in the same pool |

Correct file→VA conversion for `.rdata` is `va = 0x140000000 + (fileoff - 0x3195c00 + 0x3197000)`;
`aoe2re.off2va()` is off by 0x1400 for `.rdata`.

Functions that touch many of these paths (all share `0x140ac4090` = GetWidget): `0x141aac3d0` (50
refs, the per-slot + settings refresh, **no direct callers — reached through a vtable**),
`0x141ab7270` (0 callers), `0x141ab9060` (0 callers), `0x141abc6c0` = `UpdateLobbySettings`
(4 callers: `0x141aad8e4`, `0x141aadc04`, `0x141ab2d6d`, `0x141ab2e5f`), `0x141abed10`, `0x141ab8720`,
`0x141aab4a0` (32f).

## 32h. Tooling: the game's own log cannot tell us whether the screen refresh ran

Our DLL hooks `LogHelper` / `LogWarn`, which is how game log lines appear in `lanhook-<pid>.log`.
The host lobby's own strings — `UIScreenMultiplayerLobbyHost::Wake`,
`UIScreenMultiplayerLobbyHost::UpdateLobbySettings initial call`, `Lobby settings button pressed` —
exist in `.rdata` but **never fired** in the s31 or s32 runs, and the same run shows minutes of
`Sending matchinfo change` traffic. So either those log calls live in a path this lobby does not take,
or they are a different logging macro. Do not use "the log is quiet" as evidence about the UI.

## 32i. OPEN — the next measurement, decided but not built

A read-only probe in our own DLL, in the s27 `AOE2LAN_UIW` style (`lanhook.c`, opt-in env var, no
detour, no write): scan committed memory for the pointer to each widget's full path string; for each
hit whose preceding qword is an `.rdata` vtable with a sane `+0x68` setter, dump the object's first
`0x80` bytes. Run it on one **known-enabled** row (`.../MapSizeDropDown`) and one **known-disabled**
row (`.../ResourcesDropDown`, `.../LockTeams`) while the operator sits in the host lobby, and diff the
dumps. That yields the enabled-flag offset, which then answers 32f, and can be printed every few
seconds afterwards.

Timing: the operator has to be in the lobby when the probe runs. s27-style fixed `t=60s` does not
work here; run it repeatedly (e.g. t=60,90,120,…) and log only new hits.

## 32j. Unchanged / still open from s31

- Relay: the game finds and connects to `192.168.0.104:27012` by itself; our replies still say
  `relayIP 127.0.0.1`. Cross-machine play is untested (W1-c).
- Join / leave / browse from a second machine: untested live.
- `matchTypeID` is still `-1` in our update reply. Unmeasured whether the UI reads it.
- The party plane (`/game/party/peerAdd`, `/game/relationship/setPresence`, `updateTags`) still gets
  `[0,[]]` for party/relationship calls.
