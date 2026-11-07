# Session 35 — settings block: static analysis, enable polarity settled, disk xref exhausted

**No code change this session. The lobby settings block is NOT fixed.** Everything below was read
from files; nothing was launched, nothing was rebuilt, no hook was installed.

Also confirmed at the start of this session: the session-34 TLS framing fix was already in the source,
already built and already committed (`bbc7acb`) before this session began. The staged
`dbghelp.dll` (240,128 B, md5 `42868034f7cb57276e7d3a6de3b203bc`) does carry it — it contains the new
`TLS: bad record size` string, which only the fixed source emits. Handoff copy created:
`D:\dbghelp-session34-latest.dll`. Linux verification is the Linux worker's job; note that
`srvtest.exe` **cannot** verify it, because Windows SChannel never resizes the buffers, so the
offline gate passes with or without the fix.

## 1. The `+0xa5` setter's polarity is SETTLED (was UNKNOWN in s33)

`0x140a74ca0`, read from `gametext.bin`:

```
mov  byte ptr [rcx+0xa5], dl
mov  rbx, rcx
test dl, dl
jne  0x140a74ce5          ; dl != 0 -> mov byte ptr [rcx+0x22],1 ; ret
call 0x140a76c80          ; dl == 0 -> teardown:
cmp  byte ptr [rbx+0x3e0],0
mov  dword ptr [rbx+0x400],0
je   0x140a74cdb
cmp  dword ptr [rbx+0x140],2
je   0x140a74cdb
mov  byte ptr [rbx+0x3e0],0
mov  byte ptr [rbx+0x22],0
ret
```

`dl != 0` sets one byte (`+0x22 = 1`) and returns. `dl == 0` runs a teardown: `0x140a76c80` walks a
parent chain (`mov rax,[rcx+8]` loop), does a named lookup through `0x142d705a5` with two string
arguments, then `+0x400` is zeroed, `+0x3e0` is zeroed unless `+0x140 == 2`, and `+0x22 = 0`.

**Conclusion: `dl` is `enabled`. 1 = live, 0 = detached/torn down.** A "blocked" flag would not run a
detach-from-parent teardown when cleared. This is evidence from the function body, not a guess, and it
closes the question s33 left open.

`0x140a74cf0` is the bare variant — `mov byte ptr [rcx+0xa5],dl; ret`, no side effects.

Both are **virtual**: a whole-`.text` scan for `E8 rel32` call sites found **zero** direct callers of
either. `0x140a74ca0` is installed in 2 vtables (`0x1432141d8` run, `0x14331e0f8` run),
`0x140a74cf0` in 7+ (`0x143214440`, `0x1432146d0`, `0x143214aa8`, `0x1432e2b58`, `0x1432e4a50`,
`0x1432e5d70`, `0x14331c408`). So it is a base-class setter used widely — any detour on it will be
noisy and must filter or dedupe.

## 2. s33's "getter/setter pair" on vtable `0x1433fe100` is WRONG

Dumped the vtable from the exe's `.rdata`:

| slot | target | body | clean on disk |
|---|---|---|---|
| `+0x68` | `0x141f40420` | `movzx eax, byte ptr [rcx+0x45]; ret` | yes |
| `+0x70` | `0x141f40430` | `mov byte ptr [rcx+0x46], dl; ret` | yes |
| `+0x78` | `0x3e8930a3` | not a pointer — the vtable ends at `+0x70` | — |

The getter reads `+0x45`; the setter writes `+0x46`. **Different fields — they are not a pair.** s33
recorded the setter as `+0x74`; it is `+0x70`. Hooking `0x141f40430` as "SetEnabled" would have been
hooking an unrelated flag. Both are clean on disk (on-disk bytes == `gametext.bin` bytes), so both are
hookable if ever needed.

## 3. `UpdateLobbySettings` (`0x141abc6c0`) — the `rbx` gate is traced, and demoted

s33's open question ("who sets `rbx` before `test rbx,rbx` at `0x141abe0d1`") is answered:

- `r15 = rcx` = `this` (the screen). `r13` = result of `call 0x140e16500` on the global at
  `0x1442c5ca8` — a service/singleton; `[r13]` is its interface.
- At `0x141abd339`: `mov rcx,[r13]; call 0x1413d3c70; cmp qword ptr [rax],0; je 0x141abd366`.
  If that object is NULL, `rbx` stays 0. Otherwise `0x1413d3c70` is called again, `[rax]` is passed to
  `0x140daaf10` with an out-smart-pointer, and `rbx` is loaded from it at `0x141abd395`, then addref'd
  through `0x1409914c0` and released at the end through `0x1409914d0` — so `rbx` is a refcounted
  object, and `0x1413d3c70` is the same accessor used at the top of the function (`0x141abc731`).
- `rbx+0x40c` is read as a bool at `0x141abd6e3`; `rbx` is passed with `edx=2` to `0x140dc1070` at
  `0x141abdf57`.
- The guarded block is: `if (rbx) { dl = IsEventScenario([r13]) /* 0x1413d4210 */; call 0x141aab4a0(r15, dl); }`.

**Demoted, not closed.** LAN hosting works and a real lobby with slots appears, so that object almost
certainly exists and the apply call almost certainly runs. This gate is unlikely to be the cause.

## 4. Dead end: the host lobby is a data file, but the data carries no enable flag

`widgetui/screenmultiplayerlobbyhost.json` defines every dead row
(`Background/Data/GameSettings/{GameDropDown, MapSizeDropDown, DifficultyDropDown, ResourcesDropDown,
PopulationDropDown, GameSpeedDropDown, ...}`, plus `Players/PlayerN/{Team, NameDropDown}`). Their keys
are `Type, AccessibilityName, Name, Help, ViewPort, ZPlane, ValueBox, Button, StateMaterials,
ChildWidgets` — **there is no `IsEnabled`/`enabled`/`visible` property anywhere**. So the rows are not
switched off by data; the disable happens in code at runtime. (Runtime paths carry an extra `Data`
container versus the JSON: `GameSettings/Data/GameDropDown`.)

## 5. The `q0` values in the existing `wpo:` logs are STATIC, not enable state

Swept every `logs/lanhook-*.log`. Each row was dumped 8 times across sessions and the value never
changed once:

| row | `q0` | status in host lobby |
|---|---|---|
| `ButtonLocation` | `0x3f` | works |
| `MapSizeDropDown` | `0x3f` | works |
| `DataModDropDown` | `0x3f` | unknown |
| `GameDropDown` | `0x2f` | dead |
| `DifficultyDropDown` | `0x2f` | dead |
| `ResourcesDropDown` | `0x2f` | dead |
| `PopulationDropDown` | `0x2f` | dead |
| `GameSpeedDropDown` | `0x2f` | dead |
| `ButtonScenario` | `0x2f` | dead |

It correlates perfectly with works/dead (the differing bit is `0x10`) — which is exactly why it is a
trap. The values are constant over time and across launches, so they come from the widget definition,
not from live state. This confirms s33's "widget-type flag, do not read as on/off". **Caveat: no
Skirmish log was positively identified in this session**, so the "all rows work in Skirmish with the
same values" half of s33's argument is still his claim, unverified here. If anyone is tempted by
`0x10`, settle it by finding a Skirmish session log first.

## 6. Static xref is exhausted — the referencing code is not on disk

The row-path strings live in a pool at `0x14334c148`, `0x38` stride (`...1b8`, `...1f0`, `...228`,
`...260`, `...298`, `...2d0`, `...308`, `...340`), all present and readable in `.rdata`. But:

- **zero** 8-byte pointers into that pool anywhere in `.rdata` or `.data`;
- **zero** `lea r64,[rip+disp]` sites in `.text` that reach it.

Nothing on disk references those strings. Same story for RTTI: the type descriptors (e.g.
`0x1441fb6d8` for vtable `0x1433fe100`) are in `.data` and read back as digit-garbage, so class names
cannot be recovered statically. The protector means the on-disk `.data` is not the runtime `.data`.

**Consequence: no further progress on this question is possible from the files. It needs one runtime
measurement in the host lobby.**

## 7. What to do next, cheapest first

1. **`AOE2LAN_RULES=1` — already written, read-only, no new hook, no approval needed.** The Multiplayer
   button is decided by a twin-rule table (`0x141b126f0` registers the (enabled, disabled) widget pair,
   `0x141b12d60` fills one status per rule id, `0x141b12a00` evaluates every record, `0x141b12410`
   applies visibility of both twins + SetEnabled of the live one). If the settings rows are governed by
   the same table, the fix has the same shape as the MP-unlock fix — no detour needed.
   **Blocker to check first:** `PLAY-stage8-RULES.cmd` fires its readouts at 25/40/70 s and its scan at
   75 s, i.e. at the *main menu*, before any lobby exists. Either the operator must reach the host
   lobby inside ~75 s, or the probe needs to re-scan periodically. That is a small change to our own
   DLL, not a game patch.
2. **Only if that shows nothing:** a logging detour on `0x140a74ca0` (clean on disk, polarity now
   known), behind a new env var, logging `rcx`, `dl`, the caller, and the widget name if reachable —
   deduped by (name, dl) and line-capped, because it is a base-class setter called for every widget in
   the game. New hook id, so it is the operator's call: exact bytes plus a revert story (revert =
   rebuild without it; ids 4, 5 and 13 remain the only ones installed).
3. **Never** use `AOE2LAN_UIW=1` — that is the whole-memory sweep that crashed the game in s33
   (Event 1000, `0x40010006` in `KERNELBASE.dll`).
4. `0x141aab4a0`, `0x141abc6c0` and `0x140ac4090` remain encrypted on disk — never hook them. Read
   them from `gametext.bin` only.

## State at the end of this session

- Gates: `hooktest.exe` PASS, `srvtest.exe` + `srvclient.py` PASS (both run against the post-fix build
  of 2026-11-06 21:29). Game exe MD5 `affb19f03ca96965abf9e56775cab688`, untouched.
- Staged DLL 240,128 B, md5 `42868034f7cb57276e7d3a6de3b203bc`; identical in the game dir and
  `dev/lanhook`; handoff copy at `D:\dbghelp-session34-latest.dll`.
- LAN hosting still works. Host-lobby settings rows still dead. Skirmish still works.
- Still open from s32: relay answers `relayIP 127.0.0.1` while the game uses `192.168.0.104:27012`;
  cross-machine join untested; `matchTypeID` is `-1`; party plane answers `[0,[]]`.
