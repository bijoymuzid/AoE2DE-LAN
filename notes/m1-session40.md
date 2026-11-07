# Session 40 — the host lobby's AI item EXISTS and is behind one gate; root cause shared with the row locks

Supersedes `notes/m1-session39.md` for everything below. All addresses are VAs unless written
`RVA`. Everything marked MEASURED came from live runs `logs/lanhook-17808.log` (run 1) and
`logs/lanhook-17668.log` (run 2); everything else was read from `dev/lanhook/gametext.bin`
(decrypted `.text`) cross-checked against `AoE2DE_s.exe` and `widgetui/*.json`.
Game exe untouched. **Code change this session: one new read-only hook, id 15.**

## 40a. Gates

- `AoE2DE_s.exe` MD5 `affb19f03ca96965abf9e56775cab688` — unchanged.
- `hooktest.exe` PASS, `game-image iat walk: swapped 68 of 68`. `srvtest.exe` PASS.
- Staged `dbghelp.dll` MD5 **`f499bbd13a4e838f4f6b8c37267d27f4`**, **244,736 B**, identical in the
  game dir and `dev/lanhook/`. Backups kept: `dbghelp.dll.prev-s40-a`, `dbghelp.dll.prev-s40-b`.
- **Loss worth recording:** `build.cmd` ends with `copy /y dbghelp.dll ..\..\dbghelp.dll` and makes
  no backup, so the s39 staged binary (`d313af6964b08e0ab4fe6d908a6f1a01`) was overwritten before it
  could be saved. Rollback for the s39 build is now "restore `hookcore.c`/`hookcore.h`/`lanhook.c`
  from git and rebuild", not a file copy. **Copy `dbghelp.dll` to a `.prev-*` name BEFORE building.**
- Launch used: `powershell -NoProfile -ExecutionPolicy Bypass -File
  "dev\lanhook\work\launch-detached.ps1" -cmdFile PLAY-stage8-AISLOT.cmd`. Boot log confirms
  `hook filter: only 4:LogHelper,5:LogHelper2,13:LogWarn,14:WidgetSetEn,15:AISlotPick` and
  `installed AISlotPick n=11`.

## 40b. What was built (id 15, `AISlotPick`)

- New kind `HK_AISLOT 5` in `hookcore.h`; handler in `hookcore.c`; table entry
  `{"AISlotPick", 0x140D62260, EXP_AISLOT, 600000, 0, HK_AISLOT}` (id 15, grp 0 = opt-in only).
  `EXP_AISLOT = 48 83 EC 28 48 81 C1 80`. Target is 16-aligned and CLEAN on disk (28 B, 26 call
  sites); `hook_len` returns 11 (`sub rsp,0x28` + `add rcx,0x680`), no rip-relative, so the
  trampoline needs no relocation.
- Logs `caller obj tag val kind nAI via`, deduped on the hash of those, capped at 256, and it skips
  the first 20 s **for logging only** — the force path stays live from t=0. Dedup runs AFTER the
  time gate on purpose: recording boot tuples first would swallow the lobby tuples later.
- `AOE2LAN_AIKIND=0|1|2` (optional, **currently unused and now pointless — see 40d**) makes the hook
  hand the original function a fake 8-byte variant `{DWORD n; BYTE 0;}` via
  `ctx[17] = &fake - 0x680`, so the game itself computes slot n. No game memory is written and only
  caller `0xbf3c8b` is affected. This "substitute the input pointer instead of the output" trick
  works because `hooks.asm` restores rcx from `ctx[17]`.
- New `PLAY-stage8-AISLOT.cmd` = `AOE2LAN_HOOKS=4,5,13,14,15`. Default stage-8 hooks are unchanged.
- New analysis scripts in `dev/lanhook/work/`: `aistr.py` (function bounds + its string refs +
  clean/encrypted), `cleanfns.py` (for every callee in a dump: clean? how many call sites?),
  `verifydll.py` (walk `g_Hooks` in the built DLL and print each entry), `xgrp.py` (group
  rip-relative xrefs to a string by containing function). Existing: `dz.py`, `fn.py`, `cx.py`,
  `rr.py`, `aoe2re.py`.

## 40c. The AI-list mechanism, fully mapped (static, all verified)

**`0x141ab4bd0..0x141ab6ab9` is the SKIRMISH screen's slot-dropdown filler — not the host lobby's.**
Proof: it is the only function in the image that references
`"Background/Data/Players/Player1/NameDropDown"` (`0x14334c858`, one xref, at `0x141ab4e73`), and
that string lives inside the `ScreenSinglePlayerCreate` string cluster (`0x14334c018..0x14334c63a`:
`UIWidgetScreenSinglePlayerCreate Sleep/Wake`, `ScreenSinglePlayerCreate::StartGameCommon`, …). The
`MultiplayerLobbyHost` cluster is elsewhere (`0x143341848..0x1433420eb`). s39l chased this function
as "the lead"; it is real but it belongs to the wrong screen.

What it does: calls the AI-list builder `0x140bf3c30` at `0x141ab4c54` into a local vector at
`[rbp+0x568]`; clears `this+0x1f0`; for each 0x40-byte entry `new(0x48)` an item
`{vtable 0x143341698, dword, string display@0x10, string name@0x28, byte@0x40 = (entry.kind==3)}`
and push it into `this+0x1f0`. Then at **`0x141ab524b`** it skips AI item creation entirely iff
`this+0x1f0` is empty. No other filter. Element stride 0x40; the entry field read as
`[r14+0x20]` with `r14 = elem+0x18` is `elem+0x38`.

**AI-list builder `0x140bf3c30`** (ENCRYPTED, 1844 B). 7 call sites, so 7 possible `via` values
(each = call site + 5): `0xe730d8`, `0xe73287`, `0xe73885`, `0xe79002`, `0x13d4564`, **`0x1ab4c59`**,
`0x1c93e78`. Three sources, concatenated into one output vector of 0x40-byte entries:

1. **S1 — the built-in table.** `rcx = [0x1443552b8]` → `0x140d62260` → `0x14100b4c0` → a
   `vector<AiEntry>` that is copied with `0x140bf3840`.
   - `0x140d62260` (CLEAN, 28 B, 26 sites) = `kind = 0x140fa46c0(rcx+0x680); return 0x14100b560(kind)`.
   - `0x14100b560` = lazy-init once (`byte[0x144356720]`, init `0x14100b5a0`) then
     `return 0x144356760 + kind*0x110`. **3 slots of 0x110 at RVA `0x4356760`.**
   - `0x14100b4c0` = `lea rax,[rcx+0x28]; ret`. So the AI vector is `slot+0x28`.
     **Not hookable**: 5 bytes ending in `ret`, and the mini-LDE in `hookcore.c` rejects `C3`.
   - `0x140fa46c0` (CLEAN, 0x2f B, 182 sites) = the s39j getter: `t = byte[rcx+4]; t==0 ->
     dword[rcx]; t==1 -> (dword[rcx]==3)?2:0; else -> 0x1408f6a00`.
   - Initializer `0x14100b5a0..0x14100c5cc` (ENCRYPTED) resizes the table to **3** slots
     (`edx=0x110, r8d=3` at `0x14100c2d4`) and fills AI vectors of **2** and **1** entries
     (`edx=0x40, r8d=2` / `r8d=1`, destructor `0x140bf3950`). Entry layout is
     `{string name@0x00, byte has_id@0x18, dword id@0x1c, string key@0x20, dword kind@0x38}`.
     The 2-entry slot is `{"PromiDE", NEW_AI_TAG, kind 0}` and `{"RandomGame", ORIG_AI_TAG, kind 1}`
     — i.e. display "AI" and "AI (CD version)". That is 2 of the 4 names the operator sees in
     Skirmish; "AI (HD Version)" comes from S2.
   - **Tag statics** (from the four lazy getters): `NEW_AI_TAG -> 0x144093de8`,
     `ORIG_AI_TAG -> 0x144093dc8`, `HD_AI_TAG -> 0x144093e08`, `CUSTOM_AI_TAG -> 0x144093e28`.
     Getters: NEW `0x1401bf4c0`, ORIG `0x1401bf4f0`, HD `0x1401be570`, CUSTOM `0x1401be540`.
2. **S2/S3 — two file-enumeration passes** via ENCRYPTED `0x140fae720(spec, 0, ctx, out, arg5)`;
   spec `{1,5}` arg5 `9` → entries with kind 2; spec `{3,5}` arg5 `0x14093b740(9,0x40)` → kind 3.
   Pass 1 skips `"E3-p2.ai"` and rewrites `"AI (HD version)"` to `HD_AI_TAG` via
   `0x140964f30`/`0x140965d80`/`0x1409657b0`. `ctx` is the builder's `rdx`, which the caller
   derives as `[0x1413d2420([[global]])]` — different global per caller (`0x1442c5ca8` for the
   Skirmish filler, `0x1442dc4f0` for `MultiplayerPregameHostSession`).
3. **`FindAIByName` = `0x140bf43c0..0x140bf4474`** (ENCRYPTED, 181 B, exactly 1 caller:
   `0x1413ebc30`). Walks S1's vector comparing names with `0x140a17030`. It calls the slot picker at
   `0x140bf43e5`, so `caller=0xbf43ea` in the log means FindAIByName.

**Clean functions on this path** (usable as hook targets): `0x140d62260` (26 sites, hooked = id 15),
`0x140fa46c0` (182), `0x140bf35a0` (2 sites, both builder grow-paths), `0x141a22d00` (3 sites:
`0x1a31cf5`, `0x1ab4e34`, `0x1c9401f`), `0x140d62260`'s tail `0x14100b560`, `0x14093b740` (44).
Everything else on the path (`0x140bf3c30`, `0x140fae720`, `0x140bf3840`, `0x140ac4090`,
`0x140adbb30`, `0x140adeda0`, `0x140a16ef0`, `0x140a1c5b0`) is ENCRYPTED.

## 40d. MEASURED — two runs, and the s39 "wrong slot" theory is dead

Both runs: `tag=0 val=2 kind=2 nAI=2` on **every** AISlotPick line, in both screens. The mode
descriptor slot is correct and holds 2 AIs everywhere. **So `AOE2LAN_AIKIND` cannot help — do not
spend a run on it.** The list is available; the host lobby's UI just never asks for it.

`via=` (the builder's own caller, recovered by scanning `ctx[20..220]` for one of the 7 known return
addresses — the frame offset `ctx[85]` was predicted from the builder's prologue, 7 pushes +
`sub rsp,0x1d0`, and the scan found it):

| screen | t | via | meaning |
|---|---|---|---|
| host lobby | 102.203 | `0x13d4564` | fn `0x1413d44f0..0x1413d46bc` (461 B, encrypted, no strings) |
| host lobby | 102.703 | — (`caller=0xbf43ea`) | `FindAIByName` |
| host lobby | 102.703 | `0xe730d8` | `MultiplayerPregameHostSession` `0x140e72660` (CLEAN) |
| host lobby | 102.718 | `0xe73287` | same function, second call |
| skirmish | 117.297 | **`0x1ab4c59`** | the Skirmish NameDropDown filler `0x141ab4bd0` |

**`0x1ab4c59` never appears in the host-lobby window.** The lobby fetches the AI list for the
*session* (`session+0xee0`, see the move-assign at `0x140e730db..0x140e7310c`) and for
`FindAIByName`, but its dropdown filler never does.

Timeline proof (not inference) — widget names that exist in only one JSON:
host-only `ButtonBalanceTeams, ButtonCopy, ButtonLobbySettings, ButtonInvite, ButtonReadyStart,
ButtonReturn, PlaySlideshows, PlayerIcon, PlayerIconButton, BorderIcon` all at **t=102.234..102.734**;
skirmish-only `CountDropdown` at **t=117.312**. `via=0x1ab4c59` at t=117.297 is therefore Skirmish.
(Widget-name sets per screen come from `widgetui/screen*.json`; `AssistBase`/`ButtonEaseGame` are in
BOTH host and skirmish, so they do not discriminate — an earlier read of the timeline used them and
was ambiguous.)

## 40e. THE ANSWER — the host lobby's populator, and the one gate hiding "AI"

**`0x141a344f0..0x141a362aa`** (7611 B, ENCRYPTED) is the host lobby's slot-dropdown populator.
Proof: it references `"Background/Data/GameSettings/GameDropDown"` (`0x143341b98`) at `0x141a358b8`,
and that exact path occurs **only** in `widgetui/screenmultiplayerlobbyhost.json`
(host=1, skirmish=0, client=0 — note the skirmish JSON has the *different*
`GameSettings/Data/GameDropDown`). Corroborating strings in the same function: `IDS_LOBBY_BAN_PLAYER`,
`IDS_MULTIPLAYER_MUTE_NARRATOR_TEXT`, `/EloLabel`, `/Medal`.

Item construction pattern (repeats per item): `new(0xC0)` (`0x142d6dc48`) → memset →
`ecx = <string id>; call 0x140ac5480` (localize by id) *or* `lea rcx,[<IDS_KEY>]; call 0x140ac54a0`
(localize by key) → `0x140acad40(item, text, 4, style)` → push into `[rbp+0x530]`
(`0x140aca990` grow path) → `0x140adbb30(dropdown, index, &list)`.

**Every label this function can emit:**

| site | label | id / key |
|---|---|---|
| `0x141a34c64` | "Player" | `0x23fd` = 9213 |
| `0x141a353b4` | mute narrator | `IDS_MULTIPLAYER_MUTE_NARRATOR_TEXT` |
| `0x141a35510` | "Open" | `0x25d5` = 9685 |
| `0x141a355cb` | "Closed" | `0x25d4` = 9684 |
| `0x141a3568b` | ban player | `IDS_LOBBY_BAN_PLAYER` |
| `0x141a35a41` | "Open" | `0x25d5` |
| `0x141a35ae0` | "Closed" | `0x25d4` |
| `0x141a35c5f` | "Open" | `0x25d5` |
| `0x141a35d1a` | "Closed" | `0x25d4` |
| **`0x141a35df9`** | **"AI"** | **`0x29625` = 169509** |

(`169509 "AI"` confirmed in `resources/en/strings/key-value/key-value-strings-utf8.txt`.)

**Three mutually exclusive blocks, and the AI item only exists in the third:**

- **Block A** (`0x1a354a8..0x1a3571d`): Open, Closed, Ban. Gated by
  `cmp r12,[rsi+0x5e0]; je skip` and `cmp byte[rsi+0x604],0; jne skip`.
- **Block B** (`0x1a35a1d..`): Open (only if `[rbp-0x7c]==1`, else jump to `0x1a35ac6` = Closed
  only), then Closed. **Taken when `ebx == 1`.**
- **Block C** (`0x1a35c3d..`): Open, Closed, **AI** (index `edx=4`, id `0x29625`).
  **Taken when `ebx != 1`** — `cmp ebx,1` at `0x141a35a0a`, `jne 0x141a35c3d` at `0x141a35a17`.

**Where ebx comes from** (`0x141a359bb..0x141a359ce`), `rsi` = the host lobby screen object:

```
mov  rdx, [rsi + 0x1cf8]        ; the KEY
lea  rcx, [rbp + 0x230]         ; out
call 0x140e83240                ; registry lookup, returns its own out-param
mov  ebx, [rax + 0xb0]          ; the gate value
```

**`[rsi+0x1cf8]` is the SAME field §39g item N4 flagged** as the row-lock gate
(`cmp [this+0x1cf8],[0x14326b258]` → `je` skips the locking; s36/s37/s38). So one field explains
BOTH symptoms: for our LAN lobby the rows lock AND `ebx == 1` so no AI is offered. For a normal
lobby the field equals the sentinel, the rows unlock themselves, and block C would run.
That is consistent with `13204 "NOT YET RANKED: There can be no AI Players in a ranked match"`.
**This is the highest-value lead in the project right now.**

**`0x140e83240`** (ENCRYPTED, 537 B, 60 callers) = keyed registry lookup, returns `rdi` (= its `rcx`
out-param). Mutex `0x143db0580` via `0x142d6cc2b`/`0x142d6cc31`; poisoned-guard
`[0x143db05cc] == 0x7fffffff`; two `std::map`-ish containers at `0x1442e18c8` and `0x1442e18d8`
probed with `0x1404ea1a0(container, &key)`; record array base `[0x1442e18b0]` with
`lea rdx,[rcx+rcx*2]; shl rdx,6` = **stride 0xC0**; copy `0x140e81690`; on miss a `"DEFAULT"`
record (`0x14321b960`) built by `0x140e82ba0` + `0x140e81740`.
**Unresolved:** the bound check at `0x140e83336` uses magic `0x2aaaaaaaaaaaaaab` + `sar 5` = /0x60
while the index math uses 0xC0. Do not blind-walk that vector until this is settled.

**Call chain into the populator, all ENCRYPTED, no clean caller anywhere:**
`0x141a3e730..0x141a40cd9` (9642 B — already dumped as `work/host_wake.txt`) → `0x141a43d50..0x141a4451a`
(1995 B, no strings) → `0x141a344f0` at `0x1a43f2e` and `0x1a43f88`; also
`0x141a26fa0..0x141a296a1` (9986 B) → `0x141a344f0` at `0x1a2802e`. Both top functions have no `E8`
callers (virtual).

**Clean callees of `0x141a344f0`** (candidate hook targets):
- **`0x140ac5480`** — localize-by-id, 29 B, 633 sites, **8 uses in this function**, 16-aligned,
  prologue `40 53 48 83 EC 20 8B D9`, `hook_len` = 6, no rip-relative ⇒ hookable. `ecx` = the
  string id, so `(caller, id)` identifies the exact item being built. **This is the measurement to
  make next.**
- `0x140ace7f0` — only 4 call sites, called at `0x141a3547f` with
  `rcx = [rsi + r12*8 + 0x2688]` = that slot's NameDropDown widget. Gives a widget, not the screen.
- `0x140aca990` (461), `0x140ace800` (300), `0x140ac54a0` (473), `0x140e8bbc0` (10 sites, but gets a
  local, not the screen).
- **No clean callee receives `rsi`**, so `this` cannot be read from a hook argument.

Not the populator: `UpdateLobbySettings` = `0x141abc6c0` (s32) builds
`Player<N>/NameDropDown` paths and grabs the `DropDownListBox`, but only sets the handicap `%d%%`
text (vtable `+0x128`), three `SetEnabled`-style vtable `+0x60` calls, then `0x141ac3be0`
(`/AssistBase`) and `0x141ac4220` (narrator text). It does not populate items. Its own gate is
`cmp byte[r12+0x1165],0` at `0x141abdafc`. `0x141a1b6e0..0x141a1ea60` (13185 B) is the other
multiplayer lobby slot function (`IDS_HELP_PLAYER_LEFT/JOINED/READIED`, `TeamEloLabel`) and emits
only Open/Closed — **zero** AI calls. Neither `0x141a344f0` nor `0x141a1b6e0` calls
`0x140bf3c30`, `0x140bf43c0`, `0x140d62260` or `0x14100b4c0`.

## 40f. Next session, in order

1. **N8 — confirm the gate with one run.** Add hook id 16 on CLEAN `0x140ac5480`, kind = a new
   "log string id" kind, filtered to `caller` in `[0x1a344f0, 0x1a362aa]`, logging `(caller RVA,
   ecx)` deduped and capped. Early-out on the caller test before anything else (633 call sites).
   Expected if the theory holds: `0x1a35a41`/`0x1a35ae0` (block B: Open, Closed) and **no**
   `0x1a35dfe`. If `0x1a35dfe` DOES appear, the gate theory is wrong and the AI item is being
   dropped downstream in the dropdown widget — change direction.
   Needs `HK_MAX` 16 → 20: `hookcore.h` `#define HK_MAX` **and** `hooks.asm`
   `g_TailTable QWORD 16 DUP(?)`. `g_Hits`/`g_HLines`/`g_Only`/`g_HState` are all `HK_MAX`-sized and
   follow automatically. `AOE2LAN_HOOKS=4,5,13,14,15,16`. The id parser already handles
   multi-digit ids and rejects ids ≥ `g_NHooks`.
2. **N9 — the fix, in preference order.**
   - (a) Set `this->field_0x1cf8` to the sentinel `[0x14326b258]`. Fixes the rows *and* the AI item
     at the source, and would let the s38 bit-0x4 suppression be retired. Blocked on obtaining
     `this` (= `rsi` in the populator). Getting it needs `hooks.asm` extended to capture
     callee-saved regs. **TRAP:** `ctx[19]` is the LIVE return-address slot `S`, and `ctx[20..]` is
     the CALLER's stack — HK_WSET scans `ctx[20..31]` and reads `ctx[25]`. Extra saves must go
     BELOW ctx: `sub rsp,80h` → `0C0h`, `lea rdx,[rsp+20h]` → `[rsp+60h]`, which keeps
     `ctx+0x98 == S` so every existing index stays valid. Then store rbx/rsi/rdi/rbp at
     `rsp+0x20..0x38` and read them as negative ctx indices.
   - (b) Patch the matched registry record's `+0xb0`. Blocked on the 0x60-vs-0xC0 stride question.
   - (c) Server-side in `loginsrv.c`: make the game build a normal online-style lobby instead of a
     LAN one so `field_0x1cf8` gets the sentinel. Biggest change and it cuts against PLAN §4.1, but
     §40e is the "reason" that section asks for.
   **Do NOT:** force `AOE2LAN_AIKIND` (40d — the table is already right); hook `operator new`
   `0x142d6dc48` to redirect the branch (12033 call sites, far too hot); patch any function listed
   as ENCRYPTED.
3. **N7 — M2, still ranked below the AI work by operator request.** A 2-human LAN match does not
   need AI. Note for when it happens: the host lobby session already fetches and stores the AI list
   at `session+0xee0`, so the sim-side plumbing may already be intact.
4. **Do not re-open the four-row fix** (s39c). R1–R4 stay unless a specific log line shows a new
   re-lock site.

## 40g. Traps recorded so nobody pays for them twice

- **RVA vs VA.** s39j's addresses (`0x1bf4f0`, `0xbf3c30`, …) are RVAs; `VA = 0x140000000 + RVA`.
  `0x1bf4f0` → `0x1401bf4f0`, **not** `0x141bf4f0`. `dz.py` silently prints nothing for an address
  below the dump base, which looks like "no such code" rather than "bad arithmetic".
- **Do not name a helper script `grp.py`** — it shadows the stdlib `grp` module that `pathlib`
  imports, and capstone fails with a confusing circular-import error.
- **Verify builds by parsing, not by grepping.** `work/verifydll.py` walks `g_Hooks` in the built
  DLL. Byte-greps for constants fail because MSVC folds them into displacements (the AI table base
  `0x4356760` + 0x28/0x30 appears as `0x4356788`/`0x4356790`) and puts static arrays in `.rdata`
  (the 7 `via` RVAs are one contiguous DWORD table at RVA `0x24938`). Same lesson as s39b.
  `dumpbin` lives at
  `C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe`
  and is not on PATH.
- `g_Hooks` lives in **`.data`**, not `.rdata` (it is non-const) — a section-filtered scan misses it.
- The launcher returns the `cmd.exe` PID, not the game's; find the real PID from the newest
  `logs/lanhook-<pid>.log`.
- The AISlotPick target is hot: 71,203 hits in 89 s (~800/s) because `0x140d62260` is a generic
  "current game-mode descriptor" accessor, not an AI-specific one. Dedup kept the log to 3 lines.
  Any future hook on it must keep the dedup + cap.
