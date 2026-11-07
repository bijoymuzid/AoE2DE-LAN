# Session 41 — AI in the host lobby dropdown WORKS; Start is accepted; the match stops at `/game/party/peerAdd`

Supersedes `notes/m1-session40.md` for everything below. All addresses are VAs unless written
`RVA`. Everything marked MEASURED came from live runs `logs/lanhook-5064.log` (run 1, read-only),
`logs/lanhook-10268.log` (run 2, first fix) and `logs/lanhook-8264.log` (run 3, current fix);
everything else was read from `dev/lanhook/gametext.bin` (decrypted `.text`) cross-checked against
`AoE2DE_s.exe` and `widgetui/*.json`. Game exe untouched. **Code changes this session: `hooks.asm`
now snapshots callee-saved registers, `HK_MAX` 16→20, and one new hook, id 16 `AISlotLabel`.**

## 41a. Result, up front

- **Priority 1 DONE.** "AI" now appears in the multiplayer host lobby's slot dropdown, in all seven
  empty slots, verified on screen by the operator and in the log (`id=0x29625` at site `0x1a35e03`,
  seven times per lobby build).
- **The Start button now works.** No error message. The log shows `Match Started - [3842241165083521967
  AnkerGames], slot = 0`, `WorldwideAutomatchService::OnStartComplete - detected successful game
  start`, and `/game/advertisement/updateState` with `state=1`.
- **Priority 2 NOT reached: the match does not come up.** It is not an AI problem. The game then asks
  our fake server to add party peers and rejects the reply:
  `WorldwideOnPartyPeerAddAsync - response was not formatted correctly: [0,[]]` (t=57.4).
  `/game/party/peerAdd` and `/game/party/peerUpdate` have no handler in `loginsrv.c` and fall into the
  catch-all `[0,[]]` (`loginsrv.c:1649-1652`). Without a peer list the simulation never assembles.
  This is PLAN §W1-d / M2, the same class of gap as `LeaderboardStatsCache`, `NewsCache`,
  `ChatChannelCache`, `ItemCategoryCache`, `GetOfflineMessagesAsync`, … — 19 distinct caches log the
  same warning in one boot.

## 41b. Gates

- `AoE2DE_s.exe` MD5 `affb19f03ca96965abf9e56775cab688` — unchanged.
- `hooktest.exe` PASS, `game-image iat walk: swapped 68 of 68`, `post-hook ok (21, 210, 2100, 6)`.
  `srvtest.exe` PASS.
- Staged `dbghelp.dll` MD5 **`a4ab2ba4c4e9d69db27195b4cad2fc6b`**, **247,296 B**, identical in the game
  dir and `dev/lanhook/`. Backups, in order: `.prev-s41-before` (= the s40 build
  `f499bbd13a4e838f4f6b8c37267d27f4`), `.prev-s41-readonly` (= the read-only id-16 build
  `09fd1423a94a514fed366ea5c2c29adc`), `.prev-s41-aigate1` (= the one-shot-write build
  `a4340466b10f3dcd9d2a7323ef584e8a`).
- `work/verifydll.py` silently dropped the new table entry: its `kind not in (0,1,2,3,4,5)` filter
  predates `HK_LOCID 6`. Fixed. **Any new kind must be added there too.**
- Launch used: `powershell -NoProfile -ExecutionPolicy Bypass -File
  "dev\lanhook\work\launch-detached.ps1" -cmdFile PLAY-stage8-AIGATE.cmd`. Boot log confirms
  `hook filter: only 4:LogHelper,5:LogHelper2,13:LogWarn,14:WidgetSetEn,15:AISlotPick,16:AISlotLabel`
  and `installed AISlotLabel n=6`.

## 41c. §40e's gate theory is WRONG — the populator already runs block C

MEASURED (run 1, read-only). Every item the host lobby built came from **block C**:

| site | label | id |
|---|---|---|
| `0x1a35c64` | Open | `0x25d5` |
| `0x1a35d1f` | Closed | `0x25d4` |
| `0x1a35e03` | **AI** (only after the fix) | `0x29625` |

Sites `0x1a35a41`/`0x1a35ae0` (block B) never fired. So `ebx != 1` already, the registry record's
`+0xb0` is not 1, and §40e's "ebx == 1 gives no AI" is dead. Block A's sites (`0x1a34c69` "Player",
`0x1a35510`/`0x1a355cb` Open/Closed, and the by-key `0x1a353bb`/`0x1a3568b`) never fired either, so
**the earliest hook point inside a real pass is `0x1a35c64`**.

What actually gates the AI item is *inside* block C — two checks, and **both failed**:

```
141a35db1  mov  rax, [0x14326b258]        ; the "sentinel"
141a35db8  cmp  [rsi+0x1cf8], rax         ; MEASURED field = 0xffffffffffffffff, sentinel = 0
141a35dbf  jne  0x141a3601e               ; -> skips BOTH the AI item and the name loop
141a35dc5  cmp  byte [rsp+0x30], 0        ; MEASURED arg4 = 0
141a35dca  je   0x141a35e97               ; -> the name-list branch instead of one "AI" item
141a35dd0  ... new(0xC0) / memset / ecx=0x29625 / call 0x140ac5480 / 0x140acad40(item,text,4,style)
141a35e72  call 0x140adbb30(r15=dropdown, edx=4, &vec, 0)   ; AI lands at dropdown index 4
141a35e92  jmp  0x141a3601e
141a35e97  <arg4==0 branch: one item per entry of the vector [rsi+0x588..0x590], label from
            entry+0x10 via 0x140a16ef0, inserted at index rbx+4, rbx starting at 0>
```

**The sentinel is a null pointer.** `[0x14326b258]` is in `.rdata` (RVA range `0x3197000..0x3da60a8`,
section characteristics `0x40000040` = read-only), its on-disk value is `00 00 00 00 00 00 00 00`, and
**`.reloc` has no entry at that RVA** (verified by walking all 1274 reloc pages; the 25 vtable slots
immediately below it at `0x14326b180..0x14326b240` DO have type-10 DIR64 relocs, so the walk is
sound). No `mov [rip+x],reg` and no `mov qword [rip+x],imm32` store to it exists in `.text`. It reads
as an `extern const` null in another TU. Runtime MEASURED: `sent=0x0`. Corroborating: `0x141a2e917`
does `mov rdx,[rbx+0x1cf8]; test rdx,rdx; je …` — an explicit null check on the same field before the
same registry lookup — and `0x141a2e8d7` compares it to a zeroed `r12`.

So the gate is **`screen->field_0x1cf8 == 0`**, and our lobby carries **-1**.

## 41d. The same field is the Start button's gate — three doors

The single `lea` xref to `"IDS_LOBBY_SCREEN_ERROR_UNEVEN_PLAYERS"` (`0x143341be8`) is at `0x141a3ca0f`,
inside **`0x141a3c700..0x141a3ce53` = the Start Game handler**. `rsi = rdx =` the screen, `r12 = 0`
(`xor r12d,r12d` at `0x141a3c738`):

```
141a3c88d  mov rax,[0x14326b258] ; cmp [rsi+0x1cf8], rax
141a3c89b  je  0x141a3cd7c            ; DOOR 1: field==0 -> skip every check, go start the match
           ; DOOR 2 (field != 0): loop slots 0..7 over [rsi+0x1d98 + i*0xd0]
141a3c8d6    call 0x141a12820         ; copy the slot descriptor (ENCRYPTED)
141a3c8e1    call 0x140e74a60         ; CLEAN, 3 bytes: mov eax,[rcx]; ret  -> slot status
141a3c916    cmp ebx,2 ; jne skip     ; count ONLY status==2 slots, counts[team]++
141a3c980    add ebx,[rax] …          ; bl = total counted
141a3ca06    test bl,1 ; je 0x141a3cb2b ; else UNEVEN_PLAYERS  ("even number of players")
141a3cb2b  cmp r14d,1 ; je 0x141a3cd7c  ; r14d = registry record +0xb0; ==1 -> start, skip balance
           ; DOOR 3: idiv edi (edi = record +0xb4); biggest team > total/edi ->
141a3cb6a    "IDS_LOBBY_SCREEN_ERROR_UNBALANCED_TEAMS" (0x143341c10)
141a3cd7c  <the real start work: 0x141a49640(screen), then [0x1442c5ca8] (the MP service) via
            0x140e16510 / 0x140809860 / 0x140e16500 / 0x14145bdd0>
```

**Slot status values, MEASURED from the decoded `slotinfo`:** `0` = human member, `1` = empty,
`2` = AI. So door 2 counts **AI slots only** — the human host is not counted. "You must have an even
number of players in the lobby" therefore means *an even number of AI*, which is why 3 AI and 7 AI both
failed. A normal lobby never reaches door 2 at all, because its field is 0.

`slotinfo` decode recipe (worked, worth keeping): the `/game/advertisement/update` request body is
split across `HTTP BODY` / `HTTP BODY +` log lines — join the `+` continuations FIRST (the plain
regex also matches `+` lines and will shred the body), URL-decode, base64-decode, `zlib.decompress`.
Result: `"<n>,[ {profileInfo.id, stationID, teamID, factionID, raceID, rankLevel, rankMatchTypeID,
timePerFrameMS, isReady, status, metaData}, … ]"`; `metaData` is base64 of base64 of a binary
key/value blob whose strings are `ScenarioPlayerIndex` and `Team`. Empty slots carry `metaData`
`"AA=="`. All our AI slots had `teamID 0`, so door 3 would have fired next even with an even AI count.

## 41e. The field does not stay written — 17 repairs in 125 ms

Run 2 wrote the sentinel once, from the populator pass at t=66.5. The rows were still being
force-locked at **t=93.4** (`HIT WidgetSetEn … SUPPRESSED`, and the s38 suppression only fires when
bit 0x4 is being SET, which the locker at `0x1a2cd01` does only when `field != sentinel`). So the lobby
restores -1 on refresh. Run 3 MEASURED it directly: `keepgate: field -1 -> 0, fix #1…#16` between
t=56.657 and t=56.782, then `17 fixes, further fixes not logged`.

**Who writes -1 is UNRESOLVED.** There is no `mov [reg+0x1cf8],reg` store anywhere in the MP UI region
— the only three such stores in the whole `.text` are `0x14099f3a2` (a constructor zeroing a run of
fields `0x1cd0..0x1d00`), `0x1409a02bf` and `0x1409a4a54` (a COM-style destructor: `mov rcx,[rbx+0x1cf8];
test rcx,rcx; mov rax,[rcx]; mov edx,1; call [rax]; mov [rbx+0x1cf8],rsi(=0)`), all a different class.
The likely route is the generated property-thunk farm: `0x1430301cc` is
`lea rcx,[rdx+0x1cf8]; jmp 0x142b99b80`, sitting in a repeating `{lea rcx,[rdx+off]; jmp A} /
{mov rcx,[rdx+0x80]; jmp B}` pattern for offsets `0x1c38, 0x1cf8, 0x1d98, 0x1e18`. Nothing references
`0x1430301cc` statically — no absolute qword, no 32-bit RVA, no `E8` call — so it is reached through a
table built at runtime. **Do not hunt this again unless the keepgate proves insufficient**; outvoting
the writer works and is measured.

## 41f. What was built

1. **`hooks.asm` — callee-saved snapshot** (§40f item 2(a), the trap was real and is now handled).
   `sub rsp,80h` → `sub rsp,0C0h`; `rbx/rsi/rdi/rbp` stored at `[rsp+20h..38h]`; xmm0-5 moved to
   `[rsp+60h..0BFh]`; `lea rdx,[rsp+60h]`. Because `0xC0` and the old `0x80` differ by a multiple of
   16, `ctx+0x98` is still the live return-address slot and `ctx[20..]` is still the CALLER's stack,
   so **every existing ctx index is unchanged and HK_WSET needed no edit**. New: `ctx[-8]=rbx,
   ctx[-7]=rsi, ctx[-6]=rdi, ctx[-5]=rbp`. `g_TailTable QWORD 20 DUP(?)`, `HK_MAX` 16→20.
   Verified in the built DLL with `dumpbin -DISASM`, not by grepping bytes: thunk at `0x180007C20`,
   `lea rdx,[rsp+60h]`, tail jump `jmp [r11+r10*8]` with `g_TailTable` at RVA `0x3D560`.
2. **Hook id 16 `AISlotLabel`**, kind `HK_LOCID 6`, target **CLEAN** `0x140ac5480` (localize-by-id,
   29 B, 633 call sites, 16-aligned, prologue `40 53 48 83 EC 20 8B D9` = `push rbx; sub rsp,0x20;
   mov ebx,ecx`, `hook_len` 6, no rip-relative). First statement is the caller filter
   `caller < 0x1a344f0 || caller > 0x1a362aa` — early-out before anything else. Logs
   `site id screen field sent arg4 slot frame=ok|BAD`, deduped on those, cap 256, first 20 s skipped
   for logging only. `arg4` is read at `frame-0xd0`: the populator's `rsp == rbp-0x100` and the byte
   lives at `[rsp+0x30]`. **`[rsp+0x30]` is touched exactly twice in the whole 7611-byte populator** —
   the `r9b` store at `0x141a34529` and the gate at `0x1a35dc5` — so forcing it cannot affect anything
   else. `frame=ok` is a real self-check on both captured registers: it re-derives
   `[[screen + slot*8 + 0x2688] + 0x4a0]`, the chain the populator itself validated at `0x1a34542`.
3. **The writes**, all behind `AOE2LAN_AIGATE=1` (unset = pure logging, which is how run 1 was taken):
   - hook 16 writes `sentinel` into `screen+0x1cf8` and `1` into `[rbp-0xd0]`, at the block-C "Open"
     call — *before* the AI gate in the same pass, so all seven slots get the item in one build.
   - hook 14 (`WidgetSetEn`, ~6000 hits/s in a lobby) calls `lobby_keepgate()`, which re-asserts the
     sentinel using the screen pointer hook 16 captured. Guards: only ever writes the sentinel, only
     when the field is **exactly** -1, only after `[[screen+0x2690]+0x4a0]` still resolves, and it
     drops the cached pointer if any read faults. `g_LobbyScreen` is only ever set when AIGATE=1, so
     it doubles as the on/off switch. First 16 repairs are logged, then one capped line.
   - `aigate()` reads the env var once and logs which mode is live.
4. **`PLAY-stage8-AISLOT.cmd`** = run 1 (read-only, `AOE2LAN_HOOKS=4,5,13,14,15,16`).
   **`PLAY-stage8-AIGATE.cmd`** (new) = the fix (adds `AOE2LAN_AIGATE=1`). Default stage-8 hooks
   unchanged: 4, 5, 13.

## 41g. MEASURED — run 3, the fix

- t=56.1 `starting LAN hosting`; t=56.58 `starting local hosting`, `EVENT_NEWPEER`,
  **`hosting - Session is connected`**; t=13.7 `Adding LAN relay server: 192.168.0.101, GUID
  e6a12a8f-bdba-4af9-8aa2-4d595881ef53`. `BattleServer.exe` was spawned and alive (PID 1128).
- t=56.657 the populator pass: `WROTE-field WROTE-arg4` on slot 1, `WROTE-arg4` on slots 2-7
  (slot 1's write is what the rest inherit), and `site=0x1a35e03 id=0x29625` for every slot.
- t=56.657-56.782 `keepgate` repairs #1-#16.
- t=120.6 `WidgetSetEn … name="ButtonStart" old=0x4 new=0x0` — the Start button unlocking itself.
- t=126.75 `WorldwidePartyService::SetMatchState - state 1 - updating server`; t=128.36
  `/game/advertisement/updateState … state=1`; t=128.469 `OnStartComplete - detected successful game
  start`, `Match Started - …, slot = 0, ranking = 0`.
- **Then nothing.** t=178.3 `MessageCounts: inval=0/0, seek=0/0, join=0/0, ichk=0/0, sk_r=0/0, deny=` —
  the relay saw zero joins and zero integrity checks. UDP only: `recv from 192.168.0.101:27012` (903 B)
  and a LAN-advertisement packet containing the GUID above plus `"My Serv…"`. The game sits in the
  lobby; the screen never changes. Operator confirmed: "nothing happened".
- The blocking warning, t=57.36: `LogWarn "%s - response was not formatted correctly: %s"` with
  `s8="WorldwideOnPartyPeerAddAsync"`, `s9="[0,[]]"`.

## 41g2. MEASURED — run 4, the no-AI control (`logs/lanhook-17168.log`)

Same DLL, same switches (`PLAY-stage8-AIGATE.cmd`), **zero AI in any slot**. Result: identical failure.

- t=55.703 `WorldwideOnPartyPeerAddAsync - response was not formatted correctly: [0,[]]` — during
  lobby creation, before any AI exists.
- t=63.781 `SetMatchState - state 1`; t=64.484 `WorldwideOnPartyPeerUpdateAsync - response was not
  formatted correctly: [0,[]]`; t=65.375 `/game/advertisement/updateState`; t=65.484
  `OnStartComplete - detected successful game start`, `Match Started - …, slot = 0`.
- t=115.344 `MessageCounts: inval=0/0, seek=0/0, join=0/2, ichk=0/0, sk_r=0/0, deny=` — two join
  attempts, none accepted. No map, no loading screen (operator confirmed).
- **No `AISlotLabel` and no `keepgate` lines at all**: with no AI selected the populator never ran, so
  `g_LobbyScreen` was never armed and the field stayed -1. Start was still accepted, because with 0 AI
  the door-2 count is 0 (even) and the door-3 balance test is `0 <= 0`. So this run does NOT test the
  keepgate; it only proves the load failure is AI-independent.

**Conclusion: `/game/party/peerAdd` (+ `peerUpdate`) is the sole blocker between "Start accepted" and a
running match, and it has nothing to do with AI.** Both endpoints fall into `loginsrv.c`'s catch-all
`[0,[]]` (`loginsrv.c:1649-1652`); neither is named anywhere in the file.

## 41h. Next session, in order

1. **N10 — `/game/party/peerAdd` (and `peerUpdate`) in `loginsrv.c`.** This is the single blocker
   between "Start accepted" and a running match, and run 4 (§41g2) proved it is AI-independent.
   **It is testable WITHOUT the game**: `srvtest.exe` starts loginsrv on `127.0.0.1:443` and idles
   60 s while `C:/Python314/python.exe -X utf8 dev/lanhook/srvclient.py` (stdlib only) does the TLS
   handshake with SNI `pb-live-release6-api.worldsedgelink.com` and POSTs requests at it — that is how
   the login object-form reply was developed in s12/s21. Add a peerAdd case to `srvclient.py` and iterate
   offline; only spend a game run once the offline reply is shaped.
   Method that already worked once: find the parser the cache uses (s30 did this for
   `/game/advertisement/host` → parser `0x140579020`, which wants `result` + `updatedAvertisement`;
   s12/s21 did it for login → parser `0x140615b70`, named keys not a positional array), then emit
   exactly those fields. Entry point: the warning string `"%s - response was not formatted correctly:
   %s"` is logged through `0x1402BCC00` (hook id 13, already installed) and the *cache name* is `s8`,
   so the caller of that log line is the peerAdd completion handler — xref it and read the parse. Note
   `ret=0x00007ff648…` in those lines is a heap address, not a code RVA, so recover the caller from the
   frame the way HK_WSET does (`ctx[25]`), not from `ret`.
2. **N11 — after peerAdd, re-test with AI.** Expect the loading screen and a running skirmish. Then
   check the AI actually play (they are host-side simulation, so no extra networking should be needed).
   `session+0xee0` already holds the AI list (§40d), so the sim-side plumbing is probably intact.
3. **N12 — retire the s38 bit-0x4 suppression?** Now that the field is held at 0, the locker at
   `0x1a2cd01` should compute `dl=0` (enable) by itself. NOT VERIFIED — the operator did not report on
   the rows in run 3, and the suppression is still armed, so it may be masking the result. Test by
   running `AOE2LAN_HOOKS=4,5,13,15,16` (no 14) … but 14 is also the keepgate carrier, so instead test
   by temporarily neutering only the suppression block, not the hook. **Do not remove it until a run
   shows the rows unlocked without it.**
4. **N7 — M2 with a second human**, still below the AI work by operator request.

**Do NOT:** chase who writes -1 (§41e — outvoting it works); force `AOE2LAN_AIKIND` (§40d); hook
`operator new 0x142d6dc48`; patch or hook anything listed as ENCRYPTED (`0x141a344f0`, `0x141a3c700`,
`0x140e83240`, `0x141a12820`, `0x141a307e0`, `0x140adbb30`, `0x140acad40`); re-open the four-row fix.

## 41i. Traps recorded so nobody pays for them twice

- **A launch died at t=3.64 s** right after `cert: purged stale roots=1`, with 256 log lines and no
  hook activity — the boot log was byte-identical to the good run's first 256 lines apart from pointers
  and Windows cert-store enumeration order. Relaunching the same DLL worked and ran for minutes. No
  new hook can execute before t=20 s (the `WidgetSetEn` boot-window skip), so it was not the build.
  **Treat a sub-5 s exit with a clean boot log as a transient and relaunch before debugging.**
- **`build.cmd` copies over the game-dir DLL with no backup, and Windows locks the file while the game
  runs** — the copy silently fails, leaving the dev-dir and game-dir DLLs different. Always
  `md5sum` both after a build (they matched here), and always close the game first.
- `ctx[-8..-5]` are only valid because the snapshot is taken at the *hooked function's entry*, before
  it pushes anything. For `0x140ac5480` the first instruction is `push rbx`, so `rsi` at entry is the
  CALLER's `rsi` — which is exactly the populator's screen pointer. A target that reassigns a
  callee-saved register before the hook point would break this.
- `dz.py` prints nothing for an address below the dump base and happily disassembles mid-instruction
  when given a non-boundary start (`0x141a40040` produced pure garbage; `0x141a3c700` from `fn.py`
  bounds was clean). Start from a `fn.py` bound, not a guess.
- `0x140e74a60` is CLEAN but only 3 bytes (`mov eax,[rcx]; ret`) — `hook_len` needs ≥5 and the
  mini-LDE rejects `C3`, so it is not hookable despite being on the hot path.
- The registry lookup `0x140e83240` takes its key **by value** and never dereferences it (it is used
  in `cmp [node+0x20], rcx` map comparisons; miss → the `"DEFAULT"` record at `0x14321b960` built by
  `0x140e82ba0` + `0x140e81740`). So writing 0 into the field is safe to pass through it. §40e's
  unresolved 0x60-vs-0xC0 stride question is still open (`0x140e83336` bounds with `/0x60` while
  `0x140e83383` indexes with `*0xC0`) and did not need answering.
