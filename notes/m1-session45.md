# Session 45 — the parse path is all encrypted except one thunk; hook 18 + registry dump + payload ladder built and gated; cert auto-trust half-done

Supersedes `notes/m1-session44.md`. All addresses are VAs unless written `RVA`.
**NO GAME RUN THIS SESSION.** Everything below is either static reading, an offline
`srvtest`/`srvclient` measurement, or a build gate. Game exe untouched
(`affb19f03ca96965abf9e56775cab688`).

## 45a. Step 0 result — the cleanliness sweep is DONE, and it kills §44g Step 2(a)

`python work/clean_s45.py --s44f` (new file; on-disk `.text` vs `gametext.bin`):

- **CLEAN (hookable):** `0x1407db520` (hook 17 GLog), `0x14039b550`, `0x14039bb50`
  (two bond helpers — nothing uses them yet), and **`0x1407b66f0`, the MatchStartMessage
  factory thunk**. Its whole body is byte-identical on disk (pdata bounds
  `0x1407b66f0..0x1407b6707`, 24 B: `40 53 48 83 ec 30 48 8b d9 e8 … c3 cc`). It has
  **no direct callers** (`cx.py` → `[]`); dispatch reaches it through the runtime registry.
- **ENCRYPTED (never hookable):** dispatch `0x1407a7070`, envelope reader `0x1407a7620`,
  factory `0x1407cdf10`, parser #9 `0x1407b6710`, **all six member readers** (`0x14039c900`,
  `0x14057b600`, `0x14056cce0`, `0x1407d4300`, `0x1403e3dc0`, `0x1407d4490`), the helpers
  `0x14039a910` / `0x14039b340` / `0x14039b8e0` / `0x14039b7c0` / `0x14039b860` /
  `0x14039cc60`, and the polling fn `0x1406d1160`.
- **METHOD TRAP found here:** a fixed 48-byte compare says `0x1407b66f0` is "encrypted"
  because the window runs past the 24-byte function into the next (encrypted) one.
  **Compare over the pdata bounds, not a fixed window**, or a clean thunk reads as dirty.
- **Consequence:** §44g Step 2(a) ("hook a clean member reader or bond helper to name the
  failing member") is **impossible** — there is no clean one. Step 2(b), empirical payload
  binary-search, is the only H2 route. That is what got built.

**Registry shape CONFIRMED** from `work/f_dispatch.txt` (do not re-derive):
`0x1407a70a3 mov r14,[0x144c9e3e0]` (head is a POINTER to the first node) →
`0x1407a70c0 mov rax,[r14]` → `0x1407a70cc call rax` → `0x1407a7168 mov r14,[r14+8]`.
So fn at node+0, next at node+8, exactly as §44e said.

## 45b. What was built this session (all gated offline, none run in-game)

1. **Hook 18 `MSThunk` = `0x1407b66f0`**, `HK_RAW`, `grp=0` (opt-in through
   `AOE2LAN_HOOKS`). Increments `g_MSReached` (hookcore.c) and logs rcx/rdx/r8/r9 + the
   indirect call site. **Fired ⇒ MatchStartMessage IS registered and dispatch matched
   m_type ⇒ H2. Never fired while "failed to parse" appears ⇒ H1.**
2. **`registry_dump()` (loginsrv.c)** — one-shot, runs at push time (t~139, long after
   rlink init), reads `[g_ModBase()+0x4c9e3e0]` and walks up to 64 `{fn,next}` nodes under
   `__try`. Logs `MSREG head=`, `MSREG[n] node=… fn=…`, `MSREG nodes=`.
3. **The payload ladder** (loginsrv.c `ws_serve`). The shim and the hooks share a process,
   so the shim grades its own push: hook 13 increments `g_ParseFail` on every
   "failed to parse" line, hook 18 increments `g_MSReached`. Arm once on
   `g_MatchStart 1→2`, push a variant, wait 3 s, grade on the counter deltas, escalate.
   `msVar`: -1 idle, 0..2 next variant, 3 grading the last, 4 done. **Three runs collapsed
   into one.**
   - variant 0 = every member, **no trailing comma** (788 B offline)
   - variant 1 = envelope only: `result` / `m_type` / `m_profileID` (75 B)
   - variant 2 = envelope + `matchAdvertisement` (680 B)
   - no parse failure inside the window ⇒ that variant parsed ⇒ stop (no more pushes).
4. **`srvtest.c` now bumps `g_ParseFail` once a second.** Offline there is no hook 13, so
   without this the ladder grades variant 0 as "parsed" and stops after one push. That was
   the first `srvclient` FAIL this session — the ladder was right, the harness was blind.
5. **`srvclient.py`**: the trailing-comma assertion became a no-comma assertion, plus shape
   checks for variants 1 and 2 and a **termination** check (no 4th push in 6 s). The
   termination check needs a `time.time()` deadline, not a socket idle timeout: the server
   pings every ~3 s so the socket is never idle long enough to time out.
6. **`PLAY-stage8-VERBOSE.cmd`**: `AOE2LAN_HOOKS=4,5,13,14,15,16,17,18`; wait **~60 s**
   after Start, not 40. Dropping `,18` disables the new hook with no rebuild.

**MEASURED offline ladder trace** (`srvtest.log`, the shape the game run must produce):
`t=17.281 MSREG walk faulted` + `MSREG nodes=0` (expected offline: `g_ModBase()` is 0, so
the SEH guard caught it — that is the guard's proof) → `pushing variant=0` `len=788` →
`t=20.312 MSLADDER variant=0 parsefail=3 thunkHits=0` → `variant=1` `len=75` →
`t=23.328 variant=1` → `variant=2` `len=680` → `t=26.359 every variant rejected` → only
pings after that. **It escalates and it terminates.**

## 45c. Gates (current build — all re-runnable, all passed)

- `AoE2DE_s.exe` MD5 `affb19f03ca96965abf9e56775cab688` — unchanged.
- Staged `dbghelp.dll` MD5 **`350d6b6bdba952dd90e9ea9c03f3c8ba`**, identical in the game dir
  and `dev/lanhook/`. Backup taken BEFORE the first build: `.prev-s45-before` =
  `7a66dd36fe5dc3ac9e7c32aa0bd7c398` (the s44 build) in both places.
- `hooktest.exe`: `post-hook ok (21, 210, 2100, 6)`, `T7 ok (210, 6)`,
  `game-image iat walk: swapped 68 of 68`.
- `srvtest.exe 90` + `C:/Python314/python.exe -X utf8 srvclient.py`: **PASS**, including
  `updateState reply: matchState=1`, `MatchStartMessage push: 788B, matchState=1,
  members=1`, `ladder variant1 envelope-only: 75B`, `ladder variant2 envelope+advert: 680B`,
  `ladder terminated after variant2 (no 4th push in 6 s)`.
- `work/verifydll.py`: **19** HOOKDEF entries; `MSThunk va=0x1407b66f0
  exp=40 53 48 83 ec 30 48 8b wait=600000 grp=0 kind=0`; `GLog va=0x1407db520 … kind=7`.
- `dumpbin -DISASM` → `work/disasm-dll-s45.txt` (never a byte grep):
  `0x180012F33 mov rbx,qword ptr [rax+4C9E3E0h]` = the registry head read;
  `0x180007418 mov rax,1407B66F0h` = the `g_MSReached` va compare.
- Build warnings are pre-existing only (`loginsrv.c` C4090 at 674/676/678/1877/1908).

## 45d. Next session — ONE run, then read the log in this order

Launch: `powershell -NoProfile -ExecutionPolicy Bypass -File
"dev\lanhook\work\launch-detached.ps1" -cmdFile PLAY-stage8-VERBOSE.cmd`, wait ~27 s, take
the **newest** `logs/lanhook-<pid>.log` (the launcher returns the cmd.exe PID, not the
game's). **The certificate dialog STILL appears — click Yes/Install** (45e is unfinished;
clicking No kills login at ~t=18 and looks like a code failure, §44i). Healthy boot =
repeated `TLS: handshake complete (server side)` + `OnAccountEvent: Client is using
WebSockets`. Then Multiplayer → Host Game → 3 AI → Start → **wait ~60 s**.

Read, in order: `MSREG head=` / `MSREG[n] … fn=` / `MSREG nodes=`, `HIT MSThunk`,
`MSLADDER` (variant / parsefail / thunkHits per variant), and whether the map loads.

Decision table:

| observation | verdict | next |
|---|---|---|
| `MSREG` lists `0x1407b66f0` **and** `HIT MSThunk` fires | **H2** — registered, payload rejected | whichever variant stops the ladder names the fault: variant 0 ⇒ the trailing comma was the whole bug (match should load); variant 1 ⇒ a member other than `matchAdvertisement` is bad; variant 2 ⇒ one of `matchStartDate`/`ownedAppIDs`/`profileRaces`/`equippedItems`/`inProgressChallenges` |
| `MSREG head=0`, or no node holds `0x1407b66f0`/`0x1407cdf10`, and no `HIT MSThunk` | **H1** — not registered | find what populates `[0x144c9e3e0]`: xref the QWORD writers of RVA `0x4c9e3e0`, ignore the `0x1400974xx` dword-copy init block (noise), and check whether registration is gated on a mode we are not in |
| `MSREG` has the fn but `MSThunk` never fires while "failed to parse" does | dispatch walked past it | the m_type compare itself failed — check the envelope reader's `m_type` against the 17-char name at `0x14369ee08` |
| `MSLADDER PARSED - no failure logged` | that variant works | if the map still does not load, follow case 7's roster build at `0x140eec3b3` and the empty-roster path `0x140eec4a6` (§43f) and check `matchMembers` |
| game exits at ~5.6 s with a clean boot log | hook 18 tripped the tamper response despite being clean on disk | drop `,18` from `AOE2LAN_HOOKS` (no rebuild) and re-run; `MSREG` + the ladder still work |

Then Priority 2 (AI actually play — `session+0xee0` holds the AI list, §40d) and Priority 3
(second human over the tailnet, PLAN §W1-c/M2).

## 45e. Certificate auto-trust — the operator asked for it, it is NOT finished

**Goal:** no consent dialog, ever. **Why it clicks today:** `mint_cert()` generates a NEW
CSP container (`"aoe2lan-"` + 8 hex chars from `GetTickCount`) and a NEW self-signed cert on
**every launch**, and `RootRegThread`'s `CertAddCertificateContextToStore` on the user Root
store always prompts. So it is one click per run forever (and stale roots pile up —
`purge_aoe2lan_roots()` exists for that).

**Built:** `root_add_silent()` in loginsrv.c writes
`HKCU\Software\Microsoft\SystemCertificates\Root\Certificates\<SHA1 thumbprint>\Blob`
directly (no UI, no crypt32 consent path), and `RootRegThread` now tries it FIRST and only
falls back to the prompting API add if `root_present() != 1`. That ordering means the change
can only ever remove clicks, never lose trust. `RootRegThread` actually runs at BOOT
(right after `mint_cert`/`acquire_cred`, loginsrv.c ~2177) — the "deferred to first
connection" comment at line ~726 is **stale**.

**MEASURED (offline `srvtest`, no game):** `cert: silent-root CertSaveStore failed` and
`cert: silent-root Blob written bytes=0`, then the fallback ran and **a consent dialog did
pop during that offline test**. So the plumbing reaches the write and only the blob is wrong.

**MEASURED blob format** (read out of a real key,
`HKCU\…\Root\Certificates\49763A54F40547FD2787906347659D1525ED0AD5`): starts
`5C 00 00 00 01 00 00 00 04 00 00 00 00 08 00 00 19 00 00 00 …` and is crypt32's
**serialized-context-with-properties** format — `{propId, flags, size, data}` records:
prop 3 = the 20-byte SHA1 (= the key name), `0x0B` = friendly name (UTF-16), `0x14` = key
identifier (20 B), 7 = MD5 (32 B), `0x20` = a 32-byte SPKI hash, and a final record holding
the raw DER cert. **Not PKCS#7, not plain DER.**

**Probe written, NOT compiled, NOT run:** `dev/lanhook/work/certsave.c` — prints what
`CertSaveStore` yields for a memory store under four encoding combos plus what saving the
real user-Root store yields, so the formats can be compared directly. Writes nothing, cannot
pop a dialog. Build it like `mkprobe.cmd` does (host tool, may link `crypt32.lib`).
**sync.cmd copies `work/*.py` and `work/*.txt` but NOT `work/*.c`** — move `certsave.c` to
`dev/lanhook/` or it will never be committed.

Options, cheapest first, if `CertSaveStore` cannot emit that format:
- **(c) make the cert STABLE across runs** — fixed CSP container name + persist the DER
  (reuse `cert.der`, or `CryptAcquireContext` without `CRYPT_NEWKEYSET` when the container
  exists) so the click happens **once ever** instead of every run. Smallest real fix; needs
  no blob format at all. `purge_aoe2lan_roots()` needs no change (it only deletes
  same-Subject roots that are NOT byte-identical to ours).
- **(b) one elevated write** of
  `HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots\Flags = 1`
  (TurnOffUserConsent), which makes the normal API add silent. Machine-wide policy, needs
  admin. MEASURE it: time the add — under ~100 ms with no window means silent.
- **(a) hand-build the blob** from the measured layout above. Undocumented and fragile;
  last resort.

## 45f. Files added / changed this session

| file | what changed |
|---|---|
| `hookcore.h` | `extern volatile LONG g_ParseFail, g_MSReached;` (the ladder's two signals) |
| `hookcore.c` | defines both; HK_RDSTR increments `g_ParseFail` on a "failed to parse" line (reuses the s44 `contains_ci` result, so no second scan); the HK_RAW fallback increments `g_MSReached` when `g_Hooks[id].va == 0x1407B66F0` |
| `lanhook.c` | `EXP_MSTH` + hook 18 `MSThunk 0x1407B66F0 … grp=0 HK_RAW` (19 hooks, `HK_MAX` is 20) |
| `loginsrv.c` | `hx()` / `log_hex()`; `registry_dump()`; `build_match_start(BUF*, int variant)`; the `msVar`/`msAt`/`msFail0`/`msReach0` ladder in `ws_serve`; `root_add_silent()` + the silent-first `RootRegThread`; two forward decls at line ~158 |
| `srvtest.c` | idle loop bumps `g_ParseFail` 1 Hz (45b item 4) |
| `srvclient.py` | no-comma assertion, variant 1/2 shape checks, termination check with a deadline |
| `PLAY-stage8-VERBOSE.cmd` | hooks `…,17,18`; wait ~60 s; why-18-is-safe comment block |
| `work/clean_s45.py` | **new** — the cleanliness sweep (`--s44f` runs the whole §44f list) |
| `work/certsave.c` | **new, uncompiled** — the `CertSaveStore` format probe (45e) |
| `work/disasm-dll-s45.txt` | dumpbin of the s45 DLL |
| `dbghelp.dll` (both copies) | rebuilt → `350d6b6bdba952dd90e9ea9c03f3c8ba`; backups `.prev-s45-before` |

**Nothing was committed or pushed this session** (`sync.cmd` was not run). Everything above
is on disk in `D:\Age of Empires II Definitive Edition` only.

## 45g. Do NOT (new, on top of everything in §44h/§44i which still holds)

- Do NOT hook anything on the 45a ENCRYPTED list — dispatch, envelope reader, factory,
  parser #9, all six member readers, the `0x14039xxxx` helpers, the polling fn.
- Do NOT re-run a cleanliness check with a fixed byte window; use the pdata bounds (45a).
- Do NOT re-derive the registry node layout — `r14=[0x144c9e3e0]`, `fn=[r14]`,
  `next=[r14+8]`, confirmed at `0x1407a70a3` / `0x1407a70c0` / `0x1407a7168`.
- Do NOT change the ladder's stop-on-no-failure rule, add a 4th variant, or re-order the
  three, without a measurement that says to.
- Do NOT delete the `srvtest.c` 1 Hz `g_ParseFail` bump: without it the offline ladder stops
  after variant 0 and `srvclient` FAILS (45b item 4).
- Do NOT let `root_add_silent()` skip the `root_present()` re-check — that check is the only
  thing keeping the silent path from silently losing trust.
- Do NOT re-open anything in §44h / §43h.
