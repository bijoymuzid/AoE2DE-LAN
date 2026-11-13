# Linux session 5 (2026-11-11) — Create Lobby FIXED, lobbygate stack-collision FIXED, and why the 2nd-lobby Start stalled

**Bottom line.** Two bugs blocked Linux hosting and both are now fixed and verified live in `logs/lanhook-256-14226275.log`:
1. **"Creating Lan Server" infinite spinner FIXED (`iathook.c`):** `TComm_Matchmaking_RL::GetLocalRelayServerInfo` (`0x140ee9420`) compares the sender IPv4 of `BattleServer.exe`'s UDP 9999 beacon (`192.168.1.9`) against `0x140deabd0`, which calls `getaddrinfo(gethostname(), NULL, ...)`. On Linux/Wine, `/etc/hosts` resolves the machine hostname (`cachyos-x8664`) to `127.0.1.1`, so `127.0.1.1 != 192.168.1.9` and `0x140ee9420` returned 0 forever. `Hook_recvfrom` now records the sender IPv4 of any UDP 9999 beacon (`0x21 0x24 0x00`) into `g_LanBeaconIP`, and `Hook_getaddrinfo` redirects plain-hostname lookups to `g_LanBeaconIP`.
2. **`lobby_find` stack-collision crash FIXED (`lanhook.c`):** When `LobbyGateThread` scanned RW pages before `UIScreenMultiplayerLobbyHost` was constructed, `lobby_find(vt, sent)` matched its own stack frame (`vt` local variable), corrupting `stack+0x1cf8` and `stack+0x24f4` and crashing at t≈4 s. `lobby_find` now skips the current thread's stack region, requires `mbi.RegionSize >= (p - base) + 0x7df8`, and verifies the secondary subobject vtable at `[p+0x710] == g_Base + 0x32dd198`.

With both fixes deployed, the operator hosted a lobby on Linux, added 7 AI on the 2nd lobby entry, clicked Start, and reached the animated pre-match loading screen — where it stalled. The exact root cause of both the "AI only on 2nd lobby entry" and the "2nd-lobby loading screen stall" is now proven from `lanhook-256-14226275.log` and `gametext.bin`.

---

## 5a. Root cause 1 — Why the 2nd lobby stalled on the pre-match loading screen

In `lanhook-256-14226275.log`:
- **1st lobby host (`t=36.655s`):**
  - `POST /game/advertisement/host` had `connect_id=1194421069&sessionID=1194421069`.
  - `build_host_reply` returned `gatheringID: 1194421069` (echoing the client's `sessionID`, which is the login session ID).
  - At `t=36.795s`: `WorldwideAdvertisementService::Host` (`0x140351851`) set `[[g_Platform+0x1870]+0x8] = 1194421069` (the active BattleServer session ID) and connected to `BattleServer.exe` at `192.168.1.9:27012`.
- **Operator left 1st lobby (`t=548.039s`):**
  - `0x1402ffcb3..0x1402ffd94` (`Destroyed Matchinfo for sessionID 1194421069`) tore down the BattleServer session for `1194421069` and set `[[g_Platform+0x1870]+0x8] = -1` (`0x1402ffce2`).
  - At `t=549.292s`: the game sent `POST /game/advertisement/leave` with `advertisementid=1194421069`.
  - **Bug A in `loginsrv.c`:** There is no `/game/advertisement/leave` handler! It hit the catch-all and returned `[0,[]]`.
  - `WorldwideLeaveAdvertisementAsync` (`0x140339560`, vtable `0x143668cc0`) parses its response with a `{"result":0}` object reader. Because `[0,[]]` failed to parse, `0x140339a41` decremented its retry counter (`[job+0x2f0]`, initialized to `0x13 = 19` at `0x140339d5e`) and scheduled a retry every **10 seconds** (`lea rax, [rdi+0xa]` at `0x140339a47`), spamming `/game/advertisement/leave` for `1194421069` at `t=557s, 567s, 577s, ..., 647s, ..., 727s`!
- **2nd lobby host (`t=560.923s`):**
  - **Bug B in `loginsrv.c`:** The game's `POST /game/advertisement/host` always sends `sessionID=<login_session_id>` (`1194421069`) and `advertisementid=-1`. Because `build_host_reply` and `emit_advertisement` used `form_get(body, "sessionID")` as `gatheringID` / `id`, the 2nd lobby was assigned the **exact same session ID `1194421069`** as the destroyed 1st lobby!
- **Operator pressed Start in 2nd lobby (`t=643.063s`):**
  - `MatchStartMessage` was pushed at `t=643.931s` and parsed cleanly (`parsefail=0`, `MSLADDER PARSED`).
  - `AET_MatchStartNotify` (`0x140eec335`) called `0x140f10cc0` to send the final pregame host state packet and transition into the match.
  - Look at `0x140f10cfe..0x140f10d25` in `gametext.bin`:
    ```
    140f10cfe: call 0x1402ab8a0          ; rax = g_Platform ([0x144c9e5f0])
    140f10d09: call [rax->vtbl + 0x108]  ; 0x140415500 -> rax = [g_Platform + 0x1870]
    140f10d1c: call [rax->vtbl + 0x110]  ; 0x140539fc0 -> checks if session is connected!
    140f10d23: test al, al
    140f10d25: je   0x140f1128d          ; IF FALSE: SKIP "Sending final pregamehoststate packet." AND SKIP SendSyncPacketRawMemCopy!
    ```
  - And what does `0x140539fc0` check?
    1. `0x140356910`: scans active advertisements for `[adv+0x350] != 0` and checks if `[g_Platform+0x1880]->HasPeer([adv+0x358])` is true;
    2. Fallback `0x140539fdf`: reads `rdx = [[g_Platform+0x1870]+0x8]` and calls `[g_Platform+0x1880]->vtbl[0x140]` (`0x1402f0b80`), which looks up the session `1194421069` in `[g_Platform+0x1880]+0x70..0x78` and calls `0x1402cfb90` -> returns `movzbl [session+0x38]+0x2` (the connected byte).
  - Because `0x140539fc0` returned `0` (`al == 0`), `0x140f10d25` jumped straight to `0x140f1128d`: it **skipped** `"Sending final pregamehoststate packet."` and `SendSyncPacketRawMemCopy`, and **still** posted UI message `0x9` (`0x140f11261`) to `0x140d678c0`, which transitioned the UI to the pre-match loading screen with no simulation packets ever sent!

### Fix for Root Cause 1 (`loginsrv.c` + `iathook.c`)
1. **Add `/game/advertisement/leave` route in `loginsrv.c`:**
   - Reply with `{"result":0}` (same DTO shape as `peerAdd`/`peerUpdate`) and reset `g_MatchStart = 0` and `adv_set_state("0")`.
   - This stops `WorldwideLeaveAdvertisementAsync` from failing and retrying every 10 seconds.
2. **Mint a unique `gatheringID` per `/game/advertisement/host` call in `loginsrv.c`** (or check whether `emit_advertisement` + `build_host_reply` should use a monotonic `g_GatheringId` when `advertisementid=-1`, or keep `sessionID` on first host and increment on subsequent hosts):
   - Wait: verify how `update`, `updateTags`, `updateState`, and `peerAdd` use the ID returned by `build_host_reply`.
   - In `0x140334ae0` (host completion), the game copies `gatheringID` (`DTO+8`) into the advertisement as its ID, and then passes that ID as `advertisementid=<id>&sessionID=<login_sess>` in subsequent `/game/advertisement/update*` and `/game/party/peerAdd` calls!
   - Currently `build_host_reply` sets `gatheringID` from `sessionID` (because `advertisementid=-1` on `host`), and `emit_advertisement` sets `id` and `matchMembers[0].sessionID` from `sessionID`.
   - If `host` mints a fresh `g_CurrentAdvId` (or uses `sessionID + (++g_HostSeq)`), then `build_host_reply` emits `gatheringID = g_CurrentAdvId` and `yourMatchMembers[0].sessionID = g_CurrentAdvId`, and `emit_advertisement` emits `id = g_CurrentAdvId` and `matchMembers[0].sessionID = g_CurrentAdvId`!
   - Even simpler: once Root Cause 2 (below) is fixed, the operator won't *need* to leave the 1st lobby to get AI, AND fixing `/game/advertisement/leave` + `g_CurrentAdvId` makes re-hosting clean as well.
3. **Raise log caps in `iathook.c`:**
   - Raise `g_GlogLines` cap from `4000` to `50000`, `g_IatReqCap` from `900` to `10000`, and `g_IatRespCap` from `1400` to `10000` so runs longer than 300 s don't go blind on `glog:` or `SOCK` lines.

---

## 5b. Root cause 2 — Why AI was missing from the dropdown on the 1st lobby entry

Traced in `gametext.bin` (`0x141a3e730` -> `0x141a43d50` -> `0x141a344f0`):
- When the lobby screen (`UIScreenMultiplayerLobbyHost`) is entered the first time, `0x141a43d50` loops over the 8 player slots and checks the existing item count of each slot's `NameDropDown` widget via `call 0x140aded20` (`0x141a43f0e` and `0x141a43f68`):
  ```
  141a43f0e: call 0x140aded20   ; rax = NameDropDown item count
  141a43f13: test rax, rax
  141a43f16: jne  0x141a43f35   ; IF NON-ZERO: SKIP 0x141a344f0!
  ```
- On the 1st lobby entry, `0x141a344f0` runs synchronously on the main thread within microseconds of `[screen+0x1cf8]` being initialized to `-1` (`0xffffffffffffffff`) and `[screen+0x24f4]` to `0`, BEFORE `LobbyGateThread`'s 10 ms poll sees the transition.
- So the first synchronous pass of `0x141a344f0` populates `NameDropDown` with only 2 items (`Open` and `Closed`).
- A few milliseconds later, `LobbyGateThread` sets `[screen+0x1cf8] = 0` (sentinel) and `[screen+0x24f4] = 1`.
- However, on subsequent UI ticks of that 1st lobby, `0x141a43d50` sees `0x140aded20(NameDropDown) == 2 != 0`, so it **skips `0x141a344f0`**! And for the right-panel settings widgets, `0x141a3e730` only re-evaluates their lock state when a slot/ready update triggers a refresh.
- When the operator left the 1st lobby and hosted a 2nd lobby, `UIScreenMultiplayerLobbyHost` (`0x4947d300`) was reused in place while `LobbyGateThread` was already holding `+0x1cf8 = 0` and `+0x24f4 = 1`, so the 2nd lobby's initial `0x141a344f0` pass saw the unlocked fields immediately and added `AI`!

### Fix for Root Cause 2 (`lanhook.c`)
1. **Why `lobby_find` missed `UIScreenMultiplayerLobbyHost` at boot until `t=36.435s`:**
   - Look at `UIScreenMultiplayerLobbyHost`'s constructor (`0x141a23880` -> `0x141a238f0` -> `0x141a23520`):
     - `[screen+0x1608]` is a subobject of size `0xee0`, and `[screen+0x1cf8]` is `[subobj+0x6f0]`.
     - At boot construction (`0x140e6f820` / `0x141a23520`), `[screen+0x1cf8]` is **NOT** `-1` or `0` until the lobby is actually entered at `t=36.358s`!
     - Because `lobby_find` had `if (cur != (DWORD64)-1 && cur != sent) continue;`, the 1 Hz boot scan skipped the pre-created `UIScreenMultiplayerLobbyHost` (`0x4947d300`) for the entire 36 seconds at the menu, and only matched it on the next 1000 ms tick (`t=36.435s`) — **77 ms after** Create Lobby was clicked and after `0x141a344f0` had already populated `Open`/`Closed`!
   - Now that `lobby_find` already verifies THREE exact structural invariants:
     1. `[p+0x000] == g_Base + 0x33416e0` (`LOBBY_VT_RVA`),
     2. `[p+0x710] == g_Base + 0x32dd198` (`LOBBY_SUBVT_RVA`),
     3. `mbi.RegionSize >= (p - base) + 0x7df8` and not on current thread's stack,
     we do **not** need `cur == -1 || cur == sent` in `lobby_find`! Removing that filter lets `lobby_find` lock onto `UIScreenMultiplayerLobbyHost` at **t≈1 s at boot** and hold `+0x1cf8 = sent` and `+0x24f4 = 1` on a 10 ms cadence long before the user ever clicks Create Lobby!
2. **Belt-and-suspenders in `lobby_apply`:**
   - In `0x141a43f08` / `0x140aded20`:
     - For each slot `i in 0..7`, `row = [screen + 0x2688 + i*8]`, `dd = [row + 0x4a0]` (`NameDropDown`), and `0x140aded20(dd)` returns `([dd+0x5a8] - [dd+0x5a0]) >> 3` (the `std::vector` item count of `NameDropDown`).
     - If `lobby_apply` ever catches a transition where `[screen+0x1cf8] != sent` or `[screen+0x24f4] != 1`, it can also check if `([dd+0x5a8] - [dd+0x5a0]) >> 3 == 2` (only `Open`/`Closed`) and set `[dd+0x5a8] = [dd+0x5a0]` so the very next UI tick sees item count `0` and re-runs `0x141a344f0` to populate `AI`!
