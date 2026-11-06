# Session-30 — the LAN switch is real and it is already offered

Supersedes `notes/m1-session29.md` for state. Everything below is MEASURED unless the line says
INFERRED. No game file, no `.text` byte, no XAML was changed. The only code change is a read-only
readout added to `dev/lanhook/lanhook.c` (`rules_probe`).

## 30a. Offline gates (re-run, pass)

- `hooktest.exe` **68/68** (`game-image iat walk: swapped 68 of 68`).
- `srvtest.exe` + `srvclient.py` **PASS** (`leaderboards reply: object, 1 entry`).
- `AoE2DE_s.exe` crc **`4f533b6c`** — untouched.
- `dbghelp.dll` rebuilt from unchanged sources this session: crc **`579ed184`** (217,088 B). The
  bytes differ from s29's `06472804` only because a rebuild is not bit-reproducible; the source is
  the same plus the readout in 30c.

## 30b. MEASURED: the create-lobby Server dropdown already offers the LAN entry

Operator, in the live game (pid 17444), opened Multiplayer → Host Game → Create Game:

| control | contents |
|---|---|
| **Server** dropdown (`Background/Settings/RegionAnchor/RegionDropDown`) | `Default`, `LAN`, **`Use Local Lan Server`** |
| **Lobby Type** dropdown (`.../LobbyTypeAnchor/LobbyTypeDropDown`) | `Public`, `Private` |

So the LAN door is not hidden behind a flag we have to flip: the game offers it, on this install,
with our login shim in place. The s29 lead was right about the string and wrong about the widget —
the item is appended to the **Server/Region** dropdown, not the Lobby Type one.

## 30c. MEASURED: the code path, and the check that gates it

`0x1418eee60` (1032 B) is the function that fills that dropdown:

1. `0x140ac4090("Background/Settings/RegionAnchor/RegionDropDown")` → `0x140ab0660("DropDownListBox")`.
2. Loop over the item vector at `[0x1442dc4f0]+0x2628 .. +0x2630`, **stride 0x50**, one listbox item
   per record (`0x140acad40` builds the 0xc0-byte item, `0x140adbb30` appends it).
3. Then, at `0x1418ef107`: `rcx = [[0x1442dc4f0]+0x2e8]`, `call [[rcx]+0x418]`, and **only if the
   result is non-zero** it appends one more item, text key `IDS_LOBBY_CREATE_USE_LOCAL_LAN_DROPDOWN_ITEM`
   (`0x143322df0`, string id 300414 = `"Use Local Lan Server"`), at index `-1` (append).

The gate function is **`0x140f0f5c0`** (44 B):

```
mov rcx, [rcx+0x31e0]      ; null -> return false
call qword ptr [0x143197998]   ; (obj, 0)
cmp eax, 0x102
sete al
```

Read-only probe added to `rules_probe()` (same `AOE2LAN_RULES=1` flag, nothing written):

```
rules: svc slot+0x418 fn = game+0x0000000000f0f5c0
rules: svc slot+0x418 LAN item gate = 257        (low byte = 1 -> true)
rules: root dropdown item count (0x50) = 2
```

identical at t=25/40/70 s. `2` records + the appended LAN item = the three entries the operator saw.
The gate is **true on this install**, which is why the entry is there.

Note on the probe value: the function returns `char` in `al`; the readout prints the whole `eax`, so
`257` means `al = 1`. Read the low byte, not the number.

## 30d. What is still open

1. **Does selecting `Use Local Lan Server` change the host mode?** Host mode lives at
   `[advertSvc+0x1a8]`: 0 = online, 2 = offline, anything else = LAN (`0x140351343`, log lines
   `0x14367ee40/58/78`). s29 measured `starting online hosting` and then a silent failure. The test
   is one click: Server = `Use Local Lan Server`, then Create. The log must say **`starting LAN
   hosting`** instead of `starting online hosting`.
2. If it does, the next question is whether a lobby appears and whether the relay is addressed at
   the tailnet IP. The relay the game starts is `BattleServer\BattleServer.exe`; in this run the
   client logged `Adding LAN relay server: 192.168.0.104, GUID 134b56f5-…` at t=14.4 s, i.e. the
   relay is discovered on the machine's LAN address, not loopback.
3. The online host path (s29j) stays unexplained and is now the *fallback*, not the main road: no
   advertisement request is ever sent, and `WorldwideHostAsync`'s failure log never fires.

## 30e. Tooling notes

- `xr.py` was reliable this session for `.rdata` string xrefs; the one `<unconfirmed>` hit
  (`0x142f1a651`) is in a data blob, not code.
- `fn.py <addr>` gives pdata bounds; `fn.py <addr> --dump` disassembles the whole function from
  `gametext.bin`. Both were enough to read `0x1418eee60` and `0x140f0f5c0` without Ghidra.
- The `.rdata` string table is read from `AoE2DE_s.exe` directly (not `gametext.bin`, which is
  `.text` only). `widgetui/stringreference.json` maps key name → string id, and
  `resources/en/strings/key-value/key-value-strings-utf8.txt` maps id → text; that pair is how
  `300414` became `"Use Local Lan Server"`.
