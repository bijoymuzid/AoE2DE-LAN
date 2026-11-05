# Session-28 — the grey Multiplayer button is switched off by one boolean read through a rule table

Supersedes `notes/m1-session27.md` for state. Everything below is MEASURED unless the line
says INFERRED. No game file, no XAML, no `.text` byte was changed this session.

## 28a. Offline gates (re-run, pass)

- `hooktest.exe` **68/68** (`game-image iat walk: swapped 68 of 68`).
- `srvtest.exe` + `srvclient.py` **PASS** (HTTP 200, 14 JSON keys, wss 101, ping/pong, close).
- `AoE2DE_s.exe` crc **`4f533b6c`** (72,176,952 B) — untouched.
- game-dir `dbghelp.dll` crc **`9b8aa96b`** (211,456 B) — the s27 build, unchanged.
- `dev/AoE2DE_dec.exe` crc `487054ce`; `dev/lanhook/gametext.bin` crc `ca040d52` (51,990,528 B).
- XAML untouched this session; stock crc `8398949b`.

## 28b. The XAML proves what "grey" means (data side, no guessing)

`resources/_common/wpfg/screen/screensimplemainmenu.xaml`, lines 45-49: the button Style's
ControlTemplate has

```
<Trigger Property="IsEnabled" Value="False">
  <Setter TargetName="Background" Property="Fill" Value="{Binding Path=DisabledBrush ...}"/>
  <Setter TargetName="Border" Property="BorderBrush" Value="{StaticResource ControlBorderDisabledBrush}"/>
</Trigger>
```

⇒ a grey plate on this screen means **the live widget's `IsEnabled` is False**. The second,
independent grey source is the grey twins' own `ForegroundBrush="button_player_icon_disable"`.

## 28c. `IsEnabled` and `Visibility` are dependency properties with known identities

Found the property registry inside the decrypted `.text` (function at `0x141f978xx`,
`lea rdx, "IsEnabled"` at `0x141f981d2`, `lea rdx, "Visibility"` at `0x141f97f49`). The
register call stores the created property object into a global slot:

| property | DP identity slot | note |
|---|---|---|
| `IsEnabled` | **`0x144c2a478`** | registered with bool metadata (`0x141f848f0`) |
| `Visibility` | **`0x144c2a708`** | registered with `0x14204b1e0` metadata |
| `IsHitTestVisible` | `0x144c2a6d0` | |
| `Opacity` | `0x144c2a648` | default 1.0f (the only default I could read) |

Value setter is `0x141f7c450(obj, dp, boxed_value)`; boxed true is returned by `0x1407fc860`,
boxed false by `0x1407fec40` (INFERRED polarity — see 28g).

The widget-level "set enabled" is **`0x141b11ad0(widget, state)`**:
- `state == 0` → `IsEnabled = boxed TRUE`; `state != 0` → boxed FALSE;
- it then pushes `Visibility = (state ^ 1) * 2` onto the widget's *twin*, whose pointer is the
  widget field at **`+0x1d8`**.

⇒ **each button widget carries a pointer to its twin at `+0x1d8`, and the enabled/disabled
state of one drives the other's visibility.** This is the mechanism s25 guessed at and s27
could not find.

## 28d. Every writer of `IsEnabled` in the exe (complete, 63 sites, grouped)

Scan for instructions resolving to `0x144c2a478` (97 hits) filtered to those followed by a call
to `0x141f7c450`: **63 writers in 44 functions**. Grouped by the boxed value they push
(`TRUE` = `0x1407fc860`, `FALSE` = `0x1407fec40`, `?` = value computed elsewhere):

| function | value | screen (from its own strings) |
|---|---|---|
| `0x141b33c80` | TRUE | the screen-state applier (s27d) |
| `0x141c8feb0` | TRUE ×2 | **`Age2ScreenSimpleMainMenu` binder** (our screen) |
| `0x141bd2c40` | FALSE + TRUE | hotkeys screen |
| `0x141bedd80` | TRUE, ?, FALSE | event/challenge screen |
| `0x141c57b90`, `0x141c59f70`, `0x141c6d080`, `0x141cb1050`, `0x141cb63b0` | FALSE and/or TRUE | campaign / load / lobby lists |
| `0x141b11ad0` | (wrapper) setter | twin-aware enable, see 28c |
| 35 others | TRUE | show my 41 rows are all screens except ours |

**The simple main menu never disables anything through this property.** It only writes TRUE.
That is why s27's enumeration of `[vtbl+0x68]` sites came up empty, and s26b's XAML
`IsEnabled="True"` was overwritten: the real control is not a literal `SetEnabled(false)` call
anywhere — it is a *computed* argument, and it does not go through `[vtbl+0x68]` at all.

## 28e. The real control: a twin-rule table, evaluated once per UI tick

`Age2ScreenSimpleMainMenu` registers each (enabled, disabled) button pair in a rule list:

- `0x141b126f0(mgr, enabled_widget, disabled_widget)` — appends a 0x48-byte record:
  `+0 status`, `+8/+0x10 listA`, `+0x20/+0x28 listB`, `+0x38 enabled widget`, `+0x40 disabled widget`,
  default rule ids **{11, 12, 13}** written inline at `0x141b1271x` (`uStack_78=0xb, 74=0xc, 70=0xd`).
- `0x141b12890(rec, vec)` / `0x141b12820(rec, vec)` add rule ids 10/12/13 to the record.
- Pair registrations inside our binder (call sites of `0x141b126f0`):
  `0x141c901e2` = (`ButtonMultiplayer`, `ButtonMultiplayerDisabled`);
  `0x141c90352` = (`PaphosButtonMultiplayer`, `PaphosButtonMultiplayerDisabled`);
  then `0x141c9051e` Editor pair, `0x141c9077b` Mods pair, `0x141c90a43` MoreContent + Coop,
  `0x141c90c19` SingleplayerDialog, `0x141c90d42` PaphosSingleplayer, `0x141c90e8a`/`0x141c91047`
  LearnDialog, `0x141c912c2` Purchase/GrandCampaign, `0x141c90045` the first (variant) one.
- After the registration the binder passes a constant 4-int vector from `.rdata 0x14338a580`
  = **{2, 8, 4, 5}** to `0x141b12890` and a 1-int vector **{0xc}** to `0x141b12820`
  (`0x141c901ea` / `0x141c9022c` for the Multiplayer pair).
- `0x141b12a00(mgr)` — the evaluator: for every record, `status = max(map[id])` over the ids in
  listA that are *not* in listB; then calls `0x141b12410(record)`.
- `0x141b12410(record)` — the applier:
  - `status 0` → `Visibility(enabled)=2`, `SetEnabled(enabled, 1)` = **DISABLE**, `Visibility(disabled)=default`
  - `status 1` → `Visibility(enabled)=default`, `Visibility(disabled)=2`, `SetEnabled(enabled, 1)` = DISABLE
  - `status 2` → `Visibility(enabled)=2`, `SetEnabled(enabled, 0)` = **ENABLE**, `Visibility(disabled)=0`
  - other values → nothing.

## 28f. The rule table's inputs, id by id (this is the "what state does the writer read" answer)

`0x141b12d60(mgr)` fills one status per rule id, from a fixed list of sources:

| id | input | status |
|---|---|---|
| 0 | `[0x1442dc4f0]+0x2e8` → `[vtbl+0x80]()` | 0 if true, else 2 |
| 1 | same obj `[vtbl+0x88]()` **and** maintenance state `0x141027670(0x141027640())` ∈ {2,3} | 0 / 2 |
| 2 | same obj `[vtbl+0x90]()` | 0 / 2 |
| 3 | same obj `[vtbl+0x1b8](&vec)` | 0 / 2 |
| 4,5,6 | same obj `[vtbl+0x308](4)` / `(2)` / `(2)` | 0 / 2 |
| 7 | `[vtbl+0x308](2)` || `0x140e5d0a0([0x1442e1358])` && `0x14100c610(0x140d62260([0x1443552b8]), 0x17)` | 0 / 2 |
| 8 | `0x141b12b90` | ? |
| 9 | privilege query that builds `IDS_PRIVILEGE_DENIED_GENERAL_WARNING`, then `0x140d62cc0([0x1443552b8])` | 0 / 2 |
| 10 | settings bool `0x140f78fb0(9)` | 2 if false, 0 if true |
| 11 | constant | **0** |
| 12 | constant | **0** |
| **13** | **`0x140d63070([0x1443552b8])` = `movzx eax,[rcx+0x698]; ret`** | **2 if 1, 0 if 0** |
| 14 | `!0x140d62cc0([0x1443552b8])` | 0 / 2 |
| 15 | `[rbx+0x6b4] == 0x140fa46c0(&[0x1443552b8]+0x680)` | 0 / 2 |

The Multiplayer pair's effective rule set is listA `{2, 8, 4, 5, 11, 12, 13}` minus listB `{12}`
⇒ ids **2, 4, 5, 8, 11, 13** matter (11 is a constant 0). The record status is the **max** of those
six values, and the applier turns that number into (visibility, enabled) for the pair.

⇒ **The Multiplayer button's state is a function of exactly five live inputs:**

1. id 2 — `[svc].[vtbl+0x90]()` where `svc = [[0x1442dc4f0]+0x2e8]`
2. id 4 — `[svc].[vtbl+0x308](4)` (a bool query taking an int id)
3. id 5 — `[svc].[vtbl+0x308](2)`
4. id 8 — `0x141b12b90`: **two privilege queries** (args 2 and 0 through the interface's
   `[+0x10]` method, both building `IDS_PRIVILEGE_DENIED_GENERAL_WARNING`); both granted → 0,
   else → 2
5. id 13 — the byte at `[0x1443552b8]+0x698` (getter `0x140d63070`)

No other code touches this button's enabled state — that closes "what state does the writer
read". **Which of those five is wrong in our environment is NOT known**; it needs one runtime
read (see 28h/28i).

The numeric status → (visibility, enabled) mapping is read out in 28e, but its polarity is NOT
settled: ids 0/2/8/9 map "good" to 0 while ids 4/5/6/13 map "good" to 2, so the numbers are
per-rule state codes, not one good/bad flag. Do not act on that half until it is measured.

## 28g. INFERRED (flagged, not measured)

- boxed-true = `0x1407fc860`, boxed-false = `0x1407fec40`. Two independent reads agree with this
  (the state applier's "enabled" byte, and `SetEnabled(w,0)` being called where the screen means
  enabled), but no single instruction states it, so treat the polarity of 28f's last line as
  INFERRED until measured.
- `Visibility` values: 0 = visible, 2 = hidden. Same reasoning (it is what `0x141b11ad0` needs in
  order to hide a twin). Not measured.
- the applier's "default" Visibility box is a static object at `0x14425cde8`, value unknown.

## 28h. NOT known

- **Whether the byte at `[0x1443552b8]+0x698` is 0 or 1 in our login run.** It cannot be read
  from the file: `0x1443552b8` lives in `.data` *past the raw size* (BSS), and nothing in `.text`
  ever stores to that global (97 rip-relative references, all loads). One read-only runtime read
  settles it.
- Who writes `+0x698`. Byte-store scan over the whole decrypted `.text` gives 9 sites, of which
  5 are stack frames and 4 are object fields:
  - `0x142b630c5` → 0 (early-out on `0x142da1110(...)` true) and `0x142b63111` → 1 (after an
    insert/commit pair `0x142b71200`/`0x142b6e6e0`). Candidate: a sign-in/commit step.
  - `0x1418c03f5`, `0x1418c0d66`, `0x1418d68eb` — command-card widgets ("Creating button from
    JSON", "UIWidgetCommandPanel Wake"); unrelated class, same offset.
  - the getter `0x140d63070` has 9 call sites: `0x140febdf8, 0x1414fa829, 0x1419e0d6c,
    0x1419e1128, 0x141b13253, 0x141b3f5a2, 0x141be241d, 0x141bee4e8, 0x141be97d7`.
- the `[0x1442dc4f0]+0x2e8` service object's slots 0x80/0x88/0x90/0x1b8/0x308 — s26c already
  measured two of the platform vtables at runtime (rva `0x366b450`, `0x366f848`, `0x3670a10`);
  these extra slots were not read.

## 28i. What this changes

The question is now closed to five concrete inputs (28f). It is not a TestKey, not the screen
state block, not the grey twins, and not a `SetEnabled(false)` call site: the disable arrives as a
*computed* argument inside the twin-rule applier `0x141b12410`, which is why both s26 and s27 came
up empty.

Next step is one read-only runtime probe (needs the operator's approval per the standing rule),
at t≈35 s, printing:
- `[0x1443552b8]`, its `[+0]` vtable, and bytes `+0x680`, `+0x698`, `+0x6b4`;
- `[0x1442dc4f0]+0x2e8` (already done in s26), then `[vtbl+0x80]`, `+0x88`, `+0x90`, `+0x1b8`,
  and `+0x308` with args 2 and 4 — the exact five queries of 28f;
- the boolean from `0x140f78fb0(9)` and `0x140d62cc0([0x1443552b8])`.
No writes, no detours, one launch.

If the byte is already 1, then the multi-player click path is the problem (M2 territory) and this
line of attack is finished.

## 28j. Ghidra notes (added to 27k)

`dev/ghidra-scripts/targets.txt` + `dev\ghidra-decomp.cmd` still works (~60 s for 4 functions).
Batch used this session: `0x141b126f0, 0x141b12890, 0x141b12820, 0x141b11ad0` → `decomp3.c`.
Decompiled C of these four is what 28c/28e are based on.