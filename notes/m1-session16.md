# Session-16 (2026-11-04, M1) — login reply decoded from the client's own deserializer; trust is fine; one field still aborts the parse

## 16a. Headline
Session-15's "envelope shape" theory was half right and half wrong. The reply is a
**keyed object** (not the positional array the public capture shows — this build is
clientLibVersion 194, the captures are 151/169), and the client's reader is a
hand-rolled, order-sensitive JSON scanner in which **any type mismatch aborts the
whole parse**. Three real type violations were found statically and fixed
(accountType, metaData, ssoID). A fourth fix (presenceID/presencePropertyInfo/relay
keys) was already in. `Found %zd profiles` is **still 0** after 3 supervised runs, so
at least one violation remains — but the search space is now small and enumerated
(section 16d).

Also proven this session: **the Windows-Root consent click is NOT load-bearing** —
runs 19104 and 11788 completed the handshake with the prompt never accepted, so the
enum-injection path alone carries trust.

## 16b. The reader map (fact — do not re-derive)
All of this was read out of `dev/lanhook/gametext.bin` (decrypted .text,
`off = VA − 0x140001000`); the parse code is **encrypted on disk** (Arxan), so none of
it can be hooked — static + behavioural evidence only.

Chain: `LoginResult` reader `0x140615b70` → `AccountInfo` reader `0x140614060` →
`profiles[]` reader `0x1403e2ee0` (elements = 0x180B, reader `0x140620540`).
Helper ids: `0x14039c900` = int64 (strtoll, **saturates** at 2^63−1 … actually
strtoll clamps, so ids are masked to 63 bits), `0x14039c6f0` = int32,
`0x14039cc60`/`0x14039cf60` = JSON string → std::string, `0x14039b8e0` = consume
`null`, `0x14039a910`/`0x14039b340` = begin/end object, `0x1403955c0` = array<string>.

LoginResult (`0x140615b70`, field order == wire order):
| key | type | dst |
|---|---|---|
| resultCode | enum (0x140610780) | +0x30 |
| connectionToken | string | +0x00 |
| connectionID | int64 | +0x20 |
| serverTime | int64 | +0x28 |
| accountInfo | object (0x140614060) | +0x38 |
| profiles | array<ProfileInfo> (0x1403e2ee0) | +0x120 |
| banLevel / banSeconds | int32 (0x14039c6f0) | +0x138 / +0x13c |
| banMessage | string | +0x140 |
| clientSettings | array<{string,string}> (0x140619860) | +0x160 |
| selectProfile | object or null (0x140616ed0) | +0x178 |
| sslCertificates | array<string> (0x1403955c0) | +0x580 |
| shouldUseClientSync | bool (0x14039c730) | +0x598 |
| relayServers | array<endpoint> (0x140619b90 → 0x140615000) | +0x5a0 |

AccountInfo (`0x140614060`): `id` int64, `accountName` string, `accountType` **int64
enum, range-checked 0..13 (0x14061fe20, cmp eax,0xd)**, `ssoID` **int64**, `ssoStatus`
int8 enum (0x140610ec0), `country` string(+0x70), `currency` string(+0x50),
`spamAllowed` bool (0x140611270), `metaData` **string**, `profiles`
array<{profileInfo,clanID,enableCrossplay,privacySettings}> (+0x98) — **null is
accepted**.

ProfileInfo (`0x140620540`, 0x180B): entityVersion int64, id int64, name string,
metaData **string**, alias string, sanitizedAlias string, clanName string,
personalStatGroupID int64, xp int64, level int64, leaderboardRegionID int64,
banInfo object-or-null (0x140622500), platformUserID string, accountType **int64
enum (Steam = 3)**, linkedPlatformAccounts array (0x140623780), presenceID **int64**,
presenceLocalized string, presencePropertyInfo **array** (0x140623a30).

relayServers element (`0x140615000`): `region` string, `regionLocalized` string,
`publicIP` string, `rawSocketPort` int32, `webSocketPort` int32,
`outOfBandSocketPort` int32.

Independent confirmation of the enum value: the public capture's profile tuple is
`…, null, "7656119…", 3, []` and its accountInfo tuple is `[id, "/steam/…", 3, -1, 0,
"de", "eur", 2, null]` — i.e. accountType = 3 and **ssoID = −1** for Steam.
(The tuple form is what old clients used; ours wants keys.)

`profiles` count comes from `(event+0x560 − event+0x558)/24` in
`WorldwideLoginService::OnLoginResult` (`0x140684130`, log call at `0x140684542`,
retaddrs `game+0x684542`).

## 16c. Envelope now served (dev/lanhook/loginsrv.c `build_login_response`)
```json
{"resultCode":0,"connectionToken":"<digits>","connectionID":549000000,"serverTime":<now>,
 "accountInfo":{"id":<id>,"accountName":"<alias>","accountType":3,"ssoID":-1,"ssoStatus":0,
   "country":"US","currency":"eur","spamAllowed":false,"metaData":"{}","profiles":null},
 "profiles":[{"entityVersion":1,"id":<id>,"name":"<alias>","metaData":"{}","alias":"<alias>",
   "sanitizedAlias":"<alias>","clanName":"","personalStatGroupID":<stat>,"xp":0,"level":1,
   "leaderboardRegionID":2,"banInfo":null,"platformUserID":"<steamid>","accountType":3,
   "linkedPlatformAccounts":[],"presenceID":0,"presenceLocalized":"",
   "presencePropertyInfo":[]}],
 "banLevel":0,"banSeconds":0,"banMessage":"","clientSettings":[[k,v],…],
 "selectProfile":null,"sslCertificates":[],"shouldUseClientSync":false,
 "relayServers":[{"region":"LAN","regionLocalized":"LAN","publicIP":"127.0.0.1",
   "rawSocketPort":27012,"webSocketPort":27112,"outOfBandSocketPort":27212}]}
```
profileID = FNV1a64("aoe2lan:"+alias) **masked to 63 bits**.

## 16d. What is still suspect (pick up here)
Runs 19104, 11788, 14600 all: TLS ok → POST platformlogin → reply served → reply
consumed (readSession starts with `sessionID=<our token>`) → `Found 0 profiles`.
The token surviving proves the parse got at least as far as `connectionToken`.
Remaining candidates, in order:
1. `resultCode` — enum reader `0x140610780`; we send 0. Verify its valid range/name map.
2. `ssoStatus` — enum reader `0x140610ec0`; if 0 is out of range the parse aborts in
   AccountInfo (same class of failure as accountType).
3. `spamAllowed` — `0x140611270` is a *dedicated* bool reader; confirm `false` is the
   accepted token (it may want 0/1 ints).
4. `personalStatGroupID` / `leaderboardRegionID` — range/validity checks?
5. `accountInfo.profiles:null` — the null path exists (`0x14039b8e0` at
   `0x140614bc6`) but the code that reaches it depends on the cursor being exactly at
   `]`; confirm by serving an actual wrapper array instead of null.
6. Order sensitivity: the first-phase keys must appear in reader order (ours do).

## 16e. The memory probe (built, works, not yet answered)
`loginsrv.c`: after serving a login, `ProbeThread` sleeps 60 ms then scans **private
committed** memory for the raw 8-byte LE profileID (fallback: the token string).
Every access goes through `ReadProcessMemory` — an earlier version dereferenced raw
and **very likely killed the game on 2026-11-04 17:44 (run lanhook-14600 ends
mid-scan, no WER, no BsgSndRpt)**. Do not put raw derefs back.
Output: `PROBE needle=…`, `PROBE hit va=…`, 0x700-byte hexdump window, `PROBE scan
done regions=N hits=H`.
If the id is found, the dump at hit−0x100 IS `AccountInfo` (id at +0x10, accountName
+0x18, accountType +0x38, ssoID +0x40, ssoStatus +0x48, country +0x70, currency +0x50,
spamAllowed +0x90, metaData +0xb0, profiles vector +0x98) and it answers everything.
Self-test in `srvtest.log`: hits=0 is expected (server only ever holds the ASCII digits).

## 16f. Next steps (in order)
1. Re-run with the RPM probe build (`dbghelp.dll` = `fcc59505…`, staged) and read
   `PROBE hit` dumps. That is the shortest path to certainty.
2. If no hit: the parse never wrote `accountInfo.id` ⇒ the abort is at `resultCode`
   or `connectionToken` — serve `{"resultCode":0,"connectionToken":"…"}` alone and
   bisect upward from there.
3. Also fix `readSession`: it must be `<pollNum>, [[events…]]` per the documented
   capture (e.g. `23, [[...]]`), not `[1]`. Events we care about for a first login
   are the account/profile update ones; the real server pushes `ChallengeUpdatedMessage`
   etc. Shape it as `[[ ["<n>", event…] ]]` only after the login parse is green.
4. After `Found 1 profiles`: watch for `defaultProfileInfo`/AET_Login, then MP button,
   then XAL escalation check (PLAN §6.1).

## 16g. Tree state / artifacts
- `dev/lanhook/loginsrv.c`: new `build_login_response` (16c), `ProbeThread`/`mem_probe`
  (RPM-based), token+id needles, `probe_arm()` on the platformlogin route.
- `dev/lanhook/aoe2re.py`: PE/dump/xref toolkit (dump base 0x140001000; xref scan is
  byte-aligned, `fieldmap.py` prints TypesStream field tables, `xref_i32.npy` is the
  cached scan array, `pdata_funcs.json` the .pdata function list).
- `dev/lanhook/srvclient.py`: asserts the corrected types (accountType 3, metaData
  string, ssoID int, presenceID int, presencePropertyInfo array, relay keys).
- Builds: hooktest 68/68 PASS, srvtest+srvclient PASS. Staged `dbghelp.dll` =
  `fcc59505…` (192,512 B). Rollbacks `dbghelp.dll.prev-s16-*`.
  `AoE2DE_s.exe` untouched (`1e415af8…`).
- Reference (facts only, operator rule: ageLANServer is reference-only): the public
  rlink protocol captures at `wiki.librematch.org/rlink/game/login/platformlogin`
  and `…/readsession` give the old positional shapes, the enum values and the
  readSession reply structure.