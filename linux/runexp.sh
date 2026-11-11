#!/usr/bin/env bash
# runexp.sh LABEL STAGE [VAR=val ...]  — one instrumented boot experiment.
#
# Why: session 5's runs were contaminated by leftover wine processes holding
# 127.0.0.1:443 (the in-DLL login server port), so later runs talked to a dead
# process's server. This harness hard-cleans first, asserts the port is free,
# polls the Main.txt oracle, snapshots per-thread kernel wait channels, saves
# the shim log, and hard-cleans again.
#
# Oracle: Main.txt line count. 18 = the stage-8 stall wall
# ("About to setup communications handler"), >18 = booted past it.
set -uo pipefail

LABEL="$1"; STAGE="$2"; shift 2
AOE="${AOE2LAN_ROOT:-$HOME/Games/aoe}"
PFX="${AOE2LAN_PFX:-$AOE/winepfx}"
GAMELOGS="$PFX/pfx/drive_c/users/steamuser/Games/Age of Empires 2 DE/logs"
SECS="${EXP_SECONDS:-60}"
OUT="/tmp/exp-$LABEL"

hardclean() {
  pkill -9 -x AoE2DE_s.exe 2>/dev/null; pkill -9 -x winedbg 2>/dev/null
  pkill -9 -x tabtip.exe 2>/dev/null;   pkill -9 -x xalia.exe 2>/dev/null
  pkill -9 -x winedevice.exe 2>/dev/null; pkill -9 -x services.exe 2>/dev/null
  pkill -9 -x plugplay.exe 2>/dev/null; pkill -9 -x svchost.exe 2>/dev/null
  pkill -9 -x explorer.exe 2>/dev/null; pkill -9 -x rpcss.exe 2>/dev/null
  pkill -9 -x lsass.exe 2>/dev/null;    pkill -9 -x conhost.exe 2>/dev/null
  pkill -9 -x wineserver 2>/dev/null;   pkill -9 -f 'lanhub --in[i]' 2>/dev/null
  sleep 3
}
# thread snapshot: R/S counts + the busiest thread's tid and kernel wait channel
snap() {
  local pid="$1"; [ -z "$pid" ] && { echo "game=none"; return; }
  local r=0 s=0 toptid="" topcpu=0 topwc=""
  for t in /proc/$pid/task/*; do
    local st cpu
    st=$(awk '{print $3}' "$t/stat" 2>/dev/null) || continue
    cpu=$(awk '{print $14+$15}' "$t/stat" 2>/dev/null)
    [ "$st" = R ] && r=$((r+1)); [ "$st" = S ] && s=$((s+1))
    if [ "${cpu:-0}" -gt "$topcpu" ]; then
      topcpu=$cpu; toptid=$(basename "$t"); topwc=$(cat "$t/wchan" 2>/dev/null)
    fi
  done
  echo "game=$pid R=$r S=$s top=$toptid(${topcpu}j)@$topwc"
}

hardclean
if ss -tln 2>/dev/null | grep -q ':443 '; then
  echo "ABORT: 127.0.0.1:443 still held — $(ss -tlnp 2>/dev/null | grep ':443 ')"; exit 1
fi
PRE=$(ls -1t "$GAMELOGS" 2>/dev/null | grep -E '^20[0-9]{2}\.' | head -1)

cd "$AOE/AoE2DE-LAN/linux" || exit 1
if [ "${RUNEXP_DIRECT:-0}" = 1 ]; then
  # direct wine: no proton launcher, no protonfixes, no xalia/tabtip — fewer
  # moving parts and no 70%-CPU spinner in the trace.
  PROTONDIR="${AOE2LAN_PROTON:-$AOE/Proton-CachyOS Latest-x86_64_v3/proton}"; PROTONDIR="${PROTONDIR%/proton}"
  GAMEDIR="$PFX/pfx/drive_c/Games/AoE2DE"
  cp -f "${AOE2LAN_DLL:-$AOE/AoE2DE-LAN/dbghelp.dll}" "$GAMEDIR/dbghelp.dll"
  HUB="$AOE/AoE2DE-LAN/lanhub/target/release/lanhub"
  [ -x "$HUB" ] && "$HUB" --ini "$AOE/AoE2DE-LAN/aoe2lan.ini" >> "$OUT.launch.log" 2>&1 &
  sleep 1
  ( cd "$GAMEDIR" && env "$@" WINEPREFIX="$PFX/pfx" WINEDLLOVERRIDES="dbghelp,winmm=n,b" \
      AOE2LAN_STAGE="$STAGE" PROTON_NO_NTSYNC="${PROTON_NO_NTSYNC-1}" \
      setsid "$PROTONDIR/files/bin/wine" AoE2DE_s.exe ) >> "$OUT.launch.log" 2>&1 < /dev/null &
else
env "$@" AOE2LAN_PFX="$PFX" AOE2LAN_STAGE="$STAGE" \
    AOE2LAN_PROTON="${AOE2LAN_PROTON:-$AOE/Proton-CachyOS Latest-x86_64_v3/proton}" \
    setsid ./launch.sh > "$OUT.launch.log" 2>&1 < /dev/null &
fi
START=$(date +%s); PEAK=0; NEW=""
for ((i=0; i<SECS/3; i++)); do
  sleep 3
  NEW=$(ls -1t "$GAMELOGS" 2>/dev/null | grep -E '^20[0-9]{2}\.' | head -1)
  [ "$NEW" = "$PRE" ] && NEW=""
  N=0; [ -n "$NEW" ] && [ -f "$GAMELOGS/$NEW/Main.txt" ] && N=$(wc -l < "$GAMELOGS/$NEW/Main.txt")
  [ "$N" -gt "$PEAK" ] && PEAK=$N
  GP=$(pgrep -x AoE2DE_s.exe | head -1)
  [ -n "$GP" ] && [ ! -s "$OUT.maps" ] && cp "/proc/$GP/maps" "$OUT.maps" 2>/dev/null
  WS=$(pgrep -x wineserver | head -1)
  WSCPU=$(ps -o pcpu= -p "${WS:-0}" 2>/dev/null | tr -d ' ')
  TT=$(pgrep -x tabtip.exe | head -1)
  echo "t=$(( $(date +%s) - START ))s main=$N peak=$PEAK $(snap "${GP:-}") wineserver=${WSCPU:-0}% tabtip=${TT:-none}"
  if [ -z "$GP" ] && [ "$i" -gt 4 ]; then echo "(game exited)"; break; fi
done

SHIM=""
for f in $(ls -1t "$PFX/pfx/drive_c/Games/AoE2DE/logs/lanhook-"*.log 2>/dev/null | head -8); do
  grep -q "not AoE2DE_s.exe" "$f" 2>/dev/null || { SHIM="$f"; break; }
done
[ -z "$SHIM" ] && SHIM=$(ls -1t "$PFX/pfx/drive_c/Games/AoE2DE/logs/lanhook-"*.log 2>/dev/null | head -1)
[ -n "$SHIM" ] && cp "$SHIM" "$OUT.shim.log"
hardclean
echo "=== $LABEL: stage=$STAGE peak Main.txt=$PEAK $( [ "$PEAK" -gt 18 ] && echo BOOTED || echo STALLED)"
echo "=== shim log: ${SHIM:-none} -> $OUT.shim.log  (hb alive=$(grep -c 'hb alive' "$OUT.shim.log" 2>/dev/null || echo 0))"
echo "=== launch log: $OUT.launch.log"
