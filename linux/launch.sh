#!/usr/bin/env bash
# AoE2LAN Linux launcher (PLAN §4, §8-Linux, §17.2 L4).
# Starts the native lanhub, stages the W1-built dbghelp.dll proxy next to the game
# exe inside the prefix, sets the Wine/env knobs, launches the game. Additive only:
# no game file is modified (the DLL is a NEW file; remove it to uninstall).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AOE="${AOE2LAN_ROOT:-$HOME/Games/aoe}"
PFX="${AOE2LAN_PFX:-$AOE/winepfx}"
PROTON="${AOE2LAN_PROTON:-$AOE/Proton-CachyOS Latest-x86_64_v3/proton}"
GAMEDIR="$PFX/pfx/drive_c/Games/AoE2DE"
DLL="${AOE2LAN_DLL:-$REPO/dbghelp.dll}"   # delivered by W1 (gitignored); cannot be built on Linux
export AOE2LAN_STAGE="${AOE2LAN_STAGE:-8}"
export AOE2LAN_NOHOOKS="${AOE2LAN_NOHOOKS:-1}"
export AOE2LAN_HOOKS="${AOE2LAN_HOOKS:-4,5,13,14}"
export AOE2LAN_WSETVT="${AOE2LAN_WSETVT:-0}"
export AOE2LAN_AIGATE="${AOE2LAN_AIGATE:-1}"
export AOE2LAN_LOGVT="${AOE2LAN_LOGVT:-1}"
export AOE2LAN_GLOG="${AOE2LAN_GLOG:-1}"
# AOE2LAN_RTDYN=1 additionally re-points the __RTDynamicCast IAT slot, which is how
# the host-lobby AI gate (screen+0x1cf8) gets written without touching .text/.rdata.
# Not default yet: untested on wine (needs a display + a click into the host lobby).
export AOE2LAN_RTDYN="${AOE2LAN_RTDYN:-0}"

# 1. stage the proxy DLL (plain dbghelp import in the game = crash reporting only;
#    WINEDLLOVERRIDES makes ours win over Wine's builtin)
if [[ -f "$DLL" ]]; then
    cp -f "$DLL" "$GAMEDIR/dbghelp.dll"
    echo "launch: staged dbghelp.dll ($(stat -c%s "$GAMEDIR/dbghelp.dll") bytes)"
else
    echo "launch: WARNING $DLL not found — ask W1 for the dbghelp build;" >&2
    echo "launch: starting WITHOUT the proxy (Multiplayer will stay grey)" >&2
fi

# 2. native hub (build if needed); runs on host OS so it sees tailscale0
HUB="$REPO/lanhub/target/release/lanhub"
[[ -x "$HUB" ]] || cargo build --release --manifest-path "$REPO/lanhub/Cargo.toml"
"$HUB" --ini "$REPO/aoe2lan.ini" &
HUBPID=$!
trap 'kill "$HUBPID" 2>/dev/null || true' EXIT
echo "launch: lanhub pid $HUBPID (control 127.0.0.1:47100, node :47101)"

# 3. game inside the shared prefix (loopback + Documents shared with hub/relay)
cd "$GAMEDIR"
export STEAM_COMPAT_DATA_PATH="$PFX"
export STEAM_COMPAT_CLIENT_INSTALL_PATH="$HOME/.steam/steam"
#    "n,b" not "n": both our dbghelp proxy and RUNE's winmm proxy forward to system32's
#    builtin; without winmm=n,b some Proton builds load builtin winmm and trip the Steam check
export WINEDLLOVERRIDES="dbghelp,winmm=n,b"
#    ntsync off: a failing exit can wedge a thread spinning at 100% CPU that outlives the
#    launcher (notes/linux-session2.md 2d/2f). Revisit once the game reaches the menu.
#    Overridable: PROTON_NO_NTSYNC="" selects ntsync, which is itself a variable under
#    test on wine 10 (notes/linux-session3.md).
export PROTON_NO_NTSYNC="${PROTON_NO_NTSYNC-1}"
# telemetry env knobs: unknown semantics beyond PLAN §2.5 names — H4 owns silence
# in-process; nothing set here until a measurement says otherwise.
#    runinprefix, not run: "run" goes through Proton's steam.exe stub, which under
#    CachyOS delegated to the real Steam client (steam://run/813780) and hung there.
#    The RUNE crack (steam_api64.dll + steam_emu.ini, left untouched) needs no Steam.
exec "$PROTON" runinprefix AoE2DE_s.exe "$@"
