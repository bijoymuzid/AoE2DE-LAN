@echo off
rem AoE2LAN session 26 - stage 8 (working fake login) + MP unlock.
rem MP unlock = AOE2LAN_MPUNLOCK=1: dbghelp.dll re-points the three slots on the
rem privilege path, measured in s26 (plain .rdata, never encrypted):
rem   svc vtable 0x14366f848 +0xb0  keyed readiness query  -> "ready" for our key
rem   usr vtable 0x143670a10 +0xb8  signed-in name query    -> yes
rem   usr vtable 0x143670a10 +0xc8  HasPrivilege            -> 0 = allowed
rem Nothing on disk changes; a normal relaunch is back to stock behaviour.
rem Operator: double-click, sit at the menu ~50 s, hover the Multiplayer button
rem (read the bottom-right help line), click Multiplayer once, wait ~10 s, quit.
rem Report the logs/lanhook-<pid>.log name.
set AOE2LAN_STAGE=8
set AOE2LAN_MPUNLOCK=1
set RL_TELEMSHOULDNTSEND=1
set RL_TELEMREPORTPCT=0
start "" "AoE2DE_s.exe"