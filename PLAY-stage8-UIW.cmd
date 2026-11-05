@echo off
rem session 27: stage 8 login + read-only widget/vtable scan (AOE2LAN_UIW).
rem Reads game memory only; no detour, no .rdata re-point, nothing written.
rem Operator: double-click, sit at the main menu ~70 s (the scan runs at t=60 s), quit.
set AOE2LAN_STAGE=8
set AOE2LAN_UIW=1
set RL_TELEMSHOULDNTSEND=1
set RL_TELEMREPORTPCT=0
start "" "AoE2DE_s.exe"
