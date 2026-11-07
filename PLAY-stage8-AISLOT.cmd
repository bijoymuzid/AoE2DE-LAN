@echo off
rem session 40: stage 8 login + WidgetSetEn (id 14) + AISlotPick (id 15).
rem id 15 is a READ-ONLY logger on 0x140d62260, the clean "pick AI slot" helper:
rem   kind = getter(rcx+0x680); return &table[kind]   (3 slots of 0x110 @ RVA 0x4356760)
rem table[kind]+0x28 is the vector of built-in AI entries that the AI-list builder
rem 0x140bf3c30 copies into every NameDropDown. Logs caller, tag, val, kind, nAI.
rem Optional: set AOE2LAN_AIKIND=0/1/2 to force the slot for the AI-list builder only.
rem Operator: click Multiplayer -> Host Game, open an empty slot's dropdown, then
rem back out and do Single Player -> Skirmish and open an empty slot's dropdown.
set AOE2LAN_STAGE=8
set AOE2LAN_HOOKS=4,5,13,14,15
set RL_TELEMSHOULDNTSEND=1
set RL_TELEMREPORTPCT=0
start "" "AoE2DE_s.exe"
