@echo off
rem Re-stage the AoE2LAN work from the game dir into this repo, commit and push.
rem Usage: sync.cmd ["commit message"]
setlocal
set SRC=D:\Age of Empires II Definitive Edition
set DST=%~dp0
if "%~1"=="" (set MSG=session update) else (set MSG=%~1)

copy /y "%SRC%\PLAN.md" "%DST%" >nul
copy /y "%SRC%\LAN_MOD_ARCHITECTURE.md" "%DST%" >nul
copy /y "%SRC%\LAN_MOD_PLAN.md" "%DST%" >nul
copy /y "%SRC%\PLAY-stage*.cmd" "%DST%" >nul
copy /y "%SRC%\notes\*.md" "%DST%\notes\" >nul
copy /y "%SRC%\notes\*.py" "%DST%\notes\" >nul
copy /y "%SRC%\notes\rtti_tables.json" "%DST%\notes\" >nul
copy /y "%SRC%\dev\lanhook\*.c" "%DST%\dev\lanhook\" >nul
copy /y "%SRC%\dev\lanhook\*.h" "%DST%\dev\lanhook\" >nul
copy /y "%SRC%\dev\lanhook\*.asm" "%DST%\dev\lanhook\" >nul
copy /y "%SRC%\dev\lanhook\*.cmd" "%DST%\dev\lanhook\" >nul
copy /y "%SRC%\dev\lanhook\*.py" "%DST%\dev\lanhook\" >nul
copy /y "%SRC%\dev\lanhook\*.def" "%DST%\dev\lanhook\" >nul
copy /y "%SRC%\dev\lanhook\work\*.txt" "%DST%\dev\lanhook\work\" >nul
copy /y "%SRC%\dev\lanhook\work\*.py" "%DST%\dev\lanhook\work\" >nul
copy /y "%SRC%\dev\lanhook\work\*.bin" "%DST%\dev\lanhook\work\" >nul
copy /y "%SRC%\dev\lanhook\work\*.json" "%DST%\dev\lanhook\work\" >nul
copy /y "%SRC%\dev\ghidra-scripts\*.java" "%DST%\dev\ghidra-scripts\" >nul
copy /y "%SRC%\dev\ghidra-scripts\targets.txt" "%DST%\dev\ghidra-scripts\" >nul
copy /y "%SRC%\dev\ghidra*.cmd" "%DST%\dev\" >nul
copy /y "%SRC%\logs\lanhook-*.log" "%DST%\logs\" >nul

cd /d "%DST%"
git add -A
git commit -m "%MSG%"
git push
echo === synced ===
endlocal