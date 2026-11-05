@echo off
REM Import + analyze AoE2DE_s.exe into a Ghidra project (session 27).
REM Usage: ghidra-import.cmd            (first time: import + analyze)
REM        ghidra-import.cmd -process   (re-run only if the project exists)
setlocal
set TOOLS=%~dp0tools
set GHIDRA=%TOOLS%\ghidra_12.2_PUBLIC
set JAVA_HOME=%TOOLS%\jdk-25.0.5+8
set GHIDRA_HEADLESS_MAXMEM=10G
set PROJ=%~dp0ghidra-proj
if "%1"=="-process" goto process
call "%GHIDRA%\support\analyzeHeadless.bat" "%PROJ%" aoe2de -import "%~dp0..\AoE2DE_s.exe" -analysisTimeoutPerFile 10800 -log "%PROJ%\import.log" -scriptlog "%PROJ%\script.log"
goto :eof
:process
call "%GHIDRA%\support\analyzeHeadless.bat" "%PROJ%" aoe2de -process AoE2DE_s.exe -noanalysis -log "%PROJ%\process.log" -scriptlog "%PROJ%\script.log" -postScript %2 %3 %4 %5