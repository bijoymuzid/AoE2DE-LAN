@echo off
rem build lanhook.dll (dbghelp proxy + detour hooks) and hooktest.exe
set VC=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207
set SDKI=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0
set SDKU=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64
set SDKC=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64
set INC=-I"%VC%\include" -I"%SDKI%\um" -I"%SDKI%\ucrt" -I"%SDKI%\shared"
set LIBS=-LIBPATH:"%VC%\lib\x64" -LIBPATH:"%SDKU%" -LIBPATH:"%SDKC%"

"%VC%\bin\Hostx64\x64\ml64.exe" /nologo /c stubs.asm /Fo stubs.obj || exit /b 1
"%VC%\bin\Hostx64\x64\ml64.exe" /nologo /c hooks.asm  /Fo hooks.obj || exit /b 1
"%VC%\bin\Hostx64\x64\cl.exe" -nologo -MT -O1 -GS- -DNDEBUG %INC% hookcore.c -c -Fo hookcore.obj || exit /b 1
"%VC%\bin\Hostx64\x64\cl.exe" -nologo -MT -O1 -GS- -DNDEBUG %INC% iathook.c   -c -Fo iathook.obj  || exit /b 1
"%VC%\bin\Hostx64\x64\cl.exe" -nologo -MT -O1 -GS- -DNDEBUG %INC% lanhook.c  -c -Fo lanhook.obj  || exit /b 1
"%VC%\bin\Hostx64\x64\cl.exe" -nologo -MT -O1 -GS- -DNDEBUG -DWIN32_WINNT=0x0A00 %INC% loginsrv.c -c -Fo loginsrv.obj || exit /b 1
"%VC%\bin\Hostx64\x64\link.exe" -nologo -DLL -OUT:dbghelp.dll lanhook.obj hookcore.obj stubs.obj hooks.obj iathook.obj loginsrv.obj -DEF:dbghelp.def -BASE:0x180000000 -DYNAMICBASE:NO %LIBS% kernel32.lib || exit /b 1

"%VC%\bin\Hostx64\x64\cl.exe" -nologo -MT -O1 -GS- -DNDEBUG -DWIN32_LEAN_AND_MEAN %INC% hooktest.c -c -Fo hooktest.obj || exit /b 1
"%VC%\bin\Hostx64\x64\link.exe" -nologo -OUT:hooktest.exe hooktest.obj hookcore.obj hooks.obj iathook.obj %LIBS% kernel32.lib ws2_32.lib || exit /b 1

rem offline login-server validation harness
"%VC%\bin\Hostx64\x64\cl.exe" -nologo -MT -O1 -GS- -DNDEBUG -DWIN32_WINNT=0x0A00 %INC% srvtest.c loginsrv.c -c -Fo srvtest.obj || exit /b 1
"%VC%\bin\Hostx64\x64\link.exe" -nologo -OUT:srvtest.exe srvtest.obj loginsrv.obj hookcore.obj hooks.obj %LIBS% kernel32.lib ws2_32.lib || exit /b 1

rem stage the built DLL into the game dir (the game loads .\dbghelp.dll)
copy /y dbghelp.dll ..\..\dbghelp.dll >nul
echo === build ok ===
