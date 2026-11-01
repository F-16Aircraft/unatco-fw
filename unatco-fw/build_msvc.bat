@echo off
REM Build with Visual Studio Build Tools (run from "x64 Native Tools Command Prompt for VS").
REM Only Microsoft's own toolchain + Windows SDK are used. Nothing is downloaded.
setlocal
if not exist out mkdir out
rc /nologo /fo out\unatco.res unatco.rc || goto :err
cl /nologo /std:c++17 /O2 /EHsc /W3 /MT /utf-8 ^
   src\main.cpp src\view.cpp src\model.cpp src\globe.cpp src\monitor.cpp src\memscan.cpp ^
   src\netmon.cpp src\etw.cpp src\intel.cpp src\fw.cpp src\history.cpp src\geo_world.cpp src\geo_countries.cpp ^
   out\unatco.res ^
   /Fe:out\unatco_netdef.exe /Fo:out\ ^
   /link /SUBSYSTEM:WINDOWS /MACHINE:X64 ^
   user32.lib gdi32.lib ws2_32.lib iphlpapi.lib psapi.lib advapi32.lib fwpuclnt.lib shell32.lib || goto :err
echo.
echo Built: out\unatco_netdef.exe
goto :eof
:err
echo BUILD FAILED
exit /b 1
