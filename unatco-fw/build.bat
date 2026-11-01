@echo off
REM One-click build. Detects whichever C++ compiler is already on your PATH:
REM   cl (Visual Studio Build Tools)  |  g++ (MinGW-w64 / MSYS2)  |  clang++
REM Nothing is downloaded. Output: out\unatco_netdef.exe
setlocal
cd /d "%~dp0"
if not exist out mkdir out

set SRC=src\main.cpp src\view.cpp src\model.cpp src\globe.cpp src\monitor.cpp src\memscan.cpp src\netmon.cpp src\etw.cpp src\intel.cpp src\fw.cpp src\history.cpp src\geo_world.cpp src\geo_countries.cpp
set LIBS=user32.lib gdi32.lib ws2_32.lib iphlpapi.lib psapi.lib advapi32.lib fwpuclnt.lib shell32.lib
set GLIBS=-luser32 -lgdi32 -lws2_32 -liphlpapi -lpsapi -ladvapi32 -lfwpuclnt -lshell32

where cl >nul 2>&1 && goto msvc
where g++ >nul 2>&1 && goto gcc
where clang++ >nul 2>&1 && goto clang
echo No C++ compiler found on PATH.
echo Open "x64 Native Tools Command Prompt for VS", or an MSYS2 UCRT64 shell, and run this again.
goto fail

:msvc
echo [build] using MSVC cl
rc /nologo /fo out\unatco.res unatco.rc || goto fail
cl /nologo /std:c++17 /O2 /EHsc /W3 /MT /utf-8 %SRC% out\unatco.res /Fe:out\unatco_netdef.exe /Fo:out\ /link /SUBSYSTEM:WINDOWS /MACHINE:X64 %LIBS% || goto fail
goto ok

:gcc
echo [build] using MinGW g++
set RES=
where windres >nul 2>&1 && (windres unatco.rc -O coff -o out\unatco_res.o && set RES=out\unatco_res.o)
if "%RES%"=="" echo [warn] windres not found: exe will not auto-request Administrator - right-click and "Run as administrator".
g++ -std=c++17 -O2 -Wall -Wno-unused-function -static -static-libgcc -static-libstdc++ -mwindows %SRC% %RES% -o out\unatco_netdef.exe %GLIBS% || goto fail
goto ok

:clang
echo [build] using clang++
echo [warn] no manifest embedded: right-click the exe and "Run as administrator".
clang++ -std=c++17 -O2 -Wno-unused-function -mwindows %SRC% -o out\unatco_netdef.exe %GLIBS% || goto fail
goto ok

:ok
echo.
echo Built: out\unatco_netdef.exe  (right-click - Run as administrator)
pause
exit /b 0

:fail
echo.
echo BUILD FAILED. Copy the error text above and send it back - I will fix it directly.
pause
exit /b 1
