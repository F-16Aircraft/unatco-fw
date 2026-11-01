@echo off
REM Build with MinGW-w64 (g++ 11+ x86_64, e.g. from MSYS2 ucrt64). Statically links the C++ runtime.
setlocal
if not exist out mkdir out
windres unatco.rc -O coff -o out\unatco_res.o || goto :err
g++ -std=c++17 -O2 -Wall -Wno-unused-function -static -static-libgcc -static-libstdc++ -mwindows ^
    src\main.cpp src\view.cpp src\model.cpp src\globe.cpp src\monitor.cpp src\memscan.cpp ^
    src\netmon.cpp src\etw.cpp src\intel.cpp src\fw.cpp src\history.cpp src\geo_world.cpp src\geo_countries.cpp ^
    out\unatco_res.o -o out\unatco_netdef.exe ^
    -luser32 -lgdi32 -lws2_32 -liphlpapi -lpsapi -ladvapi32 -lfwpuclnt -lshell32 || goto :err
echo.
echo Built: out\unatco_netdef.exe
goto :eof
:err
echo BUILD FAILED
exit /b 1
