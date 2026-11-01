UNATCO // Network Defense Terminal
Native Windows 10/11 (x64) firewall + network monitor, written from scratch in C++17.

Build (on Windows)
Pick one toolchain. Nothing is downloaded by either script.

Toolchain	Command
Any of the below	double-click or run build.bat (auto-detects the compiler on your PATH)
Visual Studio Build Tools (+ Windows SDK)	build_msvc.bat from the x64 Native Tools Command Prompt
MinGW-w64 (e.g. MSYS2 UCRT64, g++ 11+)	run build_mingw.bat
If the MinGW link fails with undefined reference to FWPM_* (a known mingw-w64 import-library gap for the WFP GUID constants), build with MSVC instead.

Output: out\unatco_netdef.exe. It requests Administrator (manifest) because the Windows Filtering Platform, kernel ETW sessions and cross-process memory inspection all need it.

Optional: unatco_netdef.exe --home 41.88,-87.63 pins your location on the globe and skips the one-time location lookup.

"No imports"
Source contains only the C++ standard library and Windows system headers. No third-party library, package, NuGet/vcpkg dependency, header-only lib, or code generator.
Links only Windows system DLLs (user32 gdi32 ws2_32 iphlpapi psapi advapi32 fwpuclnt shell32, ntdll/dwmapi resolved at run time). The C/C++ runtime is statically linked.
Everything else - WHOIS client, ETW consumer, WFP rule management, GDI widgets, the software globe, the world outline data, the country table - is original code in src/.
No code or data is downloaded or executed at run time.
What it does
Feature	How
Every socket, per process	GetExtendedTcpTable/UdpTable (v4+v6, owning PID) polled at 5 Hz
Short-lived / "stealth" connections	Real-time kernel ETW session (Microsoft-Windows-Kernel-Network) - sees connections that open and close between polls, and UDP peers. Shown with * and counted in the header
Hidden processes	Sockets owned by a PID that process enumeration cannot see, but the kernel can open -> GHOST_PID (critical)
Local vs foreign IPs per app	Select a process: every local and foreign endpoint is listed, scope-tagged
Registration / company data	Own WHOIS client (RFC 3912): IANA referral -> ARIN/RIPE/APNIC/LACNIC/AFRINIC. Owner, netname, CIDR, registered date, abuse contact, reverse DNS
Globe	Software-rendered orthographic globe. Your position (from your public IP), one animated arc per remote IP, country labels with counts. Drag to rotate, double-click to toggle auto-rotate
Blocking	Persistent WFP block filters per application (in+out) or per remote IP; SEVER CONN resets a live IPv4 TCP connection; TERMINATE ends a process
In-memory / polymorphic malware detection
Byte signatures cannot catch polymorphic code, so there are none. Each network-active process (and a slow rotation over all others) gets a behavioural memory inspection:

executable memory with no file behind it (private/mapped RX/RWX)
PE images living outside image mappings (reflective DLL injection, manual mapping)
process hollowing / herpaderping / ghosting: image header in memory vs file on disk, kernel-side mapped file name vs reported image, non-image main module, deleted image
threads whose start address is unbacked memory (injection)
re-encoding-proof shellcode behaviours: PEB walking, API-hash loops, direct syscall stubs, get-PC tricks, FPU decoder stubs, shellcode prologues, high-entropy executable payloads
runtime mutation: executable regions whose bytes change between scans
behaviour: beaconing (low-jitter periodic connections), system-process masquerading, wrong parent (svchost), living-off-the-land binaries talking out, C2-typical ports, processes that should never use the network
Scores 0-100 (sum of independent findings). JIT hosts (browsers, .NET, JVM, Electron) legitimately generate code, so their code-related weights are reduced - not removed.

Connection history log (tamper-evident)
Every new connection (local and foreign, TCP and UDP incl. kernel-trace sightings), every security alert, and the registry data (owner, country, range, abuse contact) for each foreign IP are written to a permanent history, one file per UTC day: <folder>\netdef-YYYYMMDD.log. Loopback traffic and listening sockets are not logged. "CLEAR LOG" only clears the on-screen list, never the files.

Choose the folder: LOG FOLDER button (bottom panel), or --log-dir "D:\netlogs". The choice is remembered in unatco_netdef.cfg. Default: logs\ next to the exe. Logs are never auto-deleted.
Tamper-evident, not tamper-proof. Each record contains the SHA-256 of the previous record (across days too). Editing, deleting, inserting or reordering any record breaks the chain and VERIFY LOG (or unatco_netdef.exe --verify ["folder"]) names the first bad record. While the app runs the file is held append-only with sharing denied, and finished files are marked read-only.
What it cannot stop: an administrator or kernel-level malware can still replace or delete the files, and deleting only the newest records leaves a valid chain. Copy the "chain head" shown in the bottom panel somewhere safe now and then (or keep the folder on a different drive / write-once media); a saved head proves nothing older than it was changed.
Record format: seq <TAB> UTC time <TAB> type <TAB> fields... <TAB> prevHash <TAB> hash, types OPEN CLOSE MOVE CONN REG ALERT. Plain text - readable in any editor or spreadsheet.
Honest limits
Not compiled or run by the author on Windows hardware. It was written against the Win32 API and reviewed by reading; expect to fix a few compile or runtime errors on first build. Report them.
No tool can promise to detect all stealth malware. A kernel-mode rootkit, a protected (PPL) process, or malware that hides from user-mode APIs and ETW can evade this. Unreadable processes are marked as such, never silently treated as clean.
A user-mode firewall cannot hold a brand-new connection and ask you first (that needs a signed kernel callout driver). Blocks apply to the next connection attempt; use SEVER CONN for live ones.
Country = where the IP block is registered, placed at the country's centroid. It is not a physical server location (CDNs and VPNs register in one country, serve from another).
The kernel ETW event layouts are parsed by fixed offsets for the events listed in src/etw.cpp.
UI is pixel-sized (not DPI-aware); on high-DPI displays Windows will scale it.
Privacy / network use
WHOIS queries go to whois.iana.org and the responsible registry, TCP/43, for each foreign IP you connect to (this is how registration data is obtained).
One plain-HTTP request to ip-api.com finds your own location. Use --home lat,lon to avoid it.
Nothing else leaves the machine.
Files
src/netmon.* tables, process snapshot, hidden-PID check - src/etw.* kernel trace - src/memscan.* memory inspection - src/monitor.* scheduler + behaviour analysis - src/intel.* WHOIS/rDNS/own location - src/fw.* WFP rules - src/geo_*.cpp country table + outlines - src/globe.* renderer - src/ui.h theme/widgets - src/model.*, src/view.cpp, src/main.cpp UI.

Block rules persist in unatco_netdef.rules next to the exe and are re-created if the filters vanish.

 
    
