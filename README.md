# UNATCO // Network Defense Terminal

**Native Windows 10/11 (x64) firewall and network monitoring application written in C++17.**

UNATCO is a standalone network defense and monitoring application built directly on the Windows API. It combines connection monitoring, process inspection, network intelligence, persistent firewall rules, security event logging, and a software-rendered 3D globe into a single desktop interface.

The application is designed to operate without third-party libraries, package managers, external frameworks, or runtime downloads.

---

## Build Instructions

Build on Windows using one of the supported toolchains.

| Toolchain | Build instructions |
|---|---|
| Visual Studio Build Tools + Windows SDK | Run `build_msvc.bat` from an x64 Native Tools Command Prompt |
| MinGW-w64 (GCC 11+) | Run `build_mingw.bat` |
| Automatic detection | Double-click or execute `build.bat` |

**Output:** `out\unatco_netdef.exe`

The application requests administrator privileges through its executable manifest.

If the MinGW build fails with undefined references to `FWPM_*` symbols, use MSVC instead. This can occur because of missing Windows Filtering Platform GUID definitions in certain MinGW-w64 import libraries.

### Dependencies

The project uses:

- C++17 standard library
- Windows SDK headers
- Native Windows system APIs

No third-party libraries, package managers, NuGet/vcpkg dependencies, header-only libraries, or code generators are required.

Linked Windows system libraries:

- `user32`
- `gdi32`
- `ws2_32`
- `iphlpapi`
- `psapi`
- `advapi32`
- `fwpuclnt`
- `shell32`

`ntdll` and `dwmapi` are resolved dynamically at runtime.

The C/C++ runtime is statically linked.

All application functionality, including WHOIS, ETW consumption, WFP rule management, interface rendering, globe rendering, geographic outlines, and country data, is implemented within the project source.

No application code or geographic data is downloaded or executed at runtime.

---

## Features

### 1. Network Connection Monitoring

| Feature | Implementation |
|---|---|
| TCP connections | `GetExtendedTcpTable` |
| UDP endpoints | `GetExtendedUdpTable` |
| IPv4 and IPv6 | Supported |
| Process attribution | Owning PID |
| Refresh interval | 5 Hz |
| Connection lifecycle | Open, close, and movement tracking |

The application monitors network endpoints and associates connections with their owning processes.

### 2. Kernel ETW Monitoring

A real-time Event Tracing for Windows (ETW) session consumes events from:

`Microsoft-Windows-Kernel-Network`

This provides visibility into network activity that may occur between polling intervals, including short-lived connections and UDP peer activity.

ETW-detected connections are identified separately in the interface and included in the event history.

### 3. Hidden Process Detection

The application compares kernel-observed network activity against available process enumeration results.

If a socket belongs to a PID that cannot be located through normal process enumeration, it is identified as:

`GHOST_PID`

These findings receive a critical classification.

This indicates an attribution discrepancy, not definitive proof of a rootkit or malicious process.

### 4. Process-Level Network Intelligence

Selecting a process displays its associated network endpoints, including:

- Local IP addresses and ports.
- Remote IP addresses and ports.
- TCP and UDP activity.
- IPv4 and IPv6 endpoints.
- Local versus external address classification.

### 5. IP Registration Intelligence

An integrated WHOIS client implements RFC 3912 and follows IANA registry referrals.

Supported regional registries:

- ARIN
- RIPE NCC
- APNIC
- LACNIC
- AFRINIC

Available registration information includes:

- Network owner.
- Netname.
- CIDR allocation.
- Registration date.
- Abuse contact.
- Reverse DNS.

Registration information is associated with foreign IP addresses and incorporated into the network intelligence interface.

### 6. Software-Rendered 3D Globe

The application includes an original orthographic globe renderer.

Features include:

- User location indicator.
- Animated arcs representing remote IP connections.
- Country labels.
- Connection counts by country.
- Interactive globe rotation.
- Automatic rotation.

Controls:

- Drag to rotate.
- Double-click to toggle automatic rotation.

Geographic positioning uses country centroids rather than attempting to determine the physical location of individual servers.

Optional location override:

`unatco_netdef.exe --home 41.88,-87.63`

Providing this argument bypasses the application's public-IP location lookup.

### 7. Firewall Management

Firewall rules are implemented using the Windows Filtering Platform (WFP).

Available actions:

- Block an individual application.
- Block incoming and outgoing traffic for an application.
- Block a remote IP address.
- Persist firewall rules across application restarts.
- Recreate missing filters from saved rule definitions.

Rules are stored in:

`unatco_netdef.rules`

Blocking applies to subsequent connection attempts. Existing connections may require manual termination.

**SEVER CONN**

Resets an active IPv4 TCP connection.

**TERMINATE**

Terminates the selected process, subject to Windows access restrictions.

### 8. Behavioral Memory Inspection

The application does not rely on conventional static byte signatures as its primary malware detection mechanism.

Instead, it performs behavioral and memory-based inspections of network-active processes, alongside slower rotating inspections of other processes.

Detection categories include:

**Executable Memory Analysis**
- Private or mapped executable memory without an identifiable backing file.
- Unusual read/write/execute memory regions.
- Executable memory outside expected image mappings.

**Manual Mapping and Injection**
- PE images outside normal image mappings.
- Reflective DLL injection indicators.
- Manual mapping indicators.
- Unbacked thread start addresses.

**Process Integrity**
- Differences between in-memory executable headers and disk images.
- Discrepancies between reported executable paths and kernel-side mapped file names.
- Indicators associated with process hollowing.
- Indicators associated with herpaderping and ghosting.
- Non-image main module detection.

**Shellcode and Execution Patterns**
- PEB walking patterns.
- API hashing loops.
- Direct syscall stubs.
- Get-PC instruction patterns.
- FPU-based decoder patterns.
- Shellcode prologues.
- High-entropy executable payloads.

**Runtime Mutation**
- Changes to executable memory regions between inspections.

**Network Behavior**
- Periodic beaconing patterns.
- Low-jitter connection intervals.
- System-process masquerading indicators.
- Unusual parent-child process relationships.
- Network activity from unexpected system utilities.
- Connections involving commonly abused ports.
- Network activity from processes that ordinarily have no networking requirement.

Findings contribute to a behavioral score ranging from 0–100.

Individual findings contribute independently to the overall score.

JIT-enabled applications, including browsers, .NET applications, JVM applications, and Electron applications, receive reduced weights for certain code-related findings. These checks are not completely disabled.

**Important:** Behavioral scores are heuristic indicators, not definitive malware verdicts. Multiple indicators should be evaluated together.

### 9. Connection History and Tamper-Evident Logging

The application maintains a persistent event history.

Each UTC day receives its own log file:

`netdef-YYYYMMDD.log`

Recorded events include:

- New TCP connections.
- New UDP endpoints.
- Kernel ETW connection observations.
- Connection closures.
- Endpoint movements.
- Security alerts.
- IP registration information.
- Country and network allocation information.
- Abuse contact information.

Loopback traffic and listening sockets are excluded.

The on-screen CLEAR LOG function clears only the displayed event list. It does not delete persistent history files.

#### Hash Chain Integrity

Each record contains:

- Sequence number.
- UTC timestamp.
- Event type.
- Event-specific fields.
- Previous record SHA-256 hash.
- Current record SHA-256 hash.

The hash chain continues across daily log files.

Supported event types:

`OPEN`, `CLOSE`, `MOVE`, `CONN`, `REG`, `ALERT`

The application provides a log verification function that checks the chain and identifies the first invalid record.

Verification can also be performed from the command line:

`unatco_netdef.exe --verify`

Or against a specified directory:

`unatco_netdef.exe --verify "D:\netlogs"`

While the application is running, active log files are opened with append-only access restrictions and sharing denied. Completed files are marked read-only.

#### Log Storage

The LOG FOLDER button allows the storage directory to be changed.

Alternatively:

`unatco_netdef.exe --log-dir "D:\netlogs"`

The selected directory is saved in:

`unatco_netdef.cfg`

Default location:

`logs\` next to the executable.

Logs are never automatically deleted.

**Security limitations**

The logging system is tamper-evident, not tamper-proof.

An administrator or kernel-level attacker may still replace, modify, or delete log files.

Removing only the newest records may leave the remaining chain valid.

For stronger historical integrity, periodically save the displayed chain head somewhere separate from the logging directory. External storage or write-once media provides additional protection.

A previously saved chain head can establish whether the history preceding that checkpoint has changed.

---

## Privacy and Network Communications

The application performs the following external communications:

| Destination | Protocol | Purpose |
|---|---|---|
| `whois.iana.org` | TCP/43 | WHOIS registry referral |
| Regional WHOIS registries | TCP/43 | IP registration information |
| `ip-api.com` | HTTP | Public-IP-based location lookup |

WHOIS requests are made for foreign IP addresses encountered during network monitoring.

The regional registry responsible for an allocation receives the relevant WHOIS queries.

The public-IP location lookup can be bypassed using the `--home` argument.

No other external communications are intentionally performed by the application.

---

## Source Code Structure

| File | Responsibility |
|---|---|
| `src/netmon.*` | Network tables, connection monitoring, process attribution, hidden PID checks |
| `src/etw.*` | Kernel ETW session and event consumption |
| `src/memscan.*` | Process memory inspection |
| `src/monitor.*` | Monitoring scheduler and behavioral analysis |
| `src/intel.*` | WHOIS, reverse DNS, and location services |
| `src/fw.*` | Windows Filtering Platform firewall rules |
| `src/geo_*.cpp` | Geographic country data and world outlines |
| `src/globe.*` | Software-rendered globe |
| `src/ui.h` | Interface theme and widgets |
| `src/model.*` | Application data models |
| `src/view.cpp` | Interface rendering and presentation |
| `src/main.cpp` | Application entry point |

---

## Known Limitations

UNATCO operates within the restrictions of user-mode Windows applications.

The following limitations apply:

**Kernel-Level Threats**

A kernel-mode rootkit capable of hiding activity from Windows APIs and ETW may evade detection.

**Protected Processes**

Protected Process Light (PPL) restrictions may prevent memory inspection. Inaccessible processes are reported as unreadable rather than automatically classified as clean.

**Firewall Enforcement**

A user-mode application cannot reliably intercept every new connection and pause it for interactive approval.

That capability requires an appropriately implemented and signed kernel callout driver.

WFP rules apply to subsequent connection attempts. Existing connections may need to be terminated separately.

**Geographic Accuracy**

Country attribution represents the registration location of the IP allocation, not necessarily the physical location of the server.

CDNs, VPN providers, and distributed hosting infrastructure may operate across multiple countries.

**ETW Event Parsing**

The ETW event layouts are parsed using fixed offsets for the supported events in:

`src/etw.cpp`

Changes to Windows event layouts may require compatibility updates.

**Display Scaling**

The interface uses pixel-based dimensions and is not fully DPI-aware. Windows may scale the application on high-DPI displays.

**Detection Reliability**

No behavioral monitoring system can guarantee detection of all malicious software. Findings are indicators requiring interpretation, not proof of compromise.

---

## Development Status

The project is implemented against the Windows API but has not yet undergone a verified compilation and runtime test on Windows hardware.

The initial build may require compiler-specific corrections or runtime adjustments.

The implementation should therefore be considered experimental until it has passed:

- Successful MSVC compilation.
- Successful MinGW compilation where supported.
- Windows 10 and Windows 11 runtime testing.
- IPv4 and IPv6 connection monitoring tests.
- ETW event validation.
- WFP rule creation and persistence tests.
- Process memory inspection tests.
- Log integrity and tampering tests.
- Extended runtime stability testing.

Bug reports, reproducible test cases, and implementation improvements are welcome.

---

**UNATCO // Network Defense Terminal**

*Local monitoring. Native enforcement. Persistent intelligence.*
