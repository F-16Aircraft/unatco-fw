#pragma once
#include "common.h"

struct ProcInfo {
    DWORD pid = 0, ppid = 0;
    std::string name;        // exe base name
    std::string path;        // full image path ("" if not readable)
    bool pathKnown = false;
    bool queryable = false;  // OpenProcess succeeded
    uint64_t created = 0;    // FILETIME as 64-bit
    int threads = 0;
};

// One consistent view of the machine's network + process state.
struct NetState {
    std::vector<Conn> conns;                 // polled tables + recent ETW-only events
    std::map<DWORD, ProcInfo> procs;
    std::set<DWORD> ghostPids;               // sockets owned by PIDs no process view can see
};

namespace netmon {
// Enumerate processes (ToolHelp) with image paths.
void snapshotProcesses(std::map<DWORD, ProcInfo>& out);
// Read TCP/UDP v4+v6 tables with owning PID.
void readTables(std::vector<Conn>& out);
// Brute-force PID probe: does the kernel know this PID even if ToolHelp does not list it?
bool pidExists(DWORD pid);
// Full refresh: tables + processes + ghost-PID cross-view check.
void refresh(NetState& st);
std::string tcpStateName(DWORD s);
bool isPrivileged();                          // running elevated?
void enableDebugPrivilege();
}  // namespace netmon
