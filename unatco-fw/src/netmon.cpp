#include "netmon.h"

namespace netmon {

static std::string utf8Path(const wchar_t* w) { return narrow(w); }

void enableDebugPrivilege() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(tok, FALSE, &tp, sizeof tp, nullptr, nullptr);
    }
    CloseHandle(tok);
}

bool isPrivileged() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION el{};
    DWORD len = 0;
    BOOL ok = GetTokenInformation(tok, TokenElevation, &el, sizeof el, &len);
    CloseHandle(tok);
    return ok && el.TokenIsElevated;
}

void snapshotProcesses(std::map<DWORD, ProcInfo>& out) {
    // Image path / creation time never change for a live process, so reuse them while the
    // (pid, name, parent) triple is unchanged instead of re-opening ~300 processes at 5 Hz.
    static std::map<DWORD, ProcInfo> cache;
    static Lock cacheLock;
    Guard cg(cacheLock);
    out.clear();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof pe;
    std::map<DWORD, ProcInfo> fresh;
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcInfo p;
            p.pid = pe.th32ProcessID;
            p.ppid = pe.th32ParentProcessID;
            p.threads = (int)pe.cntThreads;
            p.name = utf8Path(pe.szExeFile);
            if (p.pid == 0) p.name = "System Idle";
            auto cit = cache.find(p.pid);
            if (cit != cache.end() && cit->second.name == p.name && cit->second.ppid == p.ppid &&
                (cit->second.pathKnown || !cit->second.queryable)) {
                p.path = cit->second.path;
                p.pathKnown = cit->second.pathKnown;
                p.queryable = cit->second.queryable;
                p.created = cit->second.created;
                fresh[p.pid] = p;
                out[p.pid] = p;
                continue;
            }
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid);
            if (h) {
                p.queryable = true;
                wchar_t buf[MAX_PATH * 2];
                DWORD n = (DWORD)(sizeof buf / sizeof buf[0]);
                if (QueryFullProcessImageNameW(h, 0, buf, &n)) {
                    p.path = utf8Path(buf);
                    p.pathKnown = true;
                }
                FILETIME c, e, k, u;
                if (GetProcessTimes(h, &c, &e, &k, &u))
                    p.created = ((uint64_t)c.dwHighDateTime << 32) | c.dwLowDateTime;
                CloseHandle(h);
            }
            fresh[p.pid] = p;
            out[p.pid] = p;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    cache.swap(fresh);          // drops entries for processes that have exited
}

bool pidExists(DWORD pid) {
    if (pid == 0 || pid == 4) return true;  // Idle / System
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        DWORD code = 0;
        bool alive = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
        CloseHandle(h);
        return alive;
    }
    // Access denied means the process exists but we may not touch it.
    return GetLastError() == ERROR_ACCESS_DENIED;
}

static void* fetchTable(int family, bool tcp, DWORD* err) {
    DWORD size = 0;
    void* buf = nullptr;
    for (int tries = 0; tries < 6; tries++) {
        DWORD r;
        if (tcp)
            r = GetExtendedTcpTable(buf, &size, FALSE, (ULONG)family, TCP_TABLE_OWNER_PID_ALL, 0);
        else
            r = GetExtendedUdpTable(buf, &size, FALSE, (ULONG)family, UDP_TABLE_OWNER_PID, 0);
        if (r == NO_ERROR) { *err = 0; return buf; }
        free(buf);
        buf = nullptr;
        if (r != ERROR_INSUFFICIENT_BUFFER) { *err = r; return nullptr; }
        size += 4096;  // table can grow between the two calls
        buf = malloc(size);
        if (!buf) { *err = ERROR_NOT_ENOUGH_MEMORY; return nullptr; }
    }
    free(buf);
    *err = ERROR_INSUFFICIENT_BUFFER;
    return nullptr;
}

static uint16_t port16(DWORD p) { return ntohs((u_short)(p & 0xFFFF)); }

void readTables(std::vector<Conn>& out) {
    DWORD err = 0;
    if (void* t = fetchTable(AF_INET, true, &err)) {
        auto* tb = (MIB_TCPTABLE_OWNER_PID*)t;
        for (DWORD i = 0; i < tb->dwNumEntries; i++) {
            const auto& r = tb->table[i];
            Conn c;
            c.proto = Proto::TCP;
            c.local = IpAddr::from4dword(r.dwLocalAddr);
            c.remote = IpAddr::from4dword(r.dwRemoteAddr);
            c.lport = port16(r.dwLocalPort);
            c.rport = port16(r.dwRemotePort);
            c.pid = r.dwOwningPid;
            c.state = r.dwState;
            out.push_back(c);
        }
        free(t);
    }
    if (void* t = fetchTable(AF_INET6, true, &err)) {
        auto* tb = (MIB_TCP6TABLE_OWNER_PID*)t;
        for (DWORD i = 0; i < tb->dwNumEntries; i++) {
            const auto& r = tb->table[i];
            Conn c;
            c.proto = Proto::TCP;
            c.local = IpAddr::from6(r.ucLocalAddr);
            c.remote = IpAddr::from6(r.ucRemoteAddr);
            c.lport = port16(r.dwLocalPort);
            c.rport = port16(r.dwRemotePort);
            c.pid = r.dwOwningPid;
            c.state = r.dwState;
            out.push_back(c);
        }
        free(t);
    }
    if (void* t = fetchTable(AF_INET, false, &err)) {
        auto* tb = (MIB_UDPTABLE_OWNER_PID*)t;
        for (DWORD i = 0; i < tb->dwNumEntries; i++) {
            const auto& r = tb->table[i];
            Conn c;
            c.proto = Proto::UDP;
            c.local = IpAddr::from4dword(r.dwLocalAddr);
            c.remote = IpAddr();  // UDP table has no peer; ETW fills those in
            c.lport = port16(r.dwLocalPort);
            c.pid = r.dwOwningPid;
            out.push_back(c);
        }
        free(t);
    }
    if (void* t = fetchTable(AF_INET6, false, &err)) {
        auto* t6 = (MIB_UDP6TABLE_OWNER_PID*)t;
        for (DWORD i = 0; i < t6->dwNumEntries; i++) {
            const auto& r = t6->table[i];
            Conn c;
            c.proto = Proto::UDP;
            c.local = IpAddr::from6(r.ucLocalAddr);
            c.remote = IpAddr();
            c.remote.v6 = true;
            c.lport = port16(r.dwLocalPort);
            c.pid = r.dwOwningPid;
            out.push_back(c);
        }
        free(t);
    }
}

void refresh(NetState& st) {
    st.conns.clear();
    st.ghostPids.clear();
    readTables(st.conns);
    snapshotProcesses(st.procs);

    // Cross-view check: a socket whose owner PID is invisible to ToolHelp *and*
    // cannot be opened is what a process-hiding rootkit looks like from here.
    std::set<DWORD> checked;
    for (const auto& c : st.conns) {
        if (st.procs.count(c.pid) || checked.count(c.pid)) continue;
        checked.insert(c.pid);
        if (c.pid == 0 || c.pid == 4) continue;
        if (pidExists(c.pid)) {
            // Exists but wasn't in the snapshot: either it was created after the snapshot
            // (race) or it is hidden from enumeration. Re-snapshot once to rule out the race.
            std::map<DWORD, ProcInfo> again;
            snapshotProcesses(again);
            if (!again.count(c.pid)) st.ghostPids.insert(c.pid);
            else st.procs[c.pid] = again[c.pid];
        }
        // PID gone entirely: connection belonged to a process that just exited. Ignore.
    }
}

std::string tcpStateName(DWORD s) {
    switch (s) {
        case MIB_TCP_STATE_CLOSED: return "CLOSED";
        case MIB_TCP_STATE_LISTEN: return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD: return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING: return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default: return "-";
    }
}

}  // namespace netmon
