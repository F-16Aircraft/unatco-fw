#include "etw.h"
#include <evntrace.h>
#include <evntcons.h>

namespace etw {

// {7DD42A49-5329-4832-8DFD-43D979153A88}  Microsoft-Windows-Kernel-Network
static const GUID kProvider =
    {0x7dd42a49, 0x5329, 0x4832, {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};

static const wchar_t* kSession = L"UNATCO_NETDEF_TRACE";

static Lock g_lock;
static std::deque<EtwConn> g_q;
static TRACEHANDLE g_session = 0;
static TRACEHANDLE g_trace = INVALID_PROCESSTRACE_HANDLE;
static HANDLE g_thread = nullptr;
static volatile bool g_running = false;

static uint16_t rd16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }  // network order
static uint32_t rd32(const uint8_t* p) { uint32_t v; memcpy(&v, p, 4); return v; }

static void WINAPI onEvent(PEVENT_RECORD rec) {
    if (!rec || !rec->UserData) return;
    const USHORT id = rec->EventHeader.EventDescriptor.Id;
    const uint8_t* d = (const uint8_t*)rec->UserData;
    const USHORT len = rec->UserDataLength;

    bool v6 = false, udp = false, inbound = false;
    switch (id) {
        case 10: case 11: case 12: case 15: break;                 // TCP v4 send/recv/connect/accept
        case 26: case 27: case 28: case 31: v6 = true; break;      // TCP v6
        case 42: case 43: udp = true; break;                       // UDP v4 send/recv
        case 58: case 59: udp = true; v6 = true; break;            // UDP v6
        default: return;
    }
    if (id == 11 || id == 15 || id == 27 || id == 31 || id == 43 || id == 59) inbound = true;

    // Layout (stable across these events): PID u32, size u32, daddr, saddr, dport u16, sport u16
    Conn c;
    c.proto = udp ? Proto::UDP : Proto::TCP;
    c.fromEtw = true;
    if (!v6) {
        if (len < 20) return;
        c.pid = rd32(d);
        c.remote = IpAddr::from4(d + 8);
        c.local = IpAddr::from4(d + 12);
        c.rport = rd16(d + 16);
        c.lport = rd16(d + 18);
    } else {
        if (len < 44) return;
        c.pid = rd32(d);
        c.remote = IpAddr::from6(d + 8);
        c.local = IpAddr::from6(d + 24);
        c.rport = rd16(d + 40);
        c.lport = rd16(d + 42);
    }
    (void)inbound;
    c.state = udp ? 0 : MIB_TCP_STATE_ESTAB;

    EtwConn e;
    e.c = c;
    e.tick = nowMs();
    Guard g(g_lock);
    if (g_q.size() > 20000) g_q.pop_front();   // bound memory if the UI stalls
    g_q.push_back(e);
}

static DWORD WINAPI traceThread(LPVOID) {
    ProcessTrace(&g_trace, 1, nullptr, nullptr);   // blocks until the session is closed
    g_running = false;
    return 0;
}

static std::vector<uint8_t> makeProps(ULONG* total) {
    ULONG nameBytes = (ULONG)((wcslen(kSession) + 1) * sizeof(wchar_t));
    *total = (ULONG)sizeof(EVENT_TRACE_PROPERTIES) + nameBytes;
    std::vector<uint8_t> buf(*total, 0);
    auto* p = (EVENT_TRACE_PROPERTIES*)buf.data();
    p->Wnode.BufferSize = *total;
    p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p->Wnode.ClientContext = 1;                       // QPC timestamps
    p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    p->LoggerNameOffset = (ULONG)sizeof(EVENT_TRACE_PROPERTIES);
    return buf;
}

bool start() {
    if (g_running) return true;
    ULONG total = 0;
    // Kill a stale session left behind by a crashed previous run.
    {
        auto pb = makeProps(&total);
        ControlTraceW(0, kSession, (EVENT_TRACE_PROPERTIES*)pb.data(), EVENT_TRACE_CONTROL_STOP);
    }
    auto pb = makeProps(&total);
    auto* props = (EVENT_TRACE_PROPERTIES*)pb.data();
    ULONG r = StartTraceW(&g_session, kSession, props);
    if (r != ERROR_SUCCESS) return false;
    r = EnableTraceEx2(g_session, &kProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                       TRACE_LEVEL_INFORMATION, 0, 0, 0, nullptr);
    if (r != ERROR_SUCCESS) { stop(); return false; }

    EVENT_TRACE_LOGFILEW lf{};
    lf.LoggerName = (LPWSTR)kSession;
    lf.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    lf.EventRecordCallback = onEvent;
    g_trace = OpenTraceW(&lf);
    if (g_trace == INVALID_PROCESSTRACE_HANDLE) { stop(); return false; }

    g_running = true;
    g_thread = CreateThread(nullptr, 0, traceThread, nullptr, 0, nullptr);
    if (!g_thread) { g_running = false; stop(); return false; }
    return true;
}

void stop() {
    ULONG total = 0;
    auto pb = makeProps(&total);
    ControlTraceW(g_session, kSession, (EVENT_TRACE_PROPERTIES*)pb.data(), EVENT_TRACE_CONTROL_STOP);
    if (g_trace != INVALID_PROCESSTRACE_HANDLE) { CloseTrace(g_trace); g_trace = INVALID_PROCESSTRACE_HANDLE; }
    if (g_thread) { WaitForSingleObject(g_thread, 2000); CloseHandle(g_thread); g_thread = nullptr; }
    g_session = 0;
    g_running = false;
}

bool running() { return g_running; }

void drain(std::vector<EtwConn>& out) {
    Guard g(g_lock);
    while (!g_q.empty()) { out.push_back(g_q.front()); g_q.pop_front(); }
}

}  // namespace etw
