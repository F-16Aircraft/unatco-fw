#include "history.h"
#include "logchain.h"
#include "netmon.h"

namespace history {

static Lock g_lock;
static std::wstring g_dir;
static std::wstring g_curPath;
static HANDLE g_file = INVALID_HANDLE_VALUE;
static std::string g_day;
static std::string g_head = logchain::genesis();
static uint64_t g_seq = 0, g_records = 0, g_lastFlush = 0, g_failures = 0;
static bool g_ready = false;
static std::map<std::string, uint64_t> g_seen;     // dedupe of conn() records

// ---------------------------------------------------------------- paths / config
static std::wstring exeDir() {
    wchar_t p[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, p, MAX_PATH);
    std::wstring w(p, n);
    size_t i = w.find_last_of(L"\\/");
    return i == std::wstring::npos ? L"" : w.substr(0, i + 1);
}
static std::wstring cfgPath() { return exeDir() + L"unatco_netdef.cfg"; }

static std::string loadCfgFolder() {
    FILE* f = _wfopen(cfgPath().c_str(), L"rb");
    if (!f) return "";
    char line[2048];
    std::string out;
    while (fgets(line, sizeof line, f)) {
        std::string s = trim(line);
        if (s.compare(0, 8, "log_dir=") == 0) out = s.substr(8);
    }
    fclose(f);
    return out;
}
static void saveCfgFolder(const std::string& dir) {
    FILE* f = _wfopen(cfgPath().c_str(), L"wb");
    if (!f) return;
    fprintf(f, "log_dir=%s\n", dir.c_str());
    fclose(f);
}

static bool makeDirs(const std::wstring& path) {
    for (size_t i = 3; i <= path.size(); i++) {         // skip "C:\" style root
        if (i == path.size() || path[i] == L'\\' || path[i] == L'/') {
            std::wstring part = path.substr(0, i);
            if (!part.empty()) CreateDirectoryW(part.c_str(), nullptr);
        }
    }
    DWORD a = GetFileAttributesW(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

static std::string stamp(std::string* day) {
    SYSTEMTIME t;
    GetSystemTime(&t);
    char b[48], d[16];
    snprintf(b, sizeof b, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
    snprintf(d, sizeof d, "%04d%02d%02d", t.wYear, t.wMonth, t.wDay);
    if (day) *day = d;
    return b;
}

static std::wstring dayPath(const std::string& day) { return g_dir + L"\\netdef-" + widen(day) + L".log"; }

static void setReadOnly(const std::wstring& p, bool ro) {
    DWORD a = GetFileAttributesW(p.c_str());
    if (a == INVALID_FILE_ATTRIBUTES) return;
    a = ro ? (a | FILE_ATTRIBUTE_READONLY) : (a & ~(DWORD)FILE_ATTRIBUTE_READONLY);
    SetFileAttributesW(p.c_str(), a);
}

// ---------------------------------------------------------------- file reading helpers
static bool readWhole(const std::wstring& path, std::string& out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    char buf[65536];
    DWORD got = 0;
    out.clear();
    while (ReadFile(h, buf, sizeof buf, &got, nullptr) && got) out.append(buf, got);
    CloseHandle(h);
    return true;
}

static void splitLines(const std::string& data, std::vector<std::string>& lines) {
    size_t p = 0;
    while (p < data.size()) {
        size_t e = data.find('\n', p);
        if (e == std::string::npos) e = data.size();
        std::string l = data.substr(p, e - p);
        if (!l.empty() && l.back() == '\r') l.pop_back();
        if (!l.empty()) lines.push_back(l);
        p = e + 1;
    }
}

static std::vector<std::wstring> listLogs(const std::wstring& dir) {
    std::vector<std::wstring> names;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\netdef-*.log").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return names;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) names.push_back(fd.cFileName);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    std::sort(names.begin(), names.end());
    return names;
}

// Continue the existing chain if the folder already holds logs.
static bool loadHead() {
    g_head = logchain::genesis();
    g_seq = 0;
    auto names = listLogs(g_dir);
    for (size_t i = names.size(); i-- > 0;) {
        std::string data;
        if (!readWhole(g_dir + L"\\" + names[i], data)) continue;
        std::vector<std::string> lines;
        splitLines(data, lines);
        if (lines.empty()) continue;
        std::string body, prev, hash;
        if (!logchain::splitLine(lines.back(), body, prev, hash)) return false;   // damaged tail
        g_head = hash;
        g_seq = strtoull(body.c_str(), nullptr, 10);
        return true;
    }
    return true;
}

// ---------------------------------------------------------------- writing
static bool openToday() {
    std::string day;
    stamp(&day);
    if (g_file != INVALID_HANDLE_VALUE && day == g_day) return true;
    if (g_file != INVALID_HANDLE_VALUE) {                  // day rollover: seal yesterday's file
        FlushFileBuffers(g_file);
        CloseHandle(g_file);
        g_file = INVALID_HANDLE_VALUE;
        setReadOnly(g_curPath, true);
    }
    std::wstring p = dayPath(day);
    setReadOnly(p, false);                                  // we marked it read-only on last exit
    // FILE_APPEND_DATA only: every write goes to the end. Share READ only: while we run, no other
    // process can open this file for writing or delete/rename it.
    g_file = CreateFileW(p.c_str(), FILE_APPEND_DATA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr,
                         OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (g_file == INVALID_HANDLE_VALUE) return false;
    g_day = day;
    g_curPath = p;
    return true;
}

static bool writeLocked(const char* type, const std::vector<std::string>& fields, bool flushNow) {
    if (!g_ready || !openToday()) { g_failures++; return false; }
    std::string body = std::to_string(g_seq + 1) + "\t" + stamp(nullptr) + "\t" + type;
    for (auto& f : fields) body += "\t" + logchain::scrub(f);
    std::string nh;
    std::string line = logchain::seal(g_head, body, &nh) + "\n";
    DWORD w = 0;
    if (!WriteFile(g_file, line.data(), (DWORD)line.size(), &w, nullptr) || w != line.size()) {
        g_failures++;
        return false;
    }
    g_seq++;
    g_head = nh;
    g_records++;
    uint64_t now = nowMs();
    if (flushNow || now - g_lastFlush > 2000) { FlushFileBuffers(g_file); g_lastFlush = now; }
    return true;
}

static void writeOpen(const std::string& note) {
    wchar_t host[64] = L"?";
    DWORD n = 64;
    GetComputerNameW(host, &n);
    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    writeLocked("OPEN", {"host=" + narrow(host), "exe=" + narrow(exe), note}, true);
}

static void closeFile(bool markReadOnly) {
    if (g_file != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(g_file);
        CloseHandle(g_file);
        g_file = INVALID_HANDLE_VALUE;
        if (markReadOnly) setReadOnly(g_curPath, true);
    }
}

static void sealOldFiles() {                                // everything except today's file is read-only
    std::string day;
    stamp(&day);
    for (auto& n : listLogs(g_dir))
        if (n != L"netdef-" + widen(day) + L".log") setReadOnly(g_dir + L"\\" + n, true);
}

// ---------------------------------------------------------------- public API
bool init(const std::string& folder, std::string* err) {
    Guard g(g_lock);
    std::string f = folder;
    if (f.empty()) f = loadCfgFolder();
    else saveCfgFolder(f);                                  // an explicit --log-dir is remembered
    g_dir = f.empty() ? exeDir() + L"logs" : widen(f);
    while (g_dir.size() > 3 && (g_dir.back() == L'\\' || g_dir.back() == L'/')) g_dir.pop_back();
    if (!makeDirs(g_dir)) { if (err) *err = "cannot create log folder"; return false; }
    bool tailOk = loadHead();
    g_ready = true;
    if (!openToday()) { g_ready = false; if (err) *err = "cannot open log file (is the folder writable?)"; return false; }
    sealOldFiles();
    writeOpen(tailOk ? "chain=continued" : "WARNING=previous log tail unreadable, chain restarted");
    return true;
}

void shutdown() {
    Guard g(g_lock);
    if (!g_ready) return;
    writeLocked("CLOSE", {"head_before_close=" + g_head}, true);
    closeFile(true);
    g_ready = false;
}

bool setFolder(const std::string& folder, std::string* err) {
    if (folder.empty()) { if (err) *err = "empty folder"; return false; }
    Guard g(g_lock);
    std::wstring nd = widen(folder);
    while (nd.size() > 3 && (nd.back() == L'\\' || nd.back() == L'/')) nd.pop_back();
    if (nd == g_dir) return true;
    if (!makeDirs(nd)) { if (err) *err = "cannot create that folder"; return false; }
    // Probe first: don't abandon the old folder if the new one is not writable.
    std::wstring probe = nd + L"\\.netdef_probe";
    HANDLE h = CreateFileW(probe.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
    if (h == INVALID_HANDLE_VALUE) { if (err) *err = "that folder is not writable"; return false; }
    CloseHandle(h);

    std::string oldHead = g_head;
    writeLocked("MOVE", {"to=" + narrow(nd.c_str()), "head=" + oldHead}, true);
    closeFile(true);
    g_dir = nd;
    g_day.clear();
    bool tailOk = loadHead();
    if (!openToday()) { g_ready = false; if (err) *err = "cannot open log file in new folder"; return false; }
    sealOldFiles();
    writeOpen(std::string("moved_from_head=") + oldHead + (tailOk ? "" : " WARNING=tail unreadable"));
    saveCfgFolder(narrow(nd.c_str()));
    g_seen.clear();
    return true;
}

std::string folder() { Guard g(g_lock); return narrow(g_dir.c_str()); }
std::string configuredFolder() {
    std::string f = loadCfgFolder();
    return f.empty() ? narrow((exeDir() + L"logs").c_str()) : f;
}
std::string head() { Guard g(g_lock); return g_head; }
uint64_t records() { Guard g(g_lock); return g_records; }

static bool isLoopback(const IpAddr& a) {
    if (!a.v6) return a.b[0] == 127;
    for (int i = 0; i < 15; i++) if (a.b[i]) return false;
    return a.b[15] == 1;
}

void conn(const Conn& c, const std::string& proc, const std::string& path) {
    if (c.proto == Proto::TCP && c.state == MIB_TCP_STATE_LISTEN) return;
    if (c.remote.isZero()) return;
    if (isLoopback(c.remote) || isLoopback(c.local)) return;      // loopback chatter is noise
    const bool tcp = c.proto == Proto::TCP;
    std::string key = std::to_string(c.pid) + (tcp ? "T" : "U") + c.remote.str() + ":" + std::to_string(c.rport);
    if (tcp) key += "<" + std::to_string(c.lport);                 // each TCP connection is distinct
    uint64_t now = nowMs();
    Guard g(g_lock);
    auto it = g_seen.find(key);
    if (it != g_seen.end() && now - it->second < (tcp ? 600000ull : 10000ull)) return;
    if (g_seen.size() > 30000) g_seen.clear();
    g_seen[key] = now;
    bool foreign = !c.remote.isLocal();
    writeLocked("CONN", {"pid=" + std::to_string(c.pid), "proc=" + proc, "path=" + path,
                         tcp ? "TCP" : "UDP", foreign ? "FOREIGN" : "LOCAL",
                         "local=" + c.local.str() + ":" + std::to_string(c.lport),
                         "remote=" + c.remote.str() + ":" + std::to_string(c.rport),
                         tcp ? netmon::tcpStateName(c.state) : "-", c.fromEtw ? "src=ETW" : "src=TABLE"}, false);
}

void registry(const IpAddr& ip, const WhoisInfo& w) {
    Guard g(g_lock);
    writeLocked("REG", {"ip=" + ip.str(), w.failed ? "status=FAILED" : "status=OK", "cc=" + w.country,
                        "owner=" + w.org, "net=" + w.netname, "range=" + (w.cidr.empty() ? w.range : w.cidr),
                        "registered=" + w.registered, "abuse=" + w.abuse, "registry=" + w.registry,
                        "host=" + w.host, w.failed ? "note=" + w.note : std::string("note=")}, false);
}

void alert(Sev sev, DWORD pid, const std::string& proc, const std::string& code, const std::string& text) {
    static const char* names[] = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"};
    Guard g(g_lock);
    writeLocked("ALERT", {std::string("sev=") + names[(int)sev], "pid=" + std::to_string(pid), "proc=" + proc,
                          "code=" + code, "text=" + text}, true);
}

std::string verify(const std::string& folderUtf8, bool* ok) {
    Guard g(g_lock);
    if (ok) *ok = false;
    std::wstring dir = folderUtf8.empty() ? g_dir : widen(folderUtf8);
    auto names = listLogs(dir);
    if (names.empty()) return "No log files found in " + narrow(dir.c_str());

    std::string prev;                 // hash the next record must chain from
    bool first = true;
    std::string note;
    size_t total = 0;
    for (size_t i = 0; i < names.size(); i++) {
        std::string data;
        if (!readWhole(dir + L"\\" + names[i], data)) return "Cannot read " + narrow(names[i].c_str());
        std::vector<std::string> lines;
        splitLines(data, lines);
        if (lines.empty()) continue;
        if (first) {
            // The chain must begin at genesis. If it does not, older records are missing or live in
            // another folder; the rest can still be verified relative to where it starts.
            std::string b, p, h;
            if (!logchain::splitLine(lines[0], b, p, h)) {
                return "TAMPERING DETECTED in " + narrow(names[i].c_str()) + ", record 1: malformed record";
            }
            prev = p;
            if (p != logchain::genesis())
                note = "  NOTE: the chain does not start at the beginning - earlier log files are missing or in another folder.";
            first = false;
        }
        logchain::Verify v = logchain::verify(lines, prev);
        total += v.lines;
        if (!v.ok)
            return "TAMPERING DETECTED in " + narrow(names[i].c_str()) + ", record " + std::to_string(v.badLine) +
                   ": " + v.why;
        prev = v.head;
    }
    if (ok) *ok = true;
    return "VERIFIED: " + std::to_string(total) + " records in " + std::to_string(names.size()) +
           " file(s). Head " + prev.substr(0, 16) + "..." + note;
}

}  // namespace history
