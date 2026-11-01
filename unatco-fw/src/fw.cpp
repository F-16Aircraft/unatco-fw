#include "fw.h"
#include <rpc.h>      // WIN32_LEAN_AND_MEAN drops it; WFP headers and RPC_C_AUTHN_WINNT need it
#include <fwpmu.h>

#ifndef RPC_C_AUTHN_WINNT
#define RPC_C_AUTHN_WINNT 10
#endif


// WFP identifiers, defined here because some toolchains (MinGW-w64) do not ship them. Values are the
// documented ones from fwpmu.h / fwpmtypes.h. Private names avoid clashing with MSVC's extern GUIDs.
static const UINT32 kFilterPersistent = 0x00000001;   // kFilterPersistent
static const GUID kSublayerUniversal = {0xeebecc03, 0xced4, 0x4380, {0x81, 0x9a, 0x27, 0x34, 0x39, 0x7b, 0x2b, 0x74}};
static const GUID kLayerConnect4     = {0xc38d57d1, 0x05a7, 0x4c33, {0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}};
static const GUID kLayerConnect6     = {0x4a72393b, 0x319f, 0x44bc, {0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}};
static const GUID kLayerAccept4      = {0xe1cd9fe7, 0xf4b5, 0x4273, {0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}};
static const GUID kLayerAccept6      = {0xa3b42c97, 0x9f04, 0x4672, {0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}};
static const GUID kCondAppId         = {0xd78e1e87, 0x8644, 0x4ea5, {0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}};
static const GUID kCondRemoteAddr    = {0xb235ae9a, 0x1d64, 0x49b8, {0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}};

namespace fw {

static HANDLE g_eng = nullptr;
static Lock g_lock;
static std::vector<FwRule> g_rules;

std::string settingsPath() {
    wchar_t p[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, p, MAX_PATH);
    std::wstring w(p, n);
    size_t i = w.find_last_of(L"\\/");
    if (i != std::wstring::npos) w.resize(i + 1);
    return narrow((w + L"unatco_netdef.rules").c_str());
}

// ---------------- persistence ----------------
static void saveRules() {
    FILE* f = nullptr;
    std::wstring wp = widen(settingsPath());
    f = _wfopen(wp.c_str(), L"wb");
    if (!f) return;
    for (auto& r : g_rules) {
        fprintf(f, "%c|%s|", r.isApp ? 'A' : 'I', r.target.c_str());
        for (size_t i = 0; i < r.ids.size(); i++)
            fprintf(f, "%s%llu", i ? "," : "", (unsigned long long)r.ids[i]);
        fprintf(f, "\n");
    }
    fclose(f);
}

static std::vector<std::string> split(const std::string& s, char d) {
    std::vector<std::string> o;
    size_t p = 0;
    for (;;) {
        size_t e = s.find(d, p);
        if (e == std::string::npos) { o.push_back(s.substr(p)); break; }
        o.push_back(s.substr(p, e - p));
        p = e + 1;
    }
    return o;
}

static bool parseIp(const std::string& s, IpAddr& out) {
    in_addr a4{};
    in6_addr a6{};
    if (InetPtonA(AF_INET, s.c_str(), &a4) == 1) { out = IpAddr::from4((uint8_t*)&a4); return true; }
    if (InetPtonA(AF_INET6, s.c_str(), &a6) == 1) { out = IpAddr::from6((uint8_t*)&a6); return true; }
    return false;
}

// ---------------- WFP primitives ----------------
static bool addFilter(const GUID& layer, FWPM_FILTER_CONDITION0* cond, const wchar_t* name, uint64_t* id) {
    FWPM_FILTER0 f{};
    f.displayData.name = const_cast<wchar_t*>(name);
    f.displayData.description = const_cast<wchar_t*>(L"UNATCO Network Defense Terminal");
    f.flags = kFilterPersistent;
    f.layerKey = layer;
    f.subLayerKey = kSublayerUniversal;
    f.weight.type = FWP_UINT8;
    f.weight.uint8 = 12;
    f.action.type = FWP_ACTION_BLOCK;
    f.numFilterConditions = 1;
    f.filterCondition = cond;
    return FwpmFilterAdd0(g_eng, &f, nullptr, id) == ERROR_SUCCESS;
}

static void delIds(const std::vector<uint64_t>& ids) {
    for (uint64_t id : ids) FwpmFilterDeleteById0(g_eng, id);
}

static bool addAppRule(const std::string& path, std::vector<uint64_t>& ids, std::string* err) {
    FWP_BYTE_BLOB* appId = nullptr;
    DWORD r = FwpmGetAppIdFromFileName0(widen(path).c_str(), &appId);
    if (r != ERROR_SUCCESS || !appId) {
        if (err) *err = "cannot resolve application id (file missing?)";
        return false;
    }
    FWPM_FILTER_CONDITION0 c{};
    c.fieldKey = kCondAppId;
    c.matchType = FWP_MATCH_EQUAL;
    c.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    c.conditionValue.byteBlob = appId;

    const GUID* layers[4] = {&kLayerConnect4, &kLayerConnect6,
                             &kLayerAccept4, &kLayerAccept6};
    bool ok = true;
    for (auto* l : layers) {
        uint64_t id = 0;
        if (addFilter(*l, &c, L"UNATCO: block application", &id)) ids.push_back(id);
        else ok = false;
    }
    FwpmFreeMemory0((void**)&appId);
    if (!ok) { delIds(ids); ids.clear(); if (err) *err = "FwpmFilterAdd0 failed (need administrator)"; }
    return ok;
}

static bool addIpRule(const IpAddr& ip, std::vector<uint64_t>& ids, std::string* err) {
    FWPM_FILTER_CONDITION0 c{};
    c.fieldKey = kCondRemoteAddr;
    c.matchType = FWP_MATCH_EQUAL;
    FWP_BYTE_ARRAY16 a16{};
    const GUID* layers[2];
    if (!ip.v6) {
        uint32_t host;
        memcpy(&host, ip.b, 4);
        c.conditionValue.type = FWP_UINT32;
        c.conditionValue.uint32 = ntohl(host);
        layers[0] = &kLayerConnect4;
        layers[1] = &kLayerAccept4;
    } else {
        memcpy(a16.byteArray16, ip.b, 16);
        c.conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
        c.conditionValue.byteArray16 = &a16;
        layers[0] = &kLayerConnect6;
        layers[1] = &kLayerAccept6;
    }
    bool ok = true;
    for (auto* l : layers) {
        uint64_t id = 0;
        if (addFilter(*l, &c, L"UNATCO: block remote address", &id)) ids.push_back(id);
        else ok = false;
    }
    if (!ok) { delIds(ids); ids.clear(); if (err) *err = "FwpmFilterAdd0 failed (need administrator)"; }
    return ok;
}

static bool filterExists(uint64_t id) {
    FWPM_FILTER0* f = nullptr;
    if (FwpmFilterGetById0(g_eng, id, &f) == ERROR_SUCCESS && f) {
        FwpmFreeMemory0((void**)&f);
        return true;
    }
    return false;
}

// ---------------- public ----------------
bool init(std::string* err) {
    DWORD r = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &g_eng);
    if (r != ERROR_SUCCESS) {
        g_eng = nullptr;
        if (err) *err = "WFP engine unavailable (run as administrator)";
        return false;
    }
    // reload rules; re-create any whose filters vanished (e.g. someone cleared the firewall)
    FILE* f = nullptr;
    f = _wfopen(widen(settingsPath()).c_str(), L"rb");
    if (f) {
        char line[1024];
        while (fgets(line, sizeof line, f)) {
            std::string s = trim(line);
            auto parts = split(s, '|');
            if (parts.size() < 3 || parts[0].size() != 1) continue;
            FwRule r2;
            r2.isApp = parts[0][0] == 'A';
            r2.target = parts[1];
            if (!parts[2].empty())
                for (auto& t : split(parts[2], ',')) r2.ids.push_back(strtoull(t.c_str(), nullptr, 10));
            bool intact = !r2.ids.empty();
            for (uint64_t id : r2.ids) if (!filterExists(id)) intact = false;
            if (!intact) {
                delIds(r2.ids);
                r2.ids.clear();
                if (r2.isApp) addAppRule(r2.target, r2.ids, nullptr);
                else { IpAddr ip; if (parseIp(r2.target, ip)) addIpRule(ip, r2.ids, nullptr); }
            }
            if (!r2.ids.empty()) g_rules.push_back(r2);
        }
        fclose(f);
        saveRules();
    }
    return true;
}

void shutdown() {
    if (g_eng) { FwpmEngineClose0(g_eng); g_eng = nullptr; }
}

bool available() { return g_eng != nullptr; }

bool blockApp(const std::string& path, std::string* err) {
    if (!g_eng) { if (err) *err = "firewall engine not open"; return false; }
    Guard g(g_lock);
    for (auto& r : g_rules) if (r.isApp && lower(r.target) == lower(path)) return true;
    FwRule r;
    r.isApp = true;
    r.target = path;
    if (!addAppRule(path, r.ids, err)) return false;
    g_rules.push_back(r);
    saveRules();
    return true;
}

bool blockIp(const IpAddr& ip, std::string* err) {
    if (!g_eng) { if (err) *err = "firewall engine not open"; return false; }
    if (ip.isLocal()) { if (err) *err = "refusing to block a local/private address"; return false; }
    Guard g(g_lock);
    for (auto& r : g_rules) if (!r.isApp && r.target == ip.str()) return true;
    FwRule r;
    r.isApp = false;
    r.target = ip.str();
    if (!addIpRule(ip, r.ids, err)) return false;
    g_rules.push_back(r);
    saveRules();
    return true;
}

static bool removeRule(bool app, const std::string& target) {
    Guard g(g_lock);
    for (size_t i = 0; i < g_rules.size(); i++) {
        auto& r = g_rules[i];
        if (r.isApp == app && lower(r.target) == lower(target)) {
            delIds(r.ids);
            g_rules.erase(g_rules.begin() + (long)i);
            saveRules();
            return true;
        }
    }
    return false;
}

bool unblockApp(const std::string& p) { return removeRule(true, p); }
bool unblockIp(const IpAddr& ip) { return removeRule(false, ip.str()); }

bool appBlocked(const std::string& p) {
    Guard g(g_lock);
    for (auto& r : g_rules) if (r.isApp && lower(r.target) == lower(p)) return true;
    return false;
}
bool ipBlocked(const IpAddr& ip) {
    Guard g(g_lock);
    std::string s = ip.str();
    for (auto& r : g_rules) if (!r.isApp && r.target == s) return true;
    return false;
}
std::vector<FwRule> rules() { Guard g(g_lock); return g_rules; }

bool sever(const Conn& c) {
    if (c.proto != Proto::TCP || c.local.v6 || c.remote.v6) return false;
    MIB_TCPROW row{};
    row.dwState = MIB_TCP_STATE_DELETE_TCB;
    memcpy(&row.dwLocalAddr, c.local.b, 4);
    memcpy(&row.dwRemoteAddr, c.remote.b, 4);
    row.dwLocalPort = htons(c.lport);
    row.dwRemotePort = htons(c.rport);
    return SetTcpEntry(&row) == NO_ERROR;
}

bool terminate(DWORD pid, std::string* err) {
    if (pid <= 4) { if (err) *err = "refusing to terminate a system process"; return false; }
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) { if (err) *err = "OpenProcess failed (protected process?)"; return false; }
    BOOL ok = TerminateProcess(h, 1);
    CloseHandle(h);
    if (!ok && err) *err = "TerminateProcess failed";
    return ok != 0;
}

}  // namespace fw
