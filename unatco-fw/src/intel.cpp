#include "intel.h"
#include "geo.h"

namespace intel {

static Lock g_lock;
static std::map<IpAddr, WhoisInfo> g_cache;
static std::map<IpAddr, uint64_t> g_retryAt;
static std::deque<IpAddr> g_queue;
static std::set<IpAddr> g_inflight;
static std::map<std::string, std::string> g_refer;   // "/8 key" -> whois server
static HANDLE g_sem = nullptr;
static HANDLE g_threads[3] = {nullptr, nullptr, nullptr};
static volatile LONG g_quit = 0;
static HomeInfo g_home;
static bool g_homeOverride = false;

static const size_t kMaxResp = 96 * 1024;

// ---------- minimal blocking TCP client with hard timeouts ----------
static std::string tcpQuery(const std::string& host, const char* port, const std::string& req,
                            int timeoutMs, std::string* err) {
    std::string out;
    addrinfo hints{}, *res = nullptr;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(host.c_str(), port, &hints, &res) != 0 || !res) {
        if (err) *err = "dns failure for " + host;
        return out;
    }
    SOCKET s = INVALID_SOCKET;
    for (addrinfo* a = res; a; a = a->ai_next) {
        s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
        int r = connect(s, a->ai_addr, (int)a->ai_addrlen);
        bool ok = (r == 0);
        if (!ok && WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set w, e;
            FD_ZERO(&w); FD_ZERO(&e);
            FD_SET(s, &w); FD_SET(s, &e);
            timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
            if (select(0, nullptr, &w, &e, &tv) > 0 && FD_ISSET(s, &w)) ok = true;
        }
        if (ok) break;
        closesocket(s);
        s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    if (s == INVALID_SOCKET) { if (err) *err = "connect failed: " + host; return out; }
    u_long nb = 0;
    ioctlsocket(s, FIONBIO, &nb);
    DWORD to = (DWORD)timeoutMs;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, sizeof to);
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&to, sizeof to);
    if (send(s, req.data(), (int)req.size(), 0) == SOCKET_ERROR) {
        if (err) *err = "send failed";
        closesocket(s);
        return out;
    }
    char buf[4096];
    uint64_t deadline = nowMs() + (uint64_t)timeoutMs * 2;
    while (out.size() < kMaxResp && nowMs() < deadline) {
        int n = recv(s, buf, sizeof buf, 0);
        if (n <= 0) break;
        out.append(buf, (size_t)n);
    }
    closesocket(s);
    if (out.size() > kMaxResp) out.resize(kMaxResp);
    return out;
}

static std::string clean(const std::string& s) {      // registry text is untrusted
    std::string r;
    for (unsigned char c : s) r += (c >= 32 && c < 127) ? (char)c : (c == '\t' ? ' ' : '?');
    return r.size() > 120 ? r.substr(0, 120) : r;
}

// ---------- WHOIS ----------
struct Kv { std::string k, v; };

static std::vector<Kv> parseKv(const std::string& txt) {
    std::vector<Kv> out;
    size_t pos = 0;
    while (pos < txt.size()) {
        size_t e = txt.find('\n', pos);
        if (e == std::string::npos) e = txt.size();
        std::string line = trim(txt.substr(pos, e - pos));
        pos = e + 1;
        if (line.empty() || line[0] == '%' || line[0] == '#') continue;
        size_t c = line.find(':');
        if (c == std::string::npos || c == 0 || c > 40) continue;
        Kv kv;
        kv.k = lower(trim(line.substr(0, c)));
        kv.v = trim(line.substr(c + 1));
        if (!kv.v.empty()) out.push_back(kv);
    }
    return out;
}

static const std::string* firstOf(const std::vector<Kv>& kv, std::initializer_list<const char*> keys) {
    for (const char* key : keys)
        for (const auto& e : kv) if (e.k == key) return &e.v;
    return nullptr;
}

static std::string referKey(const IpAddr& ip) {
    char b[24];
    if (!ip.v6) snprintf(b, sizeof b, "4:%u", ip.b[0]);
    else snprintf(b, sizeof b, "6:%02x%x", ip.b[0], ip.b[1] >> 4);
    return b;
}

static std::string findServer(const IpAddr& ip, std::string* err) {
    std::string key = referKey(ip);
    {
        Guard g(g_lock);
        auto it = g_refer.find(key);
        if (it != g_refer.end()) return it->second;
    }
    std::string r = tcpQuery("whois.iana.org", "43", ip.str() + "\r\n", 6000, err);
    for (const auto& e : parseKv(r)) {
        if (e.k == "refer" || e.k == "whois") {
            std::string srv = lower(e.v);
            // Only plain hostnames are accepted - never follow anything exotic.
            bool okc = !srv.empty() && srv.size() < 64;
            for (char c : srv) if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-')) okc = false;
            if (!okc) continue;
            Guard g(g_lock);
            g_refer[key] = srv;
            return srv;
        }
    }
    if (err && err->empty()) *err = "no registry referral";
    return std::string();
}

static void lookup(const IpAddr& ip, WhoisInfo& w) {
    std::string err;
    std::string server = findServer(ip, &err);
    if (server.empty()) { w.failed = true; w.note = err; return; }
    w.registry = server;

    std::string q = ip.str();
    if (server == "whois.arin.net") q = "n + " + q;
    std::string r = tcpQuery(server, "43", q + "\r\n", 7000, &err);
    if (r.empty()) { w.failed = true; w.note = err.empty() ? "empty response" : err; return; }

    // ARIN may hand us to another registry.
    {
        auto kv = parseKv(r);
        if (const std::string* ref = firstOf(kv, {"referralserver"})) {
            std::string s = lower(*ref);
            if (s.compare(0, 8, "whois://") == 0) {
                s = s.substr(8);
                size_t colon = s.find(':'); if (colon != std::string::npos) s.resize(colon);
                while (!s.empty() && s.back() == '/') s.pop_back();
                bool okc = !s.empty() && s.size() < 64 && s != server;
                for (char c : s) if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-')) okc = false;
                if (okc) {
                    std::string r2 = tcpQuery(s, "43", ip.str() + "\r\n", 7000, &err);
                    if (!r2.empty()) { r = r2; w.registry = s; }
                }
            }
        }
    }

    auto kv = parseKv(r);
    if (auto* v = firstOf(kv, {"inetnum", "netrange", "inet6num"})) w.range = clean(*v);
    if (auto* v = firstOf(kv, {"cidr", "route", "route6"})) w.cidr = clean(*v);
    if (auto* v = firstOf(kv, {"netname"})) w.netname = clean(*v);
    if (auto* v = firstOf(kv, {"orgname", "org-name", "owner", "descr", "customer"})) w.org = clean(*v);
    if (auto* v = firstOf(kv, {"country"})) w.country = clean(*v).substr(0, 2);
    if (auto* v = firstOf(kv, {"regdate", "created", "last-modified", "changed"})) w.registered = clean(*v);
    if (auto* v = firstOf(kv, {"orgabuseemail", "abuse-mailbox", "e-mail"})) w.abuse = clean(*v);
    for (auto& c : w.country) if (c >= 'a' && c <= 'z') c = (char)(c - 32);
    if (w.range.empty() && w.netname.empty() && w.org.empty()) {
        w.failed = true;
        w.note = "unparseable registry reply";
    }
}

static std::string reverseDns(const IpAddr& ip) {
    char host[NI_MAXHOST] = {0};
    if (!ip.v6) {
        sockaddr_in sa{}; sa.sin_family = AF_INET; memcpy(&sa.sin_addr, ip.b, 4);
        if (getnameinfo((sockaddr*)&sa, sizeof sa, host, sizeof host, nullptr, 0, NI_NAMEREQD) != 0) return "";
    } else {
        sockaddr_in6 sa{}; sa.sin6_family = AF_INET6; memcpy(&sa.sin6_addr, ip.b, 16);
        if (getnameinfo((sockaddr*)&sa, sizeof sa, host, sizeof host, nullptr, 0, NI_NAMEREQD) != 0) return "";
    }
    return clean(host);
}

static DWORD WINAPI worker(LPVOID) {
    while (!g_quit) {
        WaitForSingleObject(g_sem, 500);
        if (g_quit) break;
        IpAddr ip;
        {
            Guard g(g_lock);
            if (g_queue.empty()) continue;
            ip = g_queue.front();
            g_queue.pop_front();
        }
        WhoisInfo w;
        lookup(ip, w);
        w.host = reverseDns(ip);
        w.done = true;
        Guard g(g_lock);
        g_cache[ip] = w;
        g_inflight.erase(ip);
        if (w.failed) g_retryAt[ip] = nowMs() + 120000;
    }
    return 0;
}

// ---------- own location ----------
static double jnum(const std::string& body, const char* key, bool* ok) {
    std::string pat = std::string("\"") + key + "\":";
    size_t p = body.find(pat);
    if (p == std::string::npos) return 0;
    *ok = true;
    return atof(body.c_str() + p + pat.size());
}
static std::string jstr(const std::string& body, const char* key) {
    std::string pat = std::string("\"") + key + "\":\"";
    size_t p = body.find(pat);
    if (p == std::string::npos) return "";
    p += pat.size();
    size_t e = body.find('"', p);
    if (e == std::string::npos) return "";
    return clean(body.substr(p, e - p));
}

static DWORD WINAPI homeThread(LPVOID) {
    std::string err;
    std::string r = tcpQuery("ip-api.com", "80",
        "GET /json?fields=status,country,countryCode,city,lat,lon,query HTTP/1.0\r\n"
        "Host: ip-api.com\r\nUser-Agent: unatco-netdef\r\nConnection: close\r\n\r\n", 6000, &err);
    size_t bp = r.find("\r\n\r\n");
    std::string body = bp == std::string::npos ? "" : r.substr(bp + 4);
    HomeInfo h;
    h.pending = false;
    if (body.find("\"status\":\"success\"") != std::string::npos) {
        bool a = false, b = false;
        h.lat = jnum(body, "lat", &a);
        h.lon = jnum(body, "lon", &b);
        h.ip = jstr(body, "query");
        h.cc = jstr(body, "countryCode");
        h.country = jstr(body, "country");
        h.city = jstr(body, "city");
        h.valid = a && b;
    }
    Guard g(g_lock);
    if (!g_homeOverride) {
        double ol = g_home.lat, oo = g_home.lon;
        (void)ol; (void)oo;
        g_home = h;
    } else {
        g_home.pending = false;
        if (h.valid) { g_home.ip = h.ip; g_home.cc = h.cc; g_home.country = h.country; g_home.city = h.city; }
    }
    return 0;
}

bool init() {
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) return false;
    g_sem = CreateSemaphoreW(nullptr, 0, 100000, nullptr);
    for (auto& t : g_threads) t = CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
    HANDLE h = CreateThread(nullptr, 0, homeThread, nullptr, 0, nullptr);
    if (h) CloseHandle(h);
    return true;
}

void shutdown() {
    InterlockedExchange(&g_quit, 1);
    for (auto& t : g_threads)
        if (t) { WaitForSingleObject(t, 3000); CloseHandle(t); t = nullptr; }
    if (g_sem) CloseHandle(g_sem);
    WSACleanup();
}

WhoisInfo get(const IpAddr& ip) {
    Guard g(g_lock);
    auto it = g_cache.find(ip);
    if (it != g_cache.end()) {
        if (!it->second.failed) return it->second;
        auto rt = g_retryAt.find(ip);
        if (rt == g_retryAt.end() || nowMs() < rt->second) return it->second;
        g_cache.erase(it);                       // retry a failed lookup after the back-off
    }
    if (!g_inflight.count(ip) && g_queue.size() < 2000) {
        g_inflight.insert(ip);
        g_queue.push_back(ip);
        ReleaseSemaphore(g_sem, 1, nullptr);
    }
    return WhoisInfo();                          // done == false -> "resolving"
}

HomeInfo home() { Guard g(g_lock); return g_home; }

void setHomeOverride(double lat, double lon) {
    Guard g(g_lock);
    g_homeOverride = true;
    g_home.lat = lat; g_home.lon = lon; g_home.valid = true;
}

size_t pendingCount() { Guard g(g_lock); return g_queue.size() + g_inflight.size(); }

}  // namespace intel
