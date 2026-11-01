#include "monitor.h"
#include "etw.h"
#include "history.h"
#include "intel.h"

namespace monitor {

static Lock g_lock;
static MonSnapshot g_snap;                         // published state
static std::map<DWORD, ScanResult> g_scans;        // latest scan per pid
static std::map<DWORD, std::vector<Finding>> g_behav;
static std::set<std::string> g_raised;             // de-dup "pid:code"
static std::deque<DWORD> g_scanQ;
static std::set<DWORD> g_scanQueued;
static std::map<DWORD, uint64_t> g_firstSeen;
static std::map<DWORD, uint64_t> g_lastScanTick;
static std::map<DWORD, uint64_t> g_createdKey;     // pid reuse detection (creation time)

static HANDLE g_thMon = nullptr, g_thScan = nullptr;
static volatile LONG g_quit = 0;

// ---------------- alerts ----------------
static void raise(Sev sev, DWORD pid, const std::string& proc, const std::string& code, const std::string& text) {
    char key[96];
    snprintf(key, sizeof key, "%lu:%s", (unsigned long)pid, code.c_str());
    Guard g(g_lock);
    if (!g_raised.insert(key).second) return;
    Alert a;
    a.tick = nowMs();
    GetLocalTime(&a.when);
    a.sev = sev;
    a.pid = pid;
    a.proc = proc;
    a.text = text;
    g_snap.alerts.push_back(a);
    if (g_snap.alerts.size() > 400) g_snap.alerts.pop_front();
    history::alert(sev, pid, proc, code, text);      // permanent, hash-chained record
}

// IPs whose registry data we still owe the history log (touched by the monitor thread only).
static std::set<IpAddr> g_regPending;

static void logConn(const Conn& c, const std::map<DWORD, ProcInfo>& procs) {
    auto it = procs.find(c.pid);
    history::conn(c, it == procs.end() ? "[unknown]" : it->second.name,
                  it == procs.end() ? "" : it->second.path);
    if (!c.remote.isZero() && !c.remote.isLocal() && g_regPending.size() < 5000) g_regPending.insert(c.remote);
}

static void setBehav(DWORD pid, const char* code, int score, const std::string& text) {
    Guard g(g_lock);
    auto& v = g_behav[pid];
    for (auto& f : v) if (f.code == code) return;
    Finding f;
    f.code = code; f.score = score; f.text = text;
    f.sev = memscan::sevForScore(score);
    v.push_back(f);
}

// ---------------- behaviour heuristics ----------------
struct BKey {
    std::string proc; IpAddr ip; uint16_t port;
    bool operator<(const BKey& o) const {
        if (proc != o.proc) return proc < o.proc;
        if (!(ip == o.ip)) return ip < o.ip;
        return port < o.port;
    }
};
static std::map<BKey, std::deque<uint64_t>> g_beacon;

static bool inSet(const std::string& n, const char* const* list, size_t cnt) {
    for (size_t i = 0; i < cnt; i++) if (n == list[i]) return true;
    return false;
}

static void noteNewConn(const Conn& c, const ProcInfo* pi) {
    if (c.remote.isLocal() || c.remote.isZero()) return;
    std::string name = pi ? lower(pi->name) : "?";
    BKey k{name, c.remote, c.rport};
    auto& d = g_beacon[k];
    d.push_back(nowMs());
    if (d.size() > 24) d.pop_front();
    if (d.size() >= 6) {
        double mean = 0, var = 0;
        std::vector<double> iv;
        for (size_t i = 1; i < d.size(); i++) iv.push_back((double)(d[i] - d[i - 1]));
        for (double x : iv) mean += x;
        mean /= (double)iv.size();
        for (double x : iv) var += (x - mean) * (x - mean);
        var /= (double)iv.size();
        double cv = mean > 0 ? sqrt(var) / mean : 9;
        if (mean >= 1500 && mean <= 3600000 && cv < 0.35) {
            char t[200];
            snprintf(t, sizeof t, "periodic connections to %s:%u every ~%.1fs (jitter %.0f%%) - beaconing pattern",
                     c.remote.str().c_str(), c.rport, mean / 1000.0, cv * 100.0);
            setBehav(c.pid, "BEACONING", cv < 0.15 ? 32 : 20, t);
        }
    }
}

static void analyseProcess(const ProcInfo& p, const std::map<DWORD, ProcInfo>& all,
                           const std::vector<const Conn*>& foreignActive) {
    static const char* const noNet[] = {"notepad.exe", "calc.exe", "calculatorapp.exe", "mspaint.exe",
        "wordpad.exe", "charmap.exe", "winver.exe", "write.exe", "snippingtool.exe"};
    static const char* const lol[] = {"rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe",
        "cscript.exe", "certutil.exe", "bitsadmin.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
        "msbuild.exe", "odbcconf.exe", "cmstp.exe"};
    static const char* const sysOnly[] = {"svchost.exe", "lsass.exe", "csrss.exe", "services.exe",
        "winlogon.exe", "smss.exe", "wininit.exe", "spoolsv.exe", "taskhostw.exe"};

    std::string n = lower(p.name);
    std::string path = lower(p.path);
    char t[220];

    if (!foreignActive.empty() && inSet(n, noNet, sizeof noNet / sizeof *noNet))
        setBehav(p.pid, "UNEXPECTED_NET", 28,
                 p.name + " does not normally talk to the internet but holds a foreign connection");
    if (!foreignActive.empty() && inSet(n, lol, sizeof lol / sizeof *lol))
        setBehav(p.pid, "LOLBIN_NET", 18, p.name + " (living-off-the-land binary) is making foreign connections");

    if (p.pathKnown && inSet(n, sysOnly, sizeof sysOnly / sizeof *sysOnly)) {
        if (path.find("\\windows\\system32\\") == std::string::npos &&
            path.find("\\windows\\syswow64\\") == std::string::npos) {
            snprintf(t, sizeof t, "'%s' is running from '%s' - system process name outside System32 (masquerading)",
                     p.name.c_str(), p.path.c_str());
            setBehav(p.pid, "MASQUERADE", 60, t);
        }
    }
    if (n == "svchost.exe") {
        auto it = all.find(p.ppid);
        if (it != all.end() && lower(it->second.name) != "services.exe" && lower(it->second.name) != "msmpeng.exe") {
            snprintf(t, sizeof t, "svchost.exe parent is '%s' instead of services.exe", it->second.name.c_str());
            setBehav(p.pid, "BAD_PARENT", 40, t);
        }
    }
    static const uint16_t badPorts[] = {4444, 1337, 31337, 5555, 6666, 6667, 9001, 9030, 8888, 12345};
    for (const Conn* c : foreignActive) {
        for (uint16_t bp : badPorts) {
            if (c->rport == bp) {
                snprintf(t, sizeof t, "connection to %s:%u - port commonly used by C2 frameworks, IRC bots or Tor",
                         c->remote.str().c_str(), c->rport);
                setBehav(p.pid, "SUSPECT_PORT", 14, t);
            }
        }
    }
}

// ---------------- scan thread ----------------
static std::map<DWORD, ProcInfo> g_procCopy;

static DWORD WINAPI scanThread(LPVOID) {
    while (!g_quit) {
        DWORD pid = 0;
        ProcInfo pi;
        bool have = false;
        {
            Guard g(g_lock);
            if (!g_scanQ.empty()) {
                pid = g_scanQ.front();
                g_scanQ.pop_front();
                g_scanQueued.erase(pid);
                auto it = g_procCopy.find(pid);
                if (it != g_procCopy.end()) { pi = it->second; have = true; }
            }
        }
        if (!have) { Sleep(80); continue; }

        std::map<DWORD, std::vector<DWORD>> th;
        memscan::snapshotThreads(th);
        ScanResult r = memscan::scan(pi, th[pid]);

        Guard g(g_lock);
        auto prev = g_scans.find(pid);
        if (prev != g_scans.end()) memscan::compareSigs(prev->second, r);
        g_lastScanTick[pid] = nowMs();
        g_scans[pid] = r;
        // Alerts for the findings that matter (CRITICAL_SECTION is re-entrant, raise() re-locks).
        for (auto& f : r.findings)
            if (f.score >= 14) raise(f.sev, pid, pi.name, f.code, f.text);
    }
    return 0;
}

static void queueScan(DWORD pid, bool front) {
    Guard g(g_lock);
    if (g_scanQueued.count(pid)) {
        if (!front) return;
        for (auto it = g_scanQ.begin(); it != g_scanQ.end(); ++it) if (*it == pid) { g_scanQ.erase(it); break; }
    }
    g_scanQueued.insert(pid);
    if (front) g_scanQ.push_front(pid); else g_scanQ.push_back(pid);
}

void requestScan(DWORD pid) { queueScan(pid, true); }

// ---------------- monitor thread ----------------
struct RKey {
    DWORD pid; Proto pr; IpAddr ip; uint16_t port;
    bool operator<(const RKey& o) const {
        if (pid != o.pid) return pid < o.pid;
        if (pr != o.pr) return pr < o.pr;
        if (!(ip == o.ip)) return ip < o.ip;
        return port < o.port;
    }
};

static DWORD WINAPI monThread(LPVOID) {
    NetState st;
    std::map<RKey, EtwConn> recent;                // ETW sightings kept alive for ~20s
    std::set<Conn> prevKeys;
    std::map<DWORD, uint64_t> created;
    uint64_t lastRotate = 0;
    size_t rotateIdx = 0;
    uint64_t polls = 0, etwOnly = 0;
    std::set<RKey> etwCounted;

    while (!g_quit) {
        const uint64_t tickStart = nowMs();
        netmon::refresh(st);
        polls++;

        // --- ETW merge ---
        std::vector<EtwConn> ev;
        etw::drain(ev);
        std::set<RKey> inTable;
        for (const auto& c : st.conns)
            if (c.proto == Proto::TCP) inTable.insert({c.pid, c.proto, c.remote, c.rport});
        for (const auto& e : ev) {
            RKey k{e.c.pid, e.c.proto, e.c.remote, e.c.rport};
            if (e.c.proto == Proto::TCP && inTable.count(k)) continue;
            const bool newEtw = recent.find(k) == recent.end();
            recent[k] = e;
            if (newEtw) logConn(e.c, st.procs);
            if (!e.c.remote.isLocal() && e.c.proto == Proto::TCP && etwCounted.insert(k).second) etwOnly++;
            // PID the process list cannot explain?
            if (e.c.pid && !st.procs.count(e.c.pid) && netmon::pidExists(e.c.pid)) {
                std::map<DWORD, ProcInfo> again;
                netmon::snapshotProcesses(again);
                if (!again.count(e.c.pid)) st.ghostPids.insert(e.c.pid);
            }
        }
        const uint64_t now = nowMs();
        for (auto it = recent.begin(); it != recent.end();) {
            if (now - it->second.tick > 20000) it = recent.erase(it);
            else { st.conns.push_back(it->second.c); ++it; }
        }
        if (etwCounted.size() > 50000) etwCounted.clear();

        // --- PID reuse: forget old state when a pid gets a different creation time ---
        for (auto& kv : st.procs) {
            auto it = created.find(kv.first);
            if (it != created.end() && it->second != kv.second.created && kv.second.created) {
                Guard g(g_lock);
                g_scans.erase(kv.first); g_behav.erase(kv.first); g_lastScanTick.erase(kv.first);
                std::vector<std::string> drop;
                char pre[24]; snprintf(pre, sizeof pre, "%lu:", (unsigned long)kv.first);
                for (auto& s : g_raised) if (s.compare(0, strlen(pre), pre) == 0) drop.push_back(s);
                for (auto& s : drop) g_raised.erase(s);
            }
            created[kv.first] = kv.second.created;
        }

        // --- new-connection tracking for beaconing ---
        std::set<Conn> keys;
        for (const auto& c : st.conns) {
            if (c.proto != Proto::TCP) continue;
            if (c.state != MIB_TCP_STATE_ESTAB && c.state != MIB_TCP_STATE_SYN_SENT) continue;
            Conn k = c; k.state = 0; k.fromEtw = false;
            keys.insert(k);
            if (!prevKeys.count(k)) {
                auto it = st.procs.find(c.pid);
                logConn(c, st.procs);
                noteNewConn(c, it == st.procs.end() ? nullptr : &it->second);
            }
        }
        prevKeys.swap(keys);

        // write registry data to the history once each WHOIS lookup has finished
        for (auto it = g_regPending.begin(); it != g_regPending.end();) {
            WhoisInfo w = intel::get(*it);
            if (w.done) { history::registry(*it, w); it = g_regPending.erase(it); }
            else ++it;
        }

        // --- per process behaviour + scan scheduling ---
        std::map<DWORD, std::vector<const Conn*>> foreignBy;
        for (const auto& c : st.conns) {
            bool active = (c.proto == Proto::TCP && (c.state == MIB_TCP_STATE_ESTAB || c.state == MIB_TCP_STATE_SYN_SENT)) ||
                          (c.proto == Proto::UDP && !c.remote.isZero());
            if (active && !c.remote.isLocal() && !c.remote.isZero()) foreignBy[c.pid].push_back(&c);
        }
        {
            Guard g(g_lock);
            g_procCopy = st.procs;
        }
        for (auto& kv : st.procs) {
            if (kv.first == 0) continue;
            std::vector<const Conn*> fa;
            auto f = foreignBy.find(kv.first);
            if (f != foreignBy.end()) fa = f->second;
            analyseProcess(kv.second, st.procs, fa);
            if (!fa.empty()) {
                uint64_t last = 0;
                { Guard g(g_lock); auto it = g_lastScanTick.find(kv.first); if (it != g_lastScanTick.end()) last = it->second; }
                if (last == 0 || now - last > 20000) queueScan(kv.first, last == 0);
            }
        }
        for (DWORD gp : st.ghostPids) {
            char t[200];
            snprintf(t, sizeof t, "PID %lu owns network sockets but is invisible to process enumeration (hidden process / rootkit)",
                     (unsigned long)gp);
            setBehav(gp, "GHOST_PID", 90, t);
            raise(Sev::Critical, gp, "[hidden]", "GHOST_PID", t);
            queueScan(gp, false);
        }
        // slow rotation over every other process so silent implants are still examined
        if (now - lastRotate > 2500 && !st.procs.empty()) {
            lastRotate = now;
            auto it = st.procs.begin();
            std::advance(it, (long)(rotateIdx++ % st.procs.size()));
            uint64_t last = 0;
            { Guard g(g_lock); auto f = g_lastScanTick.find(it->first); if (f != g_lastScanTick.end()) last = f->second; }
            if (it->first > 4 && (last == 0 || now - last > 90000)) queueScan(it->first, false);
        }

        // --- publish ---
        std::map<DWORD, ProcThreat> threat;
        {
            Guard g(g_lock);
            for (auto& kv : st.procs) {
                ProcThreat pt;
                auto sc = g_scans.find(kv.first);
                if (sc != g_scans.end()) {
                    pt.scanned = true;
                    pt.unreadable = !sc->second.opened;
                    pt.jitHost = sc->second.jitHost;
                    pt.regions = sc->second.regions;
                    pt.scanMs = sc->second.ms;
                    pt.lastScan = sc->second.when;
                    pt.findings = sc->second.findings;
                }
                auto bh = g_behav.find(kv.first);
                if (bh != g_behav.end()) pt.findings.insert(pt.findings.end(), bh->second.begin(), bh->second.end());
                int total = 0;
                for (auto& f : pt.findings) total += f.score;
                pt.score = total > 100 ? 100 : total;
                if (pt.score > 0 || pt.scanned) threat[kv.first] = pt;
            }
            for (DWORD gp : st.ghostPids) {
                ProcInfo p; p.pid = gp; p.name = "[HIDDEN PROCESS]";
                st.procs[gp] = p;
                ProcThreat pt;
                auto bh = g_behav.find(gp);
                if (bh != g_behav.end()) pt.findings = bh->second;
                pt.score = 100;
                threat[gp] = pt;
            }
            // raise alerts for behaviour findings that crossed the bar
            for (auto& kv : g_behav) {
                auto pi = st.procs.find(kv.first);
                std::string nm = pi == st.procs.end() ? "?" : pi->second.name;
                for (auto& f : kv.second)
                    if (f.score >= 14) raise(f.sev, kv.first, nm, f.code, f.text);
            }

            g_snap.net = st;
            g_snap.threat.swap(threat);
            g_snap.etwOn = etw::running();
            g_snap.polls = polls;
            g_snap.etwSeen = etwOnly;
            g_snap.scansQueued = g_scanQ.size();
        }

        uint64_t spent = nowMs() - tickStart;
        if (spent < 200) Sleep((DWORD)(200 - spent));
    }
    return 0;
}

void start() {
    g_snap.admin = netmon::isPrivileged();
    netmon::enableDebugPrivilege();
    etw::start();
    g_thMon = CreateThread(nullptr, 0, monThread, nullptr, 0, nullptr);
    g_thScan = CreateThread(nullptr, 0, scanThread, nullptr, 0, nullptr);
}

void stop() {
    InterlockedExchange(&g_quit, 1);
    if (g_thMon) { WaitForSingleObject(g_thMon, 3000); CloseHandle(g_thMon); g_thMon = nullptr; }
    if (g_thScan) { WaitForSingleObject(g_thScan, 5000); CloseHandle(g_thScan); g_thScan = nullptr; }
    etw::stop();
}

MonSnapshot copy() {
    Guard g(g_lock);
    return g_snap;
}

void clearAlerts() {
    Guard g(g_lock);
    g_snap.alerts.clear();
}

}  // namespace monitor
