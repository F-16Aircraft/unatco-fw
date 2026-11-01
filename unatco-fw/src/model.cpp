#include "model.h"
#include "fw.h"
#include "geo.h"
#include "ui.h"

namespace model {

std::string endpoint(const IpAddr& ip, uint16_t port) {
    if (ip.isZero()) return port ? "*:" + std::to_string(port) : "*";
    if (ip.v6) return "[" + ip.str() + "]:" + std::to_string(port);
    return ip.str() + ":" + std::to_string(port);
}

bool isActive(const Conn& c) {
    if (c.proto == Proto::UDP) return !c.remote.isZero();
    return c.state == MIB_TCP_STATE_ESTAB || c.state == MIB_TCP_STATE_SYN_SENT ||
           c.state == MIB_TCP_STATE_SYN_RCVD || c.state == MIB_TCP_STATE_CLOSE_WAIT;
}

void build(Model& m, DWORD selectedPid, bool showAll) {
    m.snap = monitor::copy();
    m.procs.clear();
    m.targets.clear();
    m.totalForeign = 0;
    m.worstScore = 0;

    std::map<DWORD, ProcRow> rows;
    for (auto& kv : m.snap.net.procs) {
        ProcRow r;
        r.pid = kv.first;
        r.name = kv.second.name;
        r.path = kv.second.path;
        auto th = m.snap.threat.find(kv.first);
        r.score = th == m.snap.threat.end() ? 0 : th->second.score;
        r.blocked = !r.path.empty() && fw::appBlocked(r.path);
        rows[kv.first] = r;          // idle processes are filtered out below unless showAll
    }

    // IP -> best target (dedupe: one arc per remote address)
    std::map<IpAddr, GlobeTarget> tmap;
    std::map<IpAddr, int> tscore;

    for (const auto& c : m.snap.net.conns) {
        auto it = rows.find(c.pid);
        if (it == rows.end()) continue;
        ProcRow& pr = it->second;
        pr.nconn++;
        bool remoteForeign = !c.remote.isZero() && !c.remote.isLocal();
        if (remoteForeign) pr.nforeign++; else pr.nlocal++;
        if (!remoteForeign || !isActive(c)) continue;
        m.totalForeign++;

        WhoisInfo wi = intel::get(c.remote);
        GlobeTarget tg;
        tg.ip = c.remote;
        if (wi.done && !wi.failed) {
            if (const geo::Country* ct = geo::findCountry(wi.country)) {
                tg.cc = ct->cc;
                tg.country = ct->name;
                tg.lat = ct->lat;
                tg.lon = ct->lon;
            }
        }
        int sc = pr.score;
        tg.color = sc >= 45 ? theme::RED : (sc >= 20 ? theme::ORANGE : RGB(80, 220, 230));
        tg.highlight = (c.pid == selectedPid);
        tg.blocked = fw::ipBlocked(c.remote);
        auto ex = tmap.find(c.remote);
        if (ex == tmap.end()) { tmap[c.remote] = tg; tscore[c.remote] = sc; }
        else {
            if (tg.highlight) ex->second.highlight = true;
            if (sc > tscore[c.remote]) { ex->second.color = tg.color; tscore[c.remote] = sc; }
        }
    }
    for (auto& kv : tmap) {
        if (m.targets.size() >= 400) break;
        m.targets.push_back(kv.second);
    }

    for (auto& kv : rows) {
        ProcRow& r = kv.second;
        if (!showAll && r.nconn == 0 && r.score == 0) continue;
        if (r.pid == 0) continue;
        m.procs.push_back(r);
        if (r.score > m.worstScore) m.worstScore = r.score;
    }
    std::sort(m.procs.begin(), m.procs.end(), [](const ProcRow& a, const ProcRow& b) {
        if (a.score != b.score) return a.score > b.score;
        if (a.nforeign != b.nforeign) return a.nforeign > b.nforeign;
        return lower(a.name) < lower(b.name);
    });

    m.homeInfo = intel::home();
    m.home.valid = m.homeInfo.valid;
    m.home.lat = m.homeInfo.lat;
    m.home.lon = m.homeInfo.lon;
    m.home.label = m.homeInfo.city.empty() ? m.homeInfo.country : (m.homeInfo.city + ", " + m.homeInfo.cc);
}

std::vector<ConnRow> connsFor(const Model& m, DWORD pid) {
    std::vector<ConnRow> out;
    for (const auto& c : m.snap.net.conns) {
        if (c.pid != pid) continue;
        ConnRow r;
        r.c = c;
        r.foreign = !c.remote.isZero() && !c.remote.isLocal();
        r.listening = c.proto == Proto::TCP && c.state == MIB_TCP_STATE_LISTEN;
        if (r.foreign) {
            r.wi = intel::get(c.remote);
            r.ipBlocked = fw::ipBlocked(c.remote);
        }
        out.push_back(r);
    }
    std::sort(out.begin(), out.end(), [](const ConnRow& a, const ConnRow& b) {
        if (a.foreign != b.foreign) return a.foreign > b.foreign;
        if (a.listening != b.listening) return a.listening < b.listening;
        return a.c < b.c;
    });
    return out;
}

const ProcRow* findProc(const Model& m, DWORD pid) {
    for (auto& p : m.procs) if (p.pid == pid) return &p;
    return nullptr;
}

}  // namespace model
