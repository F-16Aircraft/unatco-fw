#include "app.h"
#include "fw.h"
#include "etw.h"
#include "netmon.h"
#include "geo.h"
#include "intel.h"
#include "monitor.h"
#include "history.h"

App A;

uint64_t connKey(const Conn& c) {
    uint64_t h = 1469598103934665603ULL;
    auto mix = [&](const void* p, size_t n) {
        const uint8_t* b = (const uint8_t*)p;
        for (size_t i = 0; i < n; i++) { h ^= b[i]; h *= 1099511628211ULL; }
    };
    mix(&c.proto, 1);
    mix(c.remote.b, c.remote.v6 ? 16 : 4);
    mix(&c.rport, 2);
    mix(c.local.b, c.local.v6 ? 16 : 4);
    mix(&c.lport, 2);
    return h ? h : 1;
}

const ConnRow* selectedConn() {
    for (auto& r : A.conns) if (connKey(r.c) == A.selConn) return &r;
    return nullptr;
}

void setStatus(const std::string& s, uint64_t ms) {
    A.status = s;
    A.statusUntil = nowMs() + ms;
}

// ------------------------------------------------------------------------------------------
// layout
// ------------------------------------------------------------------------------------------
static int btnWidth(const std::string& s) { return (int)s.size() * 8 + 26; }

void layoutAll(int W, int H) {
    A.W = W; A.H = H;
    const int m = 8, headH = 66;
    int alertH = H / 5;
    if (alertH < 120) alertH = 120;
    if (alertH > 200) alertH = 200;
    int top = headH + 4, bottom = H - alertH - m - 4;
    const int leftW = 392;

    A.rHeader = {0, 0, W, headH};
    A.rProc = {m, top, m + leftW, bottom};
    int xr = m + leftW + m, wr = W - xr - m;
    int bodyH = bottom - top;
    int gh = (int)(bodyH * 0.54);
    A.rGlobe = {xr, top, xr + wr, top + gh};
    int y2 = top + gh + m;
    int connW = (int)(wr * 0.60);
    A.rConn = {xr, y2, xr + connW, bottom};
    int rx = xr + connW + m;
    int half = (bottom - y2 - m) / 2;
    A.rReg = {rx, y2, xr + wr, y2 + half};
    A.rThreat = {rx, y2 + half + m, xr + wr, bottom};
    A.rAlert = {m, bottom + m, W - m, H - m};

    A.lproc.r = {A.rProc.left + 8, A.rProc.top + 26, A.rProc.right - 6, A.rProc.bottom - 8};
    A.lproc.cols = {{"PROCESS", 150, false}, {"PID", 56, true}, {"NET", 46, true}, {"THREAT", 0, false}};
    A.lconn.r = {A.rConn.left + 8, A.rConn.top + 26, A.rConn.right - 6, A.rConn.bottom - 8};
    A.lconn.cols = {{"PRO", 40, false}, {"SCOPE", 66, false}, {"LOCAL", 150, false}, {"REMOTE", 186, false},
                    {"STATE", 92, false}, {"CC", 34, false}, {"REGISTRANT / HOST", 0, false}};
    A.lalert.r = {A.rAlert.left + 8, A.rAlert.top + 26, A.rAlert.right - 6, A.rAlert.bottom - 8};
    A.lalert.cols = {{"TIME", 76, false}, {"LEVEL", 84, false}, {"PROCESS", 170, false}, {"EVENT", 0, false}};

    // toolbar (header row 2)
    struct Def { int id; const char* label; bool danger; };
    static const Def defs[] = {
        {B_BLOCK_APP, "BLOCK APP", true}, {B_UNBLOCK_APP, "ALLOW APP", false},
        {B_BLOCK_IP, "BLOCK IP", true}, {B_UNBLOCK_IP, "ALLOW IP", false},
        {B_SEVER, "SEVER CONN", true}, {B_SCAN, "SCAN MEMORY", false}, {B_KILL, "TERMINATE", true},
        {B_TOGGLE_ALL, "ALL PROCESSES", false}, {B_ROTATE, "AUTO-ROTATE", false}, {B_CLEAR, "CLEAR LOG", false},
        {B_LOG_FOLDER, "LOG FOLDER", false}, {B_VERIFY, "VERIFY LOG", false}};   // these two live in the log panel
    bool keepT = false, keepR = true;
    for (auto& b : A.btns) { if (b.id == B_TOGGLE_ALL) keepT = b.toggled; if (b.id == B_ROTATE) keepR = b.toggled; }
    A.btns.clear();
    int x = m;
    for (const auto& d : defs) {
        Button b;
        b.id = d.id; b.label = d.label; b.danger = d.danger;
        int w = btnWidth(b.label);
        if (d.id == B_VERIFY)
            b.r = {A.rAlert.right - 14 - 112, A.rAlert.top + 2, A.rAlert.right - 14, A.rAlert.top + 24};
        else if (d.id == B_LOG_FOLDER)
            b.r = {A.rAlert.right - 14 - 112 - 6 - 124, A.rAlert.top + 2, A.rAlert.right - 14 - 112 - 6, A.rAlert.top + 24};
        else {
            b.r = {x, 38, x + w, 62};
            x += w + 6;
        }
        if (d.id == B_TOGGLE_ALL) b.toggled = keepT;
        if (d.id == B_ROTATE) b.toggled = keepR;
        A.btns.push_back(b);
    }
}

// ------------------------------------------------------------------------------------------
// refresh: model -> lists
// ------------------------------------------------------------------------------------------
static std::string hhmmss(const SYSTEMTIME& t) {
    char b[32];
    snprintf(b, sizeof b, "%02d:%02d:%02d", t.wHour, t.wMinute, t.wSecond);
    return b;
}

static std::string scopeOf(const ConnRow& r) {
    if (r.listening) return "LISTEN";
    if (r.c.proto == Proto::UDP && r.c.remote.isZero()) return "BOUND";
    return r.foreign ? "FOREIGN" : "LOCAL";
}

void refreshModel() {
    model::build(A.model, A.selPid, A.showAll);
    const Model& M = A.model;

    if (A.selPid == 0 && !M.procs.empty()) A.selPid = M.procs[0].pid;

    // processes
    A.lproc.rows.clear();
    for (const auto& p : M.procs) {
        Row r;
        char pid[16], nc[16], sc[16];
        snprintf(pid, sizeof pid, "%lu", (unsigned long)p.pid);
        snprintf(nc, sizeof nc, "%d", p.nconn);
        snprintf(sc, sizeof sc, "%d", p.score);
        r.cells = {(p.blocked ? "[X] " : "") + p.name, pid, nc, sc};
        r.color = p.blocked ? theme::DIM : (p.score >= 20 ? theme::scoreColor(p.score) : theme::TEXT);
        r.bar = p.score;
        r.key = p.pid;
        A.lproc.rows.push_back(r);
    }
    A.lproc.selectKey(A.selPid);
    A.lproc.clamp();

    // connections of the selected process
    A.conns = model::connsFor(M, A.selPid);
    A.lconn.rows.clear();
    for (const auto& c : A.conns) {
        Row r;
        std::string reg;
        std::string cc = "";
        if (c.foreign) {
            if (!c.wi.done) { reg = "resolving registration data..."; cc = ".."; }
            else if (c.wi.failed) { reg = "lookup failed: " + c.wi.note; cc = "??"; }
            else {
                cc = c.wi.country.empty() ? "--" : c.wi.country;
                reg = c.wi.org.empty() ? c.wi.netname : c.wi.org;
                if (!c.wi.host.empty()) reg += "  <" + c.wi.host + ">";
            }
        }
        std::string st = c.c.proto == Proto::UDP ? (c.c.fromEtw ? "UDP*" : "UDP") :
                         (c.c.fromEtw && c.c.state == MIB_TCP_STATE_ESTAB ? "ESTAB*" : netmon::tcpStateName(c.c.state));
        r.cells = {c.c.proto == Proto::TCP ? "TCP" : "UDP", scopeOf(c),
                   model::endpoint(c.c.local, c.c.lport),
                   c.c.remote.isZero() ? "-" : model::endpoint(c.c.remote, c.c.rport),
                   st, cc, reg};
        r.color = c.ipBlocked ? theme::RED : (c.foreign ? theme::TEXT : theme::DIM);
        r.key = connKey(c.c);
        A.lconn.rows.push_back(r);
    }
    A.lconn.selectKey(A.selConn);
    if (A.lconn.sel < 0) A.selConn = 0;
    A.lconn.clamp();

    // alerts: newest first
    A.lalert.rows.clear();
    for (auto it = M.snap.alerts.rbegin(); it != M.snap.alerts.rend(); ++it) {
        Row r;
        r.cells = {hhmmss(it->when), theme::sevName(it->sev), it->proc + " [" + std::to_string(it->pid) + "]", it->text};
        r.color = theme::sevColor(it->sev);
        r.cellColors = {theme::DIM, 0, theme::TEXT, 0};
        A.lalert.rows.push_back(r);
    }
    A.lalert.clamp();

    // globe
    A.globe.setHome(M.home);
    A.globe.setTargets(M.targets);

    // button states
    const ProcRow* p = model::findProc(M, A.selPid);
    const ConnRow* c = selectedConn();
    bool havePath = p && !p->path.empty();
    for (auto& b : A.btns) {
        switch (b.id) {
            case B_BLOCK_APP:   b.enabled = A.fwOk && havePath && !p->blocked; break;
            case B_UNBLOCK_APP: b.enabled = A.fwOk && havePath && p->blocked; break;
            case B_BLOCK_IP:    b.enabled = A.fwOk && c && c->foreign && !c->ipBlocked; break;
            case B_UNBLOCK_IP:  b.enabled = A.fwOk && c && c->foreign && c->ipBlocked; break;
            case B_SEVER:       b.enabled = c && c->c.proto == Proto::TCP && !c->c.local.v6 && !c->listening && c->foreign; break;
            case B_SCAN:        b.enabled = p != nullptr; break;
            case B_KILL:        b.enabled = p && A.selPid > 4; break;
            case B_TOGGLE_ALL:  b.toggled = A.showAll; break;
            case B_ROTATE:      b.toggled = A.globe.autoRotate(); break;
            default: break;
        }
    }
}

void onSelectProc(DWORD pid) {
    if (pid == A.selPid) return;
    A.selPid = pid;
    A.selConn = 0;
    A.lconn.scroll = 0;
    A.lconn.sel = -1;
    refreshModel();
}

void onSelectConn(uint64_t key) {
    A.selConn = key;
    const ConnRow* c = selectedConn();
    if (c && c->foreign && c->wi.done && !c->wi.failed)
        if (const geo::Country* ct = geo::findCountry(c->wi.country)) A.globe.centerOn(ct->lat, ct->lon);
    refreshModel();
}

// ------------------------------------------------------------------------------------------
// painting
// ------------------------------------------------------------------------------------------
static int wrapText(HDC dc, int x, int y, int w, const std::string& s, COLORREF c, HFONT f, int maxY) {
    SelectObject(dc, f);
    SetTextColor(dc, c);
    SetBkMode(dc, TRANSPARENT);
    std::wstring ws = widen(s);
    RECT calc = {x, y, x + w, y};
    DrawTextW(dc, ws.c_str(), (int)ws.size(), &calc, DT_WORDBREAK | DT_CALCRECT | DT_NOPREFIX);
    int h = calc.bottom - calc.top;
    if (y + h > maxY) { h = maxY - y; if (h < 12) return 0; }
    RECT dr = {x, y, x + w, y + h};
    DrawTextW(dc, ws.c_str(), (int)ws.size(), &dr, DT_WORDBREAK | DT_NOPREFIX | DT_END_ELLIPSIS);
    return h;
}

static void kv(HDC dc, int x, int y, int w, const char* k, const std::string& v, COLORREF c = theme::TEXT) {
    ui::text(dc, x, y + 1, k, theme::DIM, A.f.tiny);
    RECT r = {x + 84, y, x + w, y + 16};
    ui::textIn(dc, r, v.empty() ? "-" : v, c, A.f.mono);
}

static void drawHeader(HDC dc) {
    RECT h = A.rHeader;
    ui::fill(dc, h, RGB(5, 13, 17));
    ui::line(dc, 0, h.bottom - 1, A.W, h.bottom - 1, theme::BORDER2, 2);
    // chevrons + title
    for (int i = 0; i < 3; i++) {
        POINT p[4] = {{10 + i * 12, 8}, {20 + i * 12, 8}, {30 + i * 12, 22}, {20 + i * 12, 22}};
        HBRUSH b = CreateSolidBrush(i == 2 ? theme::AMBER : theme::ACCENT);
        HPEN np = (HPEN)SelectObject(dc, GetStockObject(NULL_PEN));
        HBRUSH ob = (HBRUSH)SelectObject(dc, b);
        Polygon(dc, p, 4);
        SelectObject(dc, ob); SelectObject(dc, np); DeleteObject(b);
    }
    ui::text(dc, 56, 3, "UNATCO", theme::ACCENT, A.f.big);
    ui::text(dc, 150, 5, "//  NETWORK DEFENSE TERMINAL", theme::TEXT, A.f.head);
    ui::text(dc, 150, 20, "UNITED NATIONS ANTI-TERRORIST COALITION  -  SECTOR NET-OPS", theme::DIM, A.f.tiny);

    // status chips, right to left
    struct Chip { std::string t; COLORREF c; };
    const Model& M = A.model;
    int w = M.worstScore;
    const char* lvl = w >= 70 ? "CRITICAL" : (w >= 45 ? "HIGH" : (w >= 20 ? "ELEVATED" : "NOMINAL"));
    std::vector<Chip> chips = {
        {std::string("THREAT: ") + lvl, theme::scoreColor(w)},
        {A.fwOk ? "WFP: ARMED" : "WFP: OFFLINE", A.fwOk ? theme::GREEN : theme::RED},
        {M.snap.etwOn ? "KERNEL TRACE: LIVE" : "KERNEL TRACE: OFF", M.snap.etwOn ? theme::GREEN : theme::AMBER},
        {M.snap.admin ? "ELEVATED" : "LIMITED", M.snap.admin ? theme::GREEN : theme::AMBER},
    };
    int x = A.W - 12;
    for (auto& c : chips) {
        int tw = ui::textWidth(dc, c.t, A.f.tiny) + 20;
        RECT r = {x - tw, 10, x, 28};
        ui::fill(dc, r, RGB(8, 22, 28));
        HPEN p = CreatePen(PS_SOLID, 1, c.c);
        HPEN op = (HPEN)SelectObject(dc, p);
        HBRUSH nb = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
        Rectangle(dc, r.left, r.top, r.right, r.bottom);
        SelectObject(dc, nb); SelectObject(dc, op); DeleteObject(p);
        ui::textIn(dc, r, c.t, c.c, A.f.tiny, DT_CENTER);
        x -= tw + 6;
    }
    // status line / counters
    char buf[200];
    snprintf(buf, sizeof buf, "PROCS %d   FOREIGN LINKS %d   WHOIS QUEUE %d   STEALTH(ETW-ONLY) %llu   SCANS QUEUED %d",
             (int)M.snap.net.procs.size(), M.totalForeign, (int)intel::pendingCount(),
             (unsigned long long)M.snap.etwSeen, (int)M.snap.scansQueued);
    int sx = A.btns.empty() ? 600 : A.btns.back().r.right + 16;
    RECT sr = {sx, 36, A.W - 10, 52};
    ui::textIn(dc, sr, buf, theme::DIM, A.f.tiny, DT_RIGHT);
    if (!A.status.empty() && nowMs() < A.statusUntil) {
        RECT mr = {sx, 50, A.W - 10, 64};
        ui::textIn(dc, mr, A.status, theme::AMBER, A.f.tiny, DT_RIGHT);
    }
    int i = 0;
    for (auto& b : A.btns) {
        if (b.id != B_LOG_FOLDER && b.id != B_VERIFY) b.draw(dc, A.f, i == A.hoverBtn, i == A.downBtn);
        i++;
    }
}

static void drawRegistry(HDC dc) {
    ui::panel(dc, A.rReg, "REMOTE REGISTRATION", A.f);
    int x = A.rReg.left + 14, y = A.rReg.top + 28, w = A.rReg.right - A.rReg.left - 24;
    const ConnRow* c = selectedConn();
    if (!c) {
        wrapText(dc, x, y, w, "SELECT A CONNECTION TO INSPECT ITS REMOTE ENDPOINT.", theme::DIM, A.f.tiny, A.rReg.bottom - 6);
        return;
    }
    kv(dc, x, y, w, "ENDPOINT", model::endpoint(c->c.remote, c->c.rport), theme::AMBER); y += 17;
    if (!c->foreign) {
        wrapText(dc, x, y + 4, w, c->listening ? "LISTENING SOCKET - NO REMOTE PEER." :
                 "LOCAL / PRIVATE ADDRESS - NEVER LEAVES THIS NETWORK, NO REGISTRY ENTRY.", theme::DIM, A.f.tiny, A.rReg.bottom - 6);
        return;
    }
    const WhoisInfo& wi = c->wi;
    if (!wi.done) { wrapText(dc, x, y + 4, w, "QUERYING REGIONAL INTERNET REGISTRY...", theme::ACCENT, A.f.tiny, A.rReg.bottom - 6); return; }
    if (wi.failed) { wrapText(dc, x, y + 4, w, "LOOKUP FAILED: " + wi.note, theme::RED, A.f.tiny, A.rReg.bottom - 6); return; }
    const geo::Country* ct = geo::findCountry(wi.country);
    kv(dc, x, y, w, "HOSTNAME", wi.host); y += 17;
    kv(dc, x, y, w, "OWNER", wi.org); y += 17;
    kv(dc, x, y, w, "NETWORK", wi.netname); y += 17;
    kv(dc, x, y, w, "COUNTRY", ct ? std::string(ct->name) + " (" + wi.country + ")" : wi.country); y += 17;
    kv(dc, x, y, w, "RANGE", wi.cidr.empty() ? wi.range : wi.cidr); y += 17;
    kv(dc, x, y, w, "REGISTERED", wi.registered); y += 17;
    kv(dc, x, y, w, "ABUSE", wi.abuse); y += 17;
    kv(dc, x, y, w, "REGISTRY", wi.registry); y += 17;
    if (c->ipBlocked) kv(dc, x, y, w, "FIREWALL", "BLOCKED", theme::RED);
}

static void drawThreat(HDC dc) {
    ui::panel(dc, A.rThreat, "THREAT ANALYSIS", A.f);
    int x = A.rThreat.left + 14, y = A.rThreat.top + 28, w = A.rThreat.right - A.rThreat.left - 24;
    const Model& M = A.model;
    auto pit = M.snap.net.procs.find(A.selPid);
    if (pit == M.snap.net.procs.end()) {
        wrapText(dc, x, y, w, "NO PROCESS SELECTED.", theme::DIM, A.f.tiny, A.rThreat.bottom - 6);
        return;
    }
    const ProcInfo& p = pit->second;
    kv(dc, x, y, w, "PROCESS", p.name + "  [" + std::to_string(p.pid) + "]"); y += 17;
    kv(dc, x, y, w, "IMAGE", p.path.empty() ? "(not readable)" : p.path); y += 17;
    auto par = M.snap.net.procs.find(p.ppid);
    kv(dc, x, y, w, "PARENT", par == M.snap.net.procs.end() ? std::to_string(p.ppid) : par->second.name + "  [" + std::to_string(p.ppid) + "]"); y += 17;

    auto th = M.snap.threat.find(A.selPid);
    std::string scan = "PENDING - queued";
    COLORREF sc = theme::AMBER;
    int score = 0;
    if (th != M.snap.threat.end()) {
        score = th->second.score;
        if (th->second.unreadable) { scan = "MEMORY NOT READABLE (protected process)"; sc = theme::DIM; }
        else if (th->second.scanned) {
            char b[120];
            snprintf(b, sizeof b, "%d regions in %u ms%s", th->second.regions, th->second.scanMs,
                     th->second.jitHost ? "  (JIT host: reduced weights)" : "");
            scan = b; sc = theme::GREEN;
        }
    }
    kv(dc, x, y, w, "MEM SCAN", scan, sc); y += 20;
    RECT br = {x + 84, y, x + w - 50, y + 12};
    ui::bar(dc, br, score, theme::scoreColor(score));
    char sb[16]; snprintf(sb, sizeof sb, "%d/100", score);
    ui::text(dc, x + w - 46, y - 1, sb, theme::scoreColor(score), A.f.tiny);
    ui::text(dc, x, y - 1, "SCORE", theme::DIM, A.f.tiny);
    y += 20;

    if (th == M.snap.threat.end() || th->second.findings.empty()) {
        wrapText(dc, x, y, w, score == 0 ? "NO HOSTILE INDICATORS." : "", theme::GREEN, A.f.tiny, A.rThreat.bottom - 6);
        return;
    }
    std::vector<Finding> fs = th->second.findings;
    std::sort(fs.begin(), fs.end(), [](const Finding& a, const Finding& b) { return a.score > b.score; });
    for (auto& f : fs) {
        if (y > A.rThreat.bottom - 18) { ui::text(dc, x, A.rThreat.bottom - 16, "...", theme::DIM, A.f.tiny); break; }
        char tag[64];
        snprintf(tag, sizeof tag, "[%s +%d] %s", theme::sevName(f.sev), f.score, f.code.c_str());
        ui::text(dc, x, y, tag, theme::sevColor(f.sev), A.f.tiny);
        y += 14;
        y += wrapText(dc, x + 10, y, w - 10, f.text, theme::TEXT, A.f.tiny, A.rThreat.bottom - 6) + 4;
    }
}

void paintAll(HDC wdc) {
    if (A.W < 100 || A.H < 100) return;
    if (!A.backDC || A.bw != A.W || A.bh != A.H) {
        if (A.backDC) { SelectObject(A.backDC, A.oldBmp); DeleteDC(A.backDC); DeleteObject(A.backBmp); }
        A.backDC = CreateCompatibleDC(wdc);
        A.backBmp = CreateCompatibleBitmap(wdc, A.W, A.H);
        A.oldBmp = (HBITMAP)SelectObject(A.backDC, A.backBmp);
        A.bw = A.W; A.bh = A.H;
    }
    HDC dc = A.backDC;
    RECT all = {0, 0, A.W, A.H};
    ui::fill(dc, all, theme::BG);

    drawHeader(dc);

    char t[48];
    snprintf(t, sizeof t, "PROCESSES  [%d]", (int)A.lproc.rows.size());
    ui::panel(dc, A.rProc, t, A.f);
    A.lproc.draw(dc, A.f);

    // globe lives in its own framed region
    ui::panel(dc, A.rGlobe, "", A.f, theme::BORDER2);
    static const double t0 = (double)nowMs() / 1000.0;
    A.globe.render(dc, A.rGlobe.left + 2, A.rGlobe.top + 2, A.rGlobe.right - A.rGlobe.left - 4,
                   A.rGlobe.bottom - A.rGlobe.top - 4, A.f.tiny, A.f.head, (double)nowMs() / 1000.0 - t0);

    const ProcRow* p = model::findProc(A.model, A.selPid);
    std::string title = "CONNECTIONS  -  " + (p ? p->name : std::string("none")) +
                        (p ? "  [" + std::to_string(p->nconn) + "]" : "");
    ui::panel(dc, A.rConn, title.c_str(), A.f);
    A.lconn.draw(dc, A.f);

    drawRegistry(dc);
    drawThreat(dc);

    snprintf(t, sizeof t, "SECURITY LOG  [%d]", (int)A.lalert.rows.size());
    ui::panel(dc, A.rAlert, t, A.f);
    A.lalert.draw(dc, A.f);

    // permanent-history status + its two buttons (drawn after the panel so they sit on top of it)
    {
        int bi = 0, leftEdge = A.rAlert.right - 14;
        for (auto& b : A.btns) {
            if (b.id == B_LOG_FOLDER || b.id == B_VERIFY) {
                b.draw(dc, A.f, bi == A.hoverBtn, bi == A.downBtn);
                if (b.r.left < leftEdge) leftEdge = b.r.left;
            }
            bi++;
        }
        std::string h = history::head();
        char hs[260];
        snprintf(hs, sizeof hs, "HISTORY  %s   chain head %.16s   %llu rec", history::folder().c_str(),
                 h.c_str(), (unsigned long long)history::records());
        RECT tr = {A.rAlert.left + 260, A.rAlert.top + 4, leftEdge - 10, A.rAlert.top + 22};
        if (tr.right > tr.left) ui::textIn(dc, tr, hs, theme::DIM, A.f.tiny, DT_RIGHT);
    }

    BitBlt(wdc, 0, 0, A.W, A.H, dc, 0, 0, SRCCOPY);
}
