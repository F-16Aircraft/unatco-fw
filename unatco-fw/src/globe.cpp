#include "globe.h"
#include "geo.h"

static const double kPi = 3.14159265358979323846;
static inline double rad(double d) { return d * kPi / 180.0; }
static inline double deg(double r) { return r * 180.0 / kPi; }

static inline uint32_t pack(int r, int g, int b) {
    r = r < 0 ? 0 : (r > 255 ? 255 : r);
    g = g < 0 ? 0 : (g > 255 ? 255 : g);
    b = b < 0 ? 0 : (b > 255 ? 255 : b);
    return ((uint32_t)r << 16) | ((uint32_t)g << 8) | (uint32_t)b;
}

Globe::Globe() { geo::buildMask(); }

Globe::~Globe() {
    if (mem_) {
        if (oldBmp_) SelectObject(mem_, oldBmp_);
        DeleteDC(mem_);
    }
    if (bmp_) DeleteObject(bmp_);
}

void Globe::setHome(const GlobeHome& h) {
    home_ = h;
    if (h.valid && !easing_) { goalLam_ = h.lon; goalPhi_ = h.lat * 0.6 + 10; }
}

void Globe::setTargets(const std::vector<GlobeTarget>& t) { targets_ = t; }

void Globe::centerOn(double lat, double lon) {
    goalLam_ = lon;
    goalPhi_ = lat * 0.7;
    easing_ = true;
}

void Globe::mouseDown(int x, int y) { drag_ = true; lx_ = x; ly_ = y; easing_ = false; }
void Globe::mouseUp() { drag_ = false; }
void Globe::mouseMove(int x, int y) {
    if (!drag_) return;
    double k = 90.0 / (R_ > 1 ? R_ : 100.0);
    lam0_ -= (x - lx_) * k;
    phi0_ += (y - ly_) * k;
    if (phi0_ > 85) phi0_ = 85;
    if (phi0_ < -85) phi0_ = -85;
    while (lam0_ > 180) lam0_ -= 360;
    while (lam0_ < -180) lam0_ += 360;
    lx_ = x; ly_ = y;
}

void Globe::ensure(int w, int h) {
    if (w == bw_ && h == bh_ && bmp_) return;
    if (mem_ && oldBmp_) SelectObject(mem_, oldBmp_);
    if (bmp_) { DeleteObject(bmp_); bmp_ = nullptr; }
    HDC scr = GetDC(nullptr);
    if (!mem_) mem_ = CreateCompatibleDC(scr);
    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h;       // top-down
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    void* bits = nullptr;
    bmp_ = CreateDIBSection(scr, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    ReleaseDC(nullptr, scr);
    px_ = (uint32_t*)bits;
    oldBmp_ = (HBITMAP)SelectObject(mem_, bmp_);
    bw_ = w; bh_ = h;
}

void Globe::projectVec(double vx, double vy, double vz, double& x, double& y, double& z) const {
    const double l0 = rad(lam0_), p0 = rad(phi0_);
    double x1 = vx * cos(l0) - vz * sin(l0);
    double z1 = vx * sin(l0) + vz * cos(l0);
    double y2 = vy * cos(p0) - z1 * sin(p0);
    double z2 = vy * sin(p0) + z1 * cos(p0);
    x = x1; y = y2; z = z2;
}

void Globe::project(double lat, double lon, double r, double& x, double& y, double& z) const {
    double la = rad(lat), lo = rad(lon);
    projectVec(r * cos(la) * sin(lo), r * sin(la), r * cos(la) * cos(lo), x, y, z);
}

struct V3 { double x, y, z; };
static V3 unitVec(double lat, double lon) {
    double la = rad(lat), lo = rad(lon);
    return {cos(la) * sin(lo), sin(la), cos(la) * cos(lo)};
}

static uint32_t hashIp(const IpAddr& ip) {
    uint32_t h = 2166136261u;
    for (int i = 0; i < (ip.v6 ? 16 : 4); i++) { h ^= ip.b[i]; h *= 16777619u; }
    return h;
}

void Globe::render(HDC dst, int X, int Y, int W, int H, HFONT font, HFONT bigFont, double t) {
    if (W < 40 || H < 40) return;
    ensure(W, H);
    double dt = t - lastT_;
    if (dt < 0 || dt > 1) dt = 0.033;
    lastT_ = t;

    // view motion
    if (easing_ && !drag_) {
        double dl = goalLam_ - lam0_;
        while (dl > 180) dl -= 360;
        while (dl < -180) dl += 360;
        lam0_ += dl * std::min(1.0, dt * 4.0);
        phi0_ += (goalPhi_ - phi0_) * std::min(1.0, dt * 4.0);
        if (fabs(dl) < 0.3 && fabs(goalPhi_ - phi0_) < 0.3) easing_ = false;
    } else if (auto_ && !drag_) {
        lam0_ += dt * 6.0;
        if (lam0_ > 180) lam0_ -= 360;
    }

    cx_ = W / 2.0;
    cy_ = H / 2.0;
    R_ = std::min(W, H) * 0.5 - 26;
    if (R_ < 20) R_ = 20;

    // ---------- background + sphere dots, written straight into the DIB ----------
    const uint32_t bg = pack(4, 9, 12);
    for (int i = 0; i < W * H; i++) px_[i] = bg;

    // faint scan-lines for the CRT feel
    for (int yy = 0; yy < H; yy += 4)
        for (int xx = 0; xx < W; xx++) px_[yy * W + xx] = pack(7, 14, 18);

    const double p0 = rad(phi0_), sp0 = sin(p0), cp0 = cos(p0);
    const int step = 3;
    const int x0 = (int)(cx_ - R_) - 1, x1 = (int)(cx_ + R_) + 1;
    const int y0 = (int)(cy_ - R_) - 1, y1 = (int)(cy_ + R_) + 1;
    for (int py = y0; py <= y1; py += step) {
        for (int pxl = x0; pxl <= x1; pxl += step) {
            double nx = (pxl - cx_) / R_, ny = (cy_ - py) / R_;
            double rr = nx * nx + ny * ny;
            if (rr > 1.0) continue;
            double nz = sqrt(1.0 - rr);
            double lat = deg(asin(nz * sp0 + ny * cp0));
            double lon = lam0_ + deg(atan2(nx, nz * cp0 - ny * sp0));
            while (lon > 180) lon -= 360;
            while (lon < -180) lon += 360;
            bool land = geo::isLand(lat, lon);
            double lit = 0.35 + 0.65 * nz;               // limb darkening
            uint32_t c;
            if (land) c = pack((int)(30 * lit), (int)(190 * lit), (int)(180 * lit));
            else      c = pack((int)(5 * lit), (int)(34 * lit), (int)(44 * lit));
            int sz = land ? 2 : 1;
            for (int dy = 0; dy < sz; dy++)
                for (int dx = 0; dx < sz; dx++) {
                    int ax = pxl + dx, ay = py + dy;
                    if (ax >= 0 && ax < W && ay >= 0 && ay < H) px_[ay * W + ax] = c;
                }
        }
    }
    GdiFlush();

    // ---------- GDI overlay on the DIB ----------
    HDC dc = mem_;
    SetBkMode(dc, TRANSPARENT);
    HFONT oldFont = (HFONT)SelectObject(dc, font);

    // graticule
    HPEN gridPen = CreatePen(PS_SOLID, 1, RGB(14, 78, 88));
    HPEN oldPen = (HPEN)SelectObject(dc, gridPen);
    for (int lat = -60; lat <= 60; lat += 30) {
        bool pen = false;
        for (int lon = -180; lon <= 180; lon += 4) {
            double x, y, z;
            project(lat, lon, 1.0, x, y, z);
            if (z <= 0) { pen = false; continue; }
            int sx = (int)(cx_ + R_ * x), sy = (int)(cy_ - R_ * y);
            if (!pen) { MoveToEx(dc, sx, sy, nullptr); pen = true; } else LineTo(dc, sx, sy);
        }
    }
    for (int lon = -180; lon < 180; lon += 30) {
        bool pen = false;
        for (int lat = -88; lat <= 88; lat += 4) {
            double x, y, z;
            project(lat, lon, 1.0, x, y, z);
            if (z <= 0) { pen = false; continue; }
            int sx = (int)(cx_ + R_ * x), sy = (int)(cy_ - R_ * y);
            if (!pen) { MoveToEx(dc, sx, sy, nullptr); pen = true; } else LineTo(dc, sx, sy);
        }
    }
    SelectObject(dc, oldPen);
    DeleteObject(gridPen);

    // rim: double ring + tick marks
    HPEN rim = CreatePen(PS_SOLID, 2, RGB(60, 200, 210));
    HPEN rim2 = CreatePen(PS_SOLID, 1, RGB(20, 100, 110));
    HBRUSH nb = (HBRUSH)GetStockObject(NULL_BRUSH);
    HBRUSH ob = (HBRUSH)SelectObject(dc, nb);
    oldPen = (HPEN)SelectObject(dc, rim);
    Ellipse(dc, (int)(cx_ - R_), (int)(cy_ - R_), (int)(cx_ + R_), (int)(cy_ + R_));
    SelectObject(dc, rim2);
    double R2 = R_ + 9;
    Ellipse(dc, (int)(cx_ - R2), (int)(cy_ - R2), (int)(cx_ + R2), (int)(cy_ + R2));
    for (int a = 0; a < 360; a += 10) {
        double ca = cos(rad(a)), sa = sin(rad(a));
        double len = (a % 90 == 0) ? 14 : (a % 30 == 0 ? 9 : 5);
        MoveToEx(dc, (int)(cx_ + ca * R2), (int)(cy_ + sa * R2), nullptr);
        LineTo(dc, (int)(cx_ + ca * (R2 + len)), (int)(cy_ + sa * (R2 + len)));
    }
    SelectObject(dc, oldPen);
    SelectObject(dc, ob);
    DeleteObject(rim);
    DeleteObject(rim2);

    // ---------- connection arcs ----------
    struct Label { int x, y; std::string text; COLORREF c; };
    std::vector<Label> labels;
    std::map<std::string, std::pair<int, bool>> perCountry;     // cc -> (count, any highlighted)
    std::map<std::string, const GlobeTarget*> firstOf;

    const bool haveHome = home_.valid;
    V3 hv = unitVec(home_.lat, home_.lon);

    // draw non-highlighted first, highlighted on top
    for (int pass = 0; pass < 2; pass++) {
        for (const auto& tg : targets_) {
            if (tg.cc.empty()) continue;
            if ((pass == 1) != tg.highlight) continue;
            uint32_t hsh = hashIp(tg.ip);
            // fan out connections that land in the same country
            double jl = ((int)(hsh & 0xFF) - 128) / 128.0 * 1.4;
            double jo = ((int)((hsh >> 8) & 0xFF) - 128) / 128.0 * 1.4;
            double tlat = tg.lat + jl, tlon = tg.lon + jo;
            {
                auto& pc = perCountry[tg.cc];
                if (tg.highlight) pc.second = true;
                if (!firstOf.count(tg.cc)) firstOf[tg.cc] = &tg;
            }
            if (!haveHome) continue;
            V3 tv = unitVec(tlat, tlon);
            double dot = hv.x * tv.x + hv.y * tv.y + hv.z * tv.z;
            dot = dot > 1 ? 1 : (dot < -1 ? -1 : dot);
            double th = acos(dot);
            if (th < 0.002) continue;
            double s = sin(th);
            double h = 0.10 + 0.40 * (th / kPi);

            COLORREF col = tg.blocked ? RGB(110, 110, 110) : tg.color;
            int pw = tg.highlight ? 2 : 1;
            if (!tg.highlight) {      // dim non-selected arcs so the selection pops
                col = RGB(GetRValue(col) * 6 / 10, GetGValue(col) * 6 / 10, GetBValue(col) * 6 / 10);
            }
            HPEN ap = CreatePen(PS_SOLID, pw, col);
            HPEN old2 = (HPEN)SelectObject(dc, ap);
            const int N = 56;
            bool pen = false;
            double lastSx = 0, lastSy = 0;
            double pulseT = fmod(t * 0.30 + (hsh % 1000) / 1000.0, 1.0);
            int pulseX = -1, pulseY = -1;
            for (int i = 0; i <= N; i++) {
                double u = (double)i / N;
                double a = sin((1 - u) * th) / s, b = sin(u * th) / s;
                double r = 1.0 + h * sin(kPi * u);
                double vx = (a * hv.x + b * tv.x) * r;
                double vy = (a * hv.y + b * tv.y) * r;
                double vz = (a * hv.z + b * tv.z) * r;
                double x, y, z;
                projectVec(vx, vy, vz, x, y, z);
                bool vis = z > 0 || (x * x + y * y) > 1.0;
                int sx = (int)(cx_ + R_ * x), sy = (int)(cy_ - R_ * y);
                if (!vis) { pen = false; continue; }
                if (!pen) { MoveToEx(dc, sx, sy, nullptr); pen = true; } else LineTo(dc, sx, sy);
                lastSx = sx; lastSy = sy;
                if (fabs(u - pulseT) < 0.5 / N) { pulseX = sx; pulseY = sy; }
            }
            (void)lastSx; (void)lastSy;
            SelectObject(dc, old2);
            DeleteObject(ap);
            if (pulseX >= 0) {
                HBRUSH pb = CreateSolidBrush(tg.blocked ? RGB(150, 150, 150) : RGB(230, 255, 255));
                HBRUSH ob2 = (HBRUSH)SelectObject(dc, pb);
                HPEN np = (HPEN)SelectObject(dc, GetStockObject(NULL_PEN));
                Ellipse(dc, pulseX - 2, pulseY - 2, pulseX + 3, pulseY + 3);
                SelectObject(dc, np);
                SelectObject(dc, ob2);
                DeleteObject(pb);
            }
        }
    }

    // ---------- country markers + labels ----------
    for (auto& kv : perCountry) {
        const GlobeTarget* tg = firstOf[kv.first];
        double x, y, z;
        project(tg->lat, tg->lon, 1.0, x, y, z);
        if (z <= 0.02) continue;
        int sx = (int)(cx_ + R_ * x), sy = (int)(cy_ - R_ * y);
        bool hl = kv.second.second;
        COLORREF c = hl ? RGB(255, 190, 60) : RGB(90, 230, 240);
        HPEN mp = CreatePen(PS_SOLID, 1, c);
        HPEN old3 = (HPEN)SelectObject(dc, mp);
        HBRUSH nb2 = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
        int rr = 5 + (int)(2 * sin(t * 3 + sx));
        Ellipse(dc, sx - rr, sy - rr, sx + rr + 1, sy + rr + 1);
        Rectangle(dc, sx - 2, sy - 2, sx + 3, sy + 3);
        SelectObject(dc, nb2);
        SelectObject(dc, old3);
        DeleteObject(mp);
        char buf[160];
        int cnt = 0;
        for (const auto& t2 : targets_) if (t2.cc == kv.first) cnt++;
        snprintf(buf, sizeof buf, "%s  %s x%d", kv.first.c_str(), tg->country.c_str(), cnt);
        labels.push_back({sx + 9, sy - 7, buf, c});
    }
    // nudge overlapping labels downward
    std::sort(labels.begin(), labels.end(), [](const Label& a, const Label& b) { return a.y < b.y; });
    for (size_t i = 1; i < labels.size(); i++)
        for (size_t j = 0; j < i; j++)
            if (abs(labels[i].x - labels[j].x) < 150 && abs(labels[i].y - labels[j].y) < 13)
                labels[i].y = labels[j].y + 13;
    for (auto& l : labels) {
        SetTextColor(dc, RGB(0, 0, 0));
        TextOutA(dc, l.x + 1, l.y + 1, l.text.c_str(), (int)l.text.size());
        SetTextColor(dc, l.c);
        TextOutA(dc, l.x, l.y, l.text.c_str(), (int)l.text.size());
    }

    // ---------- home marker ----------
    if (haveHome) {
        double x, y, z;
        project(home_.lat, home_.lon, 1.0, x, y, z);
        if (z > 0) {
            int sx = (int)(cx_ + R_ * x), sy = (int)(cy_ - R_ * y);
            double ph = fmod(t * 0.9, 1.0);
            int pr = 4 + (int)(ph * 16);
            HPEN hp = CreatePen(PS_SOLID, 1, RGB(255, 255, 255));
            HPEN hp2 = CreatePen(PS_SOLID, 2, RGB(255, 190, 60));
            HPEN o4 = (HPEN)SelectObject(dc, hp);
            HBRUSH nb3 = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
            Ellipse(dc, sx - pr, sy - pr, sx + pr + 1, sy + pr + 1);
            SelectObject(dc, hp2);
            MoveToEx(dc, sx - 9, sy, nullptr); LineTo(dc, sx + 10, sy);
            MoveToEx(dc, sx, sy - 9, nullptr); LineTo(dc, sx, sy + 10);
            SelectObject(dc, nb3);
            SelectObject(dc, o4);
            DeleteObject(hp);
            DeleteObject(hp2);
            std::string lb = "[ YOU ] " + home_.label;
            SetTextColor(dc, RGB(0, 0, 0));
            TextOutA(dc, sx + 13, sy + 5, lb.c_str(), (int)lb.size());
            SetTextColor(dc, RGB(255, 210, 90));
            TextOutA(dc, sx + 12, sy + 4, lb.c_str(), (int)lb.size());
        }
    }

    // ---------- corner readouts ----------
    SelectObject(dc, bigFont ? bigFont : font);
    SetTextColor(dc, RGB(70, 210, 220));
    TextOutA(dc, 12, 8, "GLOBAL TRAFFIC MAP", 18);
    SelectObject(dc, font);
    char info[128];
    snprintf(info, sizeof info, "LAT %+06.1f  LON %+07.1f", phi0_, lam0_);
    SetTextColor(dc, RGB(40, 130, 140));
    TextOutA(dc, 12, 28, info, (int)strlen(info));
    snprintf(info, sizeof info, "ROUTES %d   REGIONS %d", (int)targets_.size(), (int)perCountry.size());
    TextOutA(dc, 12, 42, info, (int)strlen(info));
    SetTextColor(dc, RGB(40, 130, 140));
    const char* hint = "DRAG TO ROTATE";
    TextOutA(dc, 12, H - 18, hint, (int)strlen(hint));

    SelectObject(dc, oldFont);
    BitBlt(dst, X, Y, W, H, dc, 0, 0, SRCCOPY);
}
