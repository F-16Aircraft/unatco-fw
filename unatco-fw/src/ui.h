#pragma once
#include "common.h"

// UNATCO-terminal look: near-black teal glass, cyan phosphor text, amber highlights,
// angular bracketed panels. Everything is drawn by hand with GDI.
namespace theme {
const COLORREF BG      = RGB(4, 9, 12);
const COLORREF PANEL   = RGB(7, 17, 22);
const COLORREF PANEL2  = RGB(10, 26, 33);
const COLORREF BORDER  = RGB(22, 100, 110);
const COLORREF BORDER2 = RGB(40, 170, 180);
const COLORREF TEXT    = RGB(150, 228, 228);
const COLORREF DIM     = RGB(64, 128, 138);
const COLORREF ACCENT  = RGB(70, 210, 222);
const COLORREF AMBER   = RGB(255, 190, 60);
const COLORREF ORANGE  = RGB(255, 140, 50);
const COLORREF RED     = RGB(255, 70, 60);
const COLORREF GREEN   = RGB(80, 232, 140);
const COLORREF SELECT  = RGB(14, 62, 72);
const COLORREF HOVER   = RGB(10, 40, 48);

inline COLORREF sevColor(Sev s) {
    switch (s) {
        case Sev::Critical: return RED;
        case Sev::High: return ORANGE;
        case Sev::Medium: return AMBER;
        case Sev::Low: return RGB(190, 220, 120);
        default: return DIM;
    }
}
inline COLORREF scoreColor(int sc) {
    if (sc >= 70) return RED;
    if (sc >= 45) return ORANGE;
    if (sc >= 20) return AMBER;
    if (sc > 0) return RGB(190, 220, 120);
    return GREEN;
}
inline const char* sevName(Sev s) {
    switch (s) {
        case Sev::Critical: return "CRITICAL";
        case Sev::High: return "HIGH";
        case Sev::Medium: return "MEDIUM";
        case Sev::Low: return "LOW";
        default: return "INFO";
    }
}
}  // namespace theme

struct Fonts {
    HFONT mono = nullptr, monoB = nullptr, head = nullptr, big = nullptr, tiny = nullptr;
    void create() {
        mono  = CreateFontW(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FIXED_PITCH, L"Consolas");
        monoB = CreateFontW(-14, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FIXED_PITCH, L"Consolas");
        head  = CreateFontW(-15, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Bahnschrift");
        big   = CreateFontW(-24, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Bahnschrift");
        tiny  = CreateFontW(-12, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, FIXED_PITCH, L"Consolas");
    }
    void destroy() { for (HFONT f : {mono, monoB, head, big, tiny}) if (f) DeleteObject(f); }
};

// ---------------- drawing helpers ----------------
namespace ui {

inline void fill(HDC dc, const RECT& r, COLORREF c) {
    HBRUSH b = CreateSolidBrush(c);
    FillRect(dc, &r, b);
    DeleteObject(b);
}

inline void text(HDC dc, int x, int y, const std::string& s, COLORREF c, HFONT f) {
    SelectObject(dc, f);
    SetTextColor(dc, c);
    SetBkMode(dc, TRANSPARENT);
    std::wstring w = widen(s);
    TextOutW(dc, x, y, w.c_str(), (int)w.size());
}

// text clipped to a rectangle with an ellipsis
inline void textIn(HDC dc, const RECT& r, const std::string& s, COLORREF c, HFONT f, UINT fmt = DT_LEFT) {
    SelectObject(dc, f);
    SetTextColor(dc, c);
    SetBkMode(dc, TRANSPARENT);
    std::wstring w = widen(s);
    RECT rr = r;
    DrawTextW(dc, w.c_str(), (int)w.size(), &rr, fmt | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
}

inline int textWidth(HDC dc, const std::string& s, HFONT f) {
    SelectObject(dc, f);
    std::wstring w = widen(s);
    SIZE sz{};
    GetTextExtentPoint32W(dc, w.c_str(), (int)w.size(), &sz);
    return sz.cx;
}

inline void line(HDC dc, int x1, int y1, int x2, int y2, COLORREF c, int w = 1) {
    HPEN p = CreatePen(PS_SOLID, w, c);
    HPEN o = (HPEN)SelectObject(dc, p);
    MoveToEx(dc, x1, y1, nullptr);
    LineTo(dc, x2, y2);
    SelectObject(dc, o);
    DeleteObject(p);
}

// angular panel: clipped corners, bracket accents, title tab
inline void panel(HDC dc, const RECT& r, const char* title, const Fonts& f, COLORREF edge = theme::BORDER) {
    fill(dc, r, theme::PANEL);
    const int c = 10;
    POINT pts[9] = {{r.left + c, r.top}, {r.right - 1, r.top}, {r.right - 1, r.bottom - c - 1},
                    {r.right - c - 1, r.bottom - 1}, {r.left, r.bottom - 1}, {r.left, r.top + c},
                    {r.left + c, r.top}, {r.left + c, r.top}, {r.left + c, r.top}};
    HPEN p = CreatePen(PS_SOLID, 1, edge);
    HPEN o = (HPEN)SelectObject(dc, p);
    Polyline(dc, pts, 7);
    SelectObject(dc, o);
    DeleteObject(p);
    // bright corner brackets
    line(dc, r.left + c, r.top, r.left + c + 22, r.top, theme::BORDER2, 2);
    line(dc, r.right - 1, r.bottom - c - 1, r.right - 1, r.bottom - c - 23, theme::BORDER2, 2);
    if (title && *title) {
        text(dc, r.left + c + 8, r.top + 4, title, theme::ACCENT, f.head);
        int tw = textWidth(dc, title, f.head);
        line(dc, r.left + c + 14 + tw, r.top + 13, r.right - 14, r.top + 13, theme::BORDER, 1);
    }
}

inline void bar(HDC dc, const RECT& r, int pct, COLORREF c) {
    fill(dc, r, RGB(10, 28, 34));
    RECT f = r;
    f.right = r.left + (r.right - r.left) * (pct < 0 ? 0 : (pct > 100 ? 100 : pct)) / 100;
    if (f.right > f.left) fill(dc, f, c);
    HBRUSH nb = (HBRUSH)GetStockObject(NULL_BRUSH);
    HPEN p = CreatePen(PS_SOLID, 1, theme::BORDER);
    HBRUSH ob = (HBRUSH)SelectObject(dc, nb);
    HPEN op = (HPEN)SelectObject(dc, p);
    Rectangle(dc, r.left, r.top, r.right, r.bottom);
    SelectObject(dc, op); SelectObject(dc, ob); DeleteObject(p);
}

inline bool inRect(const RECT& r, int x, int y) { return x >= r.left && x < r.right && y >= r.top && y < r.bottom; }

}  // namespace ui

// ---------------- widgets ----------------
struct Button {
    RECT r{};
    std::string label;
    int id = 0;
    bool enabled = true, danger = false, toggled = false;

    void draw(HDC dc, const Fonts& f, bool hover, bool down) const {
        COLORREF edge = !enabled ? RGB(25, 55, 60) : (danger ? theme::RED : theme::BORDER2);
        COLORREF fg = !enabled ? RGB(45, 85, 92) : (danger ? RGB(255, 140, 130) : theme::TEXT);
        COLORREF bg = toggled ? theme::SELECT : theme::PANEL2;
        if (enabled && hover) bg = danger ? RGB(50, 14, 14) : theme::HOVER;
        if (enabled && down) bg = danger ? RGB(80, 20, 20) : RGB(20, 80, 92);
        ui::fill(dc, r, bg);
        HPEN p = CreatePen(PS_SOLID, 1, edge);
        HPEN o = (HPEN)SelectObject(dc, p);
        POINT pts[7] = {{r.left + 6, r.top}, {r.right - 1, r.top}, {r.right - 1, r.bottom - 7},
                        {r.right - 7, r.bottom - 1}, {r.left, r.bottom - 1}, {r.left, r.top + 6}, {r.left + 6, r.top}};
        Polyline(dc, pts, 7);
        SelectObject(dc, o);
        DeleteObject(p);
        ui::textIn(dc, r, label, toggled ? theme::AMBER : fg, f.head, DT_CENTER);
    }
};

struct Column {
    std::string title;
    int width;          // pixels (last column may be 0 = fill)
    bool right = false;
};

struct Row {
    std::vector<std::string> cells;
    COLORREF color = theme::TEXT;
    std::vector<COLORREF> cellColors;   // optional per-cell override (0 = row colour)
    int bar = -1;                       // optional threat bar percent in last column
    uint64_t key = 0;                   // identity (pid etc.)
};

struct ListBox {
    RECT r{};                  // full widget rect incl. header
    std::vector<Column> cols;
    std::vector<Row> rows;
    int scroll = 0;            // first visible row
    int sel = -1;              // selected row
    int hover = -1;
    static constexpr int kHeadH = 22;
    static constexpr int kRowH = 21;

    int visibleRows() const { int n = (r.bottom - r.top - kHeadH) / kRowH; return n < 1 ? 1 : n; }
    void clamp() {
        int mx = (int)rows.size() - visibleRows();
        if (mx < 0) mx = 0;
        if (scroll > mx) scroll = mx;
        if (scroll < 0) scroll = 0;
    }
    void wheel(int delta) { scroll -= delta * 3; clamp(); }
    int rowAt(int x, int y) const {
        if (!ui::inRect(r, x, y) || y < r.top + kHeadH) return -1;
        int i = scroll + (y - r.top - kHeadH) / kRowH;
        return i >= 0 && i < (int)rows.size() ? i : -1;
    }
    void ensureVisible(int i) {
        if (i < scroll) scroll = i;
        if (i >= scroll + visibleRows()) scroll = i - visibleRows() + 1;
        clamp();
    }
    void selectKey(uint64_t key) {
        sel = -1;
        for (size_t i = 0; i < rows.size(); i++) if (rows[i].key == key) { sel = (int)i; break; }
    }
    uint64_t selKey() const { return sel >= 0 && sel < (int)rows.size() ? rows[sel].key : 0; }

    void draw(HDC dc, const Fonts& f) const {
        // header
        RECT h = {r.left, r.top, r.right, r.top + kHeadH};
        ui::fill(dc, h, theme::PANEL2);
        int x = r.left + 6;
        int total = 0;
        for (auto& c : cols) total += c.width;
        for (size_t i = 0; i < cols.size(); i++) {
            int w = cols[i].width;
            if (i + 1 == cols.size() && w == 0) w = (r.right - r.left) - (x - r.left) - 6;
            RECT cr = {x, r.top, x + w - 4, r.top + kHeadH};
            ui::textIn(dc, cr, cols[i].title, theme::DIM, f.tiny, cols[i].right ? DT_RIGHT : DT_LEFT);
            x += w;
        }
        ui::line(dc, r.left, r.top + kHeadH - 1, r.right, r.top + kHeadH - 1, theme::BORDER);
        // rows
        int n = visibleRows();
        for (int k = 0; k < n; k++) {
            int i = scroll + k;
            if (i >= (int)rows.size()) break;
            const Row& row = rows[i];
            RECT rr = {r.left, r.top + kHeadH + k * kRowH, r.right - 8, r.top + kHeadH + (k + 1) * kRowH};
            if (i == sel) {
                ui::fill(dc, rr, theme::SELECT);
                ui::line(dc, rr.left, rr.top, rr.left, rr.bottom, theme::AMBER, 3);
            } else if (i == hover) ui::fill(dc, rr, theme::HOVER);
            int cx = r.left + 6;
            for (size_t c = 0; c < cols.size() && c < row.cells.size(); c++) {
                int w = cols[c].width;
                if (c + 1 == cols.size() && w == 0) w = (r.right - r.left) - (cx - r.left) - 14;
                COLORREF col = (c < row.cellColors.size() && row.cellColors[c]) ? row.cellColors[c] : row.color;
                if (c + 1 == cols.size() && row.bar >= 0) {
                    RECT br = {cx, rr.top + 6, cx + w - 40, rr.bottom - 6};
                    ui::bar(dc, br, row.bar, theme::scoreColor(row.bar));
                    RECT nr = {cx + w - 38, rr.top, cx + w, rr.bottom};
                    ui::textIn(dc, nr, row.cells[c], col, f.tiny, DT_RIGHT);
                } else {
                    RECT cr = {cx, rr.top, cx + w - 4, rr.bottom};
                    ui::textIn(dc, cr, row.cells[c], col, f.mono, cols[c].right ? DT_RIGHT : DT_LEFT);
                }
                cx += w;
            }
        }
        // scrollbar
        if ((int)rows.size() > n) {
            int th = r.bottom - r.top - kHeadH;
            RECT tr = {r.right - 6, r.top + kHeadH, r.right - 2, r.bottom};
            ui::fill(dc, tr, RGB(10, 28, 34));
            int hh = th * n / (int)rows.size();
            if (hh < 14) hh = 14;
            int yy = r.top + kHeadH + (th - hh) * scroll / ((int)rows.size() - n);
            RECT thumb = {r.right - 6, yy, r.right - 2, yy + hh};
            ui::fill(dc, thumb, theme::BORDER2);
        }
    }
};
