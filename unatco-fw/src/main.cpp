// UNATCO NETWORK DEFENSE TERMINAL
// Native Windows (Win32 + GDI). C++ standard library and Windows system APIs only.
#include "app.h"
#include "fw.h"
#include "intel.h"
#include "monitor.h"
#include "etw.h"
#include "geo.h"
#include "history.h"
#include <shlobj.h>

static int g_focus = 0;                 // 0 = process list, 1 = connection list
static const UINT_PTR kTimer = 1;

// ------------------------------------------------------------------------------------------
// actions
// ------------------------------------------------------------------------------------------
static bool isSystemImage(const std::string& path) {
    std::string p = lower(path);
    return p.find("\\windows\\system32\\") != std::string::npos ||
           p.find("\\windows\\syswow64\\") != std::string::npos ||
           p.find("\\windows\\explorer.exe") != std::string::npos;
}

// Folder chooser (classic dialog with an edit box, so a new path can be typed). No COM needed.
static std::string pickFolder() {
    wchar_t disp[MAX_PATH] = {0};
    BROWSEINFOW bi{};
    bi.hwndOwner = A.hwnd;
    bi.pszDisplayName = disp;
    bi.lpszTitle = L"Choose where the connection history is stored";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_EDITBOX;
    PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return "";
    wchar_t path[MAX_PATH] = {0};
    std::string out;
    if (SHGetPathFromIDListW(pidl, path)) out = narrow(path);
    ILFree(pidl);
    return out;
}

static bool confirm(const std::string& msg, bool warn) {
    int r = MessageBoxW(A.hwnd, widen(msg).c_str(), L"UNATCO NETDEF - CONFIRM",
                        MB_YESNO | (warn ? MB_ICONWARNING : MB_ICONQUESTION) | MB_DEFBUTTON2);
    return r == IDYES;
}

void onAction(int id) {
    const ProcRow* p = model::findProc(A.model, A.selPid);
    const ConnRow* c = selectedConn();
    std::string err;
    switch (id) {
        case B_BLOCK_APP:
            if (!p || p->path.empty()) break;
            if (isSystemImage(p->path) &&
                !confirm("'" + p->name + "' is a Windows system component. Blocking its image affects EVERY "
                         "process that runs from it (for example all svchost services).\n\nBlock anyway?", true))
                break;
            if (fw::blockApp(p->path, &err)) setStatus("BLOCKED APPLICATION: " + p->name + "  (persistent WFP filter)");
            else setStatus("BLOCK FAILED: " + err);
            break;
        case B_UNBLOCK_APP:
            if (p && fw::unblockApp(p->path)) setStatus("APPLICATION ALLOWED: " + p->name);
            break;
        case B_BLOCK_IP:
            if (c && c->foreign) {
                if (fw::blockIp(c->c.remote, &err)) setStatus("BLOCKED ADDRESS: " + c->c.remote.str() + "  (all processes, both directions)");
                else setStatus("BLOCK FAILED: " + err);
            }
            break;
        case B_UNBLOCK_IP:
            if (c && fw::unblockIp(c->c.remote)) setStatus("ADDRESS ALLOWED: " + c->c.remote.str());
            break;
        case B_SEVER:
            if (c) setStatus(fw::sever(c->c) ? "CONNECTION SEVERED" : "SEVER FAILED (IPv4 TCP only, needs administrator)");
            break;
        case B_SCAN:
            monitor::requestScan(A.selPid);
            setStatus("MEMORY SCAN QUEUED");
            break;
        case B_KILL:
            if (p && confirm("Terminate " + p->name + " [" + std::to_string(p->pid) + "]?\nUnsaved data in that process is lost.", true)) {
                if (fw::terminate(p->pid, &err)) setStatus("PROCESS TERMINATED: " + p->name);
                else setStatus("TERMINATE FAILED: " + err);
            }
            break;
        case B_TOGGLE_ALL: A.showAll = !A.showAll; break;
        case B_ROTATE: A.globe.setAutoRotate(!A.globe.autoRotate()); break;
        case B_CLEAR: monitor::clearAlerts(); break;   // clears the on-screen list only; the history file keeps everything
        case B_LOG_FOLDER: {
            std::string dir = pickFolder();
            if (!dir.empty()) {
                if (history::setFolder(dir, &err)) setStatus("HISTORY NOW STORED IN: " + history::folder(), 12000);
                else setStatus("LOG FOLDER NOT CHANGED: " + err, 12000);
            }
            break;
        }
        case B_VERIFY: {
            bool ok = false;
            std::string r = history::verify("", &ok);
            r += "\n\nFolder: " + history::folder() +
                 "\n\nThis detects edited, inserted, reordered or removed records inside the chain. If the NEWEST "
                 "records were deleted, only a head hash you saved earlier can reveal that.";
            MessageBoxW(A.hwnd, widen(r).c_str(), L"UNATCO NETDEF - LOG VERIFY",
                        MB_OK | (ok ? MB_ICONINFORMATION : MB_ICONERROR));
            break;
        }
    }
    refreshModel();
}

// ------------------------------------------------------------------------------------------
// input
// ------------------------------------------------------------------------------------------
static int buttonAt(int x, int y) {
    for (size_t i = 0; i < A.btns.size(); i++) if (ui::inRect(A.btns[i].r, x, y)) return (int)i;
    return -1;
}

static void moveSel(ListBox& l, int d, bool isProc) {
    if (l.rows.empty()) return;
    int i = l.sel < 0 ? 0 : l.sel + d;
    if (i < 0) i = 0;
    if (i >= (int)l.rows.size()) i = (int)l.rows.size() - 1;
    l.ensureVisible(i);
    if (isProc) onSelectProc((DWORD)l.rows[i].key);
    else onSelectConn(l.rows[i].key);
}

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
        case WM_SIZE: {
            int W = LOWORD(l), H = HIWORD(l);
            if (W > 0 && H > 0) { layoutAll(W, H); refreshModel(); }
            return 0;
        }
        case WM_GETMINMAXINFO: {
            auto* mm = (MINMAXINFO*)l;
            mm->ptMinTrackSize.x = 1280;
            mm->ptMinTrackSize.y = 760;
            return 0;
        }
        case WM_ERASEBKGND: return 1;
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC dc = BeginPaint(h, &ps);
            paintAll(dc);
            EndPaint(h, &ps);
            return 0;
        }
        case WM_TIMER: {
            uint64_t t = nowMs();
            if (t - A.lastRefresh > 250) { A.lastRefresh = t; refreshModel(); }
            InvalidateRect(h, nullptr, FALSE);
            return 0;
        }
        case WM_MOUSEMOVE: {
            int x = (short)LOWORD(l), y = (short)HIWORD(l);
            A.hoverBtn = buttonAt(x, y);
            A.lproc.hover = A.lproc.rowAt(x, y);
            A.lconn.hover = A.lconn.rowAt(x, y);
            A.lalert.hover = A.lalert.rowAt(x, y);
            if (A.globeDrag) A.globe.mouseMove(x - A.rGlobe.left, y - A.rGlobe.top);
            return 0;
        }
        case WM_LBUTTONDOWN: {
            int x = (short)LOWORD(l), y = (short)HIWORD(l);
            SetFocus(h);
            int b = buttonAt(x, y);
            if (b >= 0 && A.btns[b].enabled) { A.downBtn = b; SetCapture(h); return 0; }
            int i = A.lproc.rowAt(x, y);
            if (i >= 0) { g_focus = 0; A.lproc.sel = i; onSelectProc((DWORD)A.lproc.rows[i].key); return 0; }
            i = A.lconn.rowAt(x, y);
            if (i >= 0) { g_focus = 1; A.lconn.sel = i; onSelectConn(A.lconn.rows[i].key); return 0; }
            if (ui::inRect(A.rGlobe, x, y)) {
                A.globeDrag = true;
                A.globe.mouseDown(x - A.rGlobe.left, y - A.rGlobe.top);
                SetCapture(h);
            }
            return 0;
        }
        case WM_LBUTTONDBLCLK: {
            int x = (short)LOWORD(l), y = (short)HIWORD(l);
            if (ui::inRect(A.rGlobe, x, y)) onAction(B_ROTATE);
            return 0;
        }
        case WM_LBUTTONUP: {
            int x = (short)LOWORD(l), y = (short)HIWORD(l);
            if (A.downBtn >= 0) {
                int b = buttonAt(x, y);
                int id = A.btns[A.downBtn].id;
                bool fire = (b == A.downBtn);
                A.downBtn = -1;
                ReleaseCapture();
                if (fire) onAction(id);
                return 0;
            }
            if (A.globeDrag) { A.globeDrag = false; A.globe.mouseUp(); ReleaseCapture(); }
            return 0;
        }
        case WM_MOUSEWHEEL: {
            POINT pt = {(short)LOWORD(l), (short)HIWORD(l)};
            ScreenToClient(h, &pt);
            int d = GET_WHEEL_DELTA_WPARAM(w) / WHEEL_DELTA;
            if (ui::inRect(A.rProc, pt.x, pt.y)) A.lproc.wheel(d);
            else if (ui::inRect(A.rConn, pt.x, pt.y)) A.lconn.wheel(d);
            else if (ui::inRect(A.rAlert, pt.x, pt.y)) A.lalert.wheel(d);
            return 0;
        }
        case WM_KEYDOWN: {
            ListBox& lb = g_focus == 0 ? A.lproc : A.lconn;
            switch (w) {
                case VK_UP: moveSel(lb, -1, g_focus == 0); break;
                case VK_DOWN: moveSel(lb, +1, g_focus == 0); break;
                case VK_PRIOR: moveSel(lb, -lb.visibleRows(), g_focus == 0); break;
                case VK_NEXT: moveSel(lb, +lb.visibleRows(), g_focus == 0); break;
                case VK_TAB: g_focus = 1 - g_focus; break;
                case VK_F5: onAction(B_SCAN); break;
            }
            return 0;
        }
        case WM_DESTROY:
            KillTimer(h, kTimer);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

// ------------------------------------------------------------------------------------------
// startup
// ------------------------------------------------------------------------------------------
static void darkTitleBar(HWND h) {
    HMODULE dwm = LoadLibraryW(L"dwmapi.dll");
    if (!dwm) return;
    typedef HRESULT(WINAPI * Fn)(HWND, DWORD, LPCVOID, DWORD);
    Fn fn = (Fn)(void*)GetProcAddress(dwm, "DwmSetWindowAttribute");
    if (fn) {
        BOOL on = TRUE;
        fn(h, 20 /*DWMWA_USE_IMMERSIVE_DARK_MODE*/, &on, sizeof on);
        COLORREF cap = RGB(5, 13, 17), txt = RGB(70, 210, 222), brd = RGB(22, 100, 110);
        fn(h, 35 /*DWMWA_CAPTION_COLOR*/, &cap, sizeof cap);          // Windows 11
        fn(h, 36 /*DWMWA_TEXT_COLOR*/, &txt, sizeof txt);
        fn(h, 34 /*DWMWA_BORDER_COLOR*/, &brd, sizeof brd);
    }
    FreeLibrary(dwm);
}

static void parseArgs() {
    std::string cl = GetCommandLineA();
    size_t p = cl.find("--home");
    if (p == std::string::npos) return;
    double la = 0, lo = 0;
    if (sscanf(cl.c_str() + p + 6, " %lf,%lf", &la, &lo) == 2 && fabs(la) <= 90 && fabs(lo) <= 180)
        intel::setHomeOverride(la, lo);
}

// "--name value", "--name \"value with spaces\"", or just "--name". Returns true if the flag is present.
static bool findArg(const std::string& cl, const char* name, std::string& val) {
    size_t p = cl.find(name);
    if (p == std::string::npos) return false;
    p += strlen(name);
    while (p < cl.size() && cl[p] == ' ') p++;
    val.clear();
    if (p < cl.size() && cl[p] == '"') {
        size_t e = cl.find('"', p + 1);
        val = cl.substr(p + 1, e == std::string::npos ? std::string::npos : e - p - 1);
    } else if (p < cl.size() && cl.compare(p, 2, "--") != 0) {
        size_t e = cl.find(' ', p);
        val = cl.substr(p, e == std::string::npos ? std::string::npos : e - p);
    }
    return true;
}

int WINAPI WinMain(HINSTANCE hi, HINSTANCE, LPSTR, int show) {
    const std::string cmdline = narrow(GetCommandLineW());
    std::string argVal;
    if (findArg(cmdline, "--verify", argVal)) {          // unatco_netdef.exe --verify ["D:\logs"]
        bool ok = false;
        std::string r = history::verify(argVal.empty() ? history::configuredFolder() : argVal, &ok);
        MessageBoxW(nullptr, widen(r).c_str(), L"UNATCO NETDEF - LOG VERIFY", MB_OK | (ok ? MB_ICONINFORMATION : MB_ICONERROR));
        return ok ? 0 : 2;
    }
    HANDLE mtx = CreateMutexW(nullptr, TRUE, L"Local\\UNATCO_NETDEF_SINGLE");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxW(nullptr, L"UNATCO Network Defense Terminal is already running.", L"UNATCO NETDEF", MB_ICONINFORMATION);
        return 0;
    }

    A.f.create();
    if (!intel::init()) MessageBoxW(nullptr, L"Winsock failed to start; registration lookups are disabled.", L"UNATCO NETDEF", MB_ICONWARNING);
    parseArgs();
    std::string logDir, histErr;
    findArg(cmdline, "--log-dir", logDir);               // optional; otherwise the saved/default folder
    if (!history::init(logDir, &histErr)) histErr = histErr.empty() ? "unknown error" : histErr;
    else histErr.clear();
    A.fwOk = fw::init(&A.fwErr);
    monitor::start();

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof wc;
    wc.style = CS_DBLCLKS;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hi;
    wc.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512))   /* IDC_ARROW */;
    wc.hIcon = LoadIconW(nullptr, MAKEINTRESOURCEW(32518))   /* IDI_SHIELD */;
    wc.hIconSm = wc.hIcon;
    wc.lpszClassName = L"UnatcoNetDef";
    RegisterClassExW(&wc);

    HWND hw = CreateWindowExW(0, wc.lpszClassName, L"UNATCO // Network Defense Terminal",
                              WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 1440, 900,
                              nullptr, nullptr, hi, nullptr);
    if (!hw) return 1;
    A.hwnd = hw;
    darkTitleBar(hw);
    ShowWindow(hw, show);
    if (!A.fwOk) setStatus("FIREWALL ENGINE OFFLINE: " + A.fwErr, 15000);
    else if (!netmon::isPrivileged()) setStatus("LIMITED MODE - restart as Administrator for full telemetry", 15000);
    else setStatus("TERMINAL ONLINE - monitoring all network sockets", 8000);
    if (!histErr.empty()) setStatus("HISTORY LOG OFF: " + histErr + "  (use LOG FOLDER)", 20000);
    SetTimer(hw, kTimer, 33, nullptr);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    monitor::stop();
    history::shutdown();     // after the monitor, so its last alerts are recorded
    intel::shutdown();
    fw::shutdown();          // persistent filters stay in force
    A.f.destroy();
    if (mtx) CloseHandle(mtx);
    return (int)msg.wParam;
}
