// UNATCO NETWORK DEFENSE TERMINAL - shared types and helpers.
// Only the C++ standard library and Windows system headers are used.
// No third-party code of any kind.
#pragma once
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <cstdlib>
#include <initializer_list>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <deque>
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cmath>

// ---- tiny RAII lock (avoids std::mutex / threading-model differences) ----
struct Lock {
    CRITICAL_SECTION cs;
    Lock() { InitializeCriticalSection(&cs); }
    ~Lock() { DeleteCriticalSection(&cs); }
    Lock(const Lock&) = delete;
    Lock& operator=(const Lock&) = delete;
};
struct Guard {
    Lock& l;
    explicit Guard(Lock& x) : l(x) { EnterCriticalSection(&l.cs); }
    ~Guard() { LeaveCriticalSection(&l.cs); }
};

// ---- IP address (v4 or v6) ----
struct IpAddr {
    bool v6 = false;
    uint8_t b[16] = {0};          // v4 uses b[0..3] in network order

    bool operator<(const IpAddr& o) const {
        if (v6 != o.v6) return v6 < o.v6;
        return memcmp(b, o.b, v6 ? 16 : 4) < 0;
    }
    bool operator==(const IpAddr& o) const {
        return v6 == o.v6 && memcmp(b, o.b, v6 ? 16 : 4) == 0;
    }
    bool isZero() const {
        for (int i = 0; i < (v6 ? 16 : 4); i++) if (b[i]) return false;
        return true;
    }
    static IpAddr from4(const uint8_t* p) { IpAddr a; memcpy(a.b, p, 4); return a; }
    static IpAddr from6(const uint8_t* p) { IpAddr a; a.v6 = true; memcpy(a.b, p, 16); return a; }
    static IpAddr from4dword(DWORD d) { return from4((const uint8_t*)&d); }  // d as stored in MIB tables

    std::string str() const {
        char buf[64];
        if (!v6) {
            snprintf(buf, sizeof buf, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
            return buf;
        }
        // RFC 5952-ish: compress the longest zero run
        uint16_t w[8];
        for (int i = 0; i < 8; i++) w[i] = (uint16_t)((b[i * 2] << 8) | b[i * 2 + 1]);
        int bs = -1, bl = 0;
        for (int i = 0; i < 8;) {
            if (w[i]) { i++; continue; }
            int j = i; while (j < 8 && !w[j]) j++;
            if (j - i > bl) { bs = i; bl = j - i; }
            i = j;
        }
        if (bl < 2) bs = -1;
        std::string s;
        for (int i = 0; i < 8; i++) {
            if (i == bs) { s += "::"; i += bl - 1; continue; }
            if (!s.empty() && s.back() != ':') s += ':';
            snprintf(buf, sizeof buf, "%x", w[i]);
            s += buf;
        }
        return s;
    }
    // "Local" = never leaves the machine/LAN: loopback, private, link-local, CGNAT, multicast, unspecified
    bool isLocal() const {
        if (!v6) {
            if (b[0] == 10 || b[0] == 127 || b[0] == 0) return true;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
            if (b[0] == 192 && b[1] == 168) return true;
            if (b[0] == 169 && b[1] == 254) return true;
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true;
            if (b[0] >= 224) return true;
            return false;
        }
        bool allz = true;
        for (int i = 0; i < 15; i++) if (b[i]) allz = false;
        if (allz && (b[15] == 0 || b[15] == 1)) return true;     // :: and ::1
        if ((b[0] & 0xFE) == 0xFC) return true;                  // fc00::/7 ULA
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true; // fe80::/10
        if (b[0] == 0xFF) return true;                           // multicast
        // IPv4-mapped ::ffff:a.b.c.d
        bool m = true;
        for (int i = 0; i < 10; i++) if (b[i]) m = false;
        if (m && b[10] == 0xFF && b[11] == 0xFF) {
            IpAddr x = from4(b + 12);
            return x.isLocal();
        }
        return false;
    }
};

enum class Proto : uint8_t { TCP, UDP };

struct Conn {
    Proto proto = Proto::TCP;
    IpAddr local, remote;
    uint16_t lport = 0, rport = 0;
    DWORD pid = 0;
    DWORD state = 0;        // MIB_TCP_STATE_* (0 for UDP)
    bool fromEtw = false;   // seen only by the kernel trace
    bool operator<(const Conn& o) const {
        if (pid != o.pid) return pid < o.pid;
        if (proto != o.proto) return proto < o.proto;
        if (!(local == o.local)) return local < o.local;
        if (lport != o.lport) return lport < o.lport;
        if (!(remote == o.remote)) return remote < o.remote;
        return rport < o.rport;
    }
};

// ---- string helpers ----
inline std::string narrow(const wchar_t* w) {
    if (!w || !*w) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return std::string();
    std::string s((size_t)n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
    return s;
}
inline std::wstring widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 1) return std::wstring();
    std::wstring w((size_t)n - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}
inline std::string lower(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
    return s;
}
inline std::string baseName(const std::string& p) {
    size_t i = p.find_last_of("\\/");
    return i == std::string::npos ? p : p.substr(i + 1);
}
inline std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (unsigned char)s[a] <= ' ') a++;
    while (b > a && (unsigned char)s[b - 1] <= ' ') b--;
    return s.substr(a, b - a);
}

// ---- threat model ----
enum class Sev : int { Info = 0, Low = 1, Medium = 2, High = 3, Critical = 4 };

struct Finding {
    Sev sev = Sev::Info;
    int score = 0;          // contribution to the process threat score
    std::string code;       // short id, e.g. "RWX_PRIVATE"
    std::string text;       // human readable
};

struct Alert {
    uint64_t tick = 0;      // GetTickCount64 at creation
    SYSTEMTIME when{};
    Sev sev = Sev::Info;
    DWORD pid = 0;
    std::string proc;
    std::string text;
};

inline uint64_t nowMs() { return GetTickCount64(); }
