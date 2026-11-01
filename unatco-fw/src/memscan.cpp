#include "memscan.h"

namespace memscan {

// ------------------------------------------------------------------------------------------
// helpers
// ------------------------------------------------------------------------------------------
typedef LONG (NTAPI* NtQueryInformationThread_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static NtQueryInformationThread_t ntQueryThread() {
    static NtQueryInformationThread_t fn = nullptr;
    static bool tried = false;
    if (!tried) {
        tried = true;
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        if (nt) fn = (NtQueryInformationThread_t)(void*)GetProcAddress(nt, "NtQueryInformationThread");
    }
    return fn;
}

static const DWORD kExecBits = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
static const DWORD kWriteBits = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

static uint64_t fnv1a(const uint8_t* p, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

static double entropy(const uint8_t* p, size_t n) {
    if (n < 256) return 0;
    uint32_t cnt[256] = {0};
    for (size_t i = 0; i < n; i++) cnt[p[i]]++;
    double e = 0;
    for (int i = 0; i < 256; i++) {
        if (!cnt[i]) continue;
        double f = (double)cnt[i] / (double)n;
        e -= f * log2(f);
    }
    return e;
}

static bool hasPeHeader(const uint8_t* b, size_t n) {
    if (n < 0x100 || b[0] != 'M' || b[1] != 'Z') return false;
    uint32_t lf;
    memcpy(&lf, b + 0x3C, 4);
    if (lf < 0x40 || lf > 0x800 || lf + 0x18 > n) return false;
    return b[lf] == 'P' && b[lf + 1] == 'E' && b[lf + 2] == 0 && b[lf + 3] == 0;
}

Sev sevForScore(int s) {
    if (s >= 70) return Sev::Critical;
    if (s >= 45) return Sev::High;
    if (s >= 20) return Sev::Medium;
    if (s > 0) return Sev::Low;
    return Sev::Info;
}

static void addFinding(ScanResult& r, const char* code, int score, const std::string& text) {
    for (auto& f : r.findings)
        if (f.code == code) return;               // each behaviour is counted once per process
    Finding f;
    f.code = code;
    f.score = score;
    f.text = text;
    f.sev = sevForScore(score);
    r.findings.push_back(f);
}

// ------------------------------------------------------------------------------------------
// structural shellcode behaviours (masked byte patterns; mask bit 1 = must match)
// These survive re-encoding because they are what the code needs to *do*, not how it is spelled.
// ------------------------------------------------------------------------------------------
struct Pat {
    const char* code;
    const char* text;
    int score;
    int len;
    uint8_t b[12];
    uint8_t m[12];
};

static const Pat kPats[] = {
    {"PEB_WALK64", "PEB access via GS:[60h] (module/API resolution without imports)", 22, 9,
     {0x65, 0x48, 0x8B, 0x00, 0x25, 0x60, 0, 0, 0}, {0xFF, 0xFB, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
    {"PEB_WALK32", "PEB access via FS:[30h] (module/API resolution without imports)", 22, 6,
     {0x64, 0xA1, 0x30, 0, 0, 0}, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
    {"PEB_WALK32B", "PEB access via FS:[30h] (register form)", 22, 7,
     {0x64, 0x8B, 0x05, 0x30, 0, 0, 0}, {0xFF, 0xFF, 0xC7, 0xFF, 0xFF, 0xFF, 0xFF}},
    {"API_HASH_ROR13", "ROR-13 loop typical of API-hash resolvers", 14, 3,
     {0xC1, 0xC8, 0x0D}, {0xFF, 0xF8, 0xFF}},
    {"API_HASH_ROR13_64", "64-bit ROR-13 loop typical of API-hash resolvers", 14, 4,
     {0x48, 0xC1, 0xC8, 0x0D}, {0xF8, 0xFF, 0xF8, 0xFF}},
    {"DIRECT_SYSCALL", "inline syscall stub outside ntdll (EDR/hook evasion)", 30, 10,
     {0x4C, 0x8B, 0xD1, 0xB8, 0, 0, 0, 0, 0x0F, 0x05}, {0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF}},
    {"DIRECT_SYSCALL2", "mov eax,<ssn>; syscall sequence outside ntdll", 26, 7,
     {0xB8, 0, 0, 0, 0, 0x0F, 0x05}, {0xFF, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF}},
    {"GETPC_CALLPOP", "call $+5 / pop reg (position-independent code)", 14, 6,
     {0xE8, 0, 0, 0, 0, 0x58}, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF8}},
    {"GETPC_FPU", "FNSTENV get-PC trick (classic polymorphic decoder stub)", 24, 4,
     {0xD9, 0x74, 0x24, 0xF4}, {0xFF, 0xFF, 0xFF, 0xFF}},
    {"SHELLCODE_PROLOG64", "x64 shellcode entry prologue (cld; and rsp,-16; call)", 26, 6,
     {0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8}, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
    {"SHELLCODE_PROLOG32", "x86 shellcode entry prologue (cld; call)", 20, 6,
     {0xFC, 0xE8, 0, 0, 0, 0}, {0xFF, 0xFF, 0, 0xFF, 0xFF, 0xFF}},
};
static const int kPatCount = (int)(sizeof(kPats) / sizeof(kPats[0]));

static void scanPatterns(const uint8_t* buf, size_t n, bool inImage, ScanResult& r, bool jit) {
    if (n < 16) return;
    for (size_t i = 0; i + 12 < n; i++) {
        for (int p = 0; p < kPatCount; p++) {
            const Pat& pt = kPats[p];
            if (i + (size_t)pt.len > n) continue;
            bool ok = true;
            for (int k = 0; k < pt.len; k++)
                if ((buf[i + k] & pt.m[k]) != (pt.b[k] & pt.m[k])) { ok = false; break; }
            if (!ok) continue;
            int sc = pt.score;
            if (inImage) sc = sc / 4;       // a signed module doing this is rarely hostile
            if (jit) sc = sc / 2;
            if (sc > 0) addFinding(r, pt.code, sc, pt.text);
        }
    }
}

// ------------------------------------------------------------------------------------------
// JIT hosts generate executable memory legitimately; we reduce (not remove) their weights.
// ------------------------------------------------------------------------------------------
static bool isJitHost(HANDLE h, const std::string& name) {
    static const char* names[] = {"chrome.exe", "msedge.exe", "msedgewebview2.exe", "firefox.exe",
        "brave.exe", "opera.exe", "vivaldi.exe", "node.exe", "code.exe", "discord.exe", "slack.exe",
        "teams.exe", "ms-teams.exe", "java.exe", "javaw.exe", "dotnet.exe", "powershell.exe",
        "pwsh.exe", "devenv.exe", "spotify.exe", "steamwebhelper.exe"};
    std::string n = lower(name);
    for (auto* x : names) if (n == x) return true;
    HMODULE mods[1024];
    DWORD need = 0;
    if (EnumProcessModulesEx(h, mods, sizeof mods, &need, LIST_MODULES_ALL)) {
        size_t cnt = need / sizeof(HMODULE);
        if (cnt > 1024) cnt = 1024;
        for (size_t i = 0; i < cnt; i++) {
            wchar_t w[MAX_PATH];
            if (GetModuleBaseNameW(h, mods[i], w, MAX_PATH)) {
                std::string m = lower(narrow(w));
                if (m == "clrjit.dll" || m == "coreclr.dll" || m == "clr.dll" || m == "jvm.dll" ||
                    m == "mscorwks.dll" || m == "v8.dll")
                    return true;
            }
        }
    }
    return false;
}

// ------------------------------------------------------------------------------------------
// image integrity: does the process image in memory match the file it says it is?
// ------------------------------------------------------------------------------------------
static bool readDiskHeader(const std::string& path, uint8_t* out, size_t n, size_t* got) {
    HANDLE f = CreateFileW(widen(path).c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    DWORD g = 0;
    BOOL ok = ReadFile(f, out, (DWORD)n, &g, nullptr);
    CloseHandle(f);
    *got = g;
    return ok && g > 0x100;
}

struct PeFacts { bool ok = false; uint32_t entry = 0, sizeImage = 0, stamp = 0; uint16_t machine = 0; uint16_t nsec = 0; };

static PeFacts parsePe(const uint8_t* b, size_t n) {
    PeFacts f;
    if (!hasPeHeader(b, n)) return f;
    uint32_t lf;
    memcpy(&lf, b + 0x3C, 4);
    if (lf + 0x58 > n) return f;
    memcpy(&f.machine, b + lf + 4, 2);
    memcpy(&f.nsec, b + lf + 6, 2);
    memcpy(&f.stamp, b + lf + 8, 4);
    memcpy(&f.entry, b + lf + 0x28, 4);
    memcpy(&f.sizeImage, b + lf + 0x50, 4);
    f.ok = true;
    return f;
}

static bool pathLooksStaged(const std::string& path) {
    std::string p = lower(path);
    static const char* bad[] = {"\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\",
        "\\$recycle.bin\\", "\\programdata\\", "\\downloads\\", "\\appdata\\roaming\\"};
    for (auto* b : bad) if (p.find(b) != std::string::npos) return true;
    return false;
}

static void checkMainImage(HANDLE h, const ProcInfo& pi, ScanResult& r) {
    HMODULE mods[8];
    DWORD need = 0;
    if (!EnumProcessModulesEx(h, mods, sizeof mods, &need, LIST_MODULES_ALL) || need < sizeof(HMODULE)) {
        // A running process with an empty loader list is itself odd (unless it is very young).
        return;
    }
    uint8_t* base = (uint8_t*)mods[0];
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQueryEx(h, base, &mbi, sizeof mbi)) return;

    if (mbi.Type != MEM_IMAGE) {
        addFinding(r, "HOLLOW_NOT_IMAGE", 70,
                   "main module base is not an image mapping (process hollowing / manual map)");
        return;
    }
    // Kernel-side (VAD) name of the backing file - cannot be spoofed by editing the PEB.
    wchar_t mapped[MAX_PATH * 2] = {0};
    DWORD mlen = GetMappedFileNameW(h, base, mapped, MAX_PATH * 2);
    if (mlen == 0) {
        addFinding(r, "IMAGE_UNBACKED", 45, "process image has no backing file (deleted/ghosted image)");
    } else if (pi.pathKnown) {
        // mapped is an NT device path; compare file names + the tail of the path
        std::string mp = lower(narrow(mapped));
        std::string pp = lower(pi.path);
        std::string mb = baseName(mp), pb = baseName(pp);
        if (mb != pb)
            addFinding(r, "IMAGE_NAME_MISMATCH", 60,
                       "kernel-mapped image '" + mb + "' differs from reported image '" + pb + "'");
    }

    // header in memory vs. file on disk
    if (pi.pathKnown) {
        uint8_t mem[4096], disk[4096];
        SIZE_T got = 0;
        size_t dgot = 0;
        if (ReadProcessMemory(h, base, mem, sizeof mem, &got) && got >= 0x200 &&
            readDiskHeader(pi.path, disk, sizeof disk, &dgot)) {
            PeFacts a = parsePe(mem, got), b = parsePe(disk, dgot);
            if (a.ok && b.ok) {
                if (a.entry != b.entry || a.sizeImage != b.sizeImage || a.stamp != b.stamp ||
                    a.machine != b.machine || a.nsec != b.nsec)
                    addFinding(r, "HEADER_MISMATCH", 65,
                               "in-memory PE header differs from the file on disk (hollowing / herpaderping)");
            } else if (!a.ok && b.ok) {
                addFinding(r, "HEADER_ERASED", 40, "PE header erased from the running image");
            }
        }
    }
    if (pi.pathKnown && pathLooksStaged(pi.path))
        addFinding(r, "STAGED_PATH", 8, "image runs from a user-writable staging location");
}

// ------------------------------------------------------------------------------------------
// main scan
// ------------------------------------------------------------------------------------------
struct Region { uint8_t* base; SIZE_T size; DWORD prot; DWORD type; uint8_t* allocBase; };

ScanResult scan(const ProcInfo& pi, const std::vector<DWORD>& tids) {
    ScanResult r;
    r.pid = pi.pid;
    r.when = nowMs();
    const uint64_t t0 = GetTickCount64();
    if (pi.pid == 0 || pi.pid == 4) return r;

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pi.pid);
    if (!h) return r;                       // protected process or no privilege: opened == false
    r.opened = true;
    r.jitHost = isJitHost(h, pi.name);
    const bool jit = r.jitHost;

    // 1. walk the address space
    std::vector<Region> regs;
    {
        uint8_t* addr = nullptr;
        MEMORY_BASIC_INFORMATION mbi;
        while (regs.size() < 60000 && VirtualQueryEx(h, addr, &mbi, sizeof mbi) == sizeof mbi) {
            if (mbi.State == MEM_COMMIT)
                regs.push_back({(uint8_t*)mbi.BaseAddress, mbi.RegionSize, mbi.Protect, mbi.Type,
                                (uint8_t*)mbi.AllocationBase});
            uint8_t* next = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
            if (next <= addr) break;
            addr = next;
        }
    }
    r.regions = (int)regs.size();

    // 2. image integrity of the main module
    checkMainImage(h, pi, r);

    // 3. allocations that contain a PE header but are not image mappings
    std::set<uint8_t*> peAlloc;
    std::vector<uint8_t> buf(64 * 1024);
    const uint64_t kByteBudget = 48ull * 1024 * 1024;
    const uint64_t kTimeBudgetMs = 1500;

    for (const auto& g : regs) {
        if (g.type == MEM_IMAGE) continue;
        if (g.base != g.allocBase) continue;
        if (g.prot & (PAGE_GUARD | PAGE_NOACCESS)) continue;
        SIZE_T got = 0;
        if (ReadProcessMemory(h, g.base, buf.data(), 4096, &got) && hasPeHeader(buf.data(), got)) {
            peAlloc.insert(g.allocBase);
            r.bytesRead += got;
        }
    }

    int execPrivate = 0, execMapped = 0;
    for (const auto& g : regs) {
        if (r.bytesRead > kByteBudget || (GetTickCount64() - t0) > kTimeBudgetMs) {
            addFinding(r, "SCAN_BUDGET", 0, "scan stopped at its time/byte budget (partial coverage)");
            break;
        }
        const bool exec = (g.prot & kExecBits) != 0;
        const bool write = (g.prot & kWriteBits) != 0;
        if (g.prot & (PAGE_GUARD | PAGE_NOACCESS)) continue;

        if (g.type == MEM_IMAGE) {
            if (exec && (g.prot & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) == PAGE_EXECUTE_READWRITE)
                addFinding(r, "RWX_IMAGE", jit ? 12 : 30,
                           "writable+executable pages inside a module image (code patching / module stomping)");
            continue;
        }
        const bool priv = g.type == MEM_PRIVATE;
        const bool inPeAlloc = peAlloc.count(g.allocBase) != 0;

        if (!exec) {
            continue;
        }
        priv ? execPrivate++ : execMapped++;

        if (inPeAlloc)
            addFinding(r, "REFLECTIVE_PE", 60,
                       "executable PE image outside any image mapping (reflective DLL / manual-mapped payload)");
        if (priv && (g.prot & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE)
            addFinding(r, "RWX_PRIVATE", jit ? 6 : 28,
                       "private RWX memory: self-modifying or freshly written code with no file behind it");
        else if (priv)
            addFinding(r, "EXEC_PRIVATE", jit ? 2 : 14,
                       "executable private memory with no backing file");
        if (!priv)
            addFinding(r, "EXEC_MAPPED", jit ? 4 : 16,
                       "executable memory in a non-image file mapping");
        if (write && !priv)
            addFinding(r, "RWX_MAPPED", 20, "writable+executable non-image mapping");

        // sample the content
        SIZE_T want = g.size < buf.size() ? g.size : buf.size();
        SIZE_T got = 0;
        if (!ReadProcessMemory(h, g.base, buf.data(), want, &got) || got < 64) continue;
        r.bytesRead += got;

        RegionSig sig;
        sig.base = (uint64_t)(uintptr_t)g.base;
        sig.size = g.size;
        sig.hash = fnv1a(buf.data(), got < 16384 ? got : 16384);
        sig.exec = true;
        sig.priv = priv;
        if (r.sigs.size() < 512) r.sigs.push_back(sig);

        double e = entropy(buf.data(), got < 4096 ? got : 4096);
        if (e > 7.2)
            addFinding(r, "HIGH_ENTROPY_EXEC", jit ? 6 : 16,
                       "executable region with encrypted/packed-looking content (entropy > 7.2)");
        scanPatterns(buf.data(), got, false, r, jit);
    }

    // 4. threads that begin in unbacked memory
    NtQueryInformationThread_t q = ntQueryThread();
    if (q) {
        int checked = 0, unbacked = 0;
        for (DWORD tid : tids) {
            if (checked++ >= 96) break;
            HANDLE th = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
            if (!th) th = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
            if (!th) continue;
            PVOID start = nullptr;
            ULONG ret = 0;
            LONG st = q(th, 9 /*ThreadQuerySetWin32StartAddress*/, &start, sizeof start, &ret);
            CloseHandle(th);
            if (st != 0 || !start) continue;
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(h, start, &mbi, sizeof mbi) == sizeof mbi && mbi.State == MEM_COMMIT &&
                mbi.Type != MEM_IMAGE)
                unbacked++;
        }
        if (unbacked > 0) {
            char t[160];
            snprintf(t, sizeof t, "%d thread(s) start in memory with no backing file (injected code)", unbacked);
            addFinding(r, "THREAD_UNBACKED", jit ? 8 : 45, t);
        }
    }

    CloseHandle(h);

    int total = 0;
    for (auto& f : r.findings) total += f.score;
    (void)execPrivate; (void)execMapped;
    r.score = total > 100 ? 100 : total;
    r.ms = (uint32_t)(GetTickCount64() - t0);
    return r;
}

// ------------------------------------------------------------------------------------------
// runtime morphing: same executable region, different bytes on a later scan
// ------------------------------------------------------------------------------------------
void compareSigs(const ScanResult& prev, ScanResult& now) {
    if (!prev.opened || !now.opened) return;
    std::map<uint64_t, const RegionSig*> old;
    for (const auto& s : prev.sigs) old[s.base] = &s;
    int changed = 0;
    for (const auto& s : now.sigs) {
        auto it = old.find(s.base);
        if (it != old.end() && it->second->size == s.size && it->second->hash != s.hash && s.priv) changed++;
    }
    if (changed > 0) {
        char t[200];
        snprintf(t, sizeof t, "%d executable region(s) rewrote their own contents between scans (runtime mutation)", changed);
        addFinding(now, "SELF_MUTATING", now.jitHost ? 6 : 35, t);
        int total = 0;
        for (auto& f : now.findings) total += f.score;
        now.score = total > 100 ? 100 : total;
    }
}

// ------------------------------------------------------------------------------------------
void snapshotThreads(std::map<DWORD, std::vector<DWORD>>& byPid) {
    byPid.clear();
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (s == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te{};
    te.dwSize = sizeof te;
    if (Thread32First(s, &te)) {
        do { byPid[te.th32OwnerProcessID].push_back(te.th32ThreadID); } while (Thread32Next(s, &te));
    }
    CloseHandle(s);
}

}  // namespace memscan
