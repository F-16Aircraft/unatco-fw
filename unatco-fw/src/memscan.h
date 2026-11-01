#pragma once
#include "common.h"
#include "netmon.h"

// In-memory threat inspection of a live process.
//
// Polymorphic / fileless code defeats byte signatures, so nothing here is a hash or a
// sample signature. Instead we look for the things such code *cannot avoid*:
//   - executable memory that no file on disk backs (private/mapped RX/RWX regions)
//   - PE images living outside image mappings (reflective loading, manual mapping)
//   - the process image in memory disagreeing with the file it claims to be (hollowing,
//     herpaderping, ghosting, deleted-file images)
//   - threads that start in unbacked memory (injection)
//   - structural shellcode behaviours that survive re-encoding: PEB walking, API hashing,
//     direct syscalls, get-PC tricks, FPU decoder stubs, high-entropy executable payloads
//   - executable regions whose contents *change between scans* (runtime morphing)
struct RegionSig {
    uint64_t base = 0, size = 0, hash = 0;
    bool exec = false, priv = false;
};

struct ScanResult {
    DWORD pid = 0;
    bool opened = false;      // could we read this process at all?
    bool jitHost = false;     // browsers / .NET / JVM legitimately generate code at runtime
    int score = 0;            // 0..100
    int regions = 0;
    uint64_t bytesRead = 0;
    uint32_t ms = 0;
    uint64_t when = 0;
    std::vector<Finding> findings;
    std::vector<RegionSig> sigs;   // exec private/mapped regions, for change detection
};

namespace memscan {
void snapshotThreads(std::map<DWORD, std::vector<DWORD>>& byPid);
ScanResult scan(const ProcInfo& p, const std::vector<DWORD>& tids);
// Compare against the previous scan of the same process; appends findings for morphing code.
void compareSigs(const ScanResult& prev, ScanResult& now);
Sev sevForScore(int score);
}  // namespace memscan
