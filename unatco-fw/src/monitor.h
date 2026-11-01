#pragma once
#include "common.h"
#include "netmon.h"
#include "memscan.h"

struct ProcThreat {
    int score = 0;                       // 0..100, memory findings + behaviour findings
    std::vector<Finding> findings;
    bool scanned = false;
    bool unreadable = false;             // memory not readable (PPL / no privilege)
    bool jitHost = false;
    int regions = 0;
    uint32_t scanMs = 0;
    uint64_t lastScan = 0;
};

struct MonSnapshot {
    NetState net;
    std::map<DWORD, ProcThreat> threat;
    std::deque<Alert> alerts;
    bool etwOn = false;
    bool admin = false;
    size_t scansQueued = 0;
    uint64_t polls = 0;
    uint64_t etwSeen = 0;                // connections ETW saw that the tables never showed
};

namespace monitor {
void start();
void stop();
MonSnapshot copy();
void requestScan(DWORD pid);             // user-initiated, jumps the queue
void clearAlerts();
}  // namespace monitor
