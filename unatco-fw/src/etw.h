#pragma once
#include "common.h"

// Real-time kernel network trace (Microsoft-Windows-Kernel-Network).
// This sees connection attempts even when they open and close between two table polls,
// and gives UDP peers, which the OS tables do not expose.
struct EtwConn {
    Conn c;
    uint64_t tick = 0;
};

namespace etw {
bool start();                              // needs elevation; returns false if unavailable
void stop();
bool running();
void drain(std::vector<EtwConn>& out);     // moves queued events out
}  // namespace etw
