#pragma once
#include "common.h"

// Enforcement through the Windows Filtering Platform (user-mode management API, fwpuclnt.dll).
// Filters are PERSISTENT: they keep blocking after this program exits or crashes.
// Limit of a user-mode design: we cannot hold a *new* connection and ask first (that needs a
// kernel callout driver); blocks apply to the next connection attempt. SEVER kills live TCP/v4.
struct FwRule {
    bool isApp = true;
    std::string target;            // image path or IP string
    std::vector<uint64_t> ids;     // WFP filter ids
};

namespace fw {
bool init(std::string* err);
void shutdown();
bool available();

bool blockApp(const std::string& imagePath, std::string* err);
bool blockIp(const IpAddr& ip, std::string* err);
bool unblockApp(const std::string& imagePath);
bool unblockIp(const IpAddr& ip);
bool appBlocked(const std::string& imagePath);
bool ipBlocked(const IpAddr& ip);
std::vector<FwRule> rules();

bool sever(const Conn& c);                    // delete a live IPv4 TCP connection
bool terminate(DWORD pid, std::string* err);  // end a process

// tiny persisted settings (home location override etc.)
std::string settingsPath();
}  // namespace fw
