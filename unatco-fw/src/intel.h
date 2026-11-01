#pragma once
#include "common.h"

// Registration / ownership data for a foreign IP, fetched with our own WHOIS client
// (RFC 3912) straight from the regional registries. No third-party service is involved
// except for discovering *our own* public IP once at start-up.
struct WhoisInfo {
    bool done = false;      // lookup finished (successfully or not)
    bool failed = false;
    std::string host;       // reverse DNS name, if any
    std::string netname;
    std::string org;
    std::string country;    // ISO-3166 alpha-2 as registered (not necessarily physical location)
    std::string range;      // inetnum / NetRange
    std::string cidr;
    std::string registered;
    std::string abuse;
    std::string registry;   // which RIR answered
    std::string note;       // error text when failed
};

struct HomeInfo {
    bool valid = false;
    bool pending = true;
    std::string ip, country, cc, city;
    double lat = 0, lon = 0;
};

namespace intel {
bool init();                         // WSAStartup + worker threads
void shutdown();
WhoisInfo get(const IpAddr& ip);     // never blocks; queues a lookup the first time
HomeInfo home();
void setHomeOverride(double lat, double lon);   // manual location (config)
size_t pendingCount();
}  // namespace intel
