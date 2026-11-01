#pragma once
#include "common.h"
#include "monitor.h"
#include "intel.h"
#include "globe.h"

struct ProcRow {
    DWORD pid = 0;
    std::string name, path;
    int nconn = 0, nforeign = 0, nlocal = 0;
    int score = 0;
    bool blocked = false;
};

struct ConnRow {
    Conn c;
    bool foreign = false;
    bool listening = false;
    WhoisInfo wi;
    bool ipBlocked = false;
};

struct Model {
    MonSnapshot snap;
    std::vector<ProcRow> procs;
    std::vector<GlobeTarget> targets;
    GlobeHome home;
    HomeInfo homeInfo;
    int totalForeign = 0;
    int worstScore = 0;
};

namespace model {
bool isActive(const Conn& c);                       // established / in-flight / UDP with a peer
void build(Model& m, DWORD selectedPid, bool showAll);
std::vector<ConnRow> connsFor(const Model& m, DWORD pid);
const ProcRow* findProc(const Model& m, DWORD pid);
std::string endpoint(const IpAddr& ip, uint16_t port);
}  // namespace model
