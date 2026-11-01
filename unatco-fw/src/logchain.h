// Tamper-evident log format. Standard library only (no Windows calls) so it can be tested anywhere.
//
// One record per line:   <body> \t <prevHash> \t <hash>
//   body    = "<seq>\t<time>\t<type>\t<fields...>"   (tabs/newlines inside fields are scrubbed)
//   hash    = SHA-256( prevHash + "\n" + body )      (lowercase hex)
// prevHash of the very first record is 64 zeros; every later record carries the previous record's
// hash, across daily files too. Editing, deleting, inserting or reordering any record breaks the chain
// from that point on, and verify() reports the first bad line.
#pragma once
#include "sha256.h"
#include <string>
#include <vector>

namespace logchain {

inline std::string genesis() { return std::string(64, '0'); }

inline std::string scrub(const std::string& s) {
    std::string r;
    r.reserve(s.size());
    for (unsigned char c : s) r += (c < 32 || c == 127) ? ' ' : (char)c;
    return r;
}

// Produces the finished line (no trailing newline) and the new head hash.
inline std::string seal(const std::string& prevHash, const std::string& body, std::string* newHash) {
    std::string h = sha256::hex(prevHash + "\n" + body);
    if (newHash) *newHash = h;
    return body + "\t" + prevHash + "\t" + h;
}

struct Verify {
    bool ok = true;
    size_t lines = 0;          // records checked
    size_t badLine = 0;        // 1-based index into the checked records (0 = none)
    std::string why;
    std::string head;          // hash of the last good record
};

inline bool splitLine(const std::string& line, std::string& body, std::string& prev, std::string& hash) {
    size_t t2 = line.rfind('\t');
    if (t2 == std::string::npos || t2 == 0) return false;
    size_t t1 = line.rfind('\t', t2 - 1);
    if (t1 == std::string::npos) return false;
    body = line.substr(0, t1);
    prev = line.substr(t1 + 1, t2 - t1 - 1);
    hash = line.substr(t2 + 1);
    return prev.size() == 64 && hash.size() == 64;
}

// Verifies records in order. `startPrev` is the hash the first record must chain from
// (genesis(), or the head of the previous file when verifying a series).
inline Verify verify(const std::vector<std::string>& lines, const std::string& startPrev) {
    Verify v;
    v.head = startPrev;
    std::string running = startPrev;
    for (size_t i = 0; i < lines.size(); i++) {
        v.lines = i + 1;
        std::string body, prev, hash;
        if (!splitLine(lines[i], body, prev, hash)) {
            v.ok = false; v.badLine = i + 1; v.why = "malformed record"; return v;
        }
        if (prev != running) {
            v.ok = false; v.badLine = i + 1;
            v.why = "chain broken: a record before this one was changed, removed or reordered";
            return v;
        }
        if (sha256::hex(prev + "\n" + body) != hash) {
            v.ok = false; v.badLine = i + 1; v.why = "record content does not match its hash (edited)";
            return v;
        }
        running = hash;
        v.head = hash;
    }
    return v;
}

}  // namespace logchain
