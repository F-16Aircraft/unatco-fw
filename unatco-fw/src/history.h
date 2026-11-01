#pragma once
#include "common.h"
#include "intel.h"

// Persistent, tamper-evident connection/alert history (see logchain.h for the record format).
//  * one file per UTC day:  <folder>\netdef-YYYYMMDD.log
//  * hash-chained across files; verify() reports the first altered record
//  * the open file is held append-only with sharing denied for writers/deleters, and files are
//    marked read-only whenever they are not the one being written
// This is TAMPER-EVIDENT, not tamper-proof: an administrator or kernel-level malware can still
// replace the files. Record the head hash (shown in the UI) somewhere safe to anchor the chain.
namespace history {
bool init(const std::string& folderUtf8, std::string* err);   // "" = saved setting, else default
void shutdown();
bool setFolder(const std::string& folderUtf8, std::string* err);
std::string folder();
std::string configuredFolder();                                // saved setting or <exe dir>\logs (for --verify)
std::string head();                                            // hash of the newest record
uint64_t records();                                            // written this session

void conn(const Conn& c, const std::string& proc, const std::string& path);
void registry(const IpAddr& ip, const WhoisInfo& w);
void alert(Sev sev, DWORD pid, const std::string& proc, const std::string& code, const std::string& text);

std::string verify(const std::string& folderUtf8, bool* ok);   // human-readable result
}  // namespace history
