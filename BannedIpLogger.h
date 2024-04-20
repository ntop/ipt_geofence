//
// Created by donaldo on 17/04/24.
//

#ifndef _BANNEDIPLOGGER_H
#define _BANNEDIPLOGGER_H
#include "WatchMatches.h"
#include <unordered_map>

class BannedIpLogger {

 public:
    std::string dumpPath;
    BannedIpLogger(std::string _dumpPath) { dumpPath = _dumpPath; }
    std::unordered_map<std::string, WatchMatches*> load();
    int save(std::unordered_map<std::string, WatchMatches*> ips);

};


#endif //_BANNEDIPLOGGER_H
