//
// Created by donaldo on 17/04/24.
//

#ifndef _BANNEDIPLOGGER_H
#define _BANNEDIPLOGGER_H
#include "WatchMatches.h"
#include <unordered_map>
//#include <vector>
//#include <fstream>
//#include <iostream>
//#include <algorithm>
//#include <functional>
class BannedIpLogger {

 public:
    int load(std::unordered_map<std::string, WatchMatches*> ips);
    int save(std::unordered_map<std::string, WatchMatches*> ips);

};


#endif //_BANNEDIPLOGGER_H
