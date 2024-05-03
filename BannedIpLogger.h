//
// Created by donaldo on 17/04/24.
//

#ifndef _BANNEDIPLOGGER_H
#define _BANNEDIPLOGGER_H
#include "WatchMatches.h"
#include <unordered_map>
#include <condition_variable>

class BannedIpLogger {
private:
  std::unordered_map<std::string, WatchMatches *> ip_addresses;
  std::vector<std::string> split(std::string s, std::string delimiter);
  std::mutex mutex;
  std::thread thread_poller;
  volatile bool isRunning = true;
  std::condition_variable sleeper;
  bool is_empty(std::ifstream& pFile);
  void poller();
public:
  std::string dump_path = "/var/tmp/banned_ip_addresses.txt";
  BannedIpLogger();
  ~BannedIpLogger();
  bool load();
  bool save();
  bool findIpv4(struct in_addr *addr);
  bool findIpv6(struct in6_addr *addr);
  int addAddress(std::string addr, WatchMatches *matches);
  void release();

};


#endif //_BANNEDIPLOGGER_H
