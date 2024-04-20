//
// Created by donaldo on 17/04/24.
//

#ifndef _BANNEDIPLOGGER_H
#define _BANNEDIPLOGGER_H
#include "WatchMatches.h"
#include <unordered_map>

class BannedIpLogger {
private:
  std::unordered_map<std::string, WatchMatches*> read_as_json();
  bool save_as_json(std::unordered_map<std::string, WatchMatches*> ips);
  std::unordered_map<std::string, WatchMatches*> read_file();
  bool save_file(std::unordered_map<std::string, WatchMatches*> ips);
  //it's used to split serialized string
  std::vector<std::string> split(std::string s, std::string delimiter);
  //checks if the file is empty
  bool is_empty(std::ifstream& pFile);
public:
  std::string dumpPath = "";
  BannedIpLogger(std::string _dumpPath) { dumpPath = _dumpPath; }
  std::unordered_map<std::string, WatchMatches*> load();
  int save(std::unordered_map<std::string, WatchMatches*> ips);


};


#endif //_BANNEDIPLOGGER_H
