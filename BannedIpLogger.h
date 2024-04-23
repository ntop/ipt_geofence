//
// Created by donaldo on 17/04/24.
//

#ifndef _BANNEDIPLOGGER_H
#define _BANNEDIPLOGGER_H
#include "WatchMatches.h"
#include <unordered_map>

#define IS_HUMAN_READABLE false
/**
 * This option can be useful if combined with IS_HUMAN_READABLE = True.
 * This way, this class can operate also as a logger of banned ip addresses but without banning them.
 */
#define LOG_ONLY false

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
  std::string dumpPath = IS_HUMAN_READABLE ? "/var/tmp/banned_ip_addresses.json" : "/var/tmp/banned_ip_addresses.bin";
  std::unordered_map<std::string, WatchMatches*> load();
  int save(std::unordered_map<std::string, WatchMatches*> ips);

  void release(std::unordered_map<std::string, WatchMatches*> ips);

};


#endif //_BANNEDIPLOGGER_H
