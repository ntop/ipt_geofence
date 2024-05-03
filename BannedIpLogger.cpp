//
// Created by Donaldo on 17/04/24.
//

#include "include.h"

#define DROP_AFTER 86400 /* Drop after one day */
#define POLLER_RATE 600 /* Check entries every 10 minutes */

BannedIpLogger::BannedIpLogger() {
  load();
  thread_poller = std::thread(&BannedIpLogger::poller,this);
}
BannedIpLogger::~BannedIpLogger() {
  isRunning = false;
  sleeper.notify_all();
  if(thread_poller.joinable())
    thread_poller.join();
  save();
  release();
}

std::vector<std::string> BannedIpLogger::split(std::string s, std::string delimiter) {
  size_t pos_start = 0, pos_end, delim_len = delimiter.length();
  std::string token;
  std::vector<std::string> res;

  while ((pos_end = s.find(delimiter, pos_start)) != std::string::npos) {
    token = s.substr (pos_start, pos_end - pos_start);
    pos_start = pos_end + delim_len;
    res.push_back (token);
  }

  res.push_back (s.substr (pos_start));
  return res;
}

/* **************************************************** */

bool BannedIpLogger::is_empty(std::ifstream& pFile)
{
  return pFile.peek() == std::ifstream::traits_type::eof();
}

/* **************************************************** */

bool  BannedIpLogger::load() {
  trace->traceEvent(TRACE_NORMAL, "%s", "Started loading ips from persistent file");
  std::ifstream infile(dump_path);
  std::string line;
  if(!infile.is_open() || is_empty(infile))
    return(false);

  while(getline(infile, line)){
    if(line[0] == '\0')
      continue;
    std::vector<std::string> splitted =  split(line,"\t");
    if(splitted.size() != 3) {
      trace->traceEvent(TRACE_WARNING, "%s", "Error while reading WatchMatches, malformed line in file");
      return false;
    }
    int times = static_cast<uint32_t>(std::stoul(splitted[1]));
    int last_match = static_cast<uint32_t>(std::stoul(splitted[2]));
    if(last_match <= time(NULL) - DROP_AFTER) continue;
    ip_addresses[splitted[0]] = new WatchMatches(times, last_match);
  }

  infile.close();
  return(true);
}

/* **************************************************** */

bool BannedIpLogger::save() {
  trace->traceEvent(TRACE_NORMAL, "%s", "Writing in persistent storage banned ips");
  std::string string_serialized;
  std::ofstream wf(dump_path, std::ios::out | std::ios::binary);
  if(!wf) {
    trace->traceEvent(TRACE_WARNING, "%s", "Cannot open file!");
    return false;
  }
  for(std::unordered_map<std::string, WatchMatches *>::iterator it = ip_addresses.begin();it != ip_addresses.end(); it++) {
    string_serialized = it->first + "\t" + std::to_string(it->second->get_num_matches()) + "\t" + std::to_string(it->second->get_last_match()) + "\n";
    size_t size = string_serialized.size();
    wf.write( (char*) string_serialized.c_str(), size );
  }
  wf.close();
  if(!wf.good()) {
    trace->traceEvent(TRACE_WARNING, "%s", "Error occurred at writing time!");
    return false;
  }
  return true;
}

/* Returns occurrences if matches = NULL, otherwise updates its values */
int BannedIpLogger::addAddress(std::string addr,WatchMatches *matches) {
  std::unordered_map<std::string, WatchMatches *>::iterator it = ip_addresses.find(addr);
  if(matches == NULL && it != ip_addresses.end()) {
    it -> second ->set_last_match(time(NULL));
    return it->second->get_num_matches();
  }
  if(matches == NULL) {
    std::unique_lock<std::mutex> lock(mutex);
    ip_addresses[addr] = new WatchMatches();
    lock.unlock();
    return 1;
  }
  it->second->set_last_match(matches->get_last_match());
  it->second->set_num_matches(matches->get_num_matches());
  return 0;
}

/* **************************************************** */

void BannedIpLogger::release() {
  for (auto itr = ip_addresses.begin(); itr != ip_addresses.end();)
  {
    delete itr -> second;
    itr = ip_addresses.erase(itr);
  }
}

/* **************************************************** */

bool BannedIpLogger::findIpv4(struct in_addr *addr) {
  char saddr[INET_ADDRSTRLEN];
  struct in_addr copy;
  copy.s_addr = htonl(addr->s_addr);
  char *ip = (char *) inet_ntop(AF_INET, &copy, saddr, INET_ADDRSTRLEN);
  if(ip == NULL) return false;
  std::unordered_map<std::string, WatchMatches *>::iterator it = ip_addresses.find(std::string(ip));
  return it != ip_addresses.end();
}

/* **************************************************** */

bool BannedIpLogger::findIpv6(struct in6_addr *addr) {
  char saddr[INET6_ADDRSTRLEN];
  char *ip = (char *) inet_ntop(AF_INET6, addr, saddr, INET6_ADDRSTRLEN);
  if(ip == NULL) return false;
  std::unordered_map<std::string, WatchMatches *>::iterator it = ip_addresses.find(std::string(ip));
  return it != ip_addresses.end();
}

/* **************************************************** */

void BannedIpLogger::poller() {
  while (isRunning) {
    std::unique_lock<std::mutex> lock(mutex);
    for (auto itr = ip_addresses.begin(); itr != ip_addresses.end();) {
      if (itr->second->get_last_match() <= time(NULL) - DROP_AFTER) {
        delete itr->second;
        itr = ip_addresses.erase(itr);
      }
      else itr++;
    }
    sleeper.wait_for(lock,std::chrono::seconds(POLLER_RATE));
  }
}