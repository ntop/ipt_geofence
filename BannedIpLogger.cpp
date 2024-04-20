//
// Created by Donaldo on 17/04/24.
//

#include "include.h"

#define IS_HUMAN_READABLE true
/**
 * This option can be useful if combined with IS_HUMAN_READABLE = True.
 * This way, this class can operate also as a stacktrace of banned ips.
 */
#define SAVE_ANYWAYS true

typedef std::unordered_map<std::string, WatchMatches*> ip_map;


//TODO read ips from json file
//TODO add define for function values
//TODO move function inside this file
//TODO remove ip from file after condition is met, ??
//TODO change class name
//TODO change console logs format

std::vector<std::string> split(std::string s, std::string delimiter) {
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
bool is_empty(std::ifstream& pFile)
{
  return pFile.peek() == std::ifstream::traits_type::eof();
}

ip_map BannedIpLogger::load() {
  std::unordered_map<std::string, WatchMatches*> fetched_ip_list;
  if(dumpPath.empty()) return fetched_ip_list;
  trace->traceEvent(TRACE_NORMAL, "%s", "Started loading ips from persistent file");
  std::ifstream rf("banned_ips.dat", std::ios::out | std::ios::binary);
  if(!rf) {
    trace->traceEvent(TRACE_WARNING, "%s", "Cannot open file!");
    return fetched_ip_list;
  }

  size_t size;
  char *data;

  if(is_empty(rf)) {
    return fetched_ip_list;
  }
  rf.seekg (0, rf.end);
  int length = rf.tellg();
  rf.seekg (0, rf.beg);
  while (rf.gcount() < length){
    rf.read( (char*)&size, sizeof(size) );
    if(!rf) break;
    data = new char[size+1];
    rf.read( data, size );
    if(!rf) break;
    data[size]='\0';
    std::vector<std::string> splitted =  split(data,"$$");
    if(splitted.size() != 3) {
      trace->traceEvent(TRACE_WARNING, "%s", "Error while reading WatchMatches, malformed line in file");
      return fetched_ip_list;
    }
    //TODO check if it's necessary to handle invalid_argument and out_of_range exceptions
    int times = static_cast<uint32_t>(std::stoul(splitted[1]));
    int last_match = static_cast<uint32_t>(std::stoul(splitted[2]));
      fetched_ip_list[splitted[0]] = new WatchMatches(times, last_match );
  }
  rf.close();
  return fetched_ip_list;
}

int BannedIpLogger::save(ip_map ips) {
  if(dumpPath.empty()) return 1;
  trace->traceEvent(TRACE_NORMAL, "%s", "Writing in persistent storage banned ips");
  //serialize host ip, times of it has appeared and last seen time
  std::string string_serialized;
  std::ofstream wf(dumpPath, std::ios::out | std::ios::binary);
  if(!wf) {
    trace->traceEvent(TRACE_WARNING, "%s", "Cannot open file!");
    return 1;
  }
  for(std::unordered_map<std::string, WatchMatches*>::iterator it = ips.begin();it != ips.end(); it++) {
    WatchMatches* watches = it->second;
    watches->get_num_matches();
    string_serialized = it->first + "$$" + std::to_string(watches->get_num_matches()) + "$$" + std::to_string(watches->get_last_match());
    std::cout << string_serialized;
    size_t size = string_serialized.size();
    wf.write((char*) &size, sizeof(size_t) );
    wf.write( (char*) string_serialized.c_str(), size );
  }
  wf.close();
  if(!wf.good()) {
    trace->traceEvent(TRACE_WARNING, "%s", "Error occurred at writing time!");
    return 1;
  }
  return 0;
}
