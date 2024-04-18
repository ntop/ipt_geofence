//
// Created by Donaldo on 17/04/24.
//

//#include "BannedIpLogger.h"
#include "include.h"
//#include "WatchMatches.h"
//#include <unordered_map>
//#include <vector>
//#include <fstream>
//#include <iostream>
//#include <algorithm>
//#include <functional>
typedef std::unordered_map<std::string, WatchMatches*> Map;


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

int BannedIpLogger::load(std::unordered_map<std::string, WatchMatches*> *ips) {
  std::cout << "Started loading banned_ips.dat\n";
  std::ifstream rf("banned_ips.dat", std::ios::out | std::ios::binary);
  if(!rf) {
    std::cout << "Cannot open file!";
    return 1;
  }

  size_t size;
  char *data;
  std::unordered_map<std::string, WatchMatches*> ips_found;

  if(is_empty(rf)) {
    return 0;
  }
  rf.seekg (0, rf.end);
  int length = rf.tellg();
  rf.seekg (0, rf.beg);
  while (rf.gcount() < length){
    rf.read( (char*)&size, sizeof(size) );
    if(!rf) break;
    std::cout << "Read " << size;
    data = new char[size+1];
    rf.read( data, size );
    if(!rf) break;
    data[size]='\0';
    std::cout << "Read " << data;
    std::vector<std::string> splitted =  split(data,"$$");
    if(splitted.size() != 3) {
      std::cout << "Error while reading WatchMatches, malformed line in file\n";
      return 1;
    }
    //TODO check if it's necessary to handle invalid_argument and out_of_range exceptions
    int times = static_cast<uint32_t>(std::stoul(splitted[1]));
    int last_match = static_cast<uint32_t>(std::stoul(splitted[2]));

    ips_found[splitted[0]] = new WatchMatches(times, last_match );
  }
  //insert data after the loop has finished
  if(!ips_found.empty())
    ips -> insert(ips_found.begin(),ips_found.end());
  rf.close();
  return 0;
}

int BannedIpLogger::save(std::unordered_map<std::string, WatchMatches*> ips) {

  std::cout << "Writing in persistent storage banned ips";
  //serialize host ip, times of it has appeared and last seen time
  std::string string_serialized;
  std::ofstream wf("banned_ips.dat", std::ios::out | std::ios::binary);
  if(!wf) {
    std::cout << "Cannot open file!";
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
    std::cout << "Error occurred at writing time!";
    return 1;
  }
  return 0;
}
/*
void serialize(Serializer& out, Map const& map) {
    out << map.size();
    for (auto const& p: map) { out << p.first << p.second; }
}*/
