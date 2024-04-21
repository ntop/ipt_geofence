//
// Created by Donaldo on 17/04/24.
//

#include "include.h"

#define IS_HUMAN_READABLE false
/**
 * This option can be useful if combined with IS_HUMAN_READABLE = True.
 * This way, this class can operate also as a stacktrace of banned ips.
 */
#define SAVE_ANYWAYS true

typedef std::unordered_map<std::string, WatchMatches*> ip_map;



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
bool BannedIpLogger::is_empty(std::ifstream& pFile)
{
  return pFile.peek() == std::ifstream::traits_type::eof();
}

ip_map BannedIpLogger::load() {
  if(dumpPath.empty()) return std::unordered_map<std::string, WatchMatches*>();
  trace->traceEvent(TRACE_NORMAL, "%s", "Started loading ips from persistent file");
#if IS_HUMAN_READABLE
  return read_as_json();
#else
  return read_file();
#endif

}

int BannedIpLogger::save(ip_map ips) {
  if(dumpPath.empty()) return 1;
  trace->traceEvent(TRACE_NORMAL, "%s", "Writing in persistent storage banned ips");
#if IS_HUMAN_READABLE
  return save_as_json(ips);
#else
   return save_file(ips);
#endif
}
ip_map BannedIpLogger::read_as_json() {
  std::unordered_map<std::string, WatchMatches*> fetched_ip_list;
  Json::Value root;
  std::ifstream ifs;
  JSONCPP_STRING errs;
  Json::CharReaderBuilder builder;

  ifs.open(dumpPath);
  if(ifs.fail()) {
    trace->traceEvent(TRACE_WARNING, "%s", "Error, reading persistent file failed!");
    ifs.close();
    return fetched_ip_list;
  }

  builder["collectComments"] = true;

  if(!parseFromStream(builder, ifs, &root, &errs)) {
    std::cout << errs << std::endl;
    ifs.close();
    return fetched_ip_list;
  }
  for (Json::Value::ArrayIndex i = 0; i != root["list"].size(); i++){
    if (root["list"][i].isObject())
      if(root["list"][i]["ip"].isString() && root["list"][i]["matches"].isUInt() && root["list"][i]["lastSeen"].isUInt()) {
        //simple check for ipv4 and ipv6, not exhaustive.
        if(split(root["list"][i]["ip"].asString(),".").size() != 4 && split(root["list"][i]["ip"].asString(),":").size() != 7) return fetched_ip_list;
        fetched_ip_list[root["list"][i]["ip"].asString()] = new WatchMatches(root["list"][i]["matches"].asUInt(),
                                                                             root["list"][i]["lastSeen"].asUInt());
      }
  }
  ifs.close();
  return fetched_ip_list;
}
bool BannedIpLogger::save_as_json(std::unordered_map<std::string, WatchMatches *> ips){
  Json::Value root;
  Json::Value array(Json::arrayValue);
  Json::StyledStreamWriter writer;
  std::ofstream out(dumpPath);
  for(std::unordered_map<std::string, WatchMatches*>::iterator it = ips.begin();it != ips.end(); it++) {
    Json::Value obj(Json::objectValue);
    obj["ip"] = it -> first;
    obj["matches"] = it -> second -> get_num_matches();
    obj["lastSeen"] = it -> second -> get_last_match();
    array.append(obj);
  }
  root["list"] = array;

  writer.write(out,root);
  out.close();
  return true;
}

bool BannedIpLogger::save_file(ip_map ips) {
  //serialize host ip, times of it has appeared and last seen time
  std::string string_serialized;
  std::ofstream wf(dumpPath, std::ios::out | std::ios::binary);
  if(!wf) {
    trace->traceEvent(TRACE_WARNING, "%s", "Cannot open file!");
    return false;
  }
  for(std::unordered_map<std::string, WatchMatches*>::iterator it = ips.begin();it != ips.end(); it++) {
    WatchMatches* watches = it->second;
    watches->get_num_matches();
    string_serialized = it->first + "$$" + std::to_string(watches->get_num_matches()) + "$$" + std::to_string(watches->get_last_match());
    size_t size = string_serialized.size();
    wf.write((char*) &size, sizeof(size_t) );
    wf.write( (char*) string_serialized.c_str(), size );
  }
  wf.close();
  if(!wf.good()) {
    trace->traceEvent(TRACE_WARNING, "%s", "Error occurred at writing time!");
    return false;
  }
  return true;
}

ip_map BannedIpLogger::read_file() {
  std::unordered_map<std::string, WatchMatches*> fetched_ip_list;
  std::ifstream rf(dumpPath, std::ios::out | std::ios::binary);
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
  int read = 0;
  while (read < length){
    read += rf.gcount();
    rf.read( (char*)&size, sizeof(size) );
    if(!rf) break;
    data = new char[size+1];
    rf.read( data, size );
    if(!rf) break;
    data[size]='\0';
    std::vector<std::string> splitted =  split(data,"$$");
    delete[] data;
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

void BannedIpLogger::release(std::unordered_map<std::string, WatchMatches *> ips) {
  for (auto itr = ips.begin(); itr != ips.end();)
  {
    delete itr->second;
    itr = ips.erase(itr);
  }
}