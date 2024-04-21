//
// Created by root on 20/04/24.
//


#include "../../include.h"

Trace *trace = new Trace();

void print_test_passed(std::string message){
  printf("\x1B[32m%s\033[0m\n",message.c_str());

}

int main (int argc, char *argv[]){


  /**
   * Test 0: empty path
   */
  BannedIpLogger *no_path = new BannedIpLogger("");
  std::unordered_map<std::string, WatchMatches*> path_result = no_path -> load();
  assert(path_result.size() == 0);
  delete no_path;
  print_test_passed("Test#0 Passed");

  /**
   * Test 1: No file found
   */
  BannedIpLogger *no_file = new BannedIpLogger("XXXXXXX");
  std::unordered_map<std::string, WatchMatches*> no_result = no_file -> load();
  delete no_file;
  assert(no_result.size() == 0);
  print_test_passed("Test#1 Passed");
  /**
   * Test 2: Malformed file
   */
  BannedIpLogger *malformed = new BannedIpLogger("malformed.json");
  std::unordered_map<std::string, WatchMatches*> malformed_list;
  malformed_list["$$$$"] = new WatchMatches(1,171361377);
  for (auto itr = malformed_list.begin(); itr != malformed_list.end();)
  {
    delete itr->second;
    itr = malformed_list.erase(itr);
  }
  malformed ->save(malformed_list);
  std::unordered_map<std::string, WatchMatches*> malformed_result = malformed -> load();
  delete malformed;
  assert(malformed_result.size() == 0);
  print_test_passed("Test#2 Passed");
  /**
   * Test 3: Save and load 10.000 entries
   */
  BannedIpLogger *ip = new BannedIpLogger("test_file.json");

  const int howMany = 10000;
  std::unordered_map<std::string, WatchMatches*> matches_list;
  for(int key = 0; key < howMany; key++){
    std::string host = "192.168."+std::to_string(key/255)+"."+std::to_string(key%256);
    matches_list[host] = new WatchMatches((u_int32_t) 1,(u_int32_t)171361377);
  }
  ip ->save(matches_list);

  std::unordered_map<std::string, WatchMatches*> result = ip -> load();

  assert(result.size() == howMany);


  //Check if every entry has been loaded correctly
  int count = 0;
  for(std::unordered_map<std::string, WatchMatches*>::iterator it = result.begin(); it != result.end(); it++){
    std::unordered_map<std::string, WatchMatches*>::iterator match = matches_list.find(it->first);
    if(match != matches_list.end()) {
      count++;
      assert(match->second -> get_last_match() == it->second->get_last_match());
      assert(match->second -> get_num_matches() == it->second->get_num_matches());
    }
  }

  for (auto itr = result.begin(); itr != result.end(); )
  {
    delete itr->second;
    itr = result.erase(itr);
  }
  for (auto itr = matches_list.begin(); itr != matches_list.end();)
  {
    delete itr->second;
    itr = matches_list.erase(itr);
  }
  delete ip;
  delete trace;
  assert(count == howMany);
  print_test_passed("Test#3 Passed");
}