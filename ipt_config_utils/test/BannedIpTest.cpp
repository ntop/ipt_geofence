//
// Created by root on 20/04/24.
//


#include "../../include.h"

Trace *trace = new Trace();

void test();
void test1();
void test2();
void test3();
void test4();
void test5();


void print_test_passed(std::string message){
  printf("\x1B[32m%s\033[0m\n",message.c_str());

}

int main (int argc, char *argv[]){

  /**
   * To run this test:
   * - go to the base folder of the project
   * - run "make test"
   * - run "sudo ./ipt_test"
   *
   * If you want to check for memory leaks:
   * then run "sudo valgrind -s ./ipt_test".
   * Make sure to have valgrind installed on your device.
   */

  /**
   * Test 0: empty path
   */
  test();

  /**
   * Test 1: No file found
   */
  test1();


  /**
   * Test 2: Malformed file
   */
  test2();


  /**
   * Test 3: Save and load 10.000 entries
   */
  test3();


  /**
   * Test 4: Check if num_matches increments correctly and its time to harvest
   */
   test4();


   /**
    * Most exhaustive test.
    * How to execute:
    * Run this program, then run ipt_geofence with the following command:
    * sudo ./ipt_geofence -c sample_config.json -m dbip-country.mmdb -d test5.json
    *
    * Finally, check the test5.json file. The number of ip addresses remaining in the file depends on how long ipt_geofence runs.
    *
    * Test 5: Run NwInterface with 4 default ips that should be banned
    */
    test5();
}


void test(){
  BannedIpLogger *no_path = new BannedIpLogger("");
  std::unordered_map<std::string, WatchMatches*> path_result = no_path -> load();
  assert(path_result.size() == 0);
  delete no_path;
  print_test_passed("Test#0 Passed");
}
void test1(){
  BannedIpLogger *no_file = new BannedIpLogger("XXXXXXX");
  std::unordered_map<std::string, WatchMatches*> no_result = no_file -> load();
  delete no_file;
  assert(no_result.size() == 0);
  print_test_passed("Test#1 Passed");
}

void test2(){
  BannedIpLogger *malformed = new BannedIpLogger("test2.json");
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
}
void test3(){
  std::string outputFile = "test3.json";
  //Test when IS_HUMAN_READABLE = False
  //outputFile = "test3.bin";
  BannedIpLogger *ip = new BannedIpLogger(outputFile);

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
void test4(){
  WatchMatches *watchMatches =  new WatchMatches(1,time(NULL));

  for(int key = 1; key <= 12; key++){
    assert(watchMatches -> ready_to_harvest() == false);
    // The value should be the same bug maybe sometime there would be a small delay in computation. However, the difference should be less than 1 second.
    assert(std::abs(time(NULL) - watchMatches ->  f(key) * 100 - watchMatches->calculate_ban_time()) <= 1);
    watchMatches->inc_matches();
  }
  delete watchMatches;

  print_test_passed("Test#4 Passed");
}

void execCmd(char *cmdbuf) {
  try {
    Utils::execCmd(cmdbuf);
  } catch (...) { trace->traceEvent(TRACE_ERROR, "Error while executing '%s'", cmdbuf); }
}
void test5(){
  std::string outputFile = "test5.json";
  BannedIpLogger *ip = new BannedIpLogger(outputFile);

  const int howMany = 4;
  std::unordered_map<std::string, WatchMatches*> matches_list;
  for(int key = 0; key < howMany; key++){
    std::string host = "192.168."+std::to_string(key/255)+"."+std::to_string(key%256);
    matches_list[host] = new WatchMatches(key ,time(NULL));
  }
  ip ->save(matches_list);

  //TODO Automate this test
  /*std::string command = "sudo ./ipt_geofence -c sample_config.json -m dbip-country.mmdb -d test5.json";
  execCmd((char *) command.c_str());


  std::string kill = "sudo pkill -9 -f ipt_geofence";
  execCmd((char *) kill.c_str());*/

  int index = 0;
  std::unordered_map<std::string, WatchMatches*> result = ip -> load();
  for(std::unordered_map<std::string, WatchMatches*>::iterator it = result.begin();it != result.end(); it++) {
    if(matches_list[it->first] -> ready_to_harvest()){
      index++;
      assert(matches_list[it->first] ->ready_to_harvest() == true);
    }
    else assert(matches_list[it->first] ->ready_to_harvest() == false);
  }
  // check if the size of the remaining watches.
  assert(result.size() == howMany - index);
  print_test_passed("Test#5 Passed");
}
