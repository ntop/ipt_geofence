/*
 *
 * (C) 2021-22 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include "include.h"

/* ******************************************************* */

u_int16_t Configuration::ctry_cont2u16(char *ctry_cont_code) {
  if(ctry_cont_code == NULL || strlen(ctry_cont_code) < 2) return 0;

  return ((((u_int16_t) ctry_cont_code[0]) << 8) | ((u_int16_t) ctry_cont_code[1]));
}

/* ******************************************************* */

bool Configuration::readConfigFile(char *path) {
  Json::Value root;
  std::ifstream ifs;
  JSONCPP_STRING errs;
  Json::CharReaderBuilder builder;

  ifs.open(path);

  builder["collectComments"] = true;

  if (!parseFromStream(builder, ifs, &root, &errs)) {
    std::cout << errs << std::endl;
    return(false);
  }

  if(root["queue_id"].empty()) {
    trace->traceEvent(TRACE_ERROR, "Missing %s from %s", "queue_id", path);
    return(false);
  } else
    nfq_queue_id = root["queue_id"].asUInt();

  if(root["default_marker"].empty()) {
    trace->traceEvent(TRACE_ERROR, "Missing %s from %s", "default_marker", path);
    return(false);
  } else {
    std::string m = root["default_marker"].asString();

    default_marker = (m == "PASS") ? MARKER_PASS : MARKER_DROP;
  }

  all_tcp_ports = all_udp_ports = true;

  if(!root["monitored_ports"].empty()) {
    if(!root["monitored_ports"]["tcp"].empty()) {
      all_tcp_ports = false;

      for(Json::Value::ArrayIndex i = 0; i != root["monitored_ports"]["tcp"].size(); i++) {
	unsigned int port = root["monitored_ports"]["tcp"][i].asUInt();

	trace->traceEvent(TRACE_INFO, "Adding TCP/%u", port);
	tcp_ports[port] = true;
      }
    }

    if(!root["monitored_ports"]["udp"].empty()) {
      all_udp_ports = false;

      for(Json::Value::ArrayIndex i = 0; i != root["monitored_ports"]["udp"].size(); i++) {
	unsigned int port = root["monitored_ports"]["udp"][i].asUInt();

	trace->traceEvent(TRACE_INFO, "Adding UDP/%u", port);
	udp_ports[port] = true;
      }
    }

    if(!root["monitored_ports"]["ignored_ports"].empty()) {
      for(Json::Value::ArrayIndex i = 0; i != root["monitored_ports"]["ignored_ports"].size(); i++) {
	unsigned int port = root["monitored_ports"]["ignored_ports"][i].asUInt();

	trace->traceEvent(TRACE_INFO, "Ignoring TCP/UDP port %u", port);
	ignored_ports[port] = true;
      }
    }
  }

  if(all_tcp_ports) trace->traceEvent(TRACE_INFO, "All TCP ports will be monitored");
  if(all_udp_ports) trace->traceEvent(TRACE_INFO, "All UDP ports will be monitored");


  int counter = 4;
  do {
    std::string drop_or_pass; //drop or pass
    std::string wb_list; //the value can be one of the lists(black or white)
    int marker; 

    if(!(counter%2)){ 
      drop_or_pass = "drop";
      marker = MARKER_PASS;
      if(counter == 4)
        wb_list = "countries_whitelist";
      else
        wb_list = "continents_whitelist";
    }
    else{
      drop_or_pass = "pass";
      marker = MARKER_DROP;
      if(counter == 3)
        wb_list = "countries_blacklist";
      else
        wb_list = "continents_blacklist";
    }


    if(!root["policy"].empty()) {
      if(!root["policy"][drop_or_pass].empty()) {
        if(!root["policy"][drop_or_pass][wb_list].empty()){
            for(Json::Value::ArrayIndex i = 0; i != root["policy"][drop_or_pass][wb_list].size(); i++){
              std::string ctry_cont = root["policy"][drop_or_pass][wb_list][i].asString();
            }
        }else {
        }
      } 
    }
  } while(--counter);  

  if(!root["blacklists"].empty()) {
    for(Json::Value::ArrayIndex i = 0; i != root["blacklists"].size(); i++) {
      std::string url = root["blacklists"][i].asString();

      blacklists.loadIPsetFromURL(url.c_str());
    }
  }

  return(configured = true);
}

/* ******************************************************* */

Marker Configuration::getMarker(char *country, char *continent) {
  u_int16_t id = ctry_cont2u16(country);
  std::unordered_map<u_int16_t, Marker>::iterator it = ctrs_conts.find(id);

  if(it != ctrs_conts.end()) 
    return(it->second); // country found

  id = ctry_cont2u16(continent);
  it = ctrs_conts.find(id);
  if(it != ctrs_conts.end()) 
    return(it->second); // continent found
  
  return(default_marker);
}

/* ******************************************************* */
