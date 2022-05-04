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

bool Configuration::readConfigFile(const char *path) {
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

  if(root["default_policy"].empty()) {
    trace->traceEvent(TRACE_ERROR, "Missing %s from %s", "default_policy", path);
    return(false);
  } else {
    std::string m = root["default_policy"].asString();
    trace->traceEvent(TRACE_INFO, "Default policy: %s", m.c_str());
    default_policy = (m == "PASS") ? MARKER_PASS : MARKER_DROP;

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

    all_honeypot_ports = true;

    // Doesn't distinguish between UDP and TCP (and other protocols...)
    if (!root["monitored_ports"]["honeypot_ports"].empty()) {
      all_honeypot_ports = false;
      for (Json::Value::ArrayIndex i = 0; i != root["monitored_ports"]["honeypot_ports"].size(); i++) {
        unsigned int port = root["monitored_ports"]["honeypot_ports"][i].asUInt();

        trace->traceEvent(TRACE_INFO, "Protecting port %u", port);
        honeypot_ports[port] = true;
      }
    }
  }

  if(all_tcp_ports) trace->traceEvent(TRACE_INFO, "All TCP ports will be monitored");
  if(all_udp_ports) trace->traceEvent(TRACE_INFO, "All UDP ports will be monitored");

  std::string json_policy_str = default_policy == MARKER_DROP ? "drop" : "pass";

  if(!root["policy"].empty() && !root["policy"][json_policy_str].empty()) {

      Json::Value json_policy_obj = root["policy"][json_policy_str];
      std::string json_list_str = json_policy_str == "drop" ? "_whitelist" : "_blacklist";
      int counter = 2;
      do {
        std::string json_value_str = counter == 2 ? "countries" : "continents";
        if(json_policy_obj[json_value_str+json_list_str].empty()) {
          trace->traceEvent(TRACE_INFO, "Missing %s from %s", (json_value_str+json_list_str).c_str(), path);
        } else {
          for(Json::Value::ArrayIndex i = 0; i != json_policy_obj[json_value_str+json_list_str].size(); i++) {
            std::string ctry_cont = json_policy_obj[json_value_str+json_list_str][i].asString();

            trace->traceEvent(TRACE_INFO, "Adding %s to %s", ctry_cont.c_str(), (json_value_str+json_list_str).c_str());
            ctrs_conts[ctry_cont2u16((char*)ctry_cont.c_str())] = json_policy_str == "drop" ? MARKER_PASS : MARKER_DROP;
          }
        }
      }while(--counter);
  }
  if(!root["blacklists"].empty()) {
    size_t n_urls = root["blacklists"].size();
    blacklists.urls_Blacklist.resize(n_urls);
    for(Json::Value::ArrayIndex i = 0; i != n_urls; i++) {
      std::string url (root["blacklists"][i].asString());
      blacklists.urls_Blacklist[i] = url;
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

  return(default_policy);
}

/* ******************************************************* */

/**
 * @brief  Assuming r1.high > r2.low or viceversa, puts in 'ret'
 * the union between the two ranges. 
 * e.g. mergeRanges(15-30,20-40) returns 15-40.
 * 
 * @param r1 
 * @param r2 
 * @param ret pointer to structure which will hold the merged range
 * @return true if mergeable, false otherwise 
 */
bool Configuration::mergePortRanges (port_range r1, port_range r2, port_range *ret){
  if (r1.first < r1.second || r2.first < r2.second || !ret)
    return false; // r1 || r2 || ret is invalid
  port_range 
    l = r1.second < r2.second ? r1 : r2,  // "left" range
    r = r1.second < r2.second ? r2 : r1;  // "right" range

  if( !(l.first > r.second) )
    return false; // r1 and r2 are disjoint ranges
  
  ret->first = r.first;
  ret->second = l.second;
  
  return true;
}

void Configuration::addPortRange (port_range r){
  if (r.first < r.second){
    u_int16_t tmp = r.first;
    r.first = r.second;
    r.second = tmp;
  }

  port_range ins;
  // TODO merge ins with something already in the tree 
  //honeypot_ranges.insert()
  
}
