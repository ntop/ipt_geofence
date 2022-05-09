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


    // Doesn't distinguish between UDP and TCP (and other protocols...)
    if (!root["monitored_ports"]["honeypot_ports"].empty()) {
      for (Json::Value::ArrayIndex i = 0; i != root["monitored_ports"]["honeypot_ports"].size(); i++) {
        Json::Value honeypot_field = root["monitored_ports"]["honeypot_ports"][i];
        
        if(honeypot_field.isString()) { // port range [A-B] or "all ports except" !P
          u_int16_t except_port;
          port_range p_r;
          std::string s = honeypot_field.asString();
          
          if(s.find_first_of("!") == 0) { // Might be a !P
            if(parseAllExcept(s,&except_port)) {  // !P "overrides" port ranges but NOT single ports
              // honeypot_ports.clear();
              hp_ranges.clear();  // We don't care no more about these
              hp_all_except_ports[except_port] = true;
              trace->traceEvent(TRACE_INFO, "Protecting all ports except %u", except_port);
            }
          } else if (parsePortRange(s, &p_r)) {  // Might be a port range
            addPortRange(p_r);
            // trace->traceEvent(TRACE_INFO, "Added range..."); 
          }
        } else  {   // Single port
          hp_ports[honeypot_field.asUInt()] = true; 
          trace->traceEvent(TRACE_INFO, "Protecting port %u", honeypot_field.asUInt());
        }
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
    l = r1.second <= r2.second ? r1 : r2,  // "left" range
    r = r1.second <= r2.second ? r2 : r1;  // "right" range


  if( l.first < r.second )
    return false; // r1 and r2 are disjoint ranges
  
  if( r.first < l.first )
    ret->first = l.first; // r is completely included in l
  else
    ret->first = r.first;
  ret->second = l.second;
  trace->traceEvent(TRACE_INFO, "Merging ranges [%u-%u] and [%u-%u] into [%u-%u]",
    r1.second,r1.first,r2.second,r2.first,ret->second,ret->first
    );
  return true;
}

/**
 * @brief adds a range to hp_ranges, making sure that all
 * ranges in the set are disjoint and ordered using range upper bounds
 * 
 * @param r range to be inserted 
 */
void Configuration::addPortRange(port_range r) {
  port_range curr (r), merged (r);
  // the set must be ordered using the upper bound
  // NB: a set of pair is ordered using pair.first
  if (r.first < r.second) {
    curr.first = merged.first = r.second;
    curr.second = merged.second = r.first;
  }

  std::set<port_range>::iterator it = hp_ranges.begin();
  
  while(it != hp_ranges.end()) {
    if (mergePortRanges(curr, *it, &merged)) {
      if(merged!=*it) {  // if merge operation generate a new range
        hp_ranges.erase(it);  // remove the range now included in 'merged'
        curr = merged;  // update curr for next walk           
        it = hp_ranges.begin(); // check if new range could be merge
      } else return; 
    } else it++;
  }
  if (it == hp_ranges.end() && curr==merged) {  // walked through the whole set,
    hp_ranges.insert(curr);
    trace->traceEvent(TRACE_INFO, "Protecting range [%u-%u]",merged.second,merged.first);
  }

}

bool Configuration::parsePortRange(std::string s, port_range *r) {
  if (!r) return false;
  size_t delim;
  if ( (delim = s.find("-")) != std::string::npos){
    std::string s_l = s.substr(0,delim), s_r = s.substr(delim + 1, std::string::npos);
    return (stringToU16(s_l, &(r->first)) && stringToU16(s_r, &(r->second)));
  }
  return false;
}

bool Configuration::parseAllExcept(std::string s, u_int16_t *port){
  if (!port) return false;
  size_t delim;
  if ( (delim = s.find("!")) != std::string::npos){
    return (stringToU16(s.substr(delim + 1, std::string::npos), port));
  }
  return false;
}

bool Configuration::stringToU16(std::string s, u_int16_t *toRet) {
  if (!toRet) return false;
  char *err;
  const char *_s = s.c_str();
  unsigned long v = strtoul(_s, &err, 10);
  if (*_s != '\0' && *err == '\0' &&
      v <= USHRT_MAX) {  // string is valid number
    *toRet = v;
    return true;
  }
  // there are some invalid characters
  return false;
}

bool Configuration::isProtectedPort(u_int16_t port) {
  if  (hp_ports.find(port) != hp_ports.end() ||                      // single port match
      // included by a "!port"
      (!hp_all_except_ports.empty() && hp_all_except_ports.find(port) == hp_all_except_ports.end()) ||
      (isIncludedInRange(port))
  )
    return true;
  return false;
}

bool Configuration::isIncludedInRange(u_int16_t port) {
  port_range toSearch {port, 0}; // we don't care about .second
  std::set<port_range>::iterator it = hp_ranges.lower_bound(toSearch);
  if (it == hp_ranges.end()) // No range includes port
    return false;
  /* else */ if ((*it).second <= port)  // <= (*it).first
    return true;
  /* else */ return false;
}