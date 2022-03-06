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

u_int16_t Configuration::country2u16(char *country_code) {
  if(country_code == NULL || strlen(country_code) < 2) return 0;

  return ((((u_int16_t) country_code[0]) << 8) | ((u_int16_t) country_code[1]));
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

  if(!root["countries"].empty()) {
    if(root["countries"]["whitelist"].empty()) {
      trace->traceEvent(TRACE_INFO, "Missing %s from %s", "countries whitelist", path);
    } else {
      for(Json::Value::ArrayIndex i = 0; i != root["countries"]["whitelist"].size(); i++) {
	std::string country = root["countries"]["whitelist"][i].asString();

	trace->traceEvent(TRACE_INFO, "Adding %s to countries whitelist", country.c_str());
	countries[country2u16((char*)country.c_str())] = MARKER_PASS;
      }
    }

    if(root["countries"]["blacklist"].empty()) {
      trace->traceEvent(TRACE_INFO, "Missing %s from %s", "blacklist", path);
    } else {
      for(Json::Value::ArrayIndex i = 0; i != root["countries"]["blacklist"].size(); i++) {
	std::string country = root["countries"]["blacklist"][i].asString();

	trace->traceEvent(TRACE_INFO, "Adding %s to countries blacklist", country.c_str());
	countries[country2u16((char*)country.c_str())] = MARKER_DROP;
      }
    }
  }

  if(!root["continents"].empty()){
    if(root["continents"]["whitelist"].empty()){
      trace->traceEvent(TRACE_INFO, "Missing %s from %s", "continents whitelist", path);
    }
    else{
      for(Json::Value::ArrayIndex i = 0; i != root["continents"]["whitelist"].size(); i++){
        std::string continent = root["continents"]["whitelist"][i].asString();

        trace->traceEvent(TRACE_INFO, "Adding %s to continents whitelist", continent.c_str());
        continents[country2u16((char*)continent.c_str())] = MARKER_PASS;
      }
    }

    if(root["continents"]["blacklist"].empty()){
      trace->traceEvent(TRACE_INFO, "Missing %s from %s", "continents blacklist", path);
    }
    else{
      for(Json::Value::ArrayIndex i = 0; i != root["continents"]["blacklist"].size(); i++){
        std::string continent = root["continents"]["blacklist"][i].asString();

        trace->traceEvent(TRACE_INFO, "Adding %s to continents blacklist", continent.c_str());
        continents[country2u16((char*)continent.c_str())] = MARKER_DROP;
      }
    }
  }

  return(configured = true);
}

/* ******************************************************* */

Marker Configuration::getCountryMarker(char *country) {
  u_int16_t id = country2u16(country);
  std::unordered_map<u_int16_t, Marker>::iterator it = countries.find(id);

  if(it == countries.end())
    return(default_marker); /* Not found */
  else
    return(it->second);
}

/* ******************************************************* */
