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

#ifndef _CONFIG_H_
#define _CONFIG_H_

#define DEFAULT_PASS_MARKER  1000
#define DEFAULT_DROP_MARKER  2000

/* ******************************* */

typedef std::pair<u_int16_t,u_int16_t> port_range; // first -> upper bound && second -> lower bound

class Configuration {
 private:
  std::unordered_map<u_int16_t, Marker> ctrs_conts;
  std::unordered_map<u_int16_t, bool>   tcp_ports, udp_ports, ignored_ports, hp_ports, hp_all_except_ports;
  unsigned int nfq_queue_id;
  Marker marker_unknown;
  Marker marker_pass;
  Marker marker_drop;
  Marker default_policy;
  Blacklists blacklists;
  
  bool configured, all_tcp_ports, all_udp_ports;

  std::set<port_range> hp_ranges;
  
  u_int16_t ctry_cont2u16(char *country_code);
  bool mergePortRanges (port_range r1, port_range r2, port_range *ret);
  void addPortRange(port_range r);
  bool stringToU16(std::string s, u_int16_t *toRet);
  bool parsePortRange(std::string s, port_range *r);
  bool parseAllExcept(std::string s, u_int16_t *port);
  bool isIncludedInRange(u_int16_t port);
  
 public:
  Configuration() { nfq_queue_id = 0, marker_unknown.setValue(0); 
                    marker_pass.setValue(1000); marker_drop.setValue(2000);
                    default_policy = marker_pass; configured = false, 
                    all_tcp_ports = all_udp_ports = true; }

  bool readConfigFile(const char *path);

  inline unsigned int getQueueId() { return(nfq_queue_id); }
  inline bool isConfigured()       { return(configured);   }
  
  inline void setQueueId(int nfq_id)                        { nfq_queue_id = nfq_id;  }
  inline void setCountryMarker(u_int16_t country, Marker m) { ctrs_conts[country] = m;}
  inline Marker getMarkerUnknown()                          { return marker_unknown;  }
  inline Marker getMarkerPass()                             { return marker_pass;     }
  inline Marker getMarkerDrop()                             { return marker_drop;     }
  inline Marker getDefaultPolicy()                          { return default_policy;  }
  Marker getMarker(char *country, char *continent);
  inline bool isIgnoredPort(u_int16_t port)      { return(ignored_ports.find(port) != ignored_ports.end());            }
  inline bool isMonitoredTCPPort(u_int16_t port) { return(all_tcp_ports || (tcp_ports.find(port) != tcp_ports.end())); }
  inline bool isMonitoredUDPPort(u_int16_t port) { return(all_udp_ports || (udp_ports.find(port) != udp_ports.end())); }
  bool isProtectedPort(u_int16_t port);
  inline bool isBlacklistedIPv4(struct in_addr *addr)     { return(blacklists.isBlacklistedIPv4(addr)) ;}
  inline bool isBlacklistedIPv6(struct in6_addr *addr6)   { return(blacklists.isBlacklistedIPv6(addr6));}
  inline void loadIPsetFromURL(const char* url)  { blacklists.loadIPsetFromURL(url);}
};


#endif /* _CONFIG_H_ */
