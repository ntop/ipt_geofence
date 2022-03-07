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

/* ******************************* */

class Configuration {
 private:
  std::unordered_map<u_int16_t, Marker> countries;
  std::unordered_map<u_int16_t, bool>   tcp_ports, udp_ports, ignored_ports;
  Marker default_marker;
  Blacklists blacklists;
  unsigned int nfq_queue_id;
  bool configured, all_tcp_ports, all_udp_ports;
  
  u_int16_t country2u16(char *country_code);
  
 public:
  Configuration() { nfq_queue_id = 0, default_marker = MARKER_PASS; configured = false, all_tcp_ports = all_udp_ports = true; }

  bool readConfigFile(char *path);

  inline unsigned int getQueueId() { return(nfq_queue_id); }
  inline bool isConfigured()       { return(configured);   }
  
  inline void setQueueId(int nfq_id)                        { nfq_queue_id = nfq_id;  }
  inline void setCountryMarker(u_int16_t country, Marker m) { countries[country] = m; }
  inline Marker getDefaultMarker()                          { return(default_marker); }
  Marker getCountryMarker(char *country, char *continent);
  inline bool isIgnoredPort(u_int16_t port)      { return(ignored_ports.find(port) != ignored_ports.end());            }
  inline bool isMonitoredTCPPort(u_int16_t port) { return(all_tcp_ports || (tcp_ports.find(port) != tcp_ports.end())); }
  inline bool isMonitoredUDPPort(u_int16_t port) { return(all_udp_ports || (udp_ports.find(port) != udp_ports.end())); }
  inline bool isBlacklistedIPv4(struct in_addr *addr)                   {  return(blacklists.isBlacklistedIPv4(addr)); }
  inline bool isBlacklistedIPv6(struct in6_addr *addr6)                 { return(blacklists.isBlacklistedIPv6(addr6)); }
  
};


#endif /* _CONFIG_H_ */
