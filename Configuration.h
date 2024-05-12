/*
 *
 * (C) 2021-23 - ntop.org
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
  std::unordered_map<std::string /* name */, std::pair<std::string /* cmd */, bool /* true=geo-ip, false=block IP */> > watches;
  unsigned int nfq_queue_id;
  Marker marker_unknown;
  Marker marker_pass;
  Marker marker_drop;
  Marker default_policy;
  Lists blacklists, whitelists;
  std::string host_ip, host_name;
  std::string cmd_ban, cmd_unban;
  std::string telegram_bot_token, telegram_chat_id;
  bool configured, all_tcp_ports, all_udp_ports;
  std::string zmq_encryption_key, zmq_url;
  std::thread *telegramThread, *cmdThread;
  std::mutex telegram_queue_lock, cmd_queue_lock;
  std::queue<std::string> telegram_queue, cmd_queue;
  std::set<port_range> hp_ranges;
  bool running;
#if defined __FreeBSD__ || defined __APPLE__
  std::string ifname;
#endif
  
  u_int16_t ctry_cont2u16(char *country_code);
  bool mergePortRanges (port_range r1, port_range r2, port_range *ret);
  void addPortRange(port_range r);
  bool stringToU16(std::string s, u_int16_t *toRet);
  bool parsePortRange(std::string s, port_range *r);
  bool parseAllExcept(std::string s, u_int16_t *port);
  bool isIncludedInRange(u_int16_t port);
  void sendTelegramMessages();
  void executeCommands();
  
 public:
  Configuration();
  ~Configuration();

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

  inline void save()                                                                     { blacklists.save(); }
  inline void load(std::unordered_map<std::string, WatchMatches*>& watches_blacklist)  { blacklists.load(watches_blacklist); }
  inline void cleanAddresses()                                                                    { blacklists.cleanAddresses(); }

  inline bool isBlacklistedIPv4(struct in_addr *addr)               { return(blacklists.isListedIPv4(addr));  }
  inline bool isBlacklistedIPv6(struct in6_addr *addr6)             { return(blacklists.isListedIPv6(addr6)); }

  inline bool isWhitelistedIPv4(struct in_addr *addr)               { return(whitelists.isListedIPv4(addr));  }
  inline bool isWhitelistedIPv6(struct in6_addr *addr6)             { return(whitelists.isListedIPv6(addr6)); }

  inline std::unordered_map<std::string, std::pair<std::string, bool> >* get_watches()
                                                                    { return(&watches);                 }
  inline const char *getHostIP()                                    { return(host_ip.c_str());          }
  inline const char *getHostName()                                  { return(host_name.c_str());        }
  int sendTelegramMessage(std::string msg);
  void execDeferredCmd(std::string cmd);
  inline std::string getZMQUrl()                                    { return(zmq_url);                  }
  inline std::string getZMQEncryptionKey()                          { return(zmq_encryption_key);       }

#if defined __FreeBSD__ || defined __APPLE__
  void setInterfaceName(char *_ifname)                              { ifname.assign(_ifname);           }
  const char* getInterfaceName()                                    { return(ifname.c_str());           }
#endif

  inline std::string getCmd(bool ban_cmd)                           { return(ban_cmd ? cmd_ban : cmd_unban); }
};


#endif /* _CONFIG_H_ */
