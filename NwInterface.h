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

#ifndef _NETWORK_INTERFACE_H_
#define _NETWORK_INTERFACE_H_

/* ********************************************** */

typedef std::list<std::string>::iterator list_it;

class NwInterface {
 private:
#ifdef __linux__
  int queueId;
  struct nfq_handle *nfHandle;
  struct nfq_q_handle *queueHandle;
  int nf_fd;
#endif
  Firewall *fw;
  pthread_t pollLoop;
  bool ifaceRunning;
  Configuration *conf, *shadowConf = NULL;
  GeoIP *geoip;
  std::thread *reloaderThread;
  double banTimeout = 900.0; // 15 minutes
  std::unordered_map<std::string, WatchMatches*> watches_blacklist;
  std::string confPath;
  ZMQ *zmq;
#ifndef __linux__
  pcap_t *pcap_handle;
  int pcap_handle_fileno;
#endif
  std::unordered_map<std::string, std::pair<std::string,bool> > *watches;
  std::vector<FILE*> pipes;
  std::vector<std::pair<int, std::string>> pipes_fileno;
  
  Marker makeVerdict(u_int8_t proto, u_int16_t vlanId,
		     u_int16_t sport,
		     u_int16_t dport,
         char *src, char *dst,
         bool ipv4, bool ipv6);
  const char* getProtoName(u_int8_t proto);
  void logFlow(const char *proto_name,
	       char *src_host, u_int16_t sport, char *src_country, char *src_continent, bool src_blacklisted,
	       char *dst_host, u_int16_t dport, char *dst_country, char *dst_continent, bool dst_blacklisted,
	       bool pass_verdict);
  void logHostBan(char *host_ip, bool ban_ip, std::string reason, std::string country);
  
  bool isPrivateIPv4(u_int32_t addr /* network byte order */);
  bool isPrivateIPv6(struct ndpi_in6_addr ip6addr);
  bool isBroadMulticastIPv4(u_int32_t addr /* network byte order */);
  void reloadConfLoop();
  u_int32_t computeNextReloadTime();
  bool isBanned(char *host, struct in_addr *a4, struct ndpi_in6_addr *a6);
  void harvestWatches();
  char* intoaV4(unsigned int addr, char* buf, u_short bufLen);
  char* intoaV6(struct ndpi_ndpi_in6_addr ipv6, u_int8_t bitmask, char* buf, u_short bufLen);
  void ban(char *host, bool ban_ip, std::string reason, std::string country);
  void ban_ipv4(u_int32_t ip4 /* network byte order */, bool ban_ip, std::string reason, std::string country);
  void ban_ipv6(struct ndpi_in6_addr ipv6, bool ban_ip, std::string reason, std::string country);
  std::string execCmd(const char* cmd);
  void addCommonJSON(Json::Value *root);
  void logStartStop(bool start);
  int sendTelegramMessage(std::string message);
  
 public:
  NwInterface(u_int nf_device_id, Configuration *_c, GeoIP *_g, std::string c_path);
  ~NwInterface();

#ifdef __linux__
  inline int getQueueId()                       { return(queueId);                     };
  inline int get_fd()                           { return(nf_fd);                       };
  inline struct nfq_handle*   get_nfHandle()    { return(nfHandle);                    };
  inline struct nfq_q_handle* get_queueHandle() { return(queueHandle);                 };
#endif
  
  inline void stopPolling()                     { ifaceRunning = false;                };
  Marker dissectPacket(const u_char *payload, u_int payload_len);
  inline bool isRunning()                       { return(ifaceRunning);                };
  void packetPollLoop();
  void flush_ban();
};

#endif /* _NETWORK_INTERFACE_H_ */
