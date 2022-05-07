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

#ifndef _NETWORK_INTERFACE_H_
#define _NETWORK_INTERFACE_H_

/* ********************************************** */

typedef std::list<std::string>::iterator list_it;

class NwInterface {
 private:
  int queueId;
  struct nfq_handle *nfHandle;
  struct nfq_q_handle *queueHandle;
  int nf_fd;
  pthread_t pollLoop;
  bool ifaceRunning;
  Configuration *conf, *shadowConf = NULL;
  GeoIP *geoip;
  std::thread *reloaderThread;
  std::list<std::string> honey_banned_timesorted;
  std::map<std::string, std::pair<time_t, list_it>> honey_banned_time;
  Blacklists honey_banned;
  double banTimeout = 900.0; // 15 minutes

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

  bool isPrivateIPv4(u_int32_t addr /* network byte order */);
  bool isPrivateIPv6(const char *ip6addr);
  void reloadConfLoop();
  u_int32_t computeNextReloadTime();
  bool isBanned(char *host, struct in_addr *a4, struct in6_addr *a6);
  void honeyHarvesting(int n);

 public:
  NwInterface(u_int nf_device_id, Configuration *_c, GeoIP *_g, std::string c_path);
  ~NwInterface();

  inline int getQueueId()                       { return(queueId);                     };
  inline void stopPolling()                     { ifaceRunning = false;                };
  Marker dissectPacket(const u_char *payload, u_int payload_len);
  inline bool isRunning()                       { return(ifaceRunning);                };
  inline int get_fd()                           { return(nf_fd);                       };
  inline struct nfq_handle*   get_nfHandle()    { return(nfHandle);                    };
  inline struct nfq_q_handle* get_queueHandle() { return(queueHandle);                 };
  void packetPollLoop();
  std::string confPath;
};

#endif /* _NETWORK_INTERFACE_H_ */
