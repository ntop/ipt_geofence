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

class NwInterface {
 private:
  int queueId;
  struct nfq_handle *nfHandle;
  struct nfq_q_handle *queueHandle;
  int nf_fd;
  pthread_t pollLoop;
  bool ifaceRunning; 
  Configuration *conf;
  GeoIP *geoip;
  
  Marker makeVerdict(u_int8_t proto, u_int16_t vlanId,
		     u_int32_t saddr, u_int16_t sport,
		     u_int32_t daddr, u_int16_t dport
         const char *src, const char *dst,
         bool ipv4, bool ipv6);
  const char* getProtoName(u_int8_t proto);
  bool isPrivateIPv4(u_int32_t addr /* network byte order */);
  bool isPrivateIPv6(const char *ip6addr);
  
 public:
  NwInterface(u_int nf_device_id, Configuration *_c, GeoIP *_g);
  ~NwInterface();

  inline int getQueueId()                       { return(queueId);                     };
  inline void stopPolling()                     { ifaceRunning = false;                };
  Marker dissectPacket(const u_char *payload, u_int payload_len);
  inline bool isRunning()                       { return(ifaceRunning);                };
  inline int get_fd()                           { return(nf_fd);                       };
  inline struct nfq_handle*   get_nfHandle()    { return(nfHandle);                    };
  inline struct nfq_q_handle* get_queueHandle() { return(queueHandle);                 };
  void packetPollLoop();
};

#endif /* _NETWORK_INTERFACE_H_ */

