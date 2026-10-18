/*
 *
 * (C) 2021-26 - ntop.org
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

#define TOO_MANY_INVALID_ATTEMPTS    3
#define NUM_PURGE_LOOP             300

/* #define DEBUG */

#ifdef __linux__
/* Forward */
int netfilter_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		       struct nfq_data *nfa, void *data);
#endif

/* **************************************************** */

NwInterface::NwInterface(u_int nf_device_id,
			 Configuration *_c,
			 GeoIP *_g, std::string c_path) {
  conf = _c, geoip = _g, confPath = c_path;
  reloaderThread = NULL;
  ifaceRunning = false;

  fw = NULL;

#ifdef __linux__
  fw = new LinuxFirewall();
#else
#if defined __FreeBSD__
  fw = new FreeBSDFirewall();
#endif
#endif

  if(fw) fw->setup();

#ifdef __linux__
  queueId = nf_device_id, nfHandle = nfq_open();

  if(nfHandle == NULL) {
    trace->traceEvent(TRACE_ERROR, "Unable to get netfilter handle [queueId=%d]", queueId);
    throw 1;
  }

  if(nfq_unbind_pf(nfHandle, AF_INET) < 0) {
    trace->traceEvent(TRACE_ERROR, "Unable to unbind [queueId=%d]: are you root ?", queueId);
    throw 1;
  }

  if(nfq_bind_pf(nfHandle, AF_INET) < 0) {
    trace->traceEvent(TRACE_ERROR, "Unable to bind [queueId=%d]", queueId);
    throw 1;
  }

  if((queueHandle = nfq_create_queue(nfHandle, queueId, &netfilter_callback, this)) == NULL) {
    trace->traceEvent(TRACE_ERROR, "Unable to attach to NF_QUEUE %d: is it already in use?", queueId);
    throw 1;
  } else
    trace->traceEvent(TRACE_NORMAL, "Successfully connected to NF_QUEUE %d", queueId);

#if !defined(__mips__)
  nfnl_rcvbufsiz(nfq_nfnlh(nfHandle), NF_BUFFER_SIZE);
#endif

  if(nfq_set_mode(queueHandle, NFQNL_COPY_PACKET, 0XFFFF) < 0) {
    trace->traceEvent(TRACE_ERROR, "Unable to set packet_copy mode");
    throw 1;
  }

  if(nfq_set_queue_maxlen(queueHandle, NF_MAX_QUEUE_LEN) < 0) {
    trace->traceEvent(TRACE_ERROR, "Unable to set queue len");
    throw 1;
  }

#ifdef NFQA_CFG_F_FAIL_OPEN
  /* When the queue is full accept packets instead of dropping them (i.e. never cut the host off) */
  if(nfq_set_queue_flags(queueHandle, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN) < 0)
    trace->traceEvent(TRACE_WARNING, "Unable to set NFQUEUE fail-open mode");
#endif

  nf_fd = nfq_fd(nfHandle);

  /* Not inherited by the commands (e.g. ban/unban) we spawn */
  fcntl(nf_fd, F_SETFD, FD_CLOEXEC);

#if defined(SOL_NETLINK) && defined(NETLINK_NO_ENOBUFS)
  {
    int one = 1;

    /* Don't report ENOBUFS when the socket buffer overflows: packets are lost anyway */
    setsockopt(nf_fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, sizeof(one));
  }
#endif
#endif

  if(!conf->getZMQUrl().empty()) {
    std::string url = conf->getZMQUrl();
    std::string enc = conf->getZMQEncryptionKey();
    zmq = new ZMQ(url.c_str(), enc.c_str());
  } else
    zmq = NULL;

  flush_ban();

  refreshLocalAddresses(0);
}

/* **************************************************** */

NwInterface::~NwInterface() {
#ifdef __linux__
  /*
    Detach from NFQUEUE first: the poll loop is over, so from now on
    nobody would issue verdicts and (with the queue still bound)
    all the host traffic would be stuck in the queue
  */
  nf_fd = 0;
  if(queueHandle) nfq_destroy_queue(queueHandle), queueHandle = NULL;
  if(nfHandle)    nfq_close(nfHandle), nfHandle = NULL;
#endif

#ifndef __linux__
  if(pcap_handle != NULL)
    pcap_close(pcap_handle);
#endif

  for(u_int i=0, s = watchers.size(); i < s; i++) {
    WatcherItam *item = watchers[i];

    delete item;
  }

  for(std::map<IPAddress, WatchMatches*>::iterator it = watches_blacklist.begin();
      it != watches_blacklist.end(); it++)
    delete it->second;

  /* Wait until the reload thread ends */
  if(reloaderThread) {
    reloaderThread->join();
    delete reloaderThread;
  }

  if(retiredConf) delete retiredConf.exchange(NULL);
  if(shadowConf)  delete shadowConf.exchange(NULL);

  flush_ban();

  logStartStop(false /* stop */);
  if(zmq) delete zmq;
  if(fw) {
    fw->tearDown();
    delete fw;
  }

  /*
    The interface owns the configuration (it can be replaced at runtime
    by reloadConfLoop): delete it last as its destructor flushes pending
    Telegram messages/commands such as the above stop notification
  */
  delete conf;
}

/* **************************************************** */

#ifdef __linux__
int netfilter_callback(struct nfq_q_handle *qh,
		       struct nfgenmsg *nfmsg,
		       struct nfq_data *nfa,
		       void *data) {
  const u_char *payload;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
  /* The HW address is readeable only at certain hook points and it is the source address */
  struct nfqnl_msg_packet_hw *hdr = nfq_get_packet_hw(nfa);
  NwInterface *iface = (NwInterface *)data;
  u_int payload_len;
  u_int32_t id = ph ? ntohl(ph->packet_id) : 0;
  u_int16_t marker;
  u_int8_t null_mac[6] = {0};

  if(!ph) return(-1);

#ifdef HAVE_NFQ_SET_VERDICT2
  payload_len = nfq_get_payload(nfa, (unsigned char **)&payload);
#else
  payload_len = nfq_get_payload(nfa, (char **)&payload);
#endif

  marker = iface->dissectPacket(hdr ? true : false, payload, payload_len).get();

  return(nfq_set_verdict2(qh, id, NF_ACCEPT, marker, 0, NULL));
}
#endif

/* **************************************************** */

bool NwInterface::startWatcher(std::string label, std::pair<std::string, bool> item) {
  WatcherItam *i = new WatcherItam();

  i->label = label;

  if(!i->start(item.first)) {
    trace->traceEvent(TRACE_ERROR, "Unable to run watch %s: %s", item.first.c_str(), strerror(errno));
    delete i;
    return(false);
  } else {
    i->mode = item.second;

    watchers.push_back(i);

    trace->traceEvent(TRACE_NORMAL, "Added watch %s [%s][pid %d]",
		      i->label.c_str(), i->cmd.c_str(), (int)i->pid);
    return(true);
  }
}

/* **************************************************** */

void NwInterface::packetPollLoop() {
  struct nfq_handle *h;
  int fd;
  u_int num_loops = 0;

  pthread_setname_np(pthread_self(), __FUNCTION__);

  watches = conf->get_watches();

  /* Start watches */
  for(std::map<std::string, std::pair<std::string, bool>>::iterator it = watches->begin(); it != watches->end(); it++) {
    std::pair<std::string, bool> item = it->second;

    startWatcher(it->first, item);
  }

  ifaceRunning = true;
  /* Spawn reload config thread in background, moved down here to avoid the mentioned issue */
  reloaderThread = new std::thread(&NwInterface::reloadConfLoop, this);
  logStartStop(true /* start */);

#ifdef __linux__
  h = get_nfHandle();
  fd = get_fd();
#else
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_handle = pcap_open_live(conf->getInterfaceName(), 1600, 0 /* promisc */, 1000, errbuf);

  if(pcap_handle == NULL) {
    trace->traceEvent(TRACE_ERROR, "Unable to open %s: %s",
		      conf->getInterfaceName(), errbuf);
    exit(1);
  } else
    pcap_handle_fileno = pcap_fileno(pcap_handle);
#endif

  while(isRunning()) {
    fd_set mask;
    struct timeval wait_time;
    int max_fd = fd, num, id;
    char pktBuf[65536] __attribute__ ((aligned));

    FD_ZERO(&mask);
    FD_SET(fd, &mask);

    for(u_int i=0, s = watchers.size(); i < s; i++) {
      int fd = watchers[i]->fd_fileno;

      FD_SET(fd, &mask);

      if(fd > max_fd)
	max_fd = fd;
    }

#ifndef __linux__
    if(pcap_handle_fileno != -1) {
      FD_SET(pcap_handle_fileno, &mask);

      if(pcap_handle_fileno > max_fd)
	max_fd = pcap_handle_fileno;
    }
#endif

    wait_time.tv_sec = 1, wait_time.tv_usec = 0;
    id = num = select(max_fd+1, &mask, 0, 0, &wait_time);

    num_loops++;

    if(num > 0) {
      int to_remove = -1;

#ifdef __linux__
      if(FD_ISSET(fd, &mask)) {
	/* Socket data */
	int len = recv(fd, pktBuf, sizeof(pktBuf), 0);

	// trace->traceEvent(TRACE_INFO, "Pkt len %d", len);

	if(len >= 0) {
	  int rc = nfq_handle_packet(h, pktBuf, len);

	  if(rc < 0)
	    trace->traceEvent(TRACE_ERROR, "nfq_handle_packet() failed: [len: %d][rc: %d][errno: %d]", len, rc, errno);
	} else if((errno == ENOBUFS) || (errno == EINTR) || (errno == EAGAIN)) {
	  /* Transient (e.g. ENOBUFS = packets lost under load): keep going */
	  trace->traceEvent(TRACE_WARNING, "NF_QUEUE receive error: [len: %d][errno: %d/%s]",
			    len, errno, strerror(errno));
	} else {
	  trace->traceEvent(TRACE_ERROR, "NF_QUEUE receive error: [len: %d][errno: %d/%s]",
			    len, errno, strerror(errno));
	  break;
	}

	num--;
      }
#endif

      /* Watches */
      for(u_int i=0, s = watchers.size(); i < s; i++) {
	if(FD_ISSET(watchers[i]->fd_fileno, &mask)) {
	  char ip[64];
	  bool data_read = false;

	  while(fgets(ip, sizeof(ip), watchers[i]->fd) != NULL) {
	    char ip_country[3]={}, ip_continent[3]={};
	    IPAddress addr;

	    data_read = true;

#ifdef DEBUG
	    trace->traceEvent(TRACE_ERROR, "Watch %s received %s", watchers[i]->label.c_str(), ip);
#endif
	    ip[strcspn(ip, "\r\n")] = '\0'; /* Zap trailing \n before validating */

	    if(addr.set(ip) /* Valid numeric IP */) {
	      geoip->lookup(&addr, ip_country, sizeof(ip_country), ip_continent, sizeof(ip_continent));

	      if(watchers[i]->mode == true /* geo-ip */) {
		/*
		  In this case we need to check if the returned IP
		  has to be geographically banned or not
		*/

		if(conf->isBlacklisted(&addr))
		  ban(&addr, true, true, "ban-" + watchers[i]->label, ip_country);

		if(ip_country[0] != '\0') {
		  if(conf->getMarker(ip_country, ip_continent).get() != conf->getMarkerPass().get())
		    ban(&addr, true, true, "ban-" + watchers[i]->label, ip_country);
		}
	      } else {
		/* In this case the IP has to be banned immediately */
		ban(&addr, true, true, "ban-" + watchers[i]->label, ip_country);
	      }
	    }
	  } /* while */

	  if(!data_read) {
	    /*
	      The file descriptor has been closed
	      (e.g. the application started with the pipe has died)
	    */
	    to_remove = i;
	  }
	}
      } /* for */

      if(to_remove != -1) {
	trace->traceEvent(TRACE_WARNING, "Watcher %d [%s] terminated",
			  to_remove, watchers[to_remove]->label.c_str());
	delete watchers[to_remove]; /* Reap the process(es) */
	watchers.erase(watchers.begin() + to_remove);
      }

#ifndef __linux__
	if(FD_ISSET(pcap_handle_fileno, &mask)) {
	  struct pcap_pkthdr hdr;
	  const u_char *packet = pcap_next(pcap_handle, &hdr);

	  if(packet != NULL) {
	    struct ndpi_ethhdr *e = (struct ndpi_ethhdr*)packet;
	    u_int16_t l3_proto = ntohs(e->h_proto);

	    if((l3_proto == ETHERTYPE_IP) || (l3_proto == ETHERTYPE_IPV6)) {
	      /* IPv4 or IPv6 */
	      u_int16_t marker = dissectPacket(true, &packet[sizeof(ndpi_ethhdr)],
					       hdr.caplen - sizeof(ndpi_ethhdr)).get();

	      if(marker == conf->getMarkerDrop().get()) {
		/* Eventually do an action */
	      }
	    }
	  }
	}
#endif
    }

    if((id == 0) || (num_loops > NUM_PURGE_LOOP)) {
      harvestWatches();
      num_loops = 0;
    }

    if((shadowConf != NULL) && (retiredConf == NULL)) {
      /*
	Swap configurations. The old one is deleted by the reloader thread:
	its destructor joins the Telegram/command threads that may need the
	network, i.e. this thread serving NFQUEUE (deleting it here = deadlock)
      */
      retiredConf = conf;
      conf = shadowConf.exchange(NULL);

      trace->traceEvent(TRACE_NORMAL, "New configuration has been updated");
    }
  } /* while */

  trace->traceEvent(TRACE_NORMAL, "Leaving packet poll loop");

  ifaceRunning = false;
}

/* **************************************************** */

Marker NwInterface::dissectPacket(bool is_ingress_packet,
				  const u_char *payload, u_int payload_len) {
  /* We can see only IP addresses */
  u_int16_t ip_offset = 0;
  struct ndpi_iphdr *iph = (struct ndpi_iphdr *)&payload[ip_offset];
  struct ndpi_tcphdr *tcph = NULL;
  struct ndpi_udphdr *udph = NULL;
  u_int16_t src_port, dst_port;
  u_int8_t proto, ip_payload_offset = 40 /* ipv6 is 40B long */;
  IPAddress src, dst;
  u_int16_t tcp_header_len;

  if(iph->version == 6) {
    struct ndpi_ipv6hdr *ip6h = (struct ndpi_ipv6hdr *)&payload[ip_offset];

    proto = ip6h->ip6_hdr.ip6_un1_nxt;
    src.setIPv6(&ip6h->ip6_src), dst.setIPv6(&ip6h->ip6_dst);
  } else if(iph->version == 4) {
    u_int8_t frag_off = ntohs(iph->frag_off);

    if((iph->protocol == IPPROTO_UDP) && ((frag_off & 0x3FFF /* IP_MF | IP_OFFSET */) != 0))
      return(conf->getMarkerUnknown()); /* Don't block it */

    // get protocol and offset
    proto = iph->protocol;
    ip_payload_offset = iph->ihl * 4;
    src.setIPv4(iph->saddr), dst.setIPv4(iph->daddr);
  } else { // Neither ipv4 or ipv6...unlikely to be evaluated
    return(conf->getMarkerPass());
  }

  u_int8_t *nxt = ((u_int8_t *)iph + ip_payload_offset);
  u_int16_t offset = ip_offset + ip_payload_offset;
    
  switch (proto) {
  case IPPROTO_TCP:
    if((offset+sizeof(struct ndpi_tcphdr)) < payload_len) {
      tcph = (struct ndpi_tcphdr *)(nxt);
      src_port = tcph->source, dst_port = tcph->dest;

      tcp_header_len = tcph->doff * 4;
      if(payload_len >= (ip_payload_offset + tcp_header_len)) {
	if(tcp_header_len >= sizeof(struct ndpi_tcphdr)) {
	  u_int8_t *t = (u_int8_t*)tcph;
	  u_int8_t *options = (u_int8_t*)(&t[sizeof(struct ndpi_tcphdr)]);
	  u_int8_t options_len = tcp_header_len - sizeof(struct ndpi_tcphdr);
	  u_int16_t flags = ntohs(*((u_int16_t*)&t[12])) & 0xFFF;
	  u_int16_t syn_mask = TH_SYN | 0x40 /* TH_ECE */ | 0x80 /* TH_CWR */;

	  if((flags & syn_mask) && ((flags & TH_ACK) == 0)) {
	    if((options_len == 0) && (!isLocalAddress(&src))) {
	      char msg[256];
	      u_int16_t tcp_win = ntohs(tcph->window);
	      char src_country[3]={}, dst_country[3]={}, src_continent[3]={}, dst_continent[3]={} ;

	      /*
		Massive Internet scanner detected. Examples:
		- https://zmap.io
		- https://github.com/robertdavidgraham/masscan
	      */

	      if(tcp_win == 1024)
		snprintf(msg, sizeof(msg), "ban-massive-scanner-masscan");
	      else if(tcp_win == 65535)
		snprintf(msg, sizeof(msg), "ban-massive-scanner-zmap");
	      else
		snprintf(msg, sizeof(msg), "ban-massive-scanner [tcp_win %u]", tcp_win);

	      geoip->lookup(&src, src_country, sizeof(src_country), src_continent, sizeof(src_continent));
	      geoip->lookup(&dst, dst_country, sizeof(dst_country), dst_continent, sizeof(dst_continent));

	      /* Log + ban + drop */
	      logFlow("tcp-masscan", msg,
		      &src, src_port, src_country, src_continent, false,
		      &dst, dst_port, dst_country, dst_continent, false,
		      false /* drop */);

	      ban(&src, true /* ban */, true, msg, src_country);

	      /* trace->traceEvent(TRACE_ERROR, "*** %s (%s / %s)", msg, src, src_country); */

	      return(conf->getMarkerDrop()); /* Drop flow */
	    }
	  }
	}
      }
    } else
      return(conf->getMarkerUnknown()); /* Don't block it */
    break;

  case IPPROTO_UDP:
    if((offset+sizeof(struct ndpi_udphdr)) < payload_len) {
      udph = (struct ndpi_udphdr *)(nxt);
      src_port = udph->source, dst_port = udph->dest;
    } else
      return(conf->getMarkerUnknown()); /* Don't block it */
    break;

  default:
    // we do not care about ports in other protocols
    src_port = dst_port = 0;
  }

  return(makeVerdict(is_ingress_packet, proto,
		     src_port, dst_port,
		     &src, &dst));
}

/* **************************************************** */

const char* NwInterface::getProtoName(u_int8_t proto) {
  switch(proto) {
  case IPPROTO_TCP:  return("TCP");
  case IPPROTO_UDP:  return("UDP");
  case IPPROTO_ICMP: return("ICMP");
  default:           return("???");
  }
}

/* **************************************************** */

bool NwInterface::isPrivateIPv4(u_int32_t addr /* network byte order */) {
  addr = ntohl(addr);

  if(((addr & 0xFF000000) == 0x0A000000 /* 10.0.0.0/8 */)
     || ((addr & 0xFFF00000) == 0xAC100000 /* 172.16.0.0/12 */)
     || ((addr & 0xFFFF0000) == 0xC0A80000 /* 192.168.0.0/16 */)
     || ((addr & 0xFF000000) == 0x7F000000 /* 127.0.0.0/8 */)
     || ((addr & 0xFFFF0000) == 0xA9FE0000 /* 169.254.0.0/16 Link-Local communication rfc3927 */)
     )
    return(true);
  else
    return(false);
}

/* **************************************************** */

bool NwInterface::isBroadMulticastIPv4(u_int32_t addr /* network byte order */) {
  addr = ntohl(addr);

  if((addr == 0xFFFFFFFF /* 255.255.255.255 */)
     || (addr == 0x0        /* 0.0.0.0 */)
     || ((addr & 0xF0000000) == 0xE0000000 /* 224.0.0.0/4 */))
    return(true);
  else
    return(false);
}

/* **************************************************** */

bool NwInterface::isPrivateIPv6(struct ndpi_in6_addr addr) {
  bool is_link_local, is_unique_local;
  u_int32_t first_byte = ntohl(addr.u6_addr.u6_addr32[0]);

  is_link_local   = (first_byte & (0xffc00000)) == (0xfe800000); // check the first 10 bits
  is_unique_local = (first_byte & (0xfe000000)) == (0xfc000000); // check the first 7 bits

  return(is_unique_local || is_link_local);
}

/* **************************************************** */

/* Reload the addresses of this host if older than max_age seconds */
void NwInterface::refreshLocalAddresses(u_int max_age) {
  time_t now = time(NULL);
  struct ifaddrs *ifap, *ifa;
  std::set<IPAddress> addresses;

  if((max_age != 0)
     && (local_addresses_refresh_time != 0)
     && ((now - local_addresses_refresh_time) < (time_t)max_age))
    return;

  local_addresses_refresh_time = now;

  if(getifaddrs(&ifap) != 0) {
    /* Keep the previous addresses */
    trace->traceEvent(TRACE_WARNING, "Unable to read the host addresses: %s", strerror(errno));
    return;
  }

  for(ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
    IPAddress a;
    char buf[64];
    
    if(ifa->ifa_addr == NULL)
      continue;

    if(ifa->ifa_addr->sa_family == AF_INET)
      a.setIPv4(((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr);
    else if(ifa->ifa_addr->sa_family == AF_INET6)
      a.setIPv6(&((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr);
    else
      continue;

    trace->traceEvent(TRACE_NORMAL, "Local IP found: %s", a.toString(buf, sizeof(buf)));
    
    addresses.insert(a);
  }

  freeifaddrs(ifap);

  local_addresses.swap(addresses);
}

/* **************************************************** */

/*
  Return true if ip is an address of this host (including loopback).
  Addresses can change (e.g. DHCP): they are reloaded every 30 sec, or
  at most once a second when fresh is set (i.e. before banning a host)
*/
bool NwInterface::isLocalAddress(IPAddress *ip, bool fresh) {
  u_int32_t v4;

#ifdef PERIODIC_IP_RELOAD
  refreshLocalAddresses(fresh ? 1 : 30);
#endif
  
  if(ip->isIPv4())
    v4 = ip->getIPv4()->s_addr;
  else {
    struct in6_addr *a6 = ip->getIPv6();

    if(IN6_IS_ADDR_LOOPBACK(a6))
      return(true);

    if(!IN6_IS_ADDR_V4MAPPED(a6))
      return(local_addresses.find(*ip) != local_addresses.end());

    /* ::ffff:a.b.c.d */
    memcpy(&v4, &a6->s6_addr[12], 4);
  }

  if((ntohl(v4) & 0xFF000000) == 0x7F000000 /* 127.0.0.0/8 */)
    return(true);
  else {
    IPAddress a;

    a.setIPv4(v4);
    return(local_addresses.find(a) != local_addresses.end());
  }
}

/* **************************************************** */

void NwInterface::addCommonJSON(Json::Value *root) {
  (*root)["source"]["ip"]      = conf->getHostIP();
  (*root)["source"]["name"]    = conf->getHostName();
  (*root)["source"]["epoch"]   = (unsigned int)time(NULL);
  (*root)["source"]["version"] = std::string(PACKAGE_NAME) + std::string(" ") + std::string(IPT_RELEASE);
}

/* **************************************************** */

void NwInterface::logHostBan(char *host_ip,
			     bool ban_ip, bool ban_traffic,
			     std::string reason,
			     std::string country) {
  Json::Value root;
  std::string json_txt;
  Json::FastWriter writer;

  addCommonJSON(&root);
  root["reason"] = (reason.size() > 0) ? reason.c_str() : "watch-host-ban";
  root["host"]   = host_ip;
  if(!country.empty()) root["country"] = country.c_str();
  root["action"] = ban_ip ? "ban" : "unban";

  json_txt = writer.write(root);

  trace->traceEvent(TRACE_INFO, "%s", json_txt.c_str());
  
  if(zmq)
    zmq->sendMessage(ZMQ_TOPIC_NAME, json_txt.c_str());

  sendTelegramMessage(json_txt);

  if(!conf->getCmd(ban_ip).empty()) {
    std::string cmd = conf->getCmd(ban_ip) + " " + host_ip;

    conf->execDeferredCmd(cmd);
  }
}

/* **************************************************** */

void NwInterface::logStartStop(bool start) {
  Json::Value root;
  std::string json_txt;
  Json::FastWriter writer;

  addCommonJSON(&root);
  root["action"] = start ? "start" : "stop";

  json_txt = writer.write(root);

  trace->traceEvent(TRACE_NORMAL, "%s", json_txt.c_str());

  if(zmq)
    zmq->sendMessage(ZMQ_TOPIC_NAME, json_txt.c_str());

  sendTelegramMessage(json_txt);
}

/* **************************************************** */

void NwInterface::logFlow(const char *proto_name, const char *sub_reason,
			  IPAddress *src_host, u_int16_t sport, char *src_country, char *src_continent, bool src_blacklisted,
			  IPAddress *dst_host, u_int16_t dport, char *dst_country, char *dst_continent, bool dst_blacklisted,
			  bool pass_verdict) {
  Json::Value root;
  std::string json_txt;
  Json::FastWriter writer;
  char src_buf[INET6_ADDRSTRLEN], dst_buf[INET6_ADDRSTRLEN];

  /* Nothing to do: the flow is neither traced (verbose only) nor exported via ZMQ (drops only) */
  if((trace->get_trace_level() < TRACE_LEVEL_INFO) && (pass_verdict || (zmq == NULL)))
    return;

  addCommonJSON(&root);
  root["reason"] = "flow-ban";
  root["sub_reason"] = sub_reason;
  root["proto"]  = proto_name;
  root["src"]["host"] = src_host->toString(src_buf, sizeof(src_buf));
  root["src"]["port"] = sport;
  if(src_country && (src_country[0] != '\0')) root["src"]["country"] = src_country;
  if(src_continent && (src_continent[0] != '\0')) root["src"]["continent"] = src_continent;
  if(src_blacklisted) root["src"]["blacklisted"] = src_blacklisted;

  root["dst"]["host"] = dst_host->toString(dst_buf, sizeof(dst_buf));
  root["dst"]["port"] = dport;
  if(dst_country && (dst_country[0] != '\0')) root["dst"]["country"] = dst_country;
  if(dst_continent && (dst_continent[0] != '\0')) root["dst"]["continent"] = dst_continent;
  if(dst_blacklisted) root["dst"]["blacklisted"] = dst_blacklisted;

  root["verdict"] = pass_verdict ? "pass" : "drop";

  json_txt = writer.write(root);

  if(pass_verdict)
    trace->traceEvent(TRACE_INFO, "%s", json_txt.c_str());
  else {
    trace->traceEvent(TRACE_INFO, "%s", json_txt.c_str());

    if(zmq)
      zmq->sendMessage(ZMQ_TOPIC_NAME, json_txt.c_str());

    // sendTelegramMessage(json_txt);
  }
}

/* **************************************************** */

Marker NwInterface::makeVerdict(bool is_ingress_packet, u_int8_t proto,
				u_int16_t sport /* network byte order */,
				u_int16_t dport /* network byte order */,
				IPAddress *src_host, IPAddress *dst_host) {
  char src_country[3]={}, dst_country[3]={}, src_continent[3]={}, dst_continent[3]={} ;
  const char *proto_name = getProtoName(proto);
  Marker m, src_marker, dst_marker;
  u_int16_t _dport = dport;
  bool drop = false, src_local, dst_local;

  sport = ntohs(sport), dport = ntohs(dport);

  geoip->lookup(src_host, src_country, sizeof(src_country), src_continent, sizeof(src_continent));
  geoip->lookup(dst_host, dst_country, sizeof(dst_country), dst_continent, sizeof(dst_continent));

  /*
    The addresses of this host are never blocked (e.g. because they are
    listed in a blacklist feed or geolocated in a blocked country)
  */
  src_local = isLocalAddress(src_host), dst_local = isLocalAddress(dst_host);

  /* ******************************************************* */

  /* Broadcast/multicast destination (e.g. for DHCP) traffic should pass */
  if(dst_host->isIPv4() && isBroadMulticastIPv4(dst_host->getIPv4()->s_addr))
    return(conf->getMarkerPass());

  /* For all ports/protocols, check if sender/recipient are white/black-listed and if so, pass/block this flow */
  if(conf->isWhitelisted(src_host))
    return(conf->getMarkerPass()); /* Whitelisted IP (src) */

  if((!src_local) && conf->isBlacklisted(src_host)) {
    logFlow(proto_name, "blacklisted-client",
	    src_host, sport, src_country, src_continent, true,
	    dst_host, dport, dst_country, dst_continent, false,
	    false /* drop */);

    ban(src_host, true /* ban */, true, "blacklisted-client", src_country);
    return(conf->getMarkerDrop());
  }

  if(conf->isWhitelisted(dst_host))
    return(conf->getMarkerPass()); /* Whitelisted IP (dst) */

  if((!dst_local) && conf->isBlacklisted(dst_host)) {
    logFlow(proto_name, "blacklisted-server",
	    src_host, sport, src_country, src_continent, false,
	    dst_host, dport, dst_country, dst_continent, true,
	    false /* drop */);

    ban(dst_host, true /* ban */, true, "blacklisted-server", dst_country);
    return(conf->getMarkerDrop());
  }

  /* ******************************************************* */

  /*
    Locally generated flow: only the (above) destination blacklist applies,
    as the checks below (honeypot, country) judge the client, i.e. this host
  */
  if(src_local)
    return(conf->getMarkerPass());

  /* ******************************************************* */

  /* Pass flows on ignored ports */
  if(conf->isIgnoredPort(sport) || conf->isIgnoredPort(dport)) {
    logFlow(proto_name, "whitelisted-ports",
	    src_host, sport, src_country, src_continent, false,
	    dst_host, dport, dst_country, dst_continent, false,
	    true /* pass */);

    return(conf->getMarkerPass());
  }

  /* ******************************************************* */

  /* Check honeypot ports and (eventually) ban host */
  if(is_ingress_packet && conf->isProtectedPort(dport)) {
    char str[128];

    logFlow(proto_name, "blacklisted-dst-port",
	    src_host, sport, src_country, src_continent, false,
	    dst_host, dport, dst_country, dst_continent, false,
	    false /* drop */);

    snprintf(str, sizeof(str), "ban-honeypot-%d", dport);

    ban(src_host, true /* ban */, true, str, src_country);
    return(conf->getMarkerDrop());
  }

  /* ******************************************************* */

  /* On TCP/UDP ignore traffic for non-monitored ports (country blacklists won't apply here) */
  switch(proto) {
  case IPPROTO_TCP:
    if((conf->isMonitoredTCPPort(sport)) || conf->isMonitoredTCPPort(dport))
      ;
    else {
      trace->traceEvent(TRACE_INFO, "Ignoring TCP ports %u/%u", sport, dport);
      return(conf->getMarkerPass());
    }
    break;

  case IPPROTO_UDP:
    if((conf->isMonitoredUDPPort(sport)) || conf->isMonitoredUDPPort(dport))
      ;
    else {
      trace->traceEvent(TRACE_INFO, "Ignoring UDP ports %u/%u", sport, dport);
      return(conf->getMarkerPass());
    }
    break;
  }

  /* ******************************************************* */

  m = src_marker = dst_marker = conf->getDefaultPolicy();

  /* For monitored TCP/UDP ports (and ICMP) check the country blacklist */
  if(src_country[0] != '\0') {
    src_marker = conf->getMarker(src_country, src_continent);
  } else {
    /* Unknown or private IP address  */
    src_marker = conf->getMarkerPass();
  }

  if(dst_country[0] != '\0') {
    dst_marker = conf->getMarker(dst_country, dst_continent);
  } else {
    /* Unknown or private IP address */
    dst_marker = conf->getMarkerPass();
  }

  /* Final step: compute the flow verdict */
  if((src_marker.get() == conf->getMarkerPass().get())
     /* We check only the client ignoring the server country that we're protecing */
     /* && (dst_marker.get() == conf->getMarkerPass().get()) */
     ) {
    m = conf->getMarkerPass();

    logFlow(proto_name, "allowed-flow",
	    src_host, sport, src_country, src_continent, false,
	    dst_host, dport, dst_country, dst_continent, false,
	    true /* pass */);
  } else {
    std::string msg = "ban-monitored-port-" + std::to_string(dport);

    m = conf->getMarkerDrop();

    logFlow(proto_name, msg.c_str(),
	    src_host, sport, src_country, src_continent, false,
	    dst_host, dport, dst_country, dst_continent, false,
	    false /* drop */);

    if((proto == IPPROTO_TCP) || (proto == IPPROTO_UDP)) /* Ignore non TCP/UDP */
      ban(src_host, true /* ban */, true, msg, src_country);
  }

  return(m);
}

/* **************************************************** */

u_int32_t NwInterface::computeNextReloadTime() {
  u_int32_t confReloadTimeout = 86400 /* once a day */;
  u_int32_t now = time(NULL);
  u_int32_t next_reload = now + confReloadTimeout;

  /* Align to the midnight */
  next_reload -= (next_reload % confReloadTimeout);

  return(next_reload);
}

/* **************************************************** */

void NwInterface::reloadConfLoop() {
  u_int32_t next_reload = computeNextReloadTime();

  pthread_setname_np(pthread_self(), __FUNCTION__);

  trace->traceEvent(TRACE_NORMAL, "Starting reload configuration loop");

  while(isRunning()) {
    u_int32_t now = time(NULL);
    Configuration *old = retiredConf.load();

    if(old != NULL) {
      /* Might take a while (pending Telegram messages/commands) */
      delete old;
      retiredConf = NULL;
      trace->traceEvent(TRACE_NORMAL, "Old configuration has been deleted");
    }

    if(now > next_reload) {
      trace->traceEvent(TRACE_NORMAL, "Reloading config file");

      if(shadowConf != NULL) {
	/* Too early */
	trace->traceEvent(TRACE_WARNING, "An existing configuration is already available: trying again");
	next_reload = now + 300; /* 5 mins */
      } else {
	Configuration *newConf = new Configuration();

	newConf->readConfigFile(this->confPath.c_str());

	if(newConf->isConfigured()) {
	  shadowConf = newConf;
	}
	else
	  trace->traceEvent(TRACE_ERROR, "Something went wrong: please check the JSON config file");

	next_reload = computeNextReloadTime();
      }
    } else {
      // trace->traceEvent(TRACE_INFO, "Will reload in %u sec", next_reload-now);

      /* Important: make a short nap as we need to exit this thread during shutdown */
      sleep(1); /* Too early */
    }
  } /* while */

  trace->traceEvent(TRACE_NORMAL, "Reload configuration loop is over");
}

/* **************************************************** */

void NwInterface::harvestWatches() {
  u_int32_t now = time(NULL);

#ifdef DEBUG
  trace->traceEvent(TRACE_NORMAL, "NwInterface::harvestWatches()");
#endif

  for(std::map<IPAddress, WatchMatches*>::iterator it = watches_blacklist.begin();
      it != watches_blacklist.end();) {
    WatchMatches *match = it->second;

    if(match->ready_to_unban(now)) {
      /* Ban expired: unban the host but keep its history */
      IPAddress host = it->first;

      ban(&host, false /* unban */, false, "unban", "");
      match->unban();
      ++it;
    } else if(match->ready_to_forget(now)) {
      /* Not banned for BAN_MEMORY_TIME: forget it */
      delete match;
      watches_blacklist.erase(it++);
    } else
      ++it;
  }
}

/* **************************************************** */

void NwInterface::ban(IPAddress *host, bool ban_ip,
		      bool ban_traffic, std::string reason, std::string country) {
  char buf[INET6_ADDRSTRLEN];
  char ip_buf[64];
  bool is_ipv4 = host->isIPv4();
  std::map<IPAddress, WatchMatches*>::iterator it;

  if(ban_ip && isLocalAddress(host, true /* fresh */)) {
    trace->traceEvent(TRACE_WARNING, "Not banning %s [%s]: it is an address of this host",
		      host->toString(buf, sizeof(buf)), reason.c_str());
    return;
  }

#if 0
  trace->traceEvent(TRACE_NORMAL, "%s banning %s [%s]",
		    ban_ip ? "BAN" : "UNBAN",
		    host->toString(ip_buf, sizeof(ip_buf)),
		    reason.c_str());
#endif
  
  it = watches_blacklist.find(*host);

  if(ban_ip) {
    /* Ban */
    u_int32_t now = time(NULL);

    if(it == watches_blacklist.end()) {
      /* New ban */
      try {
	WatchMatches *watch = new WatchMatches(now);

	host->toString(buf, sizeof(buf));
	trace->traceEvent(TRACE_INFO, "First time (until: %u) banning %s [%s]",
			  watch->get_banned_until(), buf, reason.c_str());
	watches_blacklist[*host] = watch;
	if(fw) fw->ban(buf, is_ipv4);
	logHostBan(buf, ban_ip, ban_traffic, reason, country);
      } catch(std::bad_alloc& ex) {
	trace->traceEvent(TRACE_WARNING, "Not enough memory");
      }
    } else {
      WatchMatches *watch = it->second;
      bool was_banned = watch->is_banned();
      u_int32_t until_time;

      if(!watch->offence(now))
	return; /* Banned and already counted less than MIN_MATCH_INTERVAL ago */

      until_time = watch->ban(now);

      if(was_banned) {
	/*
	  Host still banned: just extend the ban. Do NOT call fw->ban() here:
	  the rule is already there, and this path can run for many packets
	  of a banned host (fork/exec'ing iptables would stall the poll loop)
	*/
	if(trace->get_trace_level() >= TRACE_LEVEL_INFO)
	  trace->traceEvent(TRACE_INFO, "Recurrent (times: %u/until: %u) time banning %s [%s]",
			    watch->get_num_matches(), until_time,
			    host->toString(buf, sizeof(buf)), reason.c_str());
      } else {
	/* Previously banned host (ban expired) misbehaving again */
	host->toString(buf, sizeof(buf));
	trace->traceEvent(TRACE_INFO, "Banning again (times: %u/until: %u) %s [%s]",
			  watch->get_num_matches(), until_time, buf, reason.c_str());
	if(fw) fw->ban(buf, is_ipv4);
	logHostBan(buf, ban_ip, ban_traffic, reason, country);
      }
    }
  } else {
    /* Unban */

    host->toString(buf, sizeof(buf));
    if(fw) fw->unban(buf, is_ipv4);
    logHostBan(buf, ban_ip, ban_traffic, reason, country);
  }
}

/* **************************************************** */

void NwInterface::flush_ban() {
  try {
#ifdef __linux__
    Utils::execCmd("/usr/sbin/iptables  -w -t raw -F IPT_GEOFENCE_BLACKLIST", trace);
    Utils::execCmd("/usr/sbin/ip6tables -w -t raw -F IPT_GEOFENCE_BLACKLIST", trace);
#endif
  } catch (...) {
    trace->traceEvent(TRACE_ERROR, "Error while flushing blacklists");
  }
}

/* **************************************************** */

int NwInterface::sendTelegramMessage(std::string message) {
  return(conf->sendTelegramMessage(message));
}
