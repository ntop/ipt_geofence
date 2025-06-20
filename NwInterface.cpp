/*
 *
 * (C) 2021-24 - ntop.org
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

  nf_fd = nfq_fd(nfHandle);
#endif

  if(!conf->getZMQUrl().empty()) {
    std::string url = conf->getZMQUrl();
    std::string enc = conf->getZMQEncryptionKey();
    zmq = new ZMQ(url.c_str(), enc.c_str());
  } else
    zmq = NULL;

  flush_ban();
}

/* **************************************************** */

NwInterface::~NwInterface() {
#ifndef __linux__
  if(pcap_handle != NULL)
    pcap_close(pcap_handle);
#endif

  for(u_int i=0, s = watchers.size(); i < s; i++) {
    WatcherItam *item = watchers[i];

    delete item;
  }
  
  for(std::map<std::string, WatchMatches*>::iterator it = watches_blacklist.begin();
      it != watches_blacklist.end(); it++)
    delete it->second;

  /* Wait until the reload thread ends */
  if(reloaderThread) {
    reloaderThread->join();
    delete reloaderThread;
  }

#ifdef __linux__
  nf_fd = 0;
#endif

  flush_ban();

#ifdef __linux__
  if(queueHandle) nfq_destroy_queue(queueHandle);
  if(nfHandle)    nfq_close(nfHandle);
#endif

  logStartStop(false /* stop */);
  if(zmq) delete zmq;
  if(fw)  delete fw;
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
  i->fd    = popen(item.first.c_str(), "r");
  
  if(i->fd == NULL) {
    trace->traceEvent(TRACE_ERROR, "Unable to run watch %s", item.first.c_str());
    return(false);
  } else {
    i->fd_fileno = fileno(i->fd);
    i->cmd = item.first;
    fcntl(i->fd_fileno, F_SETFL, O_NONBLOCK);
    i->mode = item.second;
    
    watchers.push_back(i);
    
    trace->traceEvent(TRACE_NORMAL, "Added watch %s [%s]", i->label.c_str(), i->cmd.c_str());
    return(true);
  }
}

/* **************************************************** */

void NwInterface::packetPollLoop() {
  struct nfq_handle *h;
  int fd;
  u_int num_loops = 0;

  pthread_setname_np(pthread_self(), __FUNCTION__);

  loadTemporarelyBannedHosts(conf->getDumpPath());

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
	} else {
	  trace->traceEvent(TRACE_ERROR, "NF_QUEUE receive error: [len: %d][errno: %d]", len, errno);
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

	    data_read = true;

#ifdef DEBUG
	    trace->traceEvent(TRACE_ERROR, "Watch %s received %s", watchers[i]->label.c_str(), ip);
#endif
	    ip[strlen(ip)-1] = '\0'; /* Zap trailing /n */
	    geoip->lookup(ip, ip_country, sizeof(ip_country), ip_continent, sizeof(ip_continent));

	    if(watchers[i]->mode == true /* geo-ip */) {
	      /*
		In this case we need to check if the returned IP
		has to be geographically banned or not
	      */

	      if(strchr(ip, ':') == NULL) {
		/* IPv4 */
		struct in_addr ip_addr;

		ip_addr.s_addr = inet_addr(ip);

		if(conf->isBlacklistedIPv4(&ip_addr))
		  ban(ip, true, true, "ban-" + watchers[i]->label, ip_country);
	      } else {
		/* IPv6 */
		struct in6_addr ip_addr;

		inet_pton(AF_INET6, ip, &ip_addr);

		if(conf->isBlacklistedIPv6(&ip_addr))
		  ban(ip, true, true, "ban-" + watchers[i]->label, ip_country);
	      }

	      if(ip_country[0] != '\0') {
		if(conf->getMarker(ip_country, ip_continent).get() != conf->getMarkerPass().get())
		  ban(ip, true, true, "ban-" + watchers[i]->label, ip_country);
	      }
	    } else {
	      /* In this case the IP has to be banned immediately */
	      ban(ip, true, true, "ban-" + watchers[i]->label, ip_country);
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

    if(shadowConf != NULL) {
      /* Swap configurations */

      delete conf;
      conf = shadowConf;
      shadowConf = NULL;

      trace->traceEvent(TRACE_NORMAL, "New configuration has been updated");
    }
  } /* while */

  saveTemporarelyBannedHosts(conf->getDumpPath());

  trace->traceEvent(TRACE_NORMAL, "Leaving packet poll loop");

  ifaceRunning = false;
}

/* **************************************************** */

Marker NwInterface::dissectPacket(bool is_ingress_packet,
				  const u_char *payload, u_int payload_len) {
  /* We can see only IP addresses */
  u_int16_t ip_offset = 0, vlan_id = 0 /* FIX */;

  if(payload_len >= ip_offset) {
    struct ndpi_iphdr *iph = (struct ndpi_iphdr *)&payload[ip_offset];
    bool ipv4 = false, ipv6 = false;
    struct ndpi_tcphdr *tcph = NULL;
    struct ndpi_udphdr *udph = NULL;
    u_int16_t src_port, dst_port;
    u_int8_t proto, ip_payload_offset = 40 /* ipv6 is 40B long */;
    char src[INET6_ADDRSTRLEN] = {}, dst[INET6_ADDRSTRLEN] = {};

    if(iph->version == 6) {
      struct ndpi_ipv6hdr *ip6h = (struct ndpi_ipv6hdr *)&payload[ip_offset];

      ipv6 = true;
      proto = ip6h->ip6_hdr.ip6_un1_nxt;

      // ipv6 address stringification
      inet_ntop(AF_INET6, &(ip6h->ip6_src), src, sizeof(src));
      inet_ntop(AF_INET6, &(ip6h->ip6_dst), dst, sizeof(dst));

      if (proto == IPPROTO_NONE) {
        /* Logging the mass scan packet detected */
        logFlow("MASS-SCAN",
          src, sport, 
          src_country, src_continent, false,
          dst, dport,
          dst_country, dst_continent, false,
          false); /* Drop */
        
        ban(src,
        true,   /* Ip address ban */
        true,   /* Traffic ban */
        "ban-massscan",
        src_country);

        return(conf->getMarkerDrop()); /* Drop packet from queue */
      }
    } else if(iph->version == 4) {
      ipv4 = true;
      u_int8_t frag_off = ntohs(iph->frag_off);
      struct in_addr a;

      if((iph->protocol == IPPROTO_UDP) && ((frag_off & 0x3FFF /* IP_MF | IP_OFFSET */) != 0))
        return(conf->getMarkerUnknown()); /* Don't block it */

      // get protocol and offset
      proto = iph->protocol;
      ip_payload_offset = iph->ihl * 4;
      // ipv4 address stringification
      a.s_addr = iph->saddr, inet_ntop(AF_INET, &a, src, sizeof(src));
      a.s_addr = iph->daddr, inet_ntop(AF_INET, &a, dst, sizeof(dst));

      if (proto == IPPROTO_IP) {
        /* Logging the mass scan packet detected */
        logFlow("MASS-SCAN",
          src,  sport,  src_country, src_continent, false,
          dst,  dport,  dst_country, dst_continent, false,
          false /* drop */);
        
        ban(src,
          true,   /* Ip address ban */
          true,   /* Traffic ban */
          "ban-massscan",
          src_country);
        
        return(conf->getMarkerDrop()); /* Drop packet from queue */
      }
    } else { // Neither ipv4 or ipv6...unlikely to be evaluated
      return(conf->getMarkerPass());
    }

    u_int8_t *nxt = ((u_int8_t *)iph + ip_payload_offset);

    switch (proto) {
    case IPPROTO_TCP:
      tcph = (struct ndpi_tcphdr *)(nxt);
      src_port = tcph->source, dst_port = tcph->dest;
      break;
    case IPPROTO_UDP:
      udph = (struct ndpi_udphdr *)(nxt);
      src_port = udph->source, dst_port = udph->dest;
      break;
    default:
      // we do not care about ports in other protocols
      src_port = dst_port = 0;
    }

    return(makeVerdict(is_ingress_packet,
		       proto, vlan_id,
		       src_port, dst_port,
		       src, dst, ipv4, ipv6));
  }

  return(conf->getMarkerPass());
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

#ifdef HAVE_NTOP_CLOUD
  if(cloud && ban_ip) {
    cloud->ban(host_ip,
	       ban_traffic ? bl_geofence_monitored_port : bl_geofence_watch,
	       (char*)reason.c_str(),
	       (char*)(ban_ip ? "ban" : "unban"),
	       (char*)country.c_str(),
	       (char*)conf->getHostIP(),
	       (char*)conf->getHostName(),
	       (char*)(std::string(PACKAGE_NAME) + std::string(" ") + std::string(IPT_RELEASE)).c_str());
  }
#endif
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

void NwInterface::logFlow(const char *proto_name,
			  char *src_host, u_int16_t sport, char *src_country, char *src_continent, bool src_blacklisted,
			  char *dst_host, u_int16_t dport, char *dst_country, char *dst_continent, bool dst_blacklisted,
			  bool pass_verdict) {
  Json::Value root;
  std::string json_txt;
  Json::FastWriter writer;

  addCommonJSON(&root);
  root["reason"] = "flow-ban";
  root["proto"]  = proto_name;
  root["src"]["host"] = src_host;
  root["src"]["port"] = sport;
  if(src_country && (src_country[0] != '\0')) root["src"]["country"] = src_country;
  if(src_continent && (src_continent[0] != '\0')) root["src"]["continent"] = src_continent;
  if(src_blacklisted) root["src"]["blacklisted"] = src_blacklisted;

  root["dst"]["host"] = dst_host;
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

Marker NwInterface::makeVerdict(bool is_ingress_packet,
				u_int8_t proto, u_int16_t vlanId,
				u_int16_t sport /* network byte order */,
				u_int16_t dport /* network byte order */,
				char *src_host, char *dst_host,
				bool ipv4, bool ipv6) {
  // Step 0 - Check ip protocol
  if(!(ipv4 || ipv6)) return(conf->getDefaultPolicy());

  struct in_addr in;
  char src_country[3]={}, dst_country[3]={}, src_continent[3]={}, dst_continent[3]={} ;
  const char *proto_name = getProtoName(proto);
  Marker m, src_marker, dst_marker;
  u_int16_t _dport = dport;
  bool drop = false;

  sport = ntohs(sport), dport = ntohs(dport);

  geoip->lookup(src_host, src_country, sizeof(src_country), src_continent, sizeof(src_continent));
  geoip->lookup(dst_host, dst_country, sizeof(dst_country), dst_continent, sizeof(dst_continent));

  /* ******************************************************* */

  /* Check if sender/recipient are blacklisted */
  if(ipv4) {
    u_int32_t saddr = inet_addr(src_host), daddr = inet_addr(dst_host);

    /* Broadcast source (e.g. for DHCP) traffic shoud paas */
    if(isBroadMulticastIPv4(daddr))
      return(conf->getMarkerPass());

    /* For all ports/protocols, check if sender/recipient are white/black-listed and if so, pass/block this flow */
    in.s_addr = saddr;
    if(conf->isWhitelistedIPv4(&in)) {
      return(conf->getMarkerPass()); /* Whitelisted IP (src) */
    }

    if(conf->isBlacklistedIPv4(&in)) {
      logFlow(proto_name,
	      src_host, sport, src_country, src_continent, true,
	      dst_host, dport, dst_country, dst_continent, false,
	      false /* drop */);

      // trace->traceEvent(TRACE_ERROR, "(1) %s <-> %s", src_host, dst_host);

      ban(src_host, true /* ban */, true, "blacklisted-client", src_country);
      return(conf->getMarkerDrop());
    }

    in.s_addr = daddr;
    if(conf->isWhitelistedIPv4(&in)) {
      return(conf->getMarkerPass()); /* Whitelisted IP (dst) */
    }

    if(conf->isBlacklistedIPv4(&in)) {
      logFlow(proto_name,
	      src_host, sport, src_country, src_continent, false,
	      dst_host, dport, dst_country, dst_continent, true,
	      false /* drop */);
      // trace->traceEvent(TRACE_ERROR, "(2) %s <-> %s", src_host, dst_host);

      ban(dst_host, true /* ban */, true, "blacklisted-server", dst_country);
      return(conf->getMarkerDrop());
    }

    // trace->traceEvent(TRACE_ERROR, "(3) %s <-> %s", src_host, dst_host);
  } else if(ipv6) {
    struct in6_addr a;

    inet_pton(AF_INET6, src_host, &a);

    if(conf->isBlacklistedIPv6(&a)) {
      logFlow(proto_name,
              src_host, sport, src_country, src_continent, true,
              dst_host, dport, dst_country, dst_continent, false,
              false /* drop */);

      ban(src_host, true /* ban */, true, "blacklisted-client", src_country);
      return(conf->getMarkerDrop());
    }

    inet_pton(AF_INET6, dst_host, &a);

    if(conf->isBlacklistedIPv6(&a)) {
      logFlow(proto_name,
              src_host, sport, src_country, src_continent, false,
              dst_host, dport, dst_country, dst_continent, true,
              false /* drop */);

      ban(dst_host, true /* ban */, true, "blacklisted-server", dst_country);
      return(conf->getMarkerDrop());
    }
  }

  /* ******************************************************* */

  /* Pass flows on ignored ports */
  if(conf->isIgnoredPort(sport) || conf->isIgnoredPort(dport)) {
    logFlow(proto_name,
	    src_host, sport, src_country, src_continent, false,
	    dst_host, dport, dst_country, dst_continent, false,
	    true /* pass */);

    return(conf->getMarkerPass());
  }

  /* ******************************************************* */

  /* Check honeypot ports and (eventually) ban host */
  if(is_ingress_packet && conf->isProtectedPort(dport)) {
    char str[128];

    logFlow(proto_name,
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
     && (dst_marker.get() == conf->getMarkerPass().get())) {
    m = conf->getMarkerPass();

    logFlow(proto_name,
	    src_host, sport, src_country, src_continent, false,
	    dst_host, dport, dst_country, dst_continent, false,
	    true /* pass */);
  } else {
    std::string msg = "ban-monitored-port-" + std::to_string(dport);

    m = conf->getMarkerDrop();

    logFlow(proto_name,
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

  shadowConf = NULL;

  pthread_setname_np(pthread_self(), __FUNCTION__);

  trace->traceEvent(TRACE_NORMAL, "Starting reload configuration loop");

  while(isRunning()) {
    u_int32_t now = time(NULL);

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
  u_int32_t when = time(NULL) - MAX_IDLENESS;

#ifdef DEBUG
  trace->traceEvent(TRACE_NORMAL, "NwInterface::harvestWatches()");
#endif

  for(std::map<std::string, WatchMatches*>::iterator it = watches_blacklist.begin();
      it != watches_blacklist.end();) {
    WatchMatches *match = it->second;

#ifdef DEBUG
    trace->traceEvent(TRACE_NORMAL, "last_match=%u / now=%u [to go: %d]",
		      match->get_last_match(), when, (match->get_last_match() - when));
#endif

    if(match->ready_to_harvest(when)) {
#ifdef DEBUG
      trace->traceEvent(TRACE_NORMAL, "Harvesting");
#endif
      ban((char*)it->first.c_str(), false /* unban */, false, "unban", "");
      delete it->second;
      watches_blacklist.erase(it++);    // or "it = m.erase(it)" since C++11
    } else
      ++it;
  }
}

/* **************************************************** */

void NwInterface::ban(char *host, bool ban_ip,
		      bool ban_traffic, std::string reason, std::string country) {
  char cmdbuf[128];
  bool is_ipv4 = (strchr(host, ':') == NULL) ? true /* IPv4 */ : false /* IPv6 */;
  std::map<std::string, WatchMatches*>::iterator it = watches_blacklist.find(std::string(host));

  // trace->traceEvent(TRACE_NORMAL, "*** %s ***", host);

  if(ban_ip) {
    /* Ban */

    if(it == watches_blacklist.end()) {
      /* New ban */
      try {
	u_int32_t until_time =  time(NULL) + DEFAULT_BAN_TIME;
	WatchMatches *watch = new WatchMatches(1, until_time);

	trace->traceEvent(TRACE_INFO, "First time (until: %u) banning %s [%s]",
			  until_time, host, reason.c_str());
	watches_blacklist[host] = watch;
	if(fw) fw->ban(host, is_ipv4);
	logHostBan(host, ban_ip, ban_traffic, reason, country);
      } catch(std::bad_alloc& ex) {
	trace->traceEvent(TRACE_WARNING, "Not enough memory");
      }
    } else {
      WatchMatches *watch = it->second;
      u_int32_t until_time;
      u_int32_t num_matches;

      /* Host already banned */
      watch->inc_matches();
      num_matches = watch->get_num_matches();
      until_time = time(NULL) + (DEFAULT_BAN_TIME * num_matches * num_matches);

      trace->traceEvent(TRACE_INFO, "Recurrent (times: %d/until: %u) time banning %s [%s]",
			watch->get_num_matches(), until_time,
			host, reason.c_str());

      watch->ban_until(until_time);
    }
  } else {
    /* Unban */

    if(fw) fw->unban(host, is_ipv4);
    logHostBan(host, ban_ip, ban_traffic, reason, country);
  }
}

/* **************************************************** */

void NwInterface::ban_ipv4(u_int32_t ip4 /* network byte order */, bool ban_ip,
			   std::string reason, std::string country) {
  char ipbuf[32], *host = Utils::intoaV4(ntohl(ip4), ipbuf, sizeof(ipbuf));

  ban(host, ban_ip, true, reason, country);
}

/* **************************************************** */

void NwInterface::ban_ipv6(struct ndpi_in6_addr ip6, bool ban_ip,
			   std::string reason, std::string country) {
  char ipbuf[64], *host = Utils::intoaV6(ip6, 128, ipbuf, sizeof(ipbuf));

  ban(host, ban_ip, true, reason, country);
}

/* **************************************************** */

void NwInterface::flush_ban() {
  try {
#ifdef __linux__
    Utils::execCmd("/usr/sbin/iptables  -F IPT_GEOFENCE_BLACKLIST", trace);
    Utils::execCmd("/usr/sbin/ip6tables -F IPT_GEOFENCE_BLACKLIST", trace);
#endif
  } catch (...) {
    trace->traceEvent(TRACE_ERROR, "Error while flushing blacklists");
  }
}

/* **************************************************** */

int NwInterface::sendTelegramMessage(std::string message) {
  return(conf->sendTelegramMessage(message));
}

/* ****************************************** */

bool NwInterface::loadTemporarelyBannedHosts(const char* path) {
  std::ifstream infile(path);
  std::string line;
  u_int32_t num_entries = 0;

  if(!infile.is_open()) {
    trace->traceEvent(TRACE_WARNING, "Unable to open file %s", path);
    return(false);
  }

  while(getline(infile, line)) {
    char item[256], *ip, *num_bans;

    if((line[0] == '#') || (line[0] == '\0'))
      continue;

    // trace->traceEvent(TRACE_INFO, "Adding %s", line.c_str());
    /* Format: IP\tnum_bans */

    snprintf(item, sizeof(item), "%s", line.c_str());
    ip = strtok(item, "\t");

    if(ip)
      num_bans = strtok(NULL, "\t");
    else
      num_bans = NULL;

    if(num_bans == NULL) {
      trace->traceEvent(TRACE_WARNING, "Skipping invalid line %s", line.c_str());
      continue;
    }

    try {
      WatchMatches *wm = new WatchMatches(atoi(num_bans), time(NULL) + DEFAULT_BAN_TIME);

      watches_blacklist[ip] = wm;
      num_entries++;
    } catch(std::bad_alloc& ex) {
      trace->traceEvent(TRACE_WARNING, "Not enough memory");
    }
  }

  trace->traceEvent(TRACE_NORMAL, "Loaded %u banned IPs to %s", num_entries, path);

  infile.close();

  return(true);
}

/* ****************************************** */

bool NwInterface::saveTemporarelyBannedHosts(const char* path){
  std::ofstream outfile(path);
  std::string line;
  u_int32_t num_entries = 0;

  if(!outfile.is_open()) {
    trace->traceEvent(TRACE_WARNING, "Unable to open file %s", path);
    return(false);
  }

  for(std::map<std::string, WatchMatches*>::iterator it = watches_blacklist.begin();
      it != watches_blacklist.end(); it++)
    outfile << it->first << "\t" << it->second->get_num_matches() << "\n", num_entries++;

  outfile.close();

  trace->traceEvent(TRACE_NORMAL, "Saved %u banned IPs to %s", num_entries, path);

  return(true);
}
