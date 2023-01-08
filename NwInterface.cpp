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

#define TOO_MANY_INVALID_ATTEMPTS   3

/* #define DEBUG */

/* Forward */
int netfilter_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		       struct nfq_data *nfa, void *data);

/* **************************************************** */

NwInterface::NwInterface(u_int nf_device_id,
			 Configuration *_c,
			 GeoIP *_g, std::string c_path) {
  conf = _c, geoip = _g, confPath = c_path;
  reloaderThread = NULL;
  ifaceRunning = false;
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
  /* Wait until the reload thread ends */
  if(reloaderThread) {
    reloaderThread->join();
    delete reloaderThread;
  }

  nf_fd = 0;

  flush_ban();
    
  if(queueHandle) nfq_destroy_queue(queueHandle);
  if(nfHandle)    nfq_close(nfHandle);

  logStartStop(false /* stop */);
  if(zmq)         delete zmq;
}

/* **************************************************** */

int netfilter_callback(struct nfq_q_handle *qh,
		       struct nfgenmsg *nfmsg,
		       struct nfq_data *nfa,
		       void *data) {
  const u_char *payload;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
  NwInterface *iface = (NwInterface *)data;
  u_int payload_len;
  u_int32_t id = ph ? ntohl(ph->packet_id) : 0;
  u_int16_t marker;

  if(!ph) return(-1);

#ifdef HAVE_NFQ_SET_VERDICT2
  payload_len = nfq_get_payload(nfa, (unsigned char **)&payload);
#else
  payload_len = nfq_get_payload(nfa, (char **)&payload);
#endif

  marker = iface->dissectPacket(payload, payload_len);

  return(nfq_set_verdict2(qh, id, NF_ACCEPT, marker, 0, NULL));
}

/* **************************************************** */

void NwInterface::packetPollLoop() {
  struct nfq_handle *h;
  int fd;
  std::unordered_map<std::string,std::string> *watches = conf->get_watches();
  std::vector<FILE*> pipes;
  std::vector<std::pair<int, std::string>> pipes_fileno;

  /* Spawn reload config thread in background */
  reloaderThread = new std::thread(&NwInterface::reloadConfLoop, this);

  /* Start watches */
  for(std::unordered_map<std::string,std::string>::iterator it = watches->begin(); it != watches->end(); it++) {
    FILE *watcher = popen(it->second.c_str(), "r");

    if(watcher == NULL) {
      trace->traceEvent(TRACE_ERROR, "Unable to run watch %s", it->first.c_str());
    } else {
      fd = fileno(watcher);

      pipes.push_back(watcher);
      fcntl(fd, F_SETFL, O_NONBLOCK);
      pipes_fileno.push_back(std::make_pair(fd, it->first));

      trace->traceEvent(TRACE_NORMAL, "Added watch %s [%s]", it->first.c_str(), it->second.c_str());
    }
  }

  ifaceRunning = true;
  logStartStop(true /* start */);

  h = get_nfHandle();
  fd = get_fd();

  while(isRunning()) {
    fd_set mask;
    struct timeval wait_time;
    int max_fd = fd, num;

    FD_ZERO(&mask);
    FD_SET(fd, &mask);

    for(u_int i=0, s = pipes_fileno.size(); i < s; i++) {
      int fd = pipes_fileno[i].first;
      
      FD_SET(fd, &mask);

      if(fd > max_fd)
	max_fd = fd;
    }

    wait_time.tv_sec = 1, wait_time.tv_usec = 0;

    num = select(max_fd+1, &mask, 0, 0, &wait_time);

    if(num > 0) {
      if(FD_ISSET(fd, &mask)) {
	/* Socket data */
	char pktBuf[8192] __attribute__ ((aligned));
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

      if(num > 0) {
	/* Watches */

	for(u_int i=0, s = pipes_fileno.size(); i < s; i++) {
	  if(FD_ISSET(pipes_fileno[i].first, &mask)) {
	    char ip[64];

	    while(fgets(ip, sizeof(ip), pipes[i]) != NULL) {
#ifdef DEBUG
	      trace->traceEvent(TRACE_ERROR, "Watch %s received %s", pipes_fileno[i].second, ip);
#endif
	      ip[strlen(ip)-1] = '\0'; /* Zap trailing /n */
	      ban(ip, true, "ban-" + pipes_fileno[i].second, "");	     
	    }
	  }
	}
      }
    } else {
      honeyHarvesting(10);
      harvestWatches();
    }

    if(shadowConf != NULL) {
      /* Swap configurations */

      delete conf;
      conf = shadowConf;
      shadowConf = NULL;

      trace->traceEvent(TRACE_NORMAL, "New configuration has been updated");
    }
  }

  for(u_int i=0, s = pipes.size(); i < s; i++)
    pclose(pipes[i]);

  for(std::unordered_map<std::string, WatchMatches*>::iterator it = watches_blacklist.begin();
      it != watches_blacklist.end(); it++)
    delete it->second;

  trace->traceEvent(TRACE_NORMAL, "Leaving netfilter packet poll loop");
  ifaceRunning = false;
}

/* **************************************************** */

Marker NwInterface::dissectPacket(const u_char *payload, u_int payload_len) {
  /* We can see only IP addresses */
  u_int16_t ip_offset = 0, vlan_id = 0 /* FIX */;

  if(payload_len >= ip_offset) {
    struct iphdr *iph = (struct iphdr *)&payload[ip_offset];
    bool ipv4 = false, ipv6 = false;

    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    u_int16_t src_port, dst_port;
    u_int8_t proto, ip_payload_offset = 40 /* ipv6 is 40B long */;
    char src[INET6_ADDRSTRLEN] = {}, dst[INET6_ADDRSTRLEN] = {};

    if(iph->version == 6) {
      ipv6 = true;
      struct ip6_hdr *ip6h = (struct ip6_hdr *)&payload[ip_offset];
      proto = ip6h->ip6_nxt;

      // ipv6 address stringification
      inet_ntop(AF_INET6, &(ip6h->ip6_src), src, sizeof(src));
      inet_ntop(AF_INET6, &(ip6h->ip6_dst), dst, sizeof(dst));

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
    } else { // Neither ipv4 or ipv6...unlikely to be evaluated
      return(conf->getMarkerPass());
    }

    u_int8_t *nxt = ((u_int8_t *)iph + ip_payload_offset);

    switch (proto) {
    case IPPROTO_TCP:
      tcph = (struct tcphdr *)(nxt);
      src_port = tcph->source, dst_port = tcph->dest;
      break;
    case IPPROTO_UDP:
      udph = (struct udphdr *)(nxt);
      src_port = udph->source, dst_port = udph->dest;
      break;
    default:
      // we do not care about ports in other protocols
      src_port = dst_port = 0;
    }

    return(makeVerdict(proto, vlan_id,
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

bool NwInterface::isPrivateIPv6(const char *ip6addr) {
  struct in6_addr a;
  inet_pton(AF_INET6,ip6addr,&a);

  // We use only the 32bit structure
  for(size_t l=0; l < 4; l++){ // change byte ordering
    a.s6_addr32[l] = ntohl(a.s6_addr32[l]);
  }

  bool is_link_local = (a.s6_addr32[0] & (0xffc00000)) == (0xfe800000); // check the first 10 bits
  bool is_unique_local = (a.s6_addr32[0] & (0xfe000000)) == (0xfc000000); // check the first 7 bits

  return is_unique_local || is_link_local;
}

/* **************************************************** */

void NwInterface::addCommonJSON(Json::Value *root) {
  (*root)["source"]["ip"]    = conf->getHostIP();
  (*root)["source"]["name"]  = conf->getHostName();
  (*root)["source"]["epoch"] = (unsigned int)time(NULL);
}

/* **************************************************** */

void NwInterface::logHostBan(char *host_ip, bool ban_ip, std::string reason, std::string country) {
  Json::Value root;
  std::string json_txt;
  Json::FastWriter writer;

  addCommonJSON(&root);
  root["reason"] = (reason.size() > 0) ? reason.c_str() : "watch-host-ban";
  root["host"]   = host_ip;
  if(!country.empty()) root["country"] = country.c_str();  
  root["action"] = ban_ip ? "ban" : "unban";

  json_txt = writer.write(root);

  trace->traceEvent(TRACE_NORMAL, "%s", json_txt.c_str());

  if(zmq)
    zmq->sendMessage(ZMQ_TOPIC_NAME, json_txt.c_str());

  sendTelegramMessage(json_txt);
}

/* **************************************************** */

void NwInterface::logStartStop(bool start) {
  Json::Value root;
  std::string json_txt;
  Json::FastWriter writer;

  addCommonJSON(&root);
  root["reason"] = start ? "start" : "stop";

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
    trace->traceEvent(TRACE_NORMAL, "%s", json_txt.c_str());

    if(zmq)
      zmq->sendMessage(ZMQ_TOPIC_NAME, json_txt.c_str());

    // sendTelegramMessage(json_txt);
  }
}

/* **************************************************** */

Marker NwInterface::makeVerdict(u_int8_t proto, u_int16_t vlanId,
				u_int16_t sport /* network byte order */,
				u_int16_t dport /* network byte order */,
				char *src_host, char *dst_host,
				bool ipv4, bool ipv6) {
  // Step 0 - Check ip protocol
  if(!(ipv4 || ipv6)) return(conf->getDefaultPolicy());

  struct in_addr in;
  char src_country[3]={}, dst_country[3]={}, src_cont[3]={}, dst_cont[3]={} ;
  const char *proto_name = getProtoName(proto);
  u_int32_t saddr = ipv4 ? inet_addr(src_host) : 0;
  u_int32_t daddr = ipv4 ? inet_addr(dst_host) : 0;
  bool saddr_private = (ipv4 ? isPrivateIPv4(saddr) : isPrivateIPv6(src_host));
  bool daddr_private = (ipv4 ? isPrivateIPv4(daddr) : isPrivateIPv6(dst_host));
  Marker m, src_marker, dst_marker;
  u_int16_t _dport = dport;
  bool drop = false;
  
  sport = ntohs(sport), dport = ntohs(dport);
 
  /* ******************************************************* */
  
  /* Check if sender/recipient are blacklisted */
  if(ipv4) {
    /* Broadcast source (e.g. for DHCP) traffic shoud paas */
    if(isBroadMulticastIPv4(daddr))
      return(conf->getMarkerPass());

    in.s_addr = saddr;
    
    /* For all ports/protocols, check if sender/recipient are blacklisted and if so, block this flow */
    if((!saddr_private) && (conf->isBlacklistedIPv4(&in) || isBanned(src_host, &in, NULL))) {
      logFlow(proto_name,
	      src_host, sport, src_country, src_cont, true,
	      dst_host, dport, dst_country, dst_cont, false,
	      false /* drop */);

      return(conf->getMarkerDrop());
    }

    in.s_addr = daddr;
    if((!daddr_private) && (conf->isBlacklistedIPv4(&in) || isBanned(dst_host, &in, NULL))) {
      logFlow(proto_name,
	      src_host, sport, src_country, src_cont, false,
	      dst_host, dport, dst_country, dst_cont, true,
	      false /* drop */);

      return(conf->getMarkerDrop());
    }
  } else if(ipv6) {
    struct in6_addr a;

    inet_pton(AF_INET6, src_host, &a);

    if((!saddr_private) && (conf->isBlacklistedIPv6(&a) || isBanned(src_host,NULL,&a))) {
      logFlow(proto_name,
              src_host, sport, src_country, src_cont, true,
              dst_host, dport, dst_country, dst_cont, false,
              false /* drop */);

      return(conf->getMarkerDrop());
    }

    inet_pton(AF_INET6, dst_host, &a);
    if((!daddr_private) && (conf->isBlacklistedIPv6(&a) || isBanned(dst_host,NULL,&a))) {
      logFlow(proto_name,
              src_host, sport, src_country, src_cont, false,
              dst_host, dport, dst_country, dst_cont, true,
              false /* drop */);

      return(conf->getMarkerDrop());
    }
  }

  /* ******************************************************* */
  
  /* Pass flows on ignored ports */
  if(conf->isIgnoredPort(sport) || conf->isIgnoredPort(dport)) {
    logFlow(proto_name,
	    src_host, sport, src_country, src_cont, false,
	    dst_host, dport, dst_country, dst_cont, false,
	    true /* pass */);

    return(conf->getMarkerPass());
  }

  /* ******************************************************* */
  
  /* Check honeypot ports and (eventually) ban host */
  if((!saddr_private) && conf->isProtectedPort(dport)) {
    drop = true, honey_banned.addAddress(src_host); // add banned host to patricia tree
    std::string h(src_host);  // string cast
    honey_banned_timesorted.push_back(h); // h is the "less older" banned host
    std::pair<time_t,list_it> map_value (time(NULL), std::prev(honey_banned_timesorted.end()));
    honey_banned_time[h] = map_value; // init/reset timer for src_host and keep track in list position

    trace->traceEvent(TRACE_INFO, "Banning host %s || Protected port %u", src_host, dport);
  }

  if(drop) {
    logFlow(proto_name,
	    src_host, sport, src_country, src_cont, false,
	    dst_host, dport, dst_country, dst_cont, false,
	    false /* drop */);

    ban(src_host, true /* ban */, "ban-honeypot", src_country);
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
  if((!saddr_private) && (geoip->lookup(src_host, src_country, sizeof(src_country), src_cont, sizeof(src_cont)))) {
    src_marker = conf->getMarker(src_country, src_cont);
  } else {
    /* Unknown or private IP address  */
    src_marker = conf->getMarkerPass();
  }

  if((!daddr_private) && (geoip->lookup(dst_host, dst_country, sizeof(dst_country), dst_cont, sizeof(dst_cont)))) {
    dst_marker = conf->getMarker(dst_country, dst_cont);
  } else {
    /* Unknown or private IP address */
    dst_marker = conf->getMarkerPass();
  }
  
  /* Final step: compute the flow verdict */
  if((src_marker == conf->getMarkerPass()) && (dst_marker == conf->getMarkerPass())) {
    m = conf->getMarkerPass();

    logFlow(proto_name,
	    src_host, sport, src_country, src_cont, false,
	    dst_host, dport, dst_country, dst_cont, false,
	    true /* pass */);
  } else {
    std::string msg = "ban-monitored-port-" + std::to_string(dport);
  
    m = conf->getMarkerDrop();

    logFlow(proto_name,
	    src_host, sport, src_country, src_cont, false,
	    dst_host, dport, dst_country, dst_cont, false,
	    false /* drop */);

    if((proto == IPPROTO_TCP) || (proto == IPPROTO_UDP)) /* Ignore non TCP/UDP */
      ban(src_host, true /* ban */, msg, src_country);
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

/**
 * @param host char* address representation
 * @note a4 and a6 shouldn't be both set
 */
bool NwInterface::isBanned(char *host, struct in_addr *a4, struct in6_addr *a6){
  if(( a4 && !honey_banned.isBlacklistedIPv4(a4)) ||
      ( a6 && !honey_banned.isBlacklistedIPv6(a6)))
    return false;

  // => host was had been banned
  std::map<std::string,std::pair<time_t,list_it>>::iterator h = honey_banned_time.find(host);

  if(h != honey_banned_time.end()){ // this should always be true
    if(difftime(time(NULL),h->second.first) >= banTimeout){ // ban timeout has expired
      honey_banned_timesorted.erase(h->second.second); // remove from list
      honey_banned_time.erase(h); // remove from map
      honey_banned.removeAddress(host); // remove from patricia tree
      return false;
    }
    else
      return true;  // still banned
  }

  return false; // should never get here
}

/* **************************************************** */

/**
 * @param n number of entries to be removed
 */
void NwInterface::honeyHarvesting(int n){
  list_it it;
  int x = n;
  time_t now = time(NULL);
		   
  while(x--) {
    // if( {list is empty} || {there aren't elements to be cleaned})
    if((it = honey_banned_timesorted.begin()) == honey_banned_timesorted.end() ||
	difftime(now,honey_banned_time.find(*it)->second.first) <= banTimeout)
      break;

    // else remove banned host
    std::string s(*it); // convert to char*
    char h[s.size() + 1];
    strcpy(h,s.c_str());

    honey_banned.removeAddress(h);      // remove from patricia
    honey_banned_time.erase(s);         // remove from map
    honey_banned_timesorted.erase(it);  // remove from list
  }

  if(++x != n) // avoid trace flooding
    trace->traceEvent(TRACE_NORMAL, "Banned hosts harvesting -> %d entries erased || %lu currently banned hosts\n",
		      n-x, honey_banned_time.size());
}

/* **************************************************** */

void NwInterface::harvestWatches() {
  u_int32_t when = time(NULL) - MAX_IDLENESS;

  for(std::unordered_map<std::string, WatchMatches*>::iterator it = watches_blacklist.begin();  it != watches_blacklist.end();) {
    if(it->second->ready_to_harvest(when)) {
      ban((char*)it->first.c_str(), false /* unban */, "unban", "");
      delete it->second;
      watches_blacklist.erase(it++);    // or "it = m.erase(it)" since C++11
    } else
      ++it;
  }
}

/* **************************************************** */

void NwInterface::ban(char *host, bool ban_ip, std::string reason, std::string country) {
  char cmdbuf[128];
  bool is_ipv4 = (strchr(host, ':') == NULL) ? true /* IPv4 */ : false /* IPv6 */;
  std::unordered_map<std::string, WatchMatches*>::iterator it = watches_blacklist.find(std::string(host));
  
  if(it == watches_blacklist.end()) {
    watches_blacklist[host] = new WatchMatches();

    snprintf(cmdbuf, sizeof(cmdbuf), "/usr/sbin/ip%stables %s IPT_GEOFENCE_BLACKLIST -s %s -j DROP",
	     is_ipv4 ? "" : "6",
	     ban_ip ? "-I" : "-D", host);
    
    logHostBan(host, ban_ip, reason, country);
    
    try {
      execCmd(cmdbuf);
    } catch (...) {
      trace->traceEvent(TRACE_ERROR, "Error while executing '%s'", cmdbuf);
    }    
  } else {
    WatchMatches *m = it->second;
    
    m->inc_matches(); /* TODO increment unban time */
  }
}

/* **************************************************** */

void NwInterface::ban_ipv4(u_int32_t ip4 /* network byte order */, bool ban_ip,
			   std::string reason, std::string country) {
  char ipbuf[32], *host = Utils::intoaV4(ntohl(ip4), ipbuf, sizeof(ipbuf));

  ban(host, ban_ip, reason, country);
}

/* **************************************************** */

void NwInterface::ban_ipv6(struct ndpi_in6_addr ip6, bool ban_ip,
			   std::string reason, std::string country) {
  char ipbuf[64], *host = Utils::intoaV6(ip6, 128, ipbuf, sizeof(ipbuf));

  ban(host, ban_ip, reason, country);
}

/* **************************************************** */

void NwInterface::flush_ban() {
  try {
    execCmd("/usr/sbin/iptables  -F IPT_GEOFENCE_BLACKLIST");
    execCmd("/usr/sbin/ip6tables -F IPT_GEOFENCE_BLACKLIST");
  } catch (...) {
    trace->traceEvent(TRACE_ERROR, "Error while flushing blacklists");
  }
}

/* **************************************************** */

std::string NwInterface::execCmd(const char* cmd) {
  std::string result = "";
  FILE* pipe = popen(cmd, "r");

  trace->traceEvent(TRACE_INFO, "Executing %s", cmd);

  if(!pipe)
    throw std::runtime_error("popen() failed!");

  try {
    char buffer[128];

    while(fgets(buffer, sizeof buffer, pipe) != NULL)
      result += buffer;
  } catch (...) {
    pclose(pipe);
    throw;
  }

  pclose(pipe);

  return(result);
}

/* **************************************************** */

int NwInterface::sendTelegramMessage(std::string message) {
  return(conf->sendTelegramMessage(message));
}
