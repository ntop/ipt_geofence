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

/* Forward */
int netfilter_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		       struct nfq_data *nfa, void *data);

/* **************************************************** */

NwInterface::NwInterface(u_int nf_device_id,
				       Configuration *_c,
				       GeoIP *_g) {
  conf = _c, geoip = _g;

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
    trace->traceEvent(TRACE_NORMAL, "Succesfully connected to NF_QUEUE %d", queueId);

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
}

/* **************************************************** */

NwInterface::~NwInterface() {
  if(queueHandle) nfq_destroy_queue(queueHandle);
  if(nfHandle)    nfq_close(nfHandle);

  nf_fd = 0;
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
  u_int32_t id = ntohl(ph->packet_id);
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

  ifaceRunning = true;

  h = get_nfHandle();
  fd = get_fd();

  while(isRunning()) {
    fd_set mask;
    struct timeval wait_time;

    FD_ZERO(&mask);
    FD_SET(fd, &mask);
    wait_time.tv_sec = 1, wait_time.tv_usec = 0;

    if(select(fd+1, &mask, 0, 0, &wait_time) > 0) {
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
    }
  }

  trace->traceEvent(TRACE_NORMAL, "Leaving netfilter packet poll loop");

  ifaceRunning = false;
}

/* **************************************************** */

Marker NwInterface::dissectPacket(const u_char *payload, u_int payload_len) {
  /* We can see only IP addresses */
  u_int16_t ip_offset = 0, vlan_id = 0 /* FIX */;

  if (payload_len >= ip_offset) {
    struct iphdr *iph = (struct iphdr *)&payload[ip_offset];
    bool ipv4 = false, ipv6 = false;

    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    u_int16_t src_port, dst_port, ip_payload_offset = 40 /* ipv6 is 40B long */;
    u_int8_t proto;
    char src[INET6_ADDRSTRLEN] = {}, dst[INET6_ADDRSTRLEN] = {};

    if (iph->version == 6) {
      ipv6 = true;
      struct ip6_hdr *ip6h = (struct ip6_hdr *)&payload[ip_offset];
      proto = ip6h->ip6_nxt;

      // ipv6 address stringification
      inet_ntop(AF_INET6, &(ip6h->ip6_src), src, sizeof(src));
      inet_ntop(AF_INET6, &(ip6h->ip6_src), dst, sizeof(dst));
      // trace->traceEvent(TRACE_DEBUG, "\t%s : %u\t%s : %u", src, src_port, dst, dst_port);

      // return (MARKER_PASS); /* TODO */
    } else if (iph->version == 4) {
      ipv4 = true;
      u_int8_t frag_off = ntohs(iph->frag_off);
      struct in_addr a;

      if ((iph->protocol == IPPROTO_UDP) && ((frag_off & 0x3FFF /* IP_MF | IP_OFFSET */) != 0))
        return (MARKER_UNKNOWN); /* Don't block it */

      // get protocol and offset
      proto = iph->protocol;
      ip_payload_offset = iph->ihl * 4;
      // ipv4 address stringification
      a.s_addr = iph->saddr, inet_ntop(AF_INET, &a, src, sizeof(src));
      a.s_addr = iph->daddr, inet_ntop(AF_INET, &a, dst, sizeof(dst));
    } else { // Neither ipv4 or ipv6...unlikely to be evaluated
      return (MARKER_PASS);
    }

    switch (proto) {
      case IPPROTO_UDP:
        tcph = (struct tcphdr *)(iph + ip_payload_offset);
        src_port = tcph->source, dst_port = tcph->dest;
        break;
      case IPPROTO_TCP:
        udph = (struct udphdr *)(iph + ip_payload_offset);
        src_port = udph->source, dst_port = udph->dest;
        break;
      default:
        // we do not care about ports in other protocols
        src_port = dst_port = 0;
    }
    return (makeVerdict(proto, vlan_id,
                        src_port, dst_port,
                        src,dst, ipv4,ipv6));
  }
  return (MARKER_PASS);
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
  u_int32_t a = ntohl(addr);
  
  if(((a & 0xFF000000) == 0x0A000000 /* 10.0.0.0/8 */)
     || ((a & 0xFFF00000) == 0xAC100000 /* 172.16.0.0/12 */)
     || ((a & 0xFFFF0000) == 0xC0A80000 /* 192.168.0.0/16 */)
     || ((a & 0xFF000000) == 0x7F000000 /* 127.0.0.0/8 */)
     || ((a & 0xFFFF0000) == 0xA9FE0000 /* 169.254.0.0/16 Link-Local communication rfc3927 */)
     || (a == 0xFFFFFFFF /* 255.255.255.255 */)
     || (a == 0x0        /* 0.0.0.0 */)
     || ((a & 0xF0000000) == 0xE0000000 /* 224.0.0.0/4 */))
    return(true);
  else
    return(false);
}

bool NwInterface::isPrivateIPv6(const char *ip6addr) {
  struct in6_addr a;
  inet_pton(AF_INET6,ip6addr,&a);
  bool isUniqueLocal = a.s6_addr[0] == (u_int8_t)253 || a.s6_addr[0] == (u_int8_t)252;
  if (isUniqueLocal || IN6_IS_ADDR_LINKLOCAL(ip6addr)) 
    trace->traceEvent(TRACE_WARNING,"Address %s is private", ip6addr);
  return isUniqueLocal || IN6_IS_ADDR_LINKLOCAL(ip6addr);
}


/* **************************************************** */

Marker NwInterface::makeVerdict(u_int8_t proto, u_int16_t vlanId,
				u_int16_t sport /* network byte order */,
				u_int16_t dport /* network byte order */,
        char *src_host, char *dst_host,
        bool ipv4, bool ipv6) {
  struct in_addr in;
  char src_ctry[3]={}, dst_ctry[3]={}, src_cont[3]={}, dst_cont[3]={} ;
  const char *proto_name = getProtoName(proto);

  // trace->traceEvent(TRACE_DEBUG, "%s %s %s : %u -> %s : %u",ipv4 ? "IPv4" : (ipv6 ? "IPv6" : "???"),
  //   proto_name, src_host, sport, dst_host, dport);

  u_int32_t saddr = ipv4 ? inet_addr(src_host) : 0;
  u_int32_t daddr = ipv4 ? inet_addr(dst_host) : 0;
  bool pass_local = true,
    saddr_private = (ipv4 ? isPrivateIPv4(saddr) : (ipv6 ? isPrivateIPv6(src_host) : false)),
    daddr_private = (ipv4 ? isPrivateIPv4(saddr) : (ipv6 ? isPrivateIPv6(dst_host) : false));
  Marker m, src_marker, dst_marker;

  /* Check if sender/recipient are blacklisted */
  if (ipv4){
  in.s_addr = saddr;
  if((!saddr_private) && conf->isBlacklistedIPv4(&in)) {
    trace->traceEvent(TRACE_WARNING,
		      "%s %s :%u (Blacklist) -> %s :%u [DROP]",
		      proto_name,
		      src_host, sport,
		      dst_host, dport);

    return(MARKER_DROP);
  }

  in.s_addr = daddr;
  if((!daddr_private) && conf->isBlacklistedIPv4(&in)) {
    trace->traceEvent(TRACE_WARNING,
		      "%s %s :%u -> %s :%u (Blacklist) [DROP]",
		      proto_name,
		      src_host, sport,
		      dst_host, dport);
    return(MARKER_DROP);
  }
  }
  
  sport = ntohs(sport), dport = ntohs(dport);

  // trace->traceEvent(TRACE_NORMAL, "Processing %u -> %u", sport, dport);
  
  switch(proto) {
  case IPPROTO_TCP:
    if((conf->isMonitoredTCPPort(sport)) || conf->isMonitoredTCPPort(dport))
      ;
    else {
      trace->traceEvent(TRACE_INFO, "Ignoring TCP ports %u/%u", sport, dport);
      return(MARKER_PASS);
    }
    break;

  case IPPROTO_UDP:
    if((!conf->isMonitoredUDPPort(sport)) || conf->isMonitoredUDPPort(dport))
      ;
    else {
      trace->traceEvent(TRACE_INFO, "Ignoring UDP ports %u/%u", sport, dport);
      return(MARKER_PASS);
    }
    break;
  }

  m = src_marker = dst_marker = conf->getDefaultMarker();

  if((!saddr_private) && (geoip->lookup(src_host, src_ctry, sizeof(src_ctry), src_cont, sizeof(src_cont)))) {
    src_marker = conf->getMarker(src_ctry,src_cont);
    pass_local = false;
  } else {
    /* Unknown or private IP address  */
    // src_marker = MARKER_PASS;
  }

  if((!daddr_private) && (geoip->lookup(dst_host, dst_ctry, sizeof(dst_ctry), dst_cont, sizeof(dst_cont)))) {
    dst_marker = conf->getMarker(dst_ctry, dst_cont);
    pass_local = false;
  } else {
    /* Unknown or private IP address  */
    // dst_marker = MARKER_PASS;
  }
  // trace->traceEvent(TRACE_WARNING,"%u %u",dst_marker,src_marker); // TODO remove this
  trace->traceEvent(TRACE_WARNING,"%u %u",saddr_private,daddr_private); // TODO remove this
  if((conf->isIgnoredPort(sport) || conf->isIgnoredPort(dport))
     || ((src_marker == MARKER_PASS) && (dst_marker == MARKER_PASS))) {
    m = MARKER_PASS;
    
    trace->traceEvent(TRACE_INFO,
		      "%s %s :%u %s %s -> %s :%u %s %s [PASS]",
		      proto_name,
		      src_host, sport, src_ctry, src_cont,
		      dst_host, dport, dst_ctry, dst_cont);
  } else {
    m = MARKER_DROP;

    trace->traceEvent(TRACE_WARNING,
		      "%s %s :%u %s %s -> %s :%u %s %s [DROP]",
		      proto_name,
		      src_host, sport, src_ctry, src_cont,
		      dst_host, dport, dst_ctry, dst_cont);
  }
  
  return(m);
}
