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
    trace->traceEvent(TRACE_ERROR, "Unable to unbind [queueId=%d]", queueId);
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

  switch((payload[ip_offset] & 0xf0) >> 4) {
  case 4:
    /* OK */
    break;
  default:
    return(MARKER_PASS); /* Pass */
  }

  if(payload_len >= ip_offset) {
    struct iphdr *iph = (struct iphdr *) &payload[ip_offset];

    if(iph->version != 4) {
      /* This is not IPv4 */
      return(MARKER_PASS); /* TODO */
    } else {
      u_int8_t *l4;
      struct tcphdr *tcph;
      struct udphdr *udph;
      u_int16_t src_port, dst_port;
      u_int8_t l4_proto, frag_off = ntohs(iph->frag_off);

      if((iph->protocol == IPPROTO_UDP) && ((frag_off & 0x3FFF /* IP_MF | IP_OFFSET */ ) != 0))
	return(MARKER_UNKNOWN); /* Don't block it */

      l4_proto = iph->protocol;
      l4 = ((u_int8_t *) iph + iph->ihl * 4);

      switch(l4_proto) {
      case IPPROTO_TCP:
	tcph = (struct tcphdr *)l4;
	src_port = tcph->source, dst_port = tcph->dest;
	break;

      case IPPROTO_UDP:
	udph = (struct udphdr *)l4;
	src_port = udph->source,  dst_port = udph->dest;
	break;

      default:
	return(MARKER_PASS);
	break;
      }

      return(makeVerdict(l4_proto, vlan_id,
			 iph->saddr, src_port,
			 iph->daddr, dst_port));
    }
  }

  return(MARKER_PASS);
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

Marker NwInterface::makeVerdict(u_int8_t proto, u_int16_t vlanId,
				u_int32_t saddr /* network byte order */,
				u_int16_t sport /* network byte order */,
				u_int32_t daddr /* network byte order */,
				u_int16_t dport /* network byte order */) {
  struct in_addr in;
  char country_code[3], continent_code[5], *host, src_host[32], dst_host[32], src_cc[3], dst_cc[3], src_con[5], dst_con[5];
  const char *proto_name = getProtoName(proto);
  bool pass_local = true;
  Marker m, src_maker, dst_marker;
  
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

  src_maker = dst_marker = conf->getDefaultMarker();

  in.s_addr = saddr;
  host = inet_ntoa(in);
  strncpy(src_host, host, sizeof(src_host)-1);  

  if(geoip->lookup(host, country_code, sizeof(country_code), continent_code, sizeof(continent_code))) {
    src_maker = conf->getMarker(continent_code);
    if(src_maker != MARKER_PASS)
       src_maker = conf->getMarker(country_code);

    strncpy(src_cc, country_code, sizeof(src_cc)-1);
    strncpy(src_con, continent_code, sizeof(src_con)-1);
    pass_local = false;
  } else {
    /* Unknown or private IP address  */
    src_cc[0] = '\0';
    src_con[0] = '\0';
    src_maker = MARKER_PASS;
  }

  in.s_addr = daddr;
  host = inet_ntoa(in);
  strncpy(dst_host, host, sizeof(dst_host)-1);

  if(geoip->lookup(host = inet_ntoa(in), country_code, sizeof(country_code), continent_code, sizeof(continent_code))) {
    dst_marker = conf->getMarker(continent_code);
    if(dst_marker != MARKER_PASS)
       dst_marker = conf->getMarker(country_code);

    strncpy(dst_cc, country_code, sizeof(dst_cc)-1);
    strncpy(dst_con, continent_code, sizeof(dst_con)-1);
    pass_local = false;
  } else {
    /* Unknown or private IP address  */
    dst_cc[0] = '\0';
    dst_con[0] = '\0';
    dst_marker = MARKER_PASS;
  }

  if((conf->isIgnoredPort(sport) || conf->isIgnoredPort(dport))
     || ((src_maker == MARKER_PASS) && (dst_marker == MARKER_PASS))) {
    m = MARKER_PASS;
    
    trace->traceEvent(TRACE_INFO,
		      "%s %s:%u %s %s -> %s:%u %s %s [PASS]",
		      proto_name,
		      src_host, sport, src_cc, src_con,
		      dst_host, dport, dst_cc, dst_con);
  } else {
    m = MARKER_DROP;

    trace->traceEvent(TRACE_WARNING,
		      "%s %s:%u %s %s -> %s:%u %s %s [DROP]",
		      proto_name,
		      src_host, sport, src_cc, src_con,
		      dst_host, dport, dst_cc, dst_con);
  }
  
  return(m);
}
