/*
 *
 * Code based on
 *
 * (C) 2011-2014 Luigi Rizzo, Matteo Landi
 *
 * BSD license
 *
 * A netmap application to bridge two network interfaces,
 * or one interface and the host stack.
 *
 * $FreeBSD$
 */

#if defined __FreeBSD__

#include <libnetmap.h>
#include <signal.h>
#include <stdio.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>

static int verbose = 0;
static int zerocopy = 1; /* enable zerocopy if possible */
static unsigned long thread_id;

/* https://github.com/rumpkernel/drv-netif-netmap/blob/master/include/net/netmap_user.h */
static inline void nm_pkt_copy_local(const void *_src, void *_dst, int l)
{
  const uint64_t *src = (const uint64_t *)_src;
  uint64_t *dst = (uint64_t *)_dst;

  if (unlikely(l >= 1024)) {
    memcpy(dst, src, l);
    return;
  }
  for (; likely(l > 0); l-=64) {
    *dst++ = *src++;
    *dst++ = *src++;
    *dst++ = *src++;
    *dst++ = *src++;
    *dst++ = *src++;
    *dst++ = *src++;
    *dst++ = *src++;
    *dst++ = *src++;
  }
}

/*
 * How many slots do we (user application) have on this
 * set of queues ?
 */
static int
rx_slots_avail(struct nmport_d *d)
{
  u_int i, tot = 0;

  for (i = d->first_rx_ring; i <= d->last_rx_ring; i++) {
    tot += nm_ring_space(NETMAP_RXRING(d->nifp, i));
  }

  return tot;
}

static int
tx_slots_avail(struct nmport_d *d)
{
  u_int i, tot = 0;

  for (i = d->first_tx_ring; i <= d->last_tx_ring; i++) {
    tot += nm_ring_space(NETMAP_TXRING(d->nifp, i));
  }

  return tot;
}

static int
filter_packet(char *buf, int len)
{

  // Block ICMP
  if(len >= 34 &&
     *((uint16_t *) (buf + 12)) == 0x0008 &&
     *((uint8_t *)  (buf + 23)) == 0x1) {
    return 0;
  }

  // Pass anything else
  return 1;
}


/*
 * Move up to 'limit' pkts from rxring to txring, swapping buffers
 * if zerocopy is possible. Otherwise fall back on packet copying.
 */
static int
rings_move(NwInterface *iface, Configuration *conf,
	   struct netmap_ring *rxring, struct netmap_ring *txring,
	   u_int limit, const char *msg, u_int8_t direction)
{
  u_int j, k, m = 0;

  /* print a warning if any of the ring flags is set (e.g. NM_REINIT) */
  // if(rxring->flags || txring->flags) D("%s rxflags %x txflags %x",  msg, rxring->flags, txring->flags);
  j = rxring->head; /* RX */
  k = txring->head; /* TX */

  m = nm_ring_space(rxring);
  if(m < limit)
    limit = m;

  m = nm_ring_space(txring);
  if(m < limit)
    limit = m;
  m = limit;

  while(limit-- > 0) {
    struct netmap_slot *rs = &rxring->slot[j];
    struct netmap_slot *ts = &txring->slot[k];
    const u_char *rxbuf = (const u_char*)NETMAP_BUF(rxring, rs->buf_idx);
    u_int16_t marker;

    if(rs->len > sizeof(ndpi_ethhdr)) {
      struct ndpi_ethhdr *e = (struct ndpi_ethhdr*)rxbuf;

      if((e->h_proto != ETHERTYPE_IP) && (e->h_proto != ETHERTYPE_IPV6))
	return(m); /* Np IPv4 or IPv6 */
    } else
      return(m);
    
    marker = iface->dissectPacket(&rxbuf[sizeof(ndpi_ethhdr)],
				  rs->len - sizeof(ndpi_ethhdr)).get();
    
    if(marker != conf->getMarkerDrop().get()) {
      /* swap packets */
      if(ts->buf_idx < 2 || rs->buf_idx < 2) {
	trace->traceEvent(TRACE_ERROR, "wrong index rxr[%d] = %d  -> txr[%d] = %d",
			  j, rs->buf_idx, k, ts->buf_idx);
	sleep(2);
      }

      /* copy the packet length */
      if(rs->len > rxring->nr_buf_size) {
	trace->traceEvent(TRACE_ERROR, "%s: invalid len %u, rxr[%d] -> txr[%d]",
			  msg, rs->len, j, k);
	rs->len = 0;
      } else if(verbose) {
	trace->traceEvent(TRACE_INFO, "%s: fwd len %u, rx[%d] -> tx[%d]",
			  msg, rs->len, j, k);
      }

      ts->len = rs->len;

      if(zerocopy) {
	uint32_t pkt = ts->buf_idx;
	
	ts->buf_idx = rs->buf_idx;
	rs->buf_idx = pkt;
	/* report the buffer change. */
	ts->flags |= NS_BUF_CHANGED;
	rs->flags |= NS_BUF_CHANGED;
	/* copy the NS_MOREFRAG */
	rs->flags = (rs->flags & ~NS_MOREFRAG) | (ts->flags & NS_MOREFRAG);
      } else {
	char *rxbuf = NETMAP_BUF(rxring, rs->buf_idx);
	char *txbuf = NETMAP_BUF(txring, ts->buf_idx);

	nm_pkt_copy_local(rxbuf, txbuf, ts->len);
      }
    } else {
      if(verbose)
	printf("[+] Dropping packet\n");
    }

    j = nm_ring_next(rxring, j);
    k = nm_ring_next(txring, k);
  }

  rxring->head = rxring->cur = j;
  txring->head = txring->cur = k;

  if(verbose && m > 0)
    trace->traceEvent(TRACE_INFO, "%s fwd %d packets: rxring %u --> txring %u",
		      msg, m, rxring->ringid, txring->ringid);

  return(m);
}

/* Move packets from source port to destination port. */
static int ports_move(NwInterface *iface, Configuration *conf,
		      struct nmport_d *src, struct nmport_d *dst, u_int limit,
		      const char *msg, u_int8_t direction)
{
  struct netmap_ring *txring, *rxring;
  u_int m = 0, si = src->first_rx_ring, di = dst->first_tx_ring;

  while (si <= src->last_rx_ring && di <= dst->last_tx_ring) {
    rxring = NETMAP_RXRING(src->nifp, si);
    txring = NETMAP_TXRING(dst->nifp, di);
    if(nm_ring_empty(rxring)) {
      si++;
      continue;
    }
    if(nm_ring_empty(txring)) {
      di++;
      continue;
    }
    
    m += rings_move(iface, conf, rxring, txring, limit, msg, direction);
  }

  return(m);
}

/* ****************************************************** */

static char msg_a2b[256], msg_b2a[256];
static struct pollfd pollfd[2];
static u_int burst = 1024, wait_link = 4;
static struct nmport_d *pa = NULL, *pb = NULL;
static char *ifa = NULL, *ifb = NULL;
static char ifabuf[32] = { 0 }, ifbbuf[32] = { 0 }, buf[64];
static int pa_sw_rings, pb_sw_rings, loopback = 0, ch;
  
/* ****************************************************** */

int netmapBridgeSetup(const char *ifname) {
  if(ifname == NULL) {
    trace->traceEvent(TRACE_WARNING, "Internal model");
    return(-1);
  }
  
  snprintf(buf, sizeof(buf)-1, "ifconfig %s -rxcsum -txcsum -tso -lro", ifname);
  trace->traceEvent(TRACE_NORMAL, "Disabling HW offload on %s", ifname);
  system(buf);
  
  snprintf(ifabuf, sizeof(ifabuf) - 1, "netmap:%s^", ifname);
  snprintf(ifbbuf, sizeof(ifbbuf) - 1, "netmap:%s", ifname);

  ifa = ifabuf; /* Host stack */
  ifb = ifbbuf; /* Network device */

  pa = nmport_open(ifa);
  if(pa == NULL) {
    trace->traceEvent(TRACE_ERROR, "Cannot open %s", ifname /* ifa */);
    return(-1);
  }

  /* try to reuse the mmap() of the first interface, if possible */
  pb = nmport_open(ifb);
  if(pb == NULL) {
    trace->traceEvent(TRACE_ERROR, "Cannot open %s", ifname /* ifb */);
    nmport_close(pa);
    return(-1);
  }

  zerocopy = zerocopy && (pa->mem == pb->mem);
  // trace->traceEvent(TRACE_INFO, "zerocopy %ssupported", zerocopy ? "" : "NOT ");

  /* setup poll(2) array */
  memset(pollfd, 0, sizeof(pollfd));
  pollfd[0].fd = pa->fd;
  pollfd[1].fd = pb->fd;

  trace->traceEvent(TRACE_NORMAL, "Waiting %d sec for link to come up...", wait_link);
  sleep(wait_link);

  trace->traceEvent(TRACE_NORMAL, "Ready to process packets...");

  pa_sw_rings = (pa->reg.nr_mode == NR_REG_SW
#ifdef NR_REG_ONE_SW
		 || pa->reg.nr_mode == NR_REG_ONE_SW
#endif
		 );
  pb_sw_rings = (pb->reg.nr_mode == NR_REG_SW
#ifdef NR_REG_ONE_SW
		 || pb->reg.nr_mode == NR_REG_ONE_SW
#endif
		 );

  snprintf(msg_a2b, sizeof(msg_a2b), "%s:%s --> %s:%s",
	   pa->hdr.nr_name, pa_sw_rings ? "host" : "nic",
	   pb->hdr.nr_name, pb_sw_rings ? "host" : "nic");

  snprintf(msg_b2a, sizeof(msg_b2a), "%s:%s --> %s:%s",
	   pb->hdr.nr_name, pb_sw_rings ? "host" : "nic",
	   pa->hdr.nr_name, pa_sw_rings ? "host" : "nic");

  return(0);
}

/* ****************************************************** */

void netmapBridgeProcessPacket(NwInterface *iface, Configuration *conf) {
  int n0, n1, ret;

  pollfd[0].events = pollfd[1].events = 0;
  pollfd[0].revents = pollfd[1].revents = 0;
  n0 = rx_slots_avail(pa);
  n1 = rx_slots_avail(pb);

  if(n0)
    pollfd[1].events |= POLLOUT;
  else
    pollfd[0].events |= POLLIN;
  if(n1)
    pollfd[0].events |= POLLOUT;
  else
    pollfd[1].events |= POLLIN;

  /* poll() also cause kernel to txsync/rxsync the NICs */
  ret = poll(pollfd, 2, 100 /* ms */);

  if(ret <= 0 || verbose)
    trace->traceEvent(TRACE_INFO, "poll %s [0] ev %x %x rx %d@%d tx %d,"
		      " [1] ev %x %x rx %d@%d tx %d",
		      ret <= 0 ? "timeout" : "ok",
		      pollfd[0].events,
		      pollfd[0].revents,
		      rx_slots_avail(pa),
		      NETMAP_RXRING(pa->nifp, pa->cur_rx_ring)->head,
		      tx_slots_avail(pa),
		      pollfd[1].events,
		      pollfd[1].revents,
		      rx_slots_avail(pb),
		      NETMAP_RXRING(pb->nifp, pb->cur_rx_ring)->head,
		      tx_slots_avail(pb)
		      );

  if(ret < 0)
    return;

  if(pollfd[0].revents & POLLERR) {
    struct netmap_ring *rx = NETMAP_RXRING(pa->nifp, pa->cur_rx_ring);

    trace->traceEvent(TRACE_ERROR, "error on fd0, rx [%d,%d,%d)",
		      rx->head, rx->cur, rx->tail);
  }
  if(pollfd[1].revents & POLLERR) {
    struct netmap_ring *rx = NETMAP_RXRING(pb->nifp, pb->cur_rx_ring);

    trace->traceEvent(TRACE_ERROR, "error on fd1, rx [%d,%d,%d)",
		      rx->head, rx->cur, rx->tail);
  }

  if(pollfd[0].revents & POLLOUT)
    ports_move(iface, conf, pb, pa, burst, msg_b2a, 1 /* RX */);

  if(pollfd[1].revents & POLLOUT)
    ports_move(iface, conf, pa, pb, burst, msg_a2b, 0 /* TX */);

  /*
   * We don't need ioctl(NIOCTXSYNC) on the two file descriptors.
   * here. The kernel will txsync on next poll().
   */  
}

/* ****************************************************** */

void netmapBridgeShutdown() {
  nmport_close(pb);
  nmport_close(pa);
}

#endif /* __FreeBSD__ */
