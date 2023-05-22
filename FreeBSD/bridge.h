/*
 *  Copyright (C) 2002-23 - ntop.org
 *
 *  http://www.ntop.org/
 *
 * BSD license
 *
 */

#ifndef _BRIDGE_H_
#define _BRIDGE_H_

extern int netmapBridgeSetup(const char *ifname);
extern void netmapBridgeProcessPacket(NwInterface *iface, Configuration *conf);
extern void netmapBridgeShutdown();

#endif /* _BRIDGE_H_ */
