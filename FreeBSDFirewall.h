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

#ifndef _FREEBSD_FIREWALL_H_
#define _FREEBSD_FIREWALL_H_

/* ********************************************** */

#if defined __FreeBSD__

#define IPFW_TABLE 99

class FreeBSDFirewall : public Firewall {
 public:
  void setup() {
    char cmdbuf[128];

    snprintf(cmdbuf, sizeof(cmdbuf), "/sbin/ipfw table %u create 2>/dev/null || /sbin/ipfw table %u list > /dev/null",
	     IPFW_TABLE, IPFW_TABLE);
  }

  void teardown() {
    char cmdbuf[128];
    
    snprintf(cmdbuf, sizeof(cmdbuf), "/sbin/ipfw table %u destroy > /dev/null", IPFW_TABLE);
    execCmd(cmdbuf);
  }

  void ban(char *ip, bool is_ipv4) {
    char cmdbuf[128];    

    snprintf(cmdbuf, sizeof(cmdbuf), "/sbin/ipfw -q table %u add %s/%u", IPFW_TABLE, ip, is_ipv4 ? 32 : 128);
    execCmd(cmdbuf);
  }

  void unban(char *ip, bool is_ipv4) {
    char cmdbuf[128];    

    snprintf(cmdbuf, sizeof(cmdbuf), "/sbin/ipfw -q table %u delete %s/%u", IPFW_TABLE, ip, is_ipv4 ? 32 : 128);
    execCmd(cmdbuf);
  }
};
#endif

#endif /* _FREEBSD_FIREWALL_H_ */

  
