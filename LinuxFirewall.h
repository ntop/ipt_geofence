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

#ifndef _LINUX_FIREWALL_H_
#define _LINUX_FIREWALL_H_

/* ********************************************** */

#ifdef __linux__
class LinuxFirewall : public Firewall {
 public:
  void ban(char *ip, bool is_ipv4) {
    char cmdbuf[128];
    
    snprintf(cmdbuf, sizeof(cmdbuf), "/usr/sbin/ip%stables -I IPT_GEOFENCE_BLACKLIST -s %s -j DROP",
	     is_ipv4 ? "" : "6", ip);
    execCmd(cmdbuf);
  }

  void unban(char *ip, bool is_ipv4) {
    char cmdbuf[128];
    
    snprintf(cmdbuf, sizeof(cmdbuf), "/usr/sbin/ip%stables -D IPT_GEOFENCE_BLACKLIST -s %s -j DROP",
	     is_ipv4 ? "" : "6", ip);
    execCmd(cmdbuf);
  }
#endif
};

#endif /* _LINUX_FIREWALL_H_ */

  
