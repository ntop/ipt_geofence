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

#ifndef _LINUX_FIREWALL_H_
#define _LINUX_FIREWALL_H_

/* ********************************************** */

#ifdef __linux__
class LinuxFirewall : public Firewall {
 public:
  /*
    Notes:
    - -w waits for the xtables lock: without it iptables fails immediately
      if another process (fail2ban, docker, the cmd ban/unban scripts...)
      holds the lock, leaving the kernel out of sync with watches_blacklist
    - ban() is idempotent (-C before -I) so no duplicate rules are created
    - unban() loops until no matching rule is left: a single -D removes only
      one rule, so any duplicate would keep the host blocked until restart
  */
  void ban(char *ip, bool is_ipv4) {
    char cmdbuf[512];
    const char *v = is_ipv4 ? "" : "6";

    snprintf(cmdbuf, sizeof(cmdbuf),
	     "/usr/sbin/ip%stables -w -t raw -C IPT_GEOFENCE_BLACKLIST -s %s -j DROP 2>/dev/null"
	     " || /usr/sbin/ip%stables -w -t raw -I IPT_GEOFENCE_BLACKLIST -s %s -j DROP",
	     v, ip, v, ip);
    execCmd(cmdbuf);
  }

  void unban(char *ip, bool is_ipv4) {
    char cmdbuf[512];
    const char *v = is_ipv4 ? "" : "6";

    snprintf(cmdbuf, sizeof(cmdbuf),
	     "n=0; while [ $n -lt 64 ] && /usr/sbin/ip%stables -w -t raw -D IPT_GEOFENCE_BLACKLIST -s %s -j DROP 2>/dev/null;"
	     " do n=$((n+1)); done",
	     v, ip);
    execCmd(cmdbuf);
  }
};
#endif

#endif /* _LINUX_FIREWALL_H_ */

  
