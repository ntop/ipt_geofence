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

#ifndef _IP_ADDRESS_H_
#define _IP_ADDRESS_H_

/* ********************************************** */

/*
  IPv4/IPv6 address in numeric format (network byte order): it is
  converted to string only when needed (logs, iptables commands...)
*/
class IPAddress {
 private:
  bool ipv4;
  union {
    struct in_addr  v4;
    struct in6_addr v6;
  } addr;

 public:
  IPAddress() { ipv4 = true; memset(&addr, 0, sizeof(addr)); }

  inline void setIPv4(u_int32_t a /* network byte order */) {
    ipv4 = true, memset(&addr, 0, sizeof(addr)), addr.v4.s_addr = a;
  }

  inline void setIPv6(const void *a /* 16 bytes */) {
    ipv4 = false, memcpy(&addr.v6, a, sizeof(addr.v6));
  }

  /* Parse a numeric IPv4/IPv6 address: false if invalid */
  bool set(const char *s) {
    struct in_addr a4;
    struct in6_addr a6;

    if(s == NULL)
      return(false);
    else if(inet_pton(AF_INET, s, &a4) == 1)
      setIPv4(a4.s_addr);
    else if(inet_pton(AF_INET6, s, &a6) == 1)
      setIPv6(&a6);
    else
      return(false);

    return(true);
  }

  inline bool isIPv4()                { return(ipv4);     }
  inline struct in_addr*  getIPv4()   { return(&addr.v4); }
  inline struct in6_addr* getIPv6()   { return(&addr.v6); }

  /* buf_len should be at least INET6_ADDRSTRLEN */
  char* toString(char *buf, u_int buf_len) const {
    if(inet_ntop(ipv4 ? AF_INET : AF_INET6, &addr, buf, buf_len) == NULL)
      buf[0] = '\0';

    return(buf);
  }

  /* Used by std::map/std::set */
  bool operator<(const IPAddress &o) const {
    if(ipv4 != o.ipv4)
      return(ipv4);
    else if(ipv4)
      return(addr.v4.s_addr < o.addr.v4.s_addr);
    else
      return(memcmp(&addr.v6, &o.addr.v6, sizeof(addr.v6)) < 0);
  }
};

#endif /* _IP_ADDRESS_H_ */
