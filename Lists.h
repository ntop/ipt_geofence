/*
 *
 * (C) 2021-23 - ntop.org
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

#ifndef _LISTS_H_
#define _LISTS_H_

#include <unordered_map>
#include "WatchMatches.h"
/* ******************************* */

class Lists {
 private:
#ifdef __linux__
  std::string dump_path = "/var/tmp/banned_ip_addresses.txt";
#else
#if defined __FreeBSD__
  std::string dump_path = "/var/tmp/banned_ip_addresses.txt";
#else
#ifdef WIN32
  std::string dump_path = "banned_ip_addresses.txt"; /* Dump to current working directory */
#endif
#endif
#endif
  ndpi_patricia_tree_t *ptree_v4, *ptree_v6;
  void addAddress(int family, void *addr, int bits);
  bool findAddress(int family, struct in_addr *addr, int bits);
  bool findIpv4(struct in_addr *addr);
  bool findIpv6(struct in6_addr *addr);

 public:
  Lists();
  ~Lists();
  //this pointer will be retained after load is called
  std::unordered_map<std::string, WatchMatches*> watches_blacklist;
  bool findAddress(char *addr);
  void addAddress(char *net);
  void removeAddress(char *net);
  bool loadIPsetFromFile(const char *path);
  bool loadIPsetFromURL(const char *url);

  bool load(std::unordered_map<std::string, WatchMatches*>& watches);
  bool save();
  void cleanAddresses();

  bool isListedIPv4(struct in_addr *pin);
  bool isListedIPv6(struct in6_addr *addr6);
};


#endif /* _LISTS_H_ */
