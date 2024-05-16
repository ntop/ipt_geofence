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

/* With this number of entries the memory used by the unordered_map will be about 1gb.
 * If you want to increase the limit, remember that it tends to 10940000 * x --> 1gb * x
 */
#define MAX_ENTRIES 10940000

#include <unordered_map>
#include "WatchMatches.h"
/* ******************************* */

class Lists {
 private:
  std::string dump_path;
  ndpi_patricia_tree_t *ptree_v4, *ptree_v6;
  void addAddress(int family, void *addr, int bits);
  bool findAddress(int family, struct in_addr *addr, int bits);
  bool findIp(void *addr, bool is_ipv4);

 public:
  Lists();
  ~Lists();
  std::unordered_map<std::string, WatchMatches*> watches_blacklist;
  bool findAddress(char *addr);
  void addAddress(char *net);
  void removeAddress(char *net);
  bool loadIPsetFromFile(const char *path);
  bool loadIPsetFromURL(const char *url);

  bool load(std::unordered_map<std::string, WatchMatches*>& watches);
  bool save();
  void cleanAddresses();
  void setDumpPath(const char *path) { dump_path = std::string(path); }

  bool isListedIPv4(struct in_addr *pin);
  bool isListedIPv6(struct in6_addr *addr6);
};


#endif /* _LISTS_H_ */
