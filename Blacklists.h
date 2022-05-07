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

#ifndef _BLACKLISTS_H_
#define _BLACKLISTS_H_

/* ******************************* */

class Blacklists {
 private:
  ndpi_patricia_tree_t *ptree_v4, *ptree_v6;
  
  void addAddress(int family, void *addr, int bits);
  bool findAddress(int family, struct in_addr *addr, int bits);

 public:
  Blacklists();
  ~Blacklists();

  bool findAddress(char *addr);
  void addAddress(char *net);
  void removeAddress(char *net);
  bool loadIPsetFromFile(const char *path);
  bool loadIPsetFromURL(const char *url);

  bool isBlacklistedIPv4(struct in_addr *pin);
  bool isBlacklistedIPv6(struct in6_addr *addr6);
  std::vector<std::string> urls_Blacklist;
};


#endif /* _BLACKLISTS_H_ */
