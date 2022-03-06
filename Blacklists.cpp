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

/* ****************************************** */

Blacklists::Blacklists() {
  ptree_v4 = ndpi_patricia_new(32);
  ptree_v6 = ndpi_patricia_new(128);
}

/* ****************************************** */

static void free_ptree_data(void *data) {
  if(data) free(data);
}

/* ****************************************** */

Blacklists::~Blacklists() {
  if(ptree_v4)
    ndpi_patricia_destroy(ptree_v4, free_ptree_data);

  if(ptree_v6)
    ndpi_patricia_destroy(ptree_v6, free_ptree_data);
}

/* ****************************************** */

void Blacklists::addAddress(int family, void *addr, int bits) {
  ndpi_prefix_t prefix;
  ndpi_patricia_node_t *node;
  ndpi_patricia_tree_t *tree;

  if (family == AF_INET)
    tree = ptree_v4, ndpi_fill_prefix_v4(&prefix, (struct in_addr *) addr, bits, ptree_v4->maxbits);
  else
    tree = ptree_v6, ndpi_fill_prefix_v6(&prefix, (struct in6_addr *) addr, bits, ptree_v6->maxbits);

  if((node = ndpi_patricia_lookup(tree, &prefix)) != NULL)
    ndpi_patricia_set_node_data(node, NULL);
}

/* ****************************************** */

bool Blacklists::findAddress(char *addr) {
  ndpi_prefix_t prefix;
  ndpi_patricia_node_t *node;
  ndpi_patricia_tree_t *tree;

  if(strchr(addr, ':') != NULL) {
    struct in6_addr addr6;

    if(inet_pton(AF_INET6, addr, &addr6))
      tree = ptree_v6,ndpi_fill_prefix_v6(&prefix, &addr6, 128, tree->maxbits);
    else
      return(false);
  } else {
    struct in_addr pin;

    inet_aton(addr, &pin);
    tree = ptree_v4, ndpi_fill_prefix_v4(&prefix, &pin, 32, tree->maxbits);
  }

  if(ndpi_patricia_search_best(tree, &prefix) != NULL)
    return(true);
  else
    return(false);
}

/* ****************************************** */

void Blacklists::addAddress(char *net) {
  char *_bits = strchr(net, '/');
  u_int bits = 0;

  if(_bits)
    bits = atoi(&_bits[1]), _bits[0] = '\0';

  if(strchr(net, ':') != NULL) {
    struct in6_addr addr6;

    if(bits == 0) bits = 128;

    if(inet_pton(AF_INET6, net, &addr6))
      addAddress(AF_INET6, &addr6, bits);
  } else {
    struct in_addr pin;

    if(bits == 0) bits = 32;

    inet_aton(net, &pin);
    addAddress(AF_INET, &pin, bits);
  }
}

/* ****************************************** */

bool Blacklists::loadIPsetFromFile(char *path) {
  std::ifstream infile(path);
  std::string line;

  if(!infile.is_open())
    return(false);

  while(getline(infile, line)){
    if((line[0] == '#') || (line[0] == '\0'))
      continue;

    trace->traceEvent(TRACE_INFO, "Adding %s", line);
    addAddress((char*)line.c_str());
  }

  infile.close();

  return(true);
}
