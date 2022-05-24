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

  if(family == AF_INET)
    tree = ptree_v4, ndpi_fill_prefix_v4(&prefix, (struct in_addr *) addr, bits, ptree_v4->maxbits);
  else
    tree = ptree_v6, ndpi_fill_prefix_v6(&prefix, (struct in6_addr *) addr, bits, ptree_v6->maxbits);

  if((node = ndpi_patricia_lookup(tree, &prefix)) != NULL)
    ndpi_patricia_set_node_data(node, NULL);
}

/* ****************************************** */

bool Blacklists::isBlacklistedIPv4(struct in_addr *addr) {
  ndpi_prefix_t prefix;

  ndpi_fill_prefix_v4(&prefix, addr, 32, ptree_v4->maxbits);

  if(ndpi_patricia_search_best(ptree_v4, &prefix) != NULL)
    return(true);
  else
    return(false);
}

/* ****************************************** */

bool Blacklists::isBlacklistedIPv6(struct in6_addr *addr6) {
  ndpi_prefix_t prefix;

  ndpi_fill_prefix_v6(&prefix, addr6, 128, ptree_v6->maxbits);

  if(ndpi_patricia_search_best(ptree_v6, &prefix) != NULL)
    return(true);
  else
    return(false);
}

/* ****************************************** */

bool Blacklists::findAddress(char *addr) {
  ndpi_prefix_t prefix;
  ndpi_patricia_node_t *node;
  ndpi_patricia_tree_t *tree;

  if(strchr(addr, ':') != NULL) {
    struct in6_addr addr6;

    if(inet_pton(AF_INET6, addr, &addr6))
      return(isBlacklistedIPv6(&addr6));
    else
      return(false); /* Conversion failed */
  } else {
    struct in_addr pin;

    inet_aton(addr, &pin);
    return(isBlacklistedIPv4(&pin));
  }
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

void Blacklists::removeAddress(char *net){
  char *_bits = strchr(net, '/');
  u_int bits = 0;
  ndpi_prefix_t prefix;

  if(_bits)
    bits = atoi(&_bits[1]), _bits[0] = '\0';

  if(strchr(net, ':') != NULL) {
    struct in6_addr addr6;

    if(bits == 0) bits = 128;

    if(inet_pton(AF_INET6, net, &addr6)){
      ndpi_fill_prefix_v6(&prefix, &addr6, 128, ptree_v6->maxbits);
      ndpi_patricia_node_t *n = ndpi_patricia_search_best(ptree_v6, &prefix);
      if (n) ndpi_patricia_remove(ptree_v6,n);
    }
  } else {
    struct in_addr pin;

    if(bits == 0) bits = 32;

    inet_aton(net, &pin);
    ndpi_fill_prefix_v4(&prefix, &pin, 32, ptree_v4->maxbits);
    ndpi_patricia_node_t *n = ndpi_patricia_search_best(ptree_v4, &prefix);
    if (n) ndpi_patricia_remove(ptree_v4,n);
  }
}

/* ****************************************** */

bool Blacklists::loadIPsetFromFile(const char *path) {
  std::ifstream infile(path);
  std::string line;

  if(!infile.is_open())
    return(false);

  while(getline(infile, line)){
    if((line[0] == '#') || (line[0] == '\0'))
      continue;

    // trace->traceEvent(TRACE_INFO, "Adding %s", line.c_str());

    addAddress((char*)line.c_str());
  }

  infile.close();

  return(true);
}

/* ****************************************** */

bool Blacklists::loadIPsetFromURL(const char *url) {
  CURL *curl = curl_easy_init();
  FILE *fd;
  CURLcode res;
  char tmp_filename[64] = "/tmp/ipset_tempfile-XXXXXX";
  bool rc;

  if(!curl) {
    trace->traceEvent(TRACE_ERROR, "Unable to init curl");
    return(false);
  }

  if((fd = fopen(tmp_filename, "w")) == NULL) {
    trace->traceEvent(TRACE_ERROR, "Unable to open temporary file %s", tmp_filename);
    return(false);
  }

  trace->traceEvent(TRACE_NORMAL, "Downloading %s...", url);

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, fd);
  res = curl_easy_perform(curl);
  curl_easy_cleanup(curl);
  fclose(fd);

  if(res == CURLE_OK) {
    rc = loadIPsetFromFile(tmp_filename);
  } else {
    trace->traceEvent(TRACE_ERROR, "Error while downloading %s", url);
    rc = false;
  }

  unlink(tmp_filename); // Delete temporary file

#ifdef TEST
  trace->traceEvent(TRACE_WARNING, "=>> %s",
		    findAddress((char*)"2.57.121.1") ? "DROP" : "PASS");
#endif

  return(rc);
}
