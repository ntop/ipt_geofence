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

#include "config.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <linux/types.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <linux/netfilter.h> /* for NF_ACCEPT */
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <jsoncpp/json/json.h>
#include <maxminddb.h>
#include <ndpi_api.h>
#include <curl/curl.h>

#include <inttypes.h>
#include <netinet/ip6.h>

#include <unordered_map>
#include <fstream>
#include <iostream>

#include <thread>
#include <list>
#include <set>


/* ********************************************** */

class Marker{
 private:
  u_int16_t value;

 public:
  inline void setValue(u_int16_t v){value=v;}
  operator u_int16_t() {return value;}
};

//#if !defined(__mips__)
#define HAVE_NFQ_SET_VERDICT2 1
//#endif

#define NF_BUFFER_SIZE     (32768*16384)
#define NF_MAX_QUEUE_LEN   (8192)

/* ********************************************** */

#include "Trace.h"
#include "Blacklists.h"
#include "Configuration.h"
#include "GeoIP.h"
#include "NwInterface.h"

extern Trace *trace;