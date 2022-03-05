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
//warning
/* Global */
Trace *trace;

const char *version = PACKAGE_VERSION;
u_int32_t last_modification_time = 0;
NwInterface *iface;

/* ************************************************* */

void sigproc(int sig) {
  static int called = 0;

  if(called) {
    trace->traceEvent(TRACE_NORMAL, "Ok I am leaving now");
    _exit(0);
  } else {
    trace->traceEvent(TRACE_NORMAL, "Shutting down...");
    called = 1;
  }

  iface->stopPolling();
}

/* ************************************************* */

static void help() {
  printf("Welcome to ipt_geofence v.%s\n", version);
  printf("Copyright 2021-22 ntop.org\n");
  
  printf("\nUsage:\n");
  printf("ipt_geofence [-h][-v] -c <config file> -m <city>\n\n");
  printf("-h           | Print this help\n");
  printf("-v           | Verbose\n");
  printf("-c <config>  | Specify the configuration file\n");
  printf("-m <city>    | Local mmdb_city MMDB file\n");

  printf("\nExample: ipt_geofence -c sample_config.json -m dbip-country-lite.mmdb\n");
  
  exit(0);
}


/* ************************************************* */

int main(int argc, char *argv[]) {
  u_char c;
  const struct option long_options[] = {
    { "config",  required_argument,    NULL, 'c' },
    { "mmdb_city",  required_argument, NULL, 'm' },
    { "help",    no_argument,          NULL, 'h' },
    { "verbose", no_argument,          NULL, 'v' },
    /* End of options */
    { NULL,      no_argument,          NULL,  0 }
  };
  Configuration config;
  GeoIP geoip;
  
  trace = new Trace();

  while((c = getopt_long(argc, argv, "c:u:l:m:vVh", long_options, NULL)) != '?') {
    if(c == 255)
      break;
    else if(c == 'c')
      config.readConfigFile(optarg);
    else if(c == 'm')
      geoip.loadCountry(optarg);
    else if(c == 'v')
      trace->set_trace_level(6);
    else
      help();
  }

  if((!config.isConfigured()) || (!geoip.isLoaded()))
    help();
  
  signal(SIGTERM, sigproc);

  try {
    iface = new NwInterface(config.getQueueId(), &config, &geoip);
    
    iface->packetPollLoop();
    delete iface;
  } catch(int err) {
    trace->traceEvent(TRACE_ERROR, "Interface creation error (%d)", err);
  }
    
  return(0);
}
