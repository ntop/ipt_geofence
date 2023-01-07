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

/* Global */
Trace *trace;

const char *version = IPT_RELEASE;
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
  printf("ipt_geofence [-h][-v][-s] -c <config file> -m <city>\n\n");
  printf("-h                | Print this help\n");
  printf("-v                | Verbose\n");
  printf("-s                | Log to syslog\n");
  printf("-c <config>       | Specify the configuration file\n");
  printf("-m <city>         | Local mmdb_city MMDB file\n");
  printf("-T <message>      | [Debug] Send ZMQ test message and exits.\n");

  printf("\nExample: ipt_geofence -c sample_config.json -m dbip-country-lite.mmdb\n");

  exit(0);
}

/* ************************************************* */

int main(int argc, char *argv[]) {
  u_char c;
  std::string confPath = "";
  const struct option long_options[] = {
    { "config",      required_argument,    NULL, 'c' },
    { "mmdb_city",   required_argument,    NULL, 'm' },
    { "help",        no_argument,          NULL, 'h' },
    { "syslog",      no_argument,          NULL, 's' },
    { "zmq-test",    required_argument,    NULL, 'T' },
    { "verbose",     no_argument,          NULL, 'v' },
    /* End of options */
    { NULL,          no_argument,          NULL,  0 }
  };
  GeoIP geoip;
  const char *zmq_test_msg = NULL;
  Configuration *conf;
  
  trace = new Trace();
  conf = new Configuration();
  
  while((c = getopt_long(argc, argv, "c:u:l:m:svVT:h", long_options, NULL)) != 255) {
    switch(c) {
    case 'c':
      confPath = (optarg);
      conf->readConfigFile(confPath.c_str());
      break;

    case 'm':
      geoip.loadCountry(optarg);
      break;

    case 's':
      trace->traceToSyslogOnly();
      break;

    case 'T':
      zmq_test_msg = optarg;
      break;

    case 'v':
      trace->set_trace_level(6);
      break;

    default:
      trace->traceEvent(TRACE_WARNING, "Unknown command line option -%c", c);
      help();
    }
  }

  if(zmq_test_msg) {
    if(!conf->getZMQUrl().empty()) {
      std::string url = conf->getZMQUrl();
      std::string enc = conf->getZMQEncryptionKey();
      ZMQ zmq(url.c_str(), enc.c_str());

      trace->traceEvent(TRACE_NORMAL, "Sending message on topic %s to %s. Hold on..",
			ZMQ_TOPIC_NAME, conf->getZMQUrl().c_str());

      sleep(2); /* Wait until ZMQ is setup */

      trace->traceEvent(TRACE_NORMAL, "Sending data...");
      
      for(int i=0; i<10; i++)
	zmq.sendMessage(ZMQ_TOPIC_NAME, zmq_test_msg);

      conf->sendTelegramMessage(zmq_test_msg);
      
      return(0);
    }
  }
  
  if(!conf->isConfigured()) {
    trace->traceEvent(TRACE_ERROR, "Please check the JSON confuration file");
    help();
  } else if(!geoip.isLoaded()) {
    trace->traceEvent(TRACE_ERROR, "Please check the GeoIP confuration");
    help();
  }

  signal(SIGTERM, sigproc);
  signal(SIGINT,  sigproc);

  try {
    iface = new NwInterface(conf->getQueueId(), conf, &geoip, confPath);

    iface->packetPollLoop();
  } catch(int err) {
    trace->traceEvent(TRACE_ERROR, "Interface creation error: please fix the reported errors and try again");
  }
  
  delete iface;
  delete conf;

  return(0);
}
