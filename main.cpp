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

#include "include.h"

/* Global */
Trace *trace;

const char *version = IPT_RELEASE;
u_int32_t last_modification_time = 0;
NwInterface *iface;

#ifdef HAVE_NTOP_CLOUD
cloud_handler *cloud = NULL;

static int get_uuid(char *buf, u_int buf_len) {
  const char *cmd = "/bin/ls /dev/disk/by-uuid | sort -u|head -1";
  FILE *fp;
  int l;
  
  fp = popen(cmd, "r");
  if (fp == NULL)
    return(-1);

  memset(buf, 0, buf_len);
  fgets(buf, buf_len, fp);

  if((l = strlen(buf)) > 0)
    buf[l-1] = '\0';
  
  pclose(fp);

  return(0);
}

#endif

// #define DEBUG

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

#ifdef DEBUG
  delete iface;
  _exit(0);
#endif
}

/* ************************************************* */

static void help() {
  printf("Welcome to ipt_geofence v.%s\n", version);
  printf("Copyright 2021-24 ntop\n");

  printf("\nUsage:\n");
  printf("ipt_geofence [-h][-v][-s] -c <config file> -m <city>\n");
#if defined __FreeBSD__ || defined __APPLE__
  printf("             -i <ifname>\n\n");
#endif
  printf("-h                | Print this help\n");
  printf("-v                | Verbose\n");
  printf("-s                | Log to syslog\n");
  printf("-c <config>       | Specify the configuration file\n");
  printf("-m <city>         | Local mmdb_city MMDB file\n");
  printf("-T <message>      | [Debug] Send ZMQ test message and exits.\n");
#if defined __FreeBSD__
  printf("-i <ifname>       | Interface name\n");
#endif

  printf("\nExample: ipt_geofence -c sample_config.json -m dbip-country-lite.mmdb"
#if defined __FreeBSD__
	 " -i em0"
#else
#if defined __APPLE__
	 " -i en0"
#endif
#endif
	 "\n");

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
#if defined __FreeBSD__ || defined __APPLE__
    { "interface",   required_argument,    NULL, 'i' },
#endif
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

  while((c = getopt_long(argc, argv, "c:u:l:m:svVT:h"
#if defined __FreeBSD__ || defined __APPLE__
			 "i:"
#endif
			 , long_options, NULL)) != 255) {
    switch(c) {
#if defined __FreeBSD__ || defined __APPLE__
    case 'i':
      conf->setInterfaceName(optarg);
      break;
#endif

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
    trace->traceEvent(TRACE_ERROR, "Please check the JSON configuration file");
    help();
  } else if(!geoip.isLoaded()) {
    trace->traceEvent(TRACE_ERROR, "Please check the GeoIP configuration");
    help();
  }

  signal(SIGTERM, sigproc);
  signal(SIGINT,  sigproc);

#ifdef DEBUG
  signal(SIGALRM, sigproc);
  alarm(60);
#endif

#ifdef HAVE_NTOP_CLOUD
  char uuid[64];
  
  if(get_uuid(uuid, sizeof(uuid)) == 0) {
    if((cloud = init_ntop_cloud_from_conf(NULL /* Use system cloud.conf */,
					  uuid,
					  (char*)"ipt_geofence")) == NULL) {
      trace->traceEvent(TRACE_ERROR, "Unable to connect to the ntop cloud");
    } else {
      trace->traceEvent(TRACE_NORMAL, "Successfully connected to ntop cloud [%s]", uuid);
      
      /* Advertise the application is up */
      if(!ntop_cloud_register_msg(cloud,				  
				  (char*)"ipt_geofence",
				  (char*)PACKAGE_VERSION,
				  (char*)PACKAGE_MACHINE,
				  (char*)PACKAGE_OS,
				  (char*)"community",
				  uuid
				  )) {
	trace->traceEvent(TRACE_ERROR, "Unable to register to the cloud");
      } else {
	trace->traceEvent(TRACE_NORMAL, "Successfully registered with the cloud");
	trace->traceEvent(TRACE_NORMAL, "Unique id %s", cloud->my_topic);
      }
    }
  } else {
    trace->traceEvent(TRACE_ERROR, "Unable to connect to ntop cloud [%s]", uuid);
  }
#endif
  
  try {
    iface = new NwInterface(conf->getQueueId(), conf, &geoip, confPath);

    iface->packetPollLoop();
  } catch(int err) {
    trace->traceEvent(TRACE_ERROR,
		      "Interface creation error: please fix the reported "
		      "errors and try again");
  }

  delete iface;
  delete conf;

  return(0);
}
