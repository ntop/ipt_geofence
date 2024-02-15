/*
 *
 * (C) 2021-24 - ntop.org
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

#ifdef HAVE_NTOP_CLOUD


/* ******************************* */

static void infiniteloop(NtopCloud &obj) {
  while(true) {
    obj.poll();
  }
}

/* ******************************* */

NtopCloud::NtopCloud() {
  char uuid[64];

  if(get_uuid(uuid, sizeof(uuid)) == 0) {
    if((cloud = ntop_cloud_init_from_conf(NULL /* Use system cloud.conf */,
					  uuid,
					  (char*)"ipt_geofence")) == NULL) {
      trace->traceEvent(TRACE_ERROR, "Unable to connect to the ntop cloud");
      throw("Unable to connect to ntop cloud");
    } else {
      trace->traceEvent(TRACE_NORMAL, "Successfully connected to ntop cloud [%s]",
			ntop_cloud_get_topic_name(cloud));

      /* Advertise the application is up */
      if(!ntop_cloud_register_msg(cloud,
				  (char*)"ipt_geofence",
				  (char*)PACKAGE_VERSION,
				  (char*)PACKAGE_MACHINE,
				  (char*)PACKAGE_OS,
				  (char*)"community", uuid)) {
	trace->traceEvent(TRACE_ERROR, "Unable to register to the cloud");
	throw("Unable to connect to ntop cloud");
      } else {
	trace->traceEvent(TRACE_NORMAL, "Successfully registered with the cloud");
	trace->traceEvent(TRACE_NORMAL, "Unique id %s", ntop_cloud_get_topic_name(cloud));
      }
    }

    infinite_thread = std::thread(infiniteloop, std::ref(*this));
  } else {
    throw("Unable to connect to ntop cloud");
  }
}

/* ******************************* */

NtopCloud::~NtopCloud() {
  ntop_cloud_term(cloud);
};

/* ******************************* */

int NtopCloud::get_uuid(char *buf, u_int buf_len) {
  const char *cmd = "/bin/ls /dev/disk/by-uuid | sort -u|head -1";
  FILE *fp;
  int l;
  char *ret;

  fp = popen(cmd, "r");
  if (fp == NULL)
    return(-1);

  memset(buf, 0, buf_len);
  ret = fgets(buf, buf_len, fp);

  if(ret != NULL) {
    if((l = strlen(buf)) > 0)
      buf[l-1] = '\0';
  }

  pclose(fp);

  return(0);
}

/* ******************************* */

void NtopCloud::poll() {
  char *msg, *out_topic;
  u_int16_t out_topic_len;
  u_int32_t msg_len;
  struct timeval timeout = { 1 /* sec */, 0 };

  if(ntop_cloud_poll(cloud, &timeout,
		     &out_topic, &out_topic_len,
		     &msg, &msg_len)) {
    /* Message received */
    trace->traceEvent(TRACE_NORMAL,
		      "[topic %.*s][msg %.*s]",
		      out_topic_len, out_topic,
		      msg_len, msg);

    if(ntop_cloud_handle_message(cloud, out_topic, out_topic_len,
				 msg, msg_len, NULL, NULL) == false)
      trace->traceEvent(TRACE_WARNING, "Unable to handle received message");
  }

  if(!messages.empty()) {
    bool ret;
    BanMsg b_msg;

    m.lock();
    b_msg = messages.front();
    messages.erase(messages.begin());
    m.unlock();

    trace->traceEvent(TRACE_NORMAL, "Banning host %s", b_msg.host_ip.c_str());

    ret = ntop_cloud_report_host_blacklist(cloud,
					   (char*)b_msg.host_ip.c_str(),
					   b_msg.reason,
					   (char*)b_msg.details.c_str(),
					   (char*)b_msg.action.c_str(),
					   (char*)b_msg.additional_info.c_str(),
					   (char*)b_msg.reporter_ip.c_str(),
					   (char*)b_msg.reporter_host.c_str(),
					   (char*)b_msg.reporter_version.c_str());

    if(!ret)
      trace->traceEvent(TRACE_NORMAL, "Banning message sent %s", ret ? "OK" : "ERROR");
  }
}

/* ******************************* */

void NtopCloud::ban(char *host_ip,
		    host_blacklist_reason reason,
		    char *details,
		    char *action,
		    char *additional_info,
		    char *reporter_ip,
		    char *reporter_host,
		    char *reporter_version) {
  BanMsg b_msg;

  b_msg.host_ip = std::string(host_ip);
  b_msg.reason = reason;
  b_msg.details = std::string(details);
  b_msg.action = std::string(action);
  b_msg.additional_info = std::string(additional_info);
  b_msg.reporter_ip = std::string(reporter_ip);
  b_msg.reporter_host = std::string(reporter_host);
  b_msg.reporter_version = std::string(reporter_version);

  m.lock();
  messages.push_back(b_msg);
  m.unlock();

  trace->traceEvent(TRACE_INFO, "Queued banned host %s", host_ip);
}

/* ******************************* */

#endif
