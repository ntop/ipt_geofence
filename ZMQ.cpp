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

#ifdef HAVE_ZMQ

/* ******************************* */

ZMQ::ZMQ(char *endpoint, char *server_public_key) {
  errno = 0;
  context = zmq_ctx_new();
  
  if(context == NULL) {
    trace->traceEvent(TRACE_ERROR, "[ERROR] Unable to create ZMQ context");
    exit(1);
  }

  flow_publisher = zmq_socket(context, ZMQ_PUB);

  if(flow_publisher == NULL) {
    trace->traceEvent(TRACE_ERROR, "Unable to create ZMQ publisher");
    exit(1);
  }

  if (server_public_key != NULL) {
    char client_public_key[41];
    char client_secret_key[41];
    int rc;

    rc = zmq_curve_keypair(client_public_key, client_secret_key);

    if (rc != 0) {
      trace->traceEvent(TRACE_ERROR, "Error generating ZMQ client key pair");
      exit(1);
    }

    if (strlen(server_public_key) != 40) {
      trace->traceEvent(TRACE_ERROR, "Bad ZMQ server public key size (%lu != 40)", strlen(server_public_key));
      exit(1);
    }

    rc = zmq_setsockopt(flow_publisher, ZMQ_CURVE_SERVERKEY, server_public_key, strlen(server_public_key)+1);

    if (rc != 0) {
      trace->traceEvent(TRACE_ERROR, "Error setting ZMQ_CURVE_SERVERKEY = %s (%d)", server_public_key, errno);
      exit(1);
    }

    rc = zmq_setsockopt(flow_publisher, ZMQ_CURVE_PUBLICKEY, client_public_key, strlen(client_public_key)+1);

    if (rc != 0) {
      trace->traceEvent(TRACE_ERROR, "Error setting ZMQ_CURVE_PUBLICKEY = %s", client_public_key);
      exit(1);
    }

    rc = zmq_setsockopt(flow_publisher, ZMQ_CURVE_SECRETKEY, client_secret_key, strlen(client_secret_key)+1);

    if (rc != 0) {
      trace->traceEvent(TRACE_ERROR, "Error setting ZMQ_CURVE_SECRETKEY = %s", client_secret_key);
      exit(1);
    }
  }
  
  if(zmq_bind(flow_publisher, endpoint) != 0) {
    trace->traceEvent(TRACE_ERROR, "Unable to bind ZMQ endpoint %s [%s]", endpoint, strerror(errno));
    throw "ZMQ bind error";
  }
};

/* ******************************* */

ZMQ::~ZMQ() {
  zmq_close(flow_publisher);
  zmq_ctx_destroy(context);
};

/* ******************************* */

void ZMQ::sendMessage(const char *topic, const char *msg) {
  struct zmq_msg_hdr msg_hdr;
  u_int len = strlen(msg);
  
  snprintf(msg_hdr.url, sizeof(msg_hdr.url), "%s", topic);
  
  msg_hdr.version = 0, msg_hdr.size = len;
  zmq_send(flow_publisher, &msg_hdr, sizeof(msg_hdr), ZMQ_SNDMORE);
  zmq_send(flow_publisher, msg, msg_hdr.size, 0);
}

/* ******************************* */

#endif /* HAVE_ZMQ */
