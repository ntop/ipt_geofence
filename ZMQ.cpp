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

#define DEFAULT_ZMQ_TCP_KEEPALIVE            1  /* Keepalive ON */
#define DEFAULT_ZMQ_TCP_KEEPALIVE_IDLE       30 /* Keepalive after 30 seconds */
#define DEFAULT_ZMQ_TCP_KEEPALIVE_CNT        3  /* Keepalive send 3 probes */
#define DEFAULT_ZMQ_TCP_KEEPALIVE_INTVL      3  /* Keepalive probes sent every 3 seconds */
#define MAX_SOCKET_BUFFER_SIZE 8388608 /* 8 MB */

/* ******************************* */

ZMQ::ZMQ(char *endpoint, char *server_public_key, bool client_mode) {
  context = zmq_ctx_new();

  if(context == NULL) {
    trace->traceEvent(TRACE_ERROR, "[ERROR] Unable to create ZMQ context");
    exit(1);
  }

  zmq_socket_handler = zmq_socket(context, ZMQ_PUB /* always publisher: we produce messages */);

  if(zmq_socket_handler == NULL) {
    trace->traceEvent(TRACE_ERROR, "Unable to create ZMQ socket");
    exit(1);
  }

  if(server_public_key != NULL) {
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

    rc = zmq_setsockopt(zmq_socket_handler, ZMQ_CURVE_SERVERKEY, server_public_key, strlen(server_public_key)+1);
    if (rc != 0) {
      trace->traceEvent(TRACE_ERROR, "Error setting ZMQ_CURVE_SERVERKEY = %s (%d)", server_public_key, errno);
      exit(1);
    }

    rc = zmq_setsockopt(zmq_socket_handler, ZMQ_CURVE_PUBLICKEY, client_public_key, strlen(client_public_key)+1);
    if (rc != 0) {
      trace->traceEvent(TRACE_ERROR, "Error setting ZMQ_CURVE_PUBLICKEY = %s", client_public_key);
      exit(1);
    }

    rc = zmq_setsockopt(zmq_socket_handler, ZMQ_CURVE_SECRETKEY, client_secret_key, strlen(client_secret_key)+1);
    if (rc != 0) {
      trace->traceEvent(TRACE_ERROR, "Error setting ZMQ_CURVE_SECRETKEY = %s", client_secret_key);
      exit(1);
    }
  }

  if(true) {
    int send_buffer_len = MAX_SOCKET_BUFFER_SIZE;

    if(zmq_setsockopt(zmq_socket_handler, ZMQ_SNDBUF, &send_buffer_len, sizeof(send_buffer_len)) != 0)
      trace->traceEvent(TRACE_WARNING, "ZMQ set sending buffer failed");

    int val = DEFAULT_ZMQ_TCP_KEEPALIVE;
    if(zmq_setsockopt(zmq_socket_handler, ZMQ_TCP_KEEPALIVE, &val, sizeof(val)) != 0)
      trace->traceEvent(TRACE_ERROR, "Unable to set TCP keepalive");
    else
      trace->traceEvent(TRACE_INFO, "TCP keepalive set");

    val = DEFAULT_ZMQ_TCP_KEEPALIVE_IDLE;
    if(zmq_setsockopt(zmq_socket_handler, ZMQ_TCP_KEEPALIVE_IDLE, &val, sizeof(val)) != 0)
      trace->traceEvent(TRACE_ERROR, "Unable to set TCP keepalive idle to %u seconds", val);
    else
      trace->traceEvent(TRACE_INFO, "TCP keepalive idle set to %u seconds", val);

    val = DEFAULT_ZMQ_TCP_KEEPALIVE_CNT;
    if(zmq_setsockopt(zmq_socket_handler, ZMQ_TCP_KEEPALIVE_CNT, &val, sizeof(val)) != 0)
      trace->traceEvent(TRACE_ERROR, "Unable to set TCP keepalive count to %u", val);
    else
      trace->traceEvent(TRACE_INFO, "TCP keepalive count set to %u", val);

    val = DEFAULT_ZMQ_TCP_KEEPALIVE_INTVL;
    if(zmq_setsockopt(zmq_socket_handler, ZMQ_TCP_KEEPALIVE_INTVL, &val, sizeof(val)) != 0)
      trace->traceEvent(TRACE_ERROR, "Unable to set TCP keepalive interval to %u seconds", val);
    else
      trace->traceEvent(TRACE_INFO, "TCP keepalive interval set to %u seconds", val);
  }
  
  if(client_mode) {
    if(zmq_connect(zmq_socket_handler, endpoint) != 0) {
      trace->traceEvent(TRACE_ERROR, "Unable to connect to ZMQ endpoint %s [%s]", endpoint, strerror(errno));
      throw "ZMQ connect error";
    }
  } else {
    if(zmq_bind(zmq_socket_handler, endpoint) != 0) {
      trace->traceEvent(TRACE_ERROR, "Unable to bind ZMQ endpoint %s [%s]", endpoint, strerror(errno));
      throw "ZMQ bind error";
    }
  }
};

/* ******************************* */

ZMQ::~ZMQ() {
  zmq_close(zmq_socket_handler);
  zmq_ctx_destroy(context);
};

/* ******************************* */

void ZMQ::sendMessage(const char *topic, const char *msg) {
  struct zmq_msg_hdr msg_hdr;
  u_int len = strlen(msg);

  memset(&msg_hdr, 0, sizeof(msg_hdr));
  snprintf(msg_hdr.url, sizeof(msg_hdr.url), "%s", topic);  
  msg_hdr.source_id = 999, msg_hdr.version = ZMQ_MSG_VERSION, msg_hdr.size = len;
  
  if(zmq_send(zmq_socket_handler, &msg_hdr, sizeof(msg_hdr), ZMQ_SNDMORE) != sizeof(msg_hdr))
    trace->traceEvent(TRACE_WARNING, "ZMQ send errror");
  
  if(zmq_send(zmq_socket_handler, msg, msg_hdr.size, 0) != msg_hdr.size)
    trace->traceEvent(TRACE_WARNING, "ZMQ send errror");
  else
    trace->traceEvent(TRACE_NORMAL, "Sent [topic: %s][msg: %s]", msg_hdr.url, msg);
}

/* ******************************* */

#endif /* HAVE_ZMQ */
