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

#define USE_ENCRYPTION

int main(int argc, char *argv[]) {
  int is_server = 1;
  void *context = zmq_ctx_new();
  void *subscriber = zmq_socket(context, ZMQ_SUB);
  int rc;
  char sub_public_key[41];
  char sub_public_key_hex[83];
  char sub_secret_key[41];
  char message[13];
  const char *url = "tcp://127.0.0.1:5556";
  Trace trace;
  
#ifdef USE_ENCRYPTION
  rc = zmq_curve_keypair(sub_public_key, sub_secret_key);
  assert(rc == 0);
  
  rc = zmq_setsockopt(subscriber, ZMQ_CURVE_SECRETKEY, sub_secret_key, strlen(sub_secret_key));
  assert(rc == 0);
  
  rc = zmq_setsockopt(subscriber, ZMQ_CURVE_PUBLICKEY, sub_public_key, strlen(sub_public_key));
  assert(rc == 0);
  
  rc = zmq_setsockopt(subscriber, ZMQ_CURVE_SERVER,    &is_server,     sizeof(is_server));
  assert(rc == 0);

  Utils::toHex(sub_public_key, strlen(sub_public_key),
	       sub_public_key_hex, sizeof(sub_public_key)-1);
  trace.traceEvent(TRACE_NORMAL, "Use ZMQ server key: %s\n", sub_public_key_hex);
#endif
  
  rc = zmq_bind(subscriber, url);
  // trace.traceEvent(TRACE_NORMAL, "zmq_bind() returned %d\n", rc);
  assert(rc == 0);

  const char *topic = ""; /* Use an empty string to match all topics */
  errno = 0;
  rc = zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, topic, strlen(topic));
  // trace.traceEvent(TRACE_NORMAL, "zmq_setsockopt(%s) returned %d [%d/%s]\n", topic, rc, errno, strerror(errno));
  assert(rc == 0);

  trace.traceEvent(TRACE_NORMAL, "Listening at %s\n", url);
  
  while(1) {
    struct zmq_msg_hdr hdr;
    char buffer[1024];
    
    rc = zmq_recv(subscriber, &hdr, sizeof(hdr), 0);
    assert(rc != -1);

    hdr.size = ntohs(hdr.size);
    rc = zmq_recv(subscriber, buffer, hdr.size, 0);
    assert(rc != -1);
    
    buffer[rc] = '\0';
    trace.traceEvent(TRACE_NORMAL, "[topic: %s] %s\n", hdr.url, buffer);
  }
  
  zmq_close(subscriber);
  zmq_ctx_destroy(context);

  return 0;
}
