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

#ifndef _ZMQ_H_
#define _ZMQ_H_

/* ******************************* */

struct zmq_msg_hdr {
  char url[16];
  u_int8_t version;
  u_int16_t size;
  u_int32_t msg_id, source_id;
};

#define ZMQ_MSG_VERSION           2

class ZMQ {
 private:
  void *context, *zmq_socket_handler;

 public:
  ZMQ(const char *zmq_enpoint, const char *server_public_key);
  ~ZMQ();

  void sendMessage(const char *topic, const char *msg);
};


#endif /* _ZMQ_H_ */
