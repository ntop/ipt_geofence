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

#ifndef _NTOP_CLOUD_H_
#define _NTOP_CLOUD_H_

#ifdef HAVE_NTOP_CLOUD

/* ******************************* */

class BanMsg {
public:
  std::string host_ip;
  host_blacklist_reason reason;
  std::string details;
  std::string action;
  std::string additional_info;
  std::string reporter_ip;
  std::string reporter_host;
  std::string reporter_version;
};

/* ******************************* */

class NtopCloud {
 private:
  cloud_handler *cloud;
  std::thread   infinite_thread;
  std::vector<BanMsg> messages;
  std::mutex m;
  
  int get_uuid(char *buf, u_int buf_len);

 public:
  NtopCloud();
  ~NtopCloud();

  void poll();
  void ban(char *host_ip, host_blacklist_reason reason,
	   char *details, char *action,
	   char *additional_info, char *reporter_ip,
	   char *reporter_host, char *reporter_version);
};

extern NtopCloud *cloud;

#endif /* HAVE_NTOP_CLOUD */
#endif /* _NTOP_CLOUD_H_ */
