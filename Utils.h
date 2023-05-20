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

#ifndef _UTILS_H_
#define _UTILS_H_

class Utils {
 public:
  static std::string ltrim(std::string &s);
  static bool  toHex(char *in, u_int in_len, char *out, u_int out_len);
  static bool  fromHex(char *in, u_int in_len, char *out, u_int out_len);
  static char* intoaV4(unsigned int addr, char* buf, u_short bufLen);
  static char* intoaV6(struct ndpi_in6_addr ipv6, u_int8_t bitmask, char* buf, u_short bufLen);
  static std::string execCmd(const char *cmd);
  static int sendTelegramMessage(std::string bot_token, std::string chat_id, std::string message);
};

#endif /* _UTILS_H_ */
