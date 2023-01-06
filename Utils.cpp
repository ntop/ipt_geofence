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

bool Utils::toHex(char *in, u_int in_len, char *out, u_int out_len) {
  u_int i, j;
  static const char hex_digits[] = "0123456789ABCDEF";
  
  if(in_len > (2*out_len))
    return(false);

  for(i=0, j=0; i<in_len; i++) {
    u_char c = (u_char)in[i];
    
    out[j++] = hex_digits[c >> 4];
    out[j++] = hex_digits[c & 15];
  }

  out[j] = '\0';

  return(true);
}

/* ************************************************************* */

bool Utils::fromHex(char *in, u_int in_len,
		    char *out, u_int out_len) {
  u_int i, j;

  if((in_len/2) > out_len)
    return(false);

  for(i=0, j=0; i<in_len;) {
    char s[3];

    s[0] = in[i], s[1] = in[i+1], s[2] = 0;
    out[j++] = strtoul(s, NULL, 16);
    
    i += 2;
  }

  out[j] = '\0';

  return(true);
}

/* ****************************************************** */

char* Utils::intoaV4(unsigned int addr, char* buf, u_short bufLen) {
  char *cp;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    u_int byte = addr & 0xff;

    *--cp = byte % 10 + '0';
    byte /= 10;
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
	*--cp = byte + '0';
    }
    if(n > 1)
      *--cp = '.';
    addr >>= 8;
  } while(--n > 0);

  return(cp);
}

/* ****************************************************** */

char* Utils::intoaV6(struct ndpi_in6_addr ipv6, u_int8_t bitmask, char* buf, u_short bufLen) {
  char *ret;

  for(int32_t i = bitmask, j = 0; i > 0; i -= 8, ++j)
    ipv6.u6_addr.u6_addr8[j] &= i >= 8 ? 0xff : (u_int32_t)(( 0xffU << ( 8 - i ) ) & 0xffU );

  ret = (char*)inet_ntop(AF_INET6, &ipv6, buf, bufLen);

  if(ret == NULL) {
    /* Internal error (buffer too short) */
    buf[0] = '\0';
    return(buf);
  } else
    return(ret);
}

