/*
 *
 * (C) 2021-24 - ntop.org
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

/* ****************************************************** */

std::string Utils::ltrim(std::string &s) {
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int c) {return !std::isspace(c);}));
  return s;
}

/* ****************************************************** */

std::string Utils::execCmd(const char *cmd, Trace *t) {
  std::string command(cmd);
  std::array<char, 128> buffer;
  std::string result;
  FILE* pipe;

  t->traceEvent(TRACE_INFO, "Executing %s", cmd);
    
  pipe = popen(command.c_str(), "r");
  
  if(!pipe)
    t->traceEvent(TRACE_WARNING, "Unable to run command %s", cmd);
  else {  
    while(fgets(buffer.data(), 128, pipe) != NULL)
      result += buffer.data();  
    
    pclose(pipe);
  }

  ltrim(result);
	       
  return(result);
}

/* ****************************************************** */

/* #define CURL_DEBUG */

int Utils::sendTelegramMessage(std::string bot_token, std::string chat_id,
			       std::string message, Trace *t) {
  CURL *curl = curl_easy_init();
  long response_code = -1;
  
  if(curl) {
    char *msg = curl_easy_escape(curl, message.c_str(), message.size());
    CURLcode res;
    std::string url =
      "https://api.telegram.org/bot"
      + bot_token
      + "/sendMessage?chat_id=" + chat_id
      + "&text=" + std::string(msg);
    
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

#ifdef CURL_DEBUG
    t->traceEvent(TRACE_NORMAL, "Calling %s", url.c_str());
#endif
    res = curl_easy_perform(curl);
#ifdef CURL_DEBUG
    t->traceEvent(TRACE_NORMAL, "res: %d\n", res);
#endif
    
    if(res == CURLE_OK) {
      long response_code;
      
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

#ifdef CURL_DEBUG
      t->traceEvent(TRACE_NORMAL, "response_code: %ld\n", response_code);
#endif
    } else
      t->traceEvent(TRACE_WARNING, "cURL error: %d - %s", res, url.c_str());

    /* Free */
    free(msg);
    curl_easy_cleanup(curl); 
  }

  return(response_code);
}

/* ****************************************************** */

void Utils::zapNewline(std::string &s) {
  if((!s.empty()) && s[s.length()-1] == '\n') 
    s.erase(s.size() - 1);  
}
