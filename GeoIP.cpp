/*
 *
 * (C) 2021-26 - ntop.org
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

#ifndef min
#define min(a,b) (a < b ? a : b)
#endif

/* ********************************************************************************* */

bool GeoIP::loadCountry(const char *ip_country_data) {
  if(MMDB_open(ip_country_data, MMDB_MODE_MMAP, &mmdb_country) != MMDB_SUCCESS) {
    trace->traceEvent(TRACE_ERROR, "Unable to load %s", ip_country_data);
    return(false);
  } else
    trace->traceEvent(TRACE_NORMAL, "Successfully loaded %s", ip_country_data);

  loaded = true;

  return(true);
}

/* ********************************************************************************* */

GeoIP::~GeoIP() {
  if(loaded)
    MMDB_close(&mmdb_country);
}

/* ********************************************************************************* */

bool GeoIP::lookup(IPAddress *ip,
		   char *country_code, u_int8_t country_code_len,
		   char *continent, u_int8_t continent_len) {
  int mmdb_error;
  MMDB_lookup_result_s result;
  MMDB_entry_data_s entry_data;
  struct sockaddr_in sa4;
  struct sockaddr_in6 sa6;
  struct sockaddr *sa;

  /* Numeric lookup: no need to convert the address to string */
  if(ip->isIPv4()) {
    memset(&sa4, 0, sizeof(sa4));
    sa4.sin_family = AF_INET, sa4.sin_addr = *ip->getIPv4();
    sa = (struct sockaddr*)&sa4;
  } else {
    memset(&sa6, 0, sizeof(sa6));
    sa6.sin6_family = AF_INET6, sa6.sin6_addr = *ip->getIPv6();
    sa = (struct sockaddr*)&sa6;
  }

  result = MMDB_lookup_sockaddr(&mmdb_country, sa, &mmdb_error);

  if((mmdb_error != MMDB_SUCCESS)
     || (!result.found_entry)) {
    country_code[0] = '\0';

    return(false);
  } else {
    int status;
    
    if(country_code_len > 0) {
      status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);

      if((status != MMDB_SUCCESS) || (!entry_data.has_data))
	country_code[0] = '\0';
      else {
	int str_len = min(entry_data.data_size, country_code_len-1);

	memcpy(country_code, entry_data.utf8_string, str_len);
	country_code[str_len] = '\0';
      }
    }

    if(continent_len > 0) {
      status = MMDB_get_value(&result.entry, &entry_data, "continent", "code", NULL);

      if((status != MMDB_SUCCESS) || (!entry_data.has_data))
	continent[0] = '\0';
      else {
	int str_len = min(entry_data.data_size, continent_len-1);

	memcpy(continent, entry_data.utf8_string, str_len);
	continent[str_len] = '\0';
      }
    }
  }

  return(true);
}
