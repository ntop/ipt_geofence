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

#ifndef _GEOIP_H_
#define _GEOIP_H_

/* ******************************* */

class GeoIP {
 private:
  bool loaded;
  MMDB_s mmdb_country;
  
 public:
  GeoIP() { loaded = false; }
  ~GeoIP();

  inline bool isLoaded()       { return(loaded);   }
  bool loadCountry(const char *ip_city_data);
  bool lookup(char *ip,
	      char *country_code, u_int8_t country_code_len,
	      char *continent, u_int8_t continent_len);
};


#endif /* _GEOIP_H_ */
