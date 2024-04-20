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

#ifndef _WATCH_MATCHES_H_
#define _WATCH_MATCHES_H_

#define MAX_IDLENESS   60 /* 5 minutes */


class WatchMatches {
private:
  u_int32_t last_match, num_matches;
  /**
   * Change this parameters if you want to customize the function used for calculating the banning time.
   */
  const int function_a = 3;
  const int function_base = 6;
  const int function_b = 0.3f;
  const int function_offset = -2;
  const int max_matches = 12;
public:
  WatchMatches() { last_match = time(NULL), num_matches = 1; }
  WatchMatches(u_int32_t _num_matches, u_int32_t _last_matches) { last_match = _last_matches, num_matches = _num_matches; }
  int f(int x) {
      if (x >= max_matches) return 315360; //ban for one year at this point
      return (int) (function_a * std::pow(function_base, function_b * x) - function_offset);
  }
  inline u_int32_t get_last_match()   { return(last_match);                     }
  inline u_int32_t get_num_matches()  { return(num_matches);                    }
  inline void      inc_matches()      { num_matches++, last_match = time(NULL); }
  inline bool      ready_to_harvest() { return((last_match < time(NULL) - f(get_num_matches()) * 100 ) ? true : false); }
};


#endif /* _WATCH_MATCHES_H_ */
