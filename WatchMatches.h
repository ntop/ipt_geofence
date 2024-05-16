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

#ifndef _WATCH_MATCHES_H_
#define _WATCH_MATCHES_H_



class WatchMatches {
private:
  u_int32_t last_match;
  u_int64_t num_matches;
  int max_matches = 22;
public:
  WatchMatches() { last_match = time(NULL), num_matches = 1; }
  /* This constructor is used when we load the entries from file. */
  WatchMatches(u_int32_t _num_matches, u_int32_t _last_matches) { last_match = _last_matches, num_matches = _num_matches; }
  /*
   * Default function: max_matches = 22,
   * f(22) = 177148 * 100 ('* 100' it's required to convert in seconds) = ban for 205 days.
   * We put 22 as max value because after 23 matches the ban is greater than 1 year.
   * By changing max_matches you can change the max banning time.
   * f(1) = 3 * 100 = ban for five minutes.
   * You can change these parameters accordingly to your needs.
   * */
  int f(float x) {
      if (x >= max_matches) return 315360; //ban for one year at this point
      // /* Change this values if you want to make the function more or less steep */
      return (int) (std::pow(3, x * 0.5)) + 1.5;
  }
  bool isBanned = false;
  inline u_int32_t get_last_match()   { return(last_match);                     }
  inline u_int64_t get_num_matches()  { return(num_matches);                    }
  inline void      inc_matches()      { num_matches++, last_match = time(NULL); }
  inline bool      ready_to_harvest(u_int32_t currentTime) { return((last_match < currentTime - f(get_num_matches()) * 100 ) ? true : false); }
};

#endif /* _WATCH_MATCHES_H_ */
