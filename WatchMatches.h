/*
 *
 * (C) 2021-26 - ntop.org
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

#define DEFAULT_BAN_TIME      300 /* 5 minutes: ban time is DEFAULT_BAN_TIME * num_matches^2 */
#define MAX_NUM_MATCHES        99
#define MIN_MATCH_INTERVAL     60 /* While banned count at most one offence per minute */
#define BAN_MEMORY_TIME     86400 /* Forget a host 24h after its last ban has expired */

/*
  History of a host that has been banned. The record outlives the ban:
  when the ban expires the host is unbanned but its history is kept for
  BAN_MEMORY_TIME, so that if it misbehaves again the ban time escalates
*/
class WatchMatches {
private:
  u_int32_t last_match, num_matches, banned_until;
  bool banned;

public:
  WatchMatches(u_int32_t now) {
    last_match = now, num_matches = 1, banned = true;
    banned_until = now + DEFAULT_BAN_TIME;
  }

  inline u_int32_t get_num_matches()    { return(num_matches);  }
  inline u_int32_t get_banned_until()   { return(banned_until); }
  inline bool      is_banned()          { return(banned);       }

  /*
    Register a new offence. While banned, the offences seen less than
    MIN_MATCH_INTERVAL ago are ignored (return false): each new connection
    (including SYN retransmissions) of a banned host is still inspected,
    as NFQUEUE (mangle) comes before the IPT_GEOFENCE_BLACKLIST drop (filter)
  */
  inline bool offence(u_int32_t now) {
    if(banned && ((now - last_match) < MIN_MATCH_INTERVAL))
      return(false);

    if(num_matches < MAX_NUM_MATCHES) num_matches++;
    last_match = now;
    return(true);
  }

  /* (Re)ban the host: ban time grows with the square of the offences */
  inline u_int32_t ban(u_int32_t now) {
    u_int32_t until = now + (DEFAULT_BAN_TIME * num_matches * num_matches);

    if(until > banned_until) banned_until = until;
    banned = true;

    return(banned_until);
  }

  inline void unban()                           { banned = false;                                         }
  inline bool ready_to_unban(u_int32_t now)     { return(banned && (banned_until < now));                 }
  inline bool ready_to_forget(u_int32_t now)    { return((!banned) && ((banned_until + BAN_MEMORY_TIME) < now)); }
};

#endif /* _WATCH_MATCHES_H_ */
