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

#ifndef _LINUX_FIREWALL_H_
#define _LINUX_FIREWALL_H_

/* ********************************************** */

class Firewall {
protected:
  void execCmd(char *cmdbuf) {
    try {
      Utils::execCmd(cmdbuf);
    } catch (...) { trace->traceEvent(TRACE_ERROR, "Error while executing '%s'", cmdbuf); }
  }
  

public:
  Firewall()  { setup();     }
  ~Firewall() { tearDown();  }
  
  virtual void setup() { ; }
  virtual void tearDown() { ; }
  virtual void ban(char *ip, bool is_ipv4) { ; }
  virtual void unban(char *ip, bool is_ipv4) { ; }

};

#endif /* _LINUX_FIREWALL_H_ */

  
