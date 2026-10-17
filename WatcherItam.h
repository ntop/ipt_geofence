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

#ifndef _WATCHER_ITEM_H_
#define _WATCHER_ITEM_H_

/*
  A watch is a shell command (e.g. "tail -F log | grep ...") whose output
  (one IP per line) is read through a pipe. popen() is not used as it does
  not return the child pid, so the command could not be terminated on
  shutdown: the command runs in its own process group that stop() kills
  as a whole (i.e. all the processes of the pipeline)
*/
class WatcherItam {
public:
  std::string label;
  std::string cmd;
  bool        mode; /* true=geo-ip, false=block IP */

  FILE        *fd;
  int         fd_fileno;
  pid_t       pid; /* Also the process group id */

  WatcherItam()  { fd = NULL, fd_fileno = -1, pid = -1; }
  ~WatcherItam() { stop(); }

  /* ********************************************** */

  bool start(std::string command) {
    int p[2];
    pid_t parent = getpid();

    if(pipe(p) != 0)
      return(false);

    pid = fork();

    if(pid < 0) {
      close(p[0]), close(p[1]);
      pid = -1;
      return(false);
    }

    if(pid == 0) {
      /* Child: only async-signal-safe calls until exec */
      int max_fd = (int)sysconf(_SC_OPEN_MAX);

      setsid(); /* New session and process group (pgid = pid) */

#ifdef __linux__
      /* Terminate if ipt_geofence dies without calling stop() (e.g. SIGKILL) */
      prctl(PR_SET_PDEATHSIG, SIGTERM);
      if(getppid() != parent) _exit(1); /* Parent already gone */
#endif

      dup2(p[1], STDOUT_FILENO);

      /*
	Do not leak the ipt_geofence descriptors: an orphan watch holding
	the NFQUEUE netlink socket would keep the queue bound (and the host
	traffic stuck) after ipt_geofence has terminated
      */
      if((max_fd < 0) || (max_fd > 65536)) max_fd = 65536;
      for(int f = STDERR_FILENO + 1; f < max_fd; f++)
	close(f);

      execl("/bin/sh", "sh", "-c", command.c_str(), (char*)NULL);
      _exit(127);
    }

    /* Parent */
    close(p[1]);
    fd_fileno = p[0];
    fcntl(fd_fileno, F_SETFD, FD_CLOEXEC); /* Not inherited by other children */
    fcntl(fd_fileno, F_SETFL, O_NONBLOCK);

    if((fd = fdopen(fd_fileno, "r")) == NULL) {
      close(fd_fileno), fd_fileno = -1;
      stop();
      return(false);
    }

    cmd = command;
    return(true);
  }

  /* ********************************************** */

  /* Close the pipe, terminate all the processes of the watch and reap them */
  void stop() {
    if(fd != NULL)
      fclose(fd), fd = NULL, fd_fileno = -1;

    if(pid > 0) {
      int status;
      bool reaped = false;

      kill(-pid, SIGTERM);

      /* Give the command up to 2 sec to exit gracefully */
      for(int i = 0; i < 20; i++) {
	pid_t rc = waitpid(pid, &status, WNOHANG);

	if((rc == pid) || ((rc < 0) && (errno != EINTR))) {
	  reaped = true;
	  break;
	}

	usleep(100000);
      }

      /* Also the pipeline processes still alive (if any) */
      kill(-pid, SIGKILL);

      if(!reaped)
	waitpid(pid, &status, 0);

      pid = -1;
    }
  }
};

#endif /* _WATCHER_ITEM_H_ */
