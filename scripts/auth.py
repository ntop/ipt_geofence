#!/usr/bin/env python3

#
# (C) 2023 - ntop
#

import subprocess
import re

filename = "/var/log/auth.log"
f = subprocess.Popen(['tail','-n', '0', '-F',filename], stdout=subprocess.PIPE,stderr=subprocess.PIPE)

try:
    while True:
        line = f.stdout.readline()

        if(len(line) == 0):
            break
        else:
            line = line.decode('utf-8').strip()

        if("Connection closed by invalid user" in line):
            #  Connection closed by invalid user Nobody 1.2.3.4 port 18656 [preauth]
            res = line.split()
            ip =  res[11]
            print(ip, flush=True)
        elif("Disconnected from invalid user" in line):
            #  Connection closed by invalid user Nobody 1.2.3.4 port 18656 [preauth]
            res = line.split()
            ip =  res[10]
            print(ip, flush=True)
        elif("Failed password for" in line):
            # sshd[128237]: Failed password for nprobe from 1.2.3.4 port 49298 ssh2
            res = line.split()
            ip =  res[10]
            print(ip, flush=True)
except:
    print("")
