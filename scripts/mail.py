#!/usr/bin/env python3

#
# (C) 2023 - ntop
#

import subprocess
import re

filename = "/var/log/mail.log"

f = subprocess.Popen(['tail','-n', '0', '-F',filename], stdout=subprocess.PIPE,stderr=subprocess.PIPE)

try:
    while True:
        line = f.stdout.readline()

        if(len(line) == 0):
            break
        else:
            line = line.decode('utf-8').strip()

        if("SASL LOGIN authentication failed: authentication failure" in line):
            # warning: unknown[1.2.3.4]: SASL LOGIN authentication failed: authentication failure
            # print(line)        
            res = re.findall(r'\[.*?\]', line)
            ip = res[1][1:-1]
            print(ip, flush=True)
        elif("no auth attempts" in line):
            # dovecot: imap-login: Disconnected (no auth attempts in 0 secs): user=<>, rip=1.2.3.4, lip=5.6.7.8, TLS handshaking: Connection closed, session=<ga2E2tDx98WnY9G4>
            #print(line)
            res = re.findall(r'rip=.*? ', line)
            ip = res[0][4:-2].strip()
            print(ip, flush=True)
except:
    print("")
