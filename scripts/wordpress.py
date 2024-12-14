#!/usr/bin/env python3

#
# (C) 2023 - ntop
#

import subprocess
import re
import sys
import os
import time

if(len(sys.argv) != 2):
    print("Usage: wordpress.py <filename>")
    exit(0)


filename = sys.argv[1]

debug = False
#debug = True

if(debug == False):
    f = subprocess.Popen(['tail','-n', '0', '-F',filename], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
else:
    f = subprocess.Popen(['cat',filename], stdout=subprocess.PIPE,stderr=subprocess.PIPE)

##################################################

def hit_found(ip):
    print(ip, flush=True)

##################################################

def harvest(c, when):
    for k in c:
        if(when > (c[k]['when'] + 3600)):
            del c[ip]

##################################################

def inc_hit(c, ip, threshold, what):
    if(not(ip in c)):
        c[ip] = { 'hits': 0, 'when': now }

    c[ip]['hits'] = c[ip]['hits'] + 1
    c[ip]['when'] = now

    if(c[ip]['hits'] == threshold):
        if(debug):
            print("[" + what + "] " + ip + " = " + str(c[ip]['hits']))

        hit_found(ip)

        # Once we block an ip we delete it from the cache and start over
        del c[ip]

##################################################

def dec_hit(c, ip):
    if(ip in c):
        c[ip]['hits'] = c[ip]['hits'] - 1

        if(c[ip]['hits'] == 0):
            del c[ip]

##################################################

failure_cache = {}
redirect_cache = {}

##################################################

try:
    while True:
        line = f.stdout.readline()
        now = int(time.time())

        if(len(line) == 0):
            break
        else:
            line = line.decode('utf-8').strip()

        res = line.split(" ")
        ip =  res[0]
        ret_code = res[len(res)-2]

        # Delete entries older than 1h
        harvest(failure_cache, now)

        if(("/wp-login" in line) or ("/wp-admin" in line) or ("/wp-config" in line)):
            #  1.2.3.4 - - [09/Jan/2023:14:03:02 +0100] "GET /wp-admin/ HTTP/1.1" 401 583
            #print(line)
            hit_found(ip)

        elif(ret_code == "403"):
            inc_hit(failure_cache, ip, 10, "failure")

        elif(ret_code == "301"):
            inc_hit(redirect_cache, ip, 20, "redirect")

        elif(ret_code == "200"):
            dec_hit(failure_cache, ip)
            dec_hit(redirect_cache, ip)


except:
    print("")
