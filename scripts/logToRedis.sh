#!/bin/sh

#
# Log banned hosts to redis along with the number of times
# the host has been banned
#
# Usage: logToRedis.sh <ip address>
#

DATE=$(date '+%Y-%m-%d')
KEY="banned_hosts-$DATE"

redis-cli HINCRBY $KEY $1 1

