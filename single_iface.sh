#!/bin/bash

#
# https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture
#
# Incoming packets destined for the local system: PREROUTING -> INPUT
# Incoming packets destined to another host: PREROUTING -> FORWARD -> POSTROUTING
# Locally generated packets: OUTPUT -> POSTROUTING
#

QUEUE_ID=0

# Enable connection tracking in the kernel
modprobe nf_conntrack

# Enable accounting of conntrack entries
sysctl -w net.netfilter.nf_conntrack_acct=1 > /dev/null

# Reset all markers in the kernel connection table
conntrack -U --mark 0 > /dev/null 2>&1

# Routing needed by DNAT (DNS)
echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -F
iptables -t nat -F
iptables -t mangle -F

# Read CONNMARK and set it in mark
# (A) For incoming packets
iptables -t mangle -A PREROUTING -j CONNMARK --restore-mark
# (B) For locally generated packets
iptables -t mangle -A OUTPUT -j CONNMARK --restore-mark

# Save CONNMARK (1st rule of POSTROUTING)
iptables -t mangle -A POSTROUTING -j CONNMARK --save-mark

# PASS (1)
iptables -t mangle -A PREROUTING  --match mark --mark 1 -j ACCEPT

# DROP (2)
iptables -t mangle -A PREROUTING  --match mark --mark 2 -j DROP

# Send traffic to NFQUEUE
iptables -t mangle -A PREROUTING  -p tcp --sport 80 --match mark --mark 0 -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass
iptables -t mangle -A OUTPUT  -p tcp --dport 80 --match mark --mark 0 -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass


###################################################

# Show all
iptables -nvL -t mangle

# Flush conntrack
conntrack -F
