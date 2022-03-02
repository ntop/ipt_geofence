#!/bin/bash

#
# https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture
#
# Incoming packets destined for the local system: PREROUTING -> INPUT
# Incoming packets destined to another host: PREROUTING -> FORWARD -> POSTROUTING
# Locally generated packets: OUTPUT -> POSTROUTING
#

chain_exists()
{
    local chain_name="$1" ; shift
    
    [ $# -eq 1 ] && local table="--table $1"
    iptables $table -t mangle -n --list "$chain_name" >/dev/null 2>&1
}


if chain_exists GEO_PREROUTING; then
    # Rules already defined: nothing to do
    exit
fi

QUEUE_ID=0

# Enable connection tracking in the kernel
modprobe nf_conntrack

# Enable accounting of conntrack entries
sysctl -w net.netfilter.nf_conntrack_acct=1 > /dev/null

# Reset all markers in the kernel connection table
conntrack -U --mark 0 > /dev/null 2>&1

# Routing needed by DNAT (DNS)
echo 1 > /proc/sys/net/ipv4/ip_forward

# Flush chains (if present)
iptables -t mangle -F GEO_PREROUTING
iptables -t mangle -F GEO_POSTROUTING
iptables -t mangle -F GEO_OUTPUT
iptables -t mangle -X GEO_PREROUTING
iptables -t mangle -X GEO_POSTROUTING
iptables -t mangle -X GEO_OUTPUT

# Create chains
iptables -t mangle -N GEO_PREROUTING
iptables -t mangle -N GEO_POSTROUTING
iptables -t mangle -N GEO_OUTPUT

# Read CONNMARK and set it in mark
# (A) For incoming packets
iptables -t mangle -A GEO_PREROUTING -j CONNMARK --restore-mark

# (B) For locally generated packets
iptables -t mangle -A GEO_OUTPUT -j CONNMARK --restore-mark

# Save CONNMARK (1st rule of POSTROUTING)
iptables -t mangle -A GEO_POSTROUTING -j CONNMARK --save-mark

# PASS (1)
iptables -t mangle -A GEO_PREROUTING --match mark --mark 1 -j ACCEPT

# DROP (2)
iptables -t mangle -A GEO_PREROUTING --match mark --mark 2 -j DROP

# Send traffic to NFQUEUE
iptables -t mangle -A GEO_PREROUTING  -p tcp --match mark --mark 0 -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass
iptables -t mangle -A GEO_OUTPUT      -p tcp --match mark --mark 0 -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass

iptables -t mangle -A GEO_PREROUTING  -p udp --match mark --mark 0 -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass
iptables -t mangle -A GEO_OUTPUT      -p udp --match mark --mark 0 -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass

iptables -t mangle -A GEO_PREROUTING  -p icmp --match mark --mark 0 -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass
iptables -t mangle -A GEO_OUTPUT      -p icmp --match mark --mark 0 -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass

###################################################

# Add final return
iptables -t mangle -A GEO_PREROUTING  -j RETURN
iptables -t mangle -A GEO_POSTROUTING -j RETURN
iptables -t mangle -A GEO_OUTPUT      -j RETURN

###################################################

# Append chains
iptables -t mangle -A PREROUTING  -j GEO_PREROUTING
iptables -t mangle -A POSTROUTING -j GEO_POSTROUTING
iptables -t mangle -A OUTPUT      -j GEO_OUTPUT

###################################################

# Show all
iptables -nvL -t mangle

iptables -t mangle -L GEO_PREROUTING
iptables -t mangle -L GEO_POSTROUTING
iptables -t mangle -L GEO_OUTPUT

# Flush conntrack
conntrack -F
