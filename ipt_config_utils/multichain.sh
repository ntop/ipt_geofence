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

# User definable marker values
MARK_PASS=1000
MARK_DROP=2000

# Enable connection tracking in the kernel
modprobe nf_conntrack

# Enable accounting of conntrack entries
sysctl -w net.netfilter.nf_conntrack_acct=1 > /dev/null

# Reset all markers in the kernel connection table
conntrack -U --mark 0 > /dev/null 2>&1

# Routing needed by DNAT (DNS)
echo 1 > /proc/sys/net/ipv4/ip_forward

IPTABLES="iptables"
# We will execute this code using "ip6tables" instead of "iptables" the second time
for i in {1,2}; do
    # Flush chains (if present)
    $IPTABLES -t mangle -F GEO_PREROUTING
    $IPTABLES -t mangle -F GEO_POSTROUTING
    $IPTABLES -t mangle -F GEO_OUTPUT
    $IPTABLES -t mangle -X GEO_PREROUTING
    $IPTABLES -t mangle -X GEO_POSTROUTING
    $IPTABLES -t mangle -X GEO_OUTPUT

    # Create chains
    $IPTABLES -t mangle -N GEO_PREROUTING
    $IPTABLES -t mangle -N GEO_POSTROUTING
    $IPTABLES -t mangle -N GEO_OUTPUT

    # Read CONNMARK and set it in mark
    # (A) For incoming packets
    $IPTABLES -t mangle -A GEO_PREROUTING -j CONNMARK --restore-mark

    # (B) For locally generated packets
    $IPTABLES -t mangle -A GEO_OUTPUT -j CONNMARK --restore-mark

    # Save CONNMARK (1st rule of POSTROUTING)
    $IPTABLES -t mangle -A GEO_POSTROUTING -j CONNMARK --save-mark

    # PASS (1)
    $IPTABLES -t mangle -A GEO_PREROUTING --match mark --mark $MARK_PASS -j ACCEPT

    # DROP (2)
    $IPTABLES -t mangle -A GEO_PREROUTING --match mark --mark $MARK_DROP -j DROP

    # Send traffic to NFQUEUE
    $IPTABLES -t mangle -A GEO_PREROUTING  -p tcp --match mark --mark 0 -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass
    $IPTABLES -t mangle -A GEO_OUTPUT      -p tcp --match mark --mark 0 -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass

    $IPTABLES -t mangle -A GEO_PREROUTING  -p udp --match mark --mark 0 -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass
    $IPTABLES -t mangle -A GEO_OUTPUT      -p udp --match mark --mark 0 -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass

    $IPTABLES -t mangle -A GEO_PREROUTING  -p icmp --match mark --mark 0 -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass
    $IPTABLES -t mangle -A GEO_OUTPUT      -p icmp --match mark --mark 0 -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass

    ###################################################

    # Add final return
    $IPTABLES -t mangle -A GEO_PREROUTING  -j RETURN
    $IPTABLES -t mangle -A GEO_POSTROUTING -j RETURN
    $IPTABLES -t mangle -A GEO_OUTPUT      -j RETURN

    ###################################################

    # Append chains
    $IPTABLES -t mangle -A PREROUTING  -j GEO_PREROUTING
    $IPTABLES -t mangle -A POSTROUTING -j GEO_POSTROUTING
    $IPTABLES -t mangle -A OUTPUT      -j GEO_OUTPUT

    ###################################################

    # Show all
    $IPTABLES -nvL -t mangle

    $IPTABLES -t mangle -L GEO_PREROUTING
    $IPTABLES -t mangle -L GEO_POSTROUTING
    $IPTABLES -t mangle -L GEO_OUTPUT

    # Same code but using IPv6
    IPTABLES="ip6tables"
done

# Flush conntrack
#conntrack -F
