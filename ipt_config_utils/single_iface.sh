#!/bin/bash

#
# https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture
#
# Incoming packets destined for the local system: PREROUTING -> INPUT
# Incoming packets destined to another host: PREROUTING -> FORWARD -> POSTROUTING
# Locally generated packets: OUTPUT -> POSTROUTING
#


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
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 

IPTABLES="iptables"
# We will execute this code using "ip6tables" instead of "iptables" the second time
for i in {1,2}; do
    $IPTABLES -F
    $IPTABLES -t nat -F
    $IPTABLES -t mangle -F
    
    # Read CONNMARK and set it in mark
    # (A) For incoming packets
    $IPTABLES -t mangle -A PREROUTING -j CONNMARK --restore-mark
    # (B) For locally generated packets
    $IPTABLES -t mangle -A OUTPUT -j CONNMARK --restore-mark
    
    # Save CONNMARK (1st rule of POSTROUTING)
    $IPTABLES -t mangle -A POSTROUTING -j CONNMARK --save-mark

    # PASS (1)
    $IPTABLES -t mangle -A PREROUTING  --match mark --mark $MARK_PASS -j ACCEPT

    # DROP (2)
    $IPTABLES -t mangle -A PREROUTING  --match mark --mark $MARK_DROP -j DROP

    # Send traffic to NFQUEUE
    $IPTABLES -t mangle -A PREROUTING  -p tcp --match mark --mark 0 -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass
    $IPTABLES -t mangle -A OUTPUT      -p tcp --match mark --mark 0 -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass

    $IPTABLES -t mangle -A PREROUTING  -p udp --match mark --mark 0 -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass
    $IPTABLES -t mangle -A OUTPUT      -p udp --match mark --mark 0 -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass

    $IPTABLES -t mangle -A OUTPUT      -p icmp --match mark --mark 0 -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass
    $IPTABLES -t mangle -A OUTPUT      -p icmp --match mark --mark 0 -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass

    ###################################################

    # Show all
    $IPTABLES -nvL -t mangle

    # Same code but using IPv6
    IPTABLES="ip6tables"
done

# Flush conntrack
#conntrack -F
