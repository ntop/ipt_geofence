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
#echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 
# Do NOT enable IPv6 forwarding: it makes the kernel ignore router
# advertisements, so a SLAAC host would lose its IPv6 default route

IPTABLES="iptables"
# We will execute this code using "ip6tables" instead of "iptables" the second time
for i in {1,2}; do
    $IPTABLES -F
    $IPTABLES -t nat -F
    $IPTABLES -t mangle -F

    # Create the blacklist chain where we will store IP to ban
    # Flush all if already there
    $IPTABLES -F IPT_GEOFENCE_BLACKLIST 2>/dev/null
    $IPTABLES -X IPT_GEOFENCE_BLACKLIST 2>/dev/null
    $IPTABLES -N IPT_GEOFENCE_BLACKLIST
    # Return to the original chain
    $IPTABLES -A IPT_GEOFENCE_BLACKLIST -j RETURN
    # Jump to the blacklist chain
    $IPTABLES -I INPUT  -j IPT_GEOFENCE_BLACKLIST
    
    # Read CONNMARK and set it in mark
    # (A) For incoming packets
    $IPTABLES -t mangle -A PREROUTING -j CONNMARK --restore-mark
    # (B) For locally generated packets
    $IPTABLES -t mangle -A OUTPUT -j CONNMARK --restore-mark
    
    # Save CONNMARK (1st rule of POSTROUTING)
    $IPTABLES -t mangle -A POSTROUTING -j CONNMARK --save-mark

    # Packets for the local host (PREROUTING -> INPUT) never reach POSTROUTING,
    # and rules after NFQUEUE in PREROUTING are skipped once the verdict is
    # given: save the mark here so that the next packets of the flow skip NFQUEUE
    $IPTABLES -t mangle -A INPUT -j CONNMARK --save-mark

    # The NFQUEUE verdict is always NF_ACCEPT with a marker: enforce the
    # drop marker on the packet that has been just inspected
    #$IPTABLES -t mangle -A INPUT   --match mark --mark $MARK_DROP -j DROP
    #$IPTABLES -t mangle -A FORWARD --match mark --mark $MARK_DROP -j DROP

    # PASS (1)
    $IPTABLES -t mangle -A PREROUTING  --match mark --mark $MARK_PASS -j ACCEPT

    # DROP (2)
    $IPTABLES -t mangle -A PREROUTING  --match mark --mark $MARK_DROP -j DROP

    # Never queue loopback traffic (e.g. systemd-resolved, local databases):
    # it must not depend on ipt_geofence being alive and responsive
    $IPTABLES -t mangle -A PREROUTING  -i lo -j ACCEPT
    $IPTABLES -t mangle -A OUTPUT      -o lo -j ACCEPT

    # Send traffic to NFQUEUE. Only the first packet of a connection (NEW) is
    # queued: the verdict is stored in the connmark and enforced by the rules
    # above for the following packets, so the userland process sees one packet
    # per connection instead of all the packets of not-yet-marked flows
    $IPTABLES -t mangle -A PREROUTING  -p tcp --match mark --mark 0 -m conntrack --ctstate NEW -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass
    $IPTABLES -t mangle -A OUTPUT      -p tcp --match mark --mark 0 -m conntrack --ctstate NEW -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass

    $IPTABLES -t mangle -A PREROUTING  -p udp --match mark --mark 0 -m conntrack --ctstate NEW -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass
    $IPTABLES -t mangle -A OUTPUT      -p udp --match mark --mark 0 -m conntrack --ctstate NEW -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass

    # IPv4 only: with ip6tables "-p icmp" never matches, and queueing ICMPv6
    # could drop neighbor discovery and break IPv6 connectivity
    if [ "$IPTABLES" = "iptables" ]; then
	$IPTABLES -t mangle -A PREROUTING  -p icmp --match mark --mark 0 -m conntrack --ctstate NEW -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass
	$IPTABLES -t mangle -A OUTPUT      -p icmp --match mark --mark 0 -m conntrack --ctstate NEW -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass
    fi

    ###################################################

    # Show all
    $IPTABLES -nvL -t mangle

    # Same code but using IPv6
    IPTABLES="ip6tables"
done

# Flush conntrack
#conntrack -F
