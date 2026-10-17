#!/bin/bash

#
# ipt_geofence iptables setup for a single interface host
# (i.e. protect the services running on this host)
#
# Usage: single_iface.sh [start|stop]
#
# All the rules live in dedicated chains (IPT_GEOFENCE_*) hooked into the
# built-in chains with a single jump each. This script never flushes the
# built-in chains, never changes their policy and never touches the nat
# table, so it coexists with ufw, firewalld, docker... and can be run
# more than once (e.g. as systemd ExecStartPre) without side effects.
#
# https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture
#
# Incoming packets destined for the local system: PREROUTING -> INPUT
# Locally generated packets: OUTPUT -> POSTROUTING
#

QUEUE_ID=0

# Marker values: they must match the "markers" of the configuration file
MARK_PASS=1000
MARK_DROP=2000

# Wait (at most 10 sec) for the xtables lock if held by another tool
WAIT="-w 10"

# Chains
BLACKLIST=IPT_GEOFENCE_BLACKLIST   # filter: banned IPs (managed by ipt_geofence)
PRE=IPT_GEOFENCE_PRE               # mangle PREROUTING
OUT=IPT_GEOFENCE_OUT               # mangle OUTPUT
SAVE=IPT_GEOFENCE_SAVE             # mangle INPUT and POSTROUTING

###################################################

# Insert a rule at the top of a built-in chain (only if not present)
ensure_rule() {
    local ipt="$1" table="$2" chain="$3"; shift 3

    $ipt $WAIT -t $table -C $chain "$@" 2>/dev/null \
	|| $ipt $WAIT -t $table -I $chain 1 "$@"
}

# Delete all the occurrences of a rule (if any)
delete_rule() {
    local ipt="$1" table="$2" chain="$3"; shift 3
    local n=0

    while [ $n -lt 64 ] && $ipt $WAIT -t $table -D $chain "$@" 2>/dev/null; do
	n=$((n+1))
    done
}

# Create an empty chain (flush it if already present)
reset_chain() {
    local ipt="$1" table="$2" chain="$3"

    $ipt $WAIT -t $table -N $chain 2>/dev/null || $ipt $WAIT -t $table -F $chain
}

# Delete a chain (if present)
remove_chain() {
    local ipt="$1" table="$2" chain="$3"

    $ipt $WAIT -t $table -F $chain 2>/dev/null
    $ipt $WAIT -t $table -X $chain 2>/dev/null
}

# Remove the rules installed directly in the built-in chains by the previous
# versions of this script (they flushed the whole tables and filled them)
remove_legacy_rules() {
    local ipt="$1" proto chain

    # multichain.sh
    delete_rule  $ipt mangle PREROUTING  -j GEO_PREROUTING
    delete_rule  $ipt mangle POSTROUTING -j GEO_POSTROUTING
    remove_chain $ipt mangle GEO_PREROUTING
    remove_chain $ipt mangle GEO_POSTROUTING

    # single_iface.sh
    delete_rule $ipt mangle PREROUTING  -j CONNMARK --restore-mark
    delete_rule $ipt mangle OUTPUT      -j CONNMARK --restore-mark
    delete_rule $ipt mangle POSTROUTING -j CONNMARK --save-mark
    delete_rule $ipt mangle INPUT       -j CONNMARK --save-mark
    delete_rule $ipt mangle PREROUTING  -m mark --mark $MARK_PASS -j ACCEPT
    delete_rule $ipt mangle PREROUTING  -m mark --mark $MARK_DROP -j DROP
    delete_rule $ipt mangle PREROUTING  -i lo -j ACCEPT
    delete_rule $ipt mangle OUTPUT      -o lo -j ACCEPT

    for proto in tcp udp icmp; do
	for chain in PREROUTING OUTPUT; do
	    delete_rule $ipt mangle $chain -p $proto -m mark --mark 0 \
			-j NFQUEUE --queue-num $QUEUE_ID --queue-bypass
	    delete_rule $ipt mangle $chain -p $proto -m mark --mark 0 -m conntrack --ctstate NEW \
			-j NFQUEUE --queue-num $QUEUE_ID --queue-bypass
	done
    done
}

###################################################

stop_family() {
    local ipt="$1"

    remove_legacy_rules $ipt

    delete_rule $ipt mangle PREROUTING  -j $PRE
    delete_rule $ipt mangle OUTPUT      -j $OUT
    delete_rule $ipt mangle INPUT       -j $SAVE
    delete_rule $ipt mangle POSTROUTING -j $SAVE
    delete_rule $ipt filter INPUT       -j $BLACKLIST

    remove_chain $ipt mangle $PRE
    remove_chain $ipt mangle $OUT
    remove_chain $ipt mangle $SAVE
    remove_chain $ipt filter $BLACKLIST
}

###################################################

start_family() {
    local ipt="$1" proto protos="tcp udp"
    local queue="-m mark --mark 0 -m conntrack --ctstate NEW -j NFQUEUE --queue-num $QUEUE_ID --queue-bypass"

    # IPv4 only: with ip6tables "-p icmp" never matches, and queueing ICMPv6
    # could drop neighbor discovery and break IPv6 connectivity
    [ "$ipt" = "iptables" ] && protos="$protos icmp"

    remove_legacy_rules $ipt

    # Blacklist: created if missing but NOT flushed, as its content (the
    # banned hosts) is managed by ipt_geofence that might be running
    $ipt $WAIT -t filter -N $BLACKLIST 2>/dev/null
    delete_rule $ipt filter INPUT -j $BLACKLIST          # Remove duplicates (if any)
    ensure_rule $ipt filter INPUT -j $BLACKLIST || return 1

    reset_chain $ipt mangle $PRE  || return 1
    reset_chain $ipt mangle $OUT  || return 1
    reset_chain $ipt mangle $SAVE || return 1

    # (A) Incoming packets

    # Never queue loopback traffic (e.g. systemd-resolved, local databases):
    # it must not depend on ipt_geofence being alive and responsive
    $ipt $WAIT -t mangle -A $PRE -i lo -j RETURN
    # Read CONNMARK and set it in mark
    $ipt $WAIT -t mangle -A $PRE -j CONNMARK --restore-mark
    # PASS
    $ipt $WAIT -t mangle -A $PRE -m mark --mark $MARK_PASS -j ACCEPT
    # DROP
    $ipt $WAIT -t mangle -A $PRE -m mark --mark $MARK_DROP -j DROP
    # Send to NFQUEUE only the first packet of a connection (NEW): the verdict
    # is stored in the connmark and enforced by the rules above for the next
    # packets. --queue-bypass: if ipt_geofence is not running traffic passes
    for proto in $protos; do
	$ipt $WAIT -t mangle -A $PRE -p $proto $queue || return 1
    done

    # (B) Locally generated packets
    $ipt $WAIT -t mangle -A $OUT -o lo -j RETURN
    $ipt $WAIT -t mangle -A $OUT -j CONNMARK --restore-mark
    for proto in $protos; do
	$ipt $WAIT -t mangle -A $OUT -p $proto $queue || return 1
    done

    # (C) Save the mark (i.e. the verdict) in CONNMARK. Packets for the local
    # host (PREROUTING -> INPUT) never reach POSTROUTING: save it on INPUT too
    $ipt $WAIT -t mangle -A $SAVE -j CONNMARK --save-mark || return 1

    # Hook the chains (one jump per built-in chain, at the top)
    ensure_rule $ipt mangle PREROUTING  -j $PRE  || return 1
    ensure_rule $ipt mangle OUTPUT      -j $OUT  || return 1
    ensure_rule $ipt mangle INPUT       -j $SAVE || return 1
    ensure_rule $ipt mangle POSTROUTING -j $SAVE || return 1

    return 0
}

###################################################

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run $0 as root" >&2
    exit 1
fi

ACTION="${1:-start}"

case "$ACTION" in
    start)
	# Enable connection tracking in the kernel
	modprobe nf_conntrack 2>/dev/null

	# Enable accounting of conntrack entries
	sysctl -q -w net.netfilter.nf_conntrack_acct=1 > /dev/null 2>&1
	;;
    stop)
	;;
    *)
	echo "Usage: $0 [start|stop]" >&2
	exit 1
	;;
esac

#
# Note: the CONNMARKs of the existing connections are left untouched.
# Resetting them (as done in the past) would let the packets of the flows
# already dropped pass, as only NEW connections are sent to NFQUEUE
#

RC=0
for IPTABLES in iptables ip6tables; do
    if ! command -v $IPTABLES > /dev/null 2>&1 || ! $IPTABLES $WAIT -t mangle -S > /dev/null 2>&1; then
	echo "$IPTABLES not available: skipping it"
	continue
    fi

    if [ "$ACTION" = "start" ]; then
	if start_family $IPTABLES; then
	    echo "$IPTABLES: ipt_geofence rules installed"
	    $IPTABLES $WAIT -t mangle -S | grep IPT_GEOFENCE
	    $IPTABLES $WAIT -t filter -S | grep -- "-j $BLACKLIST"
	else
	    echo "$IPTABLES: unable to install the ipt_geofence rules" >&2
	    RC=1
	fi
    else
	stop_family $IPTABLES
	echo "$IPTABLES: ipt_geofence rules removed"
    fi
done

exit $RC
