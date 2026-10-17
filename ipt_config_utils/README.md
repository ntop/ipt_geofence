### What you can find here
This directory contains the scripts that configure iptables for the ipt_geofence tool:

- `single_iface.sh`: single interface host (protects the services running on the host itself; inspects both incoming and locally generated traffic)
- `multichain.sh`: gateway/multi interface host (inspects incoming and routed traffic; enables IPv4 forwarding). The Debian package installs it as `/etc/ipt_geofence/ipt_setup.sh`

Usage: `<script> [start|stop]` (default: `start`)

Both scripts:
- keep all their rules in dedicated chains (`IPT_GEOFENCE_*`) hooked into the built-in chains with a single jump each; they never flush the built-in chains, change their policy or touch the nat table, so they coexist with ufw, firewalld, docker...
- can be run more than once: the rules are rebuilt, the banned hosts (`IPT_GEOFENCE_BLACKLIST`) are preserved
- remove the rules installed by their previous versions
- send to NFQUEUE only the first packet of each connection (with `--queue-bypass`, so traffic passes when ipt_geofence is not running) and never loopback traffic

`stop` removes all the ipt_geofence rules and chains (banned hosts included).
