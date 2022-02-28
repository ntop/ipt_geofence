# ipt_geofence
Geographical host protection for Linux

This tool allows you to protect your host/network by preventing communications with unwanted countries (aka geofencing).

# Prerequisites
You need to install GeoIP libraries, Netfilter Queue and JSONCPP packages in addition to the compiler. For Ubuntu/Debian based systems do:

``sudo apt-get install build-essential autoconf automake autogen libmaxminddb-dev libnetfilter-queue-dev libjsoncpp-dev``

The tool also needs a GeoIP database that you can obtain from sites such as [db-ip](https://db-ip.com/db/download/ip-to-country-lite) or [maxmind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data?lang=en).

# Configuration
This tool uses NFQUEUE to receive packets from kernel and analyze them in user-space. This means that you need to confiugure the Linux firewall prior to run the application. We provide you a [simple configuration file](single_iface.sh) that shows you how to send selected packets to the applicationfor inspection.

You also need to configure a configuration file for your rules. We provide [sample_config.json](sample_config.json) as a configuration example.

# Usage
Supposing the you have configure the firewall as described above, you need to start (as root) the tool as follows

``ipt_geofence -c config.json -m dbip-country-lite.mmdb``
