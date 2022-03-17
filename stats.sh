#!/bin/bash

if [ $# -ne 1 ]; 
    then echo "Usage: $0 <output file path>"
    exit 1
fi
if [ ! -f $1 ];
    then echo "Specified file does not exist"
    exit 1
fi

output=$1

# basic stats
lines=$(grep "" $output | wc -l)
pass=$(grep "\[PASS\]" $output | wc -l)
drop=$(grep "\[DROP\]" $output | wc -l)
ignored=$(grep "Ignoring" $output | wc -l)
pass_p=$(bc <<< $pass*100/$lines)
drop_p=$(bc <<< $drop*100/$lines)
ignored_p=$(bc <<< $ignored*100/$lines)

echo "
Total lines	= $lines
Pass 		= $pass	$pass_p%
Drop 		= $drop	$drop_p%
Ignored 	= $ignored	$ignored_p%"

# count how many packets were not directed to special addresses
REG_OUT_ADDR="[A-Z]{2}\s((->)|(\[PASS\]|\[DROP\])){1}"
cmd='egrep "$REG_OUT_ADDR" "$output"'
out=$(eval $cmd | wc -l)
#eval $cmd # echo matched if you need to debug
echo "Sent outside the local network: $out"

# Regex to recognize valid IPv6 addresses
REG_IPV6="(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"

# count how many ipv6 packets were sent
cmd='egrep "$REG_IPV6" "$output"'
ipv6=$(eval $cmd | wc -l)
#eval $cmd # echo matched if you need to debug
ipv6_p=$(bc <<< "$ipv6*100/($pass+$drop+$ignored)")
echo "ipv6 packets sent: $ipv6   $ipv6_p%"

# count how many ipv6 packets were sent outside the local network
ipv6_out=$(egrep "$REG_IPV6.*$REG_OUT_ADDR" $output | wc -l)
ipv6_out_p=$(bc <<< "$ipv6_out*100/($pass+$drop+$ignored)")
echo "ipv6 packets sent outside the network: $ipv6_out  $ipv6_out_p%"



echo "
    Note: '<value>%' are calculated percentages on the total number of packets sent"
