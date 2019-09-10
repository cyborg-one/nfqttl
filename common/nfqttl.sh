#!/system/bin/sh

iptables -t mangle -D FORWARD -j NFQUEUE --queue-num 201
iptables -t mangle -A FORWARD -j NFQUEUE --queue-num 201

ip6tables -t mangle -D FORWARD -j NFQUEUE --queue-num 201
ip6tables -t mangle -A FORWARD -j NFQUEUE --queue-num 201

	while ! [ `pgrep -x nfqttl` ] ; do
	    $MODDIR/system/bin/nfqttl && sleep 1
	done
