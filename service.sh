#!/sbin/sh
MODDIR=${0%/*}
count=0
while true
do
    if ps | grep $MODDIR/nfqttl | grep -v grep | grep -q $MODDIR/nfqttl
    then
	break
    fi
    if [ "$count" -ge 8 ]
    then
	exit 1
    fi
    count=$(($count+1))
    $MODDIR/nfqttl -d -t64 -s4
    sleep 5
done

iptables -t mangle -N nfqttli
iptables -t mangle -A nfqttli -j NFQUEUE --queue-num 0x1000
iptables -t mangle -N nfqttlo
iptables -t mangle -A nfqttlo -j NFQUEUE --queue-num 0x1000
iptables -t mangle -I PREROUTING -j nfqttli
iptables -t mangle -I POSTROUTING -j nfqttlo

ip6tables -t mangle -N nfqttli
ip6tables -t mangle -A nfqttli -j NFQUEUE --queue-num 0x1000
ip6tables -t mangle -N nfqttlo
ip6tables -t mangle -A nfqttlo -j NFQUEUE --queue-num 0x1000
ip6tables -t mangle -I PREROUTING -j nfqttli
ip6tables -t mangle -I POSTROUTING -j nfqttlo
exit 0