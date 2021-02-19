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
    $MODDIR/nfqttl -n4096 -t65
    sleep 5
done

iptables -t mangle -N nfqttli
iptables -t mangle -A nfqttli -i lo -j RETURN
iptables -t mangle -A nfqttli -i tun -j RETURN
iptables -t mangle -A nfqttli -i tap -j RETURN
iptables -t mangle -A nfqttli -d 255.255.255.255 -j RETURN
iptables -t mangle -A nfqttli -m ttl ! --ttl 128 -m ttl ! --ttl 64 -m ttl ! --ttl 1 -j RETURN
iptables -t mangle -A nfqttli -m mark --mark 0x10000000 -j RETURN
iptables -t mangle -A nfqttli -j MARK --set-mark 0x10000000
iptables -t mangle -A nfqttli -j NFQUEUE --queue-num 0x1000
iptables -t mangle -I PREROUTING -j nfqttli

ip6tables -t mangle -I FORWARD -j DROP
exit 0