#!/sbin/sh
MODDIR=${0%/*}
sleep 20
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
    $MODDIR/nfqttl -n6464 -t65
    sleep 5
done


iptables -t mangle -N nfqttli
iptables -t mangle -A nfqttli -i lo -j ACCEPT
iptables -t mangle -A nfqttli -i tun+ -j ACCEPT
iptables -t mangle -A nfqttli -i tap+ -j ACCEPT
iptables -t mangle -A nfqttli -d 255.255.255.255 -j ACCEPT
iptables -t mangle -A nfqttli -p udp --dport 1900 -j ACCEPT
iptables -t mangle -A nfqttli -p udp --dport 5353 -j ACCEPT
iptables -t mangle -A nfqttli -p igmp -m ttl --ttl 1 -j ACCEPT
iptables -t mangle -A nfqttli -m ttl --ttl 1 -j NFQUEUE --queue-num 6464
iptables -t mangle -A nfqttli -m ttl --ttl 64 -j NFQUEUE --queue-num 6464
iptables -t mangle -A nfqttli -m ttl --ttl 128 -j NFQUEUE --queue-num 6464
iptables -t mangle -A PREROUTING -j nfqttli


iptables -t mangle -N nfqttlo
iptables -t mangle -A nfqttlo -m ttl ! --ttl 64 -j ACCEPT
iptables -t mangle -A nfqttlo -s 192.168.1.0/24 ! -d 192.168.1.0/24 -j NFQUEUE --queue-num 6464
iptables -t mangle -A nfqttlo -s 192.168.42.0/24 ! -d 192.168.42.0/24 -j NFQUEUE --queue-num 6464
iptables -t mangle -A nfqttlo -s 192.168.43.0/24 ! -d 192.168.43.0/24 -j NFQUEUE --queue-num 6464
iptables -t mangle -A nfqttlo -s 192.168.44.0/24 ! -d 192.168.44.0/24 -j NFQUEUE --queue-num 6464
iptables -t mangle -A OUTPUT -j nfqttlo


ip6tables -t filter -N nfqttlo
ip6tables -t filter -A nfqttlo -o eth+ -j DROP
ip6tables -t filter -A nfqttlo -o wlan+ -j DROP
ip6tables -t filter -A nfqttlo -o tiwlan+ -j DROP
ip6tables -t filter -A nfqttlo -o ra+ -j DROP
ip6tables -t filter -A nfqttlo -o bnep+ -j DROP
ip6tables -t filter -A nfqttlo -o bt-pan -j DROP
ip6tables -t filter -A nfqttlo -o rndis+ -j DROP
ip6tables -t filter -I OUTPUT -j nfqttlo
ip6tables -t filter -I FORWARD -j DROP

exit 0