#!/system/bin/sh

MODDIR=${0%/*}
iptables -t mangle -N nfqttli
iptables -t mangle -A nfqttli -j NFQUEUE --queue-num 1

iptables -t mangle -N nfqttlo
iptables -t mangle -A nfqttlo -j NFQUEUE --queue-num 1

iptables -t mangle -I PREROUTING -j nfqttli
iptables -t mangle -I POSTROUTING -j nfqttlo

ip6tables -t mangle -N nfqttli
ip6tables -t mangle -A nfqttli -j NFQUEUE --queue-num 1

ip6tables -t mangle -N nfqttlo
ip6tables -t mangle -A nfqttlo -j NFQUEUE --queue-num 1

ip6tables -t mangle -I PREROUTING -j nfqttli
ip6tables -t mangle -I POSTROUTING -j nfqttlo
cd $MODDIR

./nfqttl -d -t64 -s5