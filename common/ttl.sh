#!/system/bin/sh

iptables -t mangle -D POSTROUTING -j TTL --ttl-set 64
iptables -t mangle -I POSTROUTING -j TTL --ttl-set 64

ip6tables -t mangle -D POSTROUTING -j HL --hl-set 64
ip6tables -t mangle -A POSTROUTING -j HL --hl-set 64