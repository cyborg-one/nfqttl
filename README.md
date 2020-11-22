# Nfqttl

* Nfqttl - module for modifying the ttl value in the packet header and splitting the tcp sequence.
* For outgoing packets, the ttl value is set to 64 and the tcp sequence split.
* For incoming packets, if ttl <= 1, set to ttl 64.
* IPv6 packets are dropped.

## How to use

* Install the module using Magisk Manager (either by downloading the module within the app
or by manually downloading [a zip from releases](https://github.com/cyborg-one/nfqttl/releases)).
* Reboot.
* When the device boots, Magisk will start the module.

## Compatibility

* Magisk 20+
* Nfqueue

## Links

- [GitHub repository](https://github.com/cyborg-one/nfqttl)
- [**Donate** support Author bitcoin (btc)](https://www.blockchain.com/btc/address/bc1qxmsn9qeptpa90sxejz8em4w5rvcggnmrvq34uh)

## License

[GNU GPLv3](https://github.com/cyborg-one/nfqttl/blob/master/LICENSE).
