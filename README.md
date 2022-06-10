# Nfqttl

* Nfqttl - module for modifying the ttl value in the packet header.
* Sets the ttl value of 64 for the packet on the mobile data interface and sets the ttl value of 65 for the packet on the local interface (wifi, bluetooth).
* Splitting the TCP package.
* For incoming packets, if ttl == 1, set to ttl 64.
* IPv6 packets are dropped.

## How to use

* Download and install from storage in Magisk App the installing archive:
[nfqttl2.8.zip](https://github.com/cyborg-one/nfqttl/releases/download/2.8/nfqttl2.8.zip) or 
[nfqttl2.1.2.zip](https://github.com/cyborg-one/nfqttl/releases/download/2.1.2/nfqttl2.1.2.zip).
* Reboot.
* When device boots, Magisk will start the module.

## How it work

* The networking subsystem of the Linux kernel has a mechanism to pass network packets to the user 
application for processing (NetFilter Queue). Nfqttl receives packets, edits the ttl packet header fields and the checksum, 
and sends them back to the kernel.

## Compatibility

* Magisk 20.4+
* Nfqueue

## Links

- [GitHub repository module](https://github.com/cyborg-one/nfqttl)
- [GitHub repository source](https://github.com/cyborg-one/nfqttl-src)

## Changelog

v2.5
* Add tcp sequence split.

v2.6
* The volume of the buffer is expanded.

v2.7
* Fixes.

v2.8
* Update code.

## Donate

* bitcoin:bc1qxmsn9qeptpa90sxejz8em4w5rvcggnmrvq34uh

## License

[GNU GPLv3](https://github.com/cyborg-one/nfqttl/blob/master/LICENSE).
