# netlock

Network lock (vpn killswitch) for macOS. Uses pf firewall.

Based on [Eddie by AirVPN](https://github.com/AirVPN/Eddie).

## Installation
```sh
$ make
$ sudo make install
```
or
```sh
$ brew tap x13a/tap
$ brew install x13a/tap/netlock
```

## Usage
```text
netlock [-hV] [-vv] [-0r6l] [-c <CONFIG_DIR>] [-a <ANCHOR>] [-t <TTL>]
	[.. -s <INTERFACE>] [.. -p <INTERFACE>] [.. -O <OWNER>]
	[.. -b <DESTINATION>] [.. -i <DESTINATION>] [.. -o <DESTINATION>]
	[.. -f <PATH>]
	-{ P | E | D | L | S }

[-h] * Print help and exit
[-V] * Print version and exit

[-v] * Verbose level (2 - enable firewall logging)
[-0] * Skipass on loopback
[-r] * Extend outgoing <INTERFACE> and <DESTINATION> from routing table
[-6] * Block IPv6
[-l] * No lan
[-c] * Path to <CONFIG_DIR> (default: ~/.config/me.lucky.netlock/)
[-a] * Use <ANCHOR> (`$` will be replaced with `248.netlock`)
[-t] * Minimum outgoing <TTL>
[-s] * Skip on <INTERFACE>
[-p] * Pass on <INTERFACE>
[-O] * Pass owned by <OWNER> ( USER | u:USER | g:GROUP )
[-b] * Block <DESTINATION>
[-i] * Pass in from <DESTINATION>
[-o] * Pass out to <DESTINATION>
[-f] * Extend outgoing <DESTINATION> from configuration <PATH>

[-P] * Print rules and exit
[-E] * Enable lock
[-D] * Disable lock
[-L] * Load lock
[-S] * Show status

INTERFACE:
  ( NAME | in:NAME | out:NAME ) direction only on pass

DESTINATION:
  ( ip | host | file )

PATH:
  ( dir | file ) only .ovpn is supported, dir scan not recursive
```

## Example

To enable and pass out on utun0, pass to destinations from openvpn 
configuration file:
```sh
$ sudo netlock -0E -p out:utun0 -f ~/my.ovpn
```

To enable while connected:
```sh
$ sudo netlock -0rE
```

To enable while connected and block ipv6, pass to quad9 dns, pass to 
destinations from text file:
```sh
$ sudo netlock -0r6E -o 9.9.9.9 -o ~/destinations.txt
```

To load last configuration (ex. after system restart):
```sh
$ sudo netlock -L
```

To disable:
```sh
$ sudo netlock -D
```

To show full status:
```sh
$ sudo netlock -Sv
```

## Caveats

When enabled, local network dns queries will be blocked.

## Friends
- [killswitch](https://github.com/vpn-kill-switch/killswitch)
