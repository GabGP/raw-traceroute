# traceroute — raw-socket implementation in C

## Requirements

* Linux, `gcc` and `make`.
* Root privileges (`sudo`) to run it: the program opens RAW sockets.
* The system traceroute, only for the comparison test:
  `sudo apt-get install traceroute`.

## Compile

```sh
make            # builds build/bin/traceroute and copies it to ./traceroute
make clean      # removes build/ and ./traceroute
```

## Run

```sh
sudo ./traceroute galileo.edu
sudo ./traceroute -n -f 1 -m 30 -q 3 -w 2 -z 50 8.8.8.8
```

```
usage: traceroute [-n] [-f first_ttl] [-m max_ttl] [-q nqueries] [-w waittime_s] [-z sendwait_ms] host
```

| Flag | Meaning | Default | Accepted range |
|------|---------|---------|----------------|
| `-f first_ttl` | Initial TTL (first hop shown) | `1` | 1–255 |
| `-m max_ttl` | Maximum number of hops | `64` | 1–255 |
| `-q nqueries` | Probes sent per hop | `3` | 1–10 |
| `-w waittime_s` | Seconds to wait for a reply before it counts as a timeout | `3` | 1–60 |
| `-z sendwait_ms` | Pause between probes, in milliseconds | `100` | 0–10000 |
| `-n` | Do not resolve addresses to hostnames | off | — |

`host` can be a hostname or an IPv4 address.

## Test

Automated tests (no root needed): unit tests for checksums and header
building/parsing, and CLI argument validation.

```sh
make test
```

Live network tests (needs `sudo`):

```sh
make test-integration
```

Comparison against the system traceroute: runs both tools with the same
arguments, saves `tests/logs/own_<host>.log` and `tests/logs/system_<host>.log`,
and prints a side-by-side diff.

```sh
tests/compare.sh                       # default: 8.8.8.8 with -n -m 20 -q 3 -w 2 -z 100
tests/compare.sh galileo.edu           # another host, same default arguments
tests/compare.sh 8.8.8.8 -n -q 2 -m 12 # host first, then the shared arguments
```

To watch the probes and the ICMP replies on the wire while a trace runs:

```sh
sudo tcpdump -ni any 'icmp or udp portrange 33434-33534'
```
