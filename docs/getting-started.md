# Getting started

This guide gets the Rust CLI running locally and performs a harmless DNS
lookup.

## Build

```sh
cargo build --release
```

The executable is `target/release/ddos`.

## Run

```sh
ddos resolve localhost
ddos tcp-check example.com 443 --timeout 5
ddos http-check example.com --path / --timeout 5
ddos diagnose https://example.com --output json
```

More diagnostics:

```sh
# UDP probe: send one datagram to Cloudflare DNS and wait for a reply
ddos udp-check 1.1.1.1 53 --payload 123401000001000000000000 --timeout 3

# DNS record lookup through the built-in minimal DNS-over-UDP client
ddos dns-check example.com --dns-type A --dns-server 1.1.1.1
# OK A example.com via 1.1.1.1 (63 ms)
#   A example.com ttl 119s 172.66.147.243
#   A example.com ttl 119s 104.20.23.154

# Machine-readable formats: json, jsonl, csv
ddos diagnose https://example.com --output jsonl | head -1
```

## Load-test a local server

`load-test` is restricted to loopback URLs (`localhost`, `127.0.0.1`, `::1`)
with a 50 req/s rate cap and a 5000-request volume cap. Start any web server
you own, for example:

```sh
python3 -m http.server 3030
```

Then run:

```sh
ddos load-test http://localhost:3030 --rate 20 --count 100 --rotate-user-agent --method GET
```

```text
LOAD-TEST http://localhost:3030 sent 100 ok 100 failed 0 (5041 ms total, 19.8 req/s actual, target 20 req/s)
  statuses: 200x100
  latency min 2 ms avg 3 ms max 55 ms (user agents rotated)
```

All checks are bounded. The program does not flood, spoof, randomize targets,
or scan ranges. Batch mode is the only concurrent workflow and is capped at
eight workers over explicitly supplied targets.

[Back to README](https://github.com/rkriad585/ddos/blob/main/README.md)
