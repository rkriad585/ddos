# CLI reference

The executable is named `ddos`. Run `ddos --help` for the built-in summary.

## Basic checks

### `resolve <host> [options]`

Resolves a host and prints IPv4/IPv6 addresses. Use `--family ipv4` or
`--family ipv6` to restrict the result, and `--output json` for a
machine-readable result.

```sh
ddos resolve example.com --output json
ddos resolve example.com --family ipv6
```

### `tcp-check <host> <port> [options]`

Attempts bounded TCP connections to every resolved address. Timeout values are
1–120 seconds; retries are 0–5.

```sh
ddos tcp-check example.com 443 --timeout 5 --retry 2
```

### `http-check <host> <port|80> [options]`

Sends one HTTP `HEAD` request. The default port is 80 and the default path is
`/`. Paths must begin with `/`, contain no newlines, and be at most 2048 bytes.

```sh
ddos http-check example.com --path /health --timeout 5
```

Pass `80` explicitly or omit the port; an invalid port value is an error, not
a silent default.

## `udp-check <host> <port> [options]`

Sends one bounded UDP datagram per resolved address and waits for a reply,
an ICMP "port unreachable" error, or a timeout.

```sh
ddos udp-check 1.1.1.1 53 --payload 123401000001000000000000 --timeout 3
```

- `--payload <hex>` sends custom bytes (1–1400 bytes; default payload is
  `ping\n`).
- Retries re-send the datagram with 50 ms exponential backoff.

## `dns-check <host> [options]`

Sends one DNS query built by the built-in minimal DNS-over-UDP client.
Record types: `A`, `AAAA`, `CNAME`, `TXT`, `MX`, `NS`.

```sh
ddos dns-check example.com --dns-type A --dns-server 1.1.1.1
ddos dns-check example.com --dns-type TXT --output json | jq '.answers'
```

- `--dns-server <ip>` selects the resolver (IPv4/IPv6 literal). On Unix it
  defaults to the first `nameserver` in `/etc/resolv.conf`.
- Response codes are reported (`NXDOMAIN`, `SERVFAIL`, ...); a non-zero code
  is a failure.

## `diagnose <url|host:port> [options]`

Runs bounded DNS, TCP, and optional HTTP/HTTPS checks and reports per-address
results and total timing. HTTPS uses certificate validation through the
Rustls-backed HTTP client and reports the peer certificate subject, issuer,
serial, expiry, SANs, and validity window. Redirects are limited to five hops
by default and can be changed with `--redirects 0-10`.

```sh
ddos diagnose https://example.com/health --timeout 5
ddos diagnose https://example.com/health --output json | jq .
ddos diagnose https://example.com --method GET --expect-status 200 --show-header server
```

JSON output has schema version `1` and includes `target`, `resolved`, `http`,
`ok`, `total_elapsed_ms`, and an optional `error` field. Exit status is `0`
for a successful report, `1` when a diagnostic fails, and `2` for invalid
usage.

## HTTP request options

Custom headers, authentication, and a bounded body read work on `http-check`
and `diagnose`:

```sh
ddos diagnose https://example.com --header "X-Trace-Id: 8f14e45f" --show-header server
ddos diagnose https://api.example.com --auth basic "user:pass"
ddos diagnose https://api.example.com --auth bearer "$TOKEN"
ddos diagnose https://example.com/large.json --method GET --body-bytes 65536
ddos diagnose https://example.com --user-agent "healthbot/1.0"
```

Notes:

- `--header "Name: value"` may be repeated, up to 20 headers. `Host`,
  `Connection`, `Content-Length`, `Transfer-Encoding`, `Expect`, and
  `Authorization` are rejected: the transport manages them (use `--auth` for
  the last one).
- `--auth basic` Base64-encodes `user:pass` credentials and `--auth bearer`
  sends `Bearer <token>`; both keep credentials out of custom headers but
  remain visible to `ps`-style process listing, like `curl --user`.
- `--body-bytes` works with `--method GET` only, reads at most 1 MiB, and
  reports `body`, `body preview` and content type—sized for health checks,
  not downloads.

## Output formats

`--output` accepts `text`, `json`, `jsonl` (one compact JSON document per
line — ideal for `batch` and `repeat`), and `csv`.

```sh
ddos batch targets.txt --output jsonl | jq -c 'select(.ok == false)'
ddos diagnose https://example.com --output csv
```

## `batch <file|-> [options]`

Checks up to 100 non-empty, non-comment lines. `-` reads targets from stdin;
up to eight bounded workers process the list.

```sh
ddos batch targets.txt --output json
printf '%s\n' https://example.com https://example.org | ddos batch - --output json
```

## `repeat <url|host:port> --interval <seconds> --duration <seconds>`

Repeats one bounded diagnostic until the duration expires. The duration is
limited to one hour.

```sh
ddos repeat https://example.com --interval 10 --duration 60
```

## `load-test <url|host:port> [options]`

Consent-gated load testing for servers **you operate**: it sends sequentially
paced HTTP requests and reports status codes and latency.

Hard restrictions — these are enforced, not advisory:

- **Loopback targets only** (`localhost`, `127.0.0.1`, `::1`). Any other host
  name or address is refused with exit code 2.
- Rate cap: `--rate 1-50` requests per second (default 10); requests are
  sequential with pacing, so no concurrency is possible.
- Volume cap: `--count 1-5000` total requests (default 20).

```sh
ddos load-test http://localhost:3030 --rate 20 --count 100
ddos load-test http://localhost:3030 --method GET --rotate-user-agent --output json
```

Options: `--rotate-user-agent` selects a different user agent per request
from a pool of current browser user agents (Chrome, Firefox, Safari, Edge —
desktop and mobile), for testing user-agent-based rules on your own server;
standard HTTP
options (`--header`, `--method`, `--expect-status`, ...) apply. Output
`json`, `jsonl`, and `csv` modes report `sent`, `ok`, `failed`, a status
histogram, latency min/avg/max, and the actual request rate.

Use this to verify your own rate limiting, connection limits, and blocking
rules once per change. For anything beyond loopback — including servers you
own on a network you do not control — use a dedicated consent-based tool
(`k6`, `wrk`, `hey`) in accordance with your provider's terms.

## Configuration

Default config file: `$XDG_CONFIG_HOME/ddos/config.toml`
(usually `~/.config/ddos/config.toml`), `%APPDATA%\ddos\config.toml` on
Windows. It uses `key = value` lines; `#` starts a comment.

```toml
# ~/.config/ddos/config.toml
timeout = 5
retries = 1
output = "text"
family = "any"
method = "HEAD"
redirects = 5
# user-agent = "healthbot/1.0"
# auth-basic = "user:pass"
# header = "X-Trace-Id: 8f14e45f"
# show-header = "server"
# expect-status = 200
```

Precedence: CLI arguments > `DDOS_*` environment variables > config file.
Use `--config <path>` for an alternate file (it must exist) and
`--no-config` to ignore the default file for one run.

`DDOS_*` variables: `DDOS_TIMEOUT`, `DDOS_RETRIES`, `DDOS_OUTPUT`, `DDOS_PATH`,
`DDOS_METHOD`, `DDOS_FAMILY`, `DDOS_EXPECT_STATUS`, `DDOS_REDIRECTS`,
`DDOS_PROXY`, `DDOS_USER_AGENT`, `DDOS_BODY_BYTES`, `DDOS_SHOW_HEADER`
(comma separated), `DDOS_HEADER` (semicolon separated `"Name: value"` items),
`DDOS_AUTH` (`basic:USER:PASS` or `bearer:TOKEN`), `DDOS_RATE`,
`DDOS_COUNT`, and `DDOS_ROTATE_USER_AGENT` (`true`/`false`, load-test).

```sh
DDOS_OUTPUT=json DDOS_TIMEOUT=10 ddos diagnose https://example.com
```

## Common options

- `--output text|json|jsonl|csv` selects human or machine-readable output.
- `--timeout <seconds>` sets a 1–120 second operation timeout.
- `--retry <count>` enables 0–5 bounded retries.
- `--family any|ipv4|ipv6` restricts which resolved addresses are used.
- `--method HEAD|GET` selects the bounded request method.
- `--expect-status <code>` makes the selected status the success condition.
- `--show-header <name>` includes selected response headers.
- `--redirects <count>` allows 0–10 redirects.
- `--proxy <url>` uses an explicit HTTP/HTTPS proxy; otherwise standard proxy
  environment variables remain available to the HTTP client.
- `--verbose` includes failed address details in text output.
- `--config <path>` / `--no-config` control configuration loading (above).

## Shell completions

Completion definitions are provided in [`completions/`](https://github.com/rkriad585/ddos/tree/main/completions)
for Bash, Zsh, Fish, PowerShell, and Nushell.

## Maintenance commands

- `ddos self-update` runs the official platform installer.
- `ddos self-uninstall` removes the current executable.
- `ddos --version` prints the Cargo package version.
- `ddos --help` prints usage.

[Back to README](https://github.com/rkriad585/ddos/blob/main/README.md)
