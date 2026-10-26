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

Sample output:

```text
$ ddos resolve example.com --output csv
host,family,address
example.com,ipv4,104.20.23.154
example.com,ipv4,172.66.147.243
example.com,ipv6,2606:4700:10::6814:179a
example.com,ipv6,2606:4700:10::ac42:93f3
```

Resolve exits `1` when no addresses are available.

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

Sample output against a resolver that answers (payload shown is a small
hand-built DNS query for `example.com/A`):

```text
$ ddos udp-check 1.1.1.1 53 --payload 123401000001000000000000076578616d706c6503636f6d0000010001 --timeout 3 --verbose
OK 1.1.1.1:53 (34 ms)
  ipv4 1.1.1.1:53 answered (34 ms, 61 bytes)
```

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

Sample output:

```text
$ ddos dns-check example.com --dns-type A --dns-server 1.1.1.1
OK A example.com via 1.1.1.1 (63 ms)
  A example.com ttl 119s 172.66.147.243
  A example.com ttl 119s 104.20.23.154
```

A domain with no records of the requested type reports an error:

```text
FAIL CNAME example.org via 9.9.9.9 (121 ms)
  error: no CNAME records returned
```

## `tls-check <host> [port|443] [options]`

Connects with Rustls certificate validation and reports the peer certificate
subject, issuer, serial, validity window, expiry status, SANs, negotiated TLS
protocol, and cipher suite. The port defaults to `443`.

```sh
ddos tls-check example.com
ddos tls-check example.com 8443 --output json
```

Text output:

```text
OK TLS example.com:443 (91 ms)
TLS: CN=example.com -> C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 3 (expires Dec 25 22:56:35 2026 +00:00) serial 01:ee:e6:aa:bb:52:1d:5e:14:fc:31:5f:d9:98:56:90
  valid from: Jul 27 22:56:36 2026 +00:00
  expired: false
  protocol: TLSv1_3
  cipher suite: TLS13_AES_256_GCM_SHA384
  SANs: example.com, *.example.com
```

## `user-agents [--output ...]`

Prints the built-in realistic browser user-agent pool used by
`--rotate-user-agent` and `--random-user-agent`.

```sh
ddos user-agents
ddos user-agents --output json
```

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

## `report <url|host:port> [options]`

Runs the same bounded diagnostic as `diagnose`, forces the HTTP security-header
audit on, and prints a Markdown assessment report suitable for an engagement
write-up:

```sh
ddos report https://client.example --scope scope.txt > assessment.md
ddos report https://client.example --scope scope.txt --audit-log engagement.jsonl
```

The report includes:

- overall pass/fail and a summary table for DNS, TCP, HTTP, TLS, and security
  headers;
- resolved addresses with connection status and latency;
- HTTP status, body size, and every checked security header;
- TLS subject, issuer, serial, validity window, protocol, cipher suite, and
  SANs;
- the active scope file and a note that the checks are automated and bounded.

Use `--output json|jsonl|csv` to emit the underlying `DiagnosticReport`
instead of Markdown.

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

## HTTP security header audit

`--audit-headers` adds a quick defensive review to `http-check` and
`diagnose`. It checks for HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`,
`Referrer-Policy`, `Permissions-Policy`, and the two cross-origin isolation
headers:

```sh
ddos http-check client.example 443 --audit-headers
ddos diagnose https://client.example --audit-headers --output json
```

Text output marks each header `present` or `missing`; JSON includes a
`security_headers` array with names, presence, and values. The audit also
computes a weighted score (0–100) and letter grade (A–F), exposed as
`security_score` and `security_grade` in JSON and shown in text and Markdown
reports. CSP carries 25 points, HSTS 15, and the other six headers 10 each.
This is a diagnostic aid, not a full web-application scanner.

## `port-scan <host> [options]`

Runs a bounded TCP connect scan against one host. The default list covers 45
common ports; supply a custom CSV/range spec with `--ports`. Ranges are
inclusive, duplicates are removed, and the total is capped at 1000 ports
across at most four resolved addresses. `--concurrency 1-8` controls workers
(default 8), and each connect uses the configured timeout capped at 3 seconds.

```sh
ddos port-scan 127.0.0.1 --ports 3030,3043,8080,9000-9010
ddos port-scan client.example --ports 1-1000 --scope scope.txt --output json
```

Loopback targets are allowed without a scope file. Every non-loopback target
must be listed in `--scope`, otherwise the command exits `2` before scanning.
Text output prints open ports by default; add `--verbose` to see closed ports
and connect errors. JSON includes every result plus `open`, `open_count`, and
`scanned_count`.

## `path-discovery <url|host:port> [options]`

Sends a bounded GET request for each path in the built-in 69-entry wordlist or
a custom `--wordlist` file (maximum 200 paths). Requests are sequential with a
25 ms gap, redirects are not followed, and TLS certificate probing is skipped
so self-signed lab targets still return status codes.

```sh
ddos path-discovery http://127.0.0.1:3030
ddos path-discovery https://client.example --wordlist paths.txt --scope scope.txt
ddos path-discovery http://127.0.0.1:3030 --output json
```

Interesting statuses are `2xx`, `3xx`, `401`, `403`, `405`, and `500`. Text
output prints only interesting paths unless `--verbose` is set; JSON includes
every result with status, `content_length`, `location`, latency, and an
`interesting` flag. Non-loopback targets require `--scope`.

## `cors-check <url|host:port> [options]`

Sends one GET request with an `Origin` header and inspects the CORS response
headers. The default origin is `https://evil.example`; override it with
`--origin`.

```sh
ddos cors-check http://127.0.0.1:3030/api/users
ddos cors-check https://client.example/api --origin https://app.client.example --scope scope.txt
```

Findings include wildcard origins, wildcard plus credentials, reflected
origins, reflected origins plus credentials, the opaque `null` origin, and a
missing `Vary: Origin` on reflected responses. Severity ranges from low to
critical. The command exits `1` when it reports a finding and `0` when the CORS
configuration is absent or fixed.

## `cookie-check <url|host:port> [options]`

Sends one GET request, collects every `Set-Cookie` header, and audits the
cookie attributes.

```sh
ddos cookie-check http://127.0.0.1:3030/api/login
ddos cookie-check https://client.example/login --scope scope.txt --output json
```

Each cookie reports `Secure`, `HttpOnly`, `SameSite`, `Domain`, `Path`,
`Max-Age`, and `Expires`. Findings cover missing `Secure`, `HttpOnly`, or
`SameSite`, `SameSite=None` without `Secure`, invalid SameSite values, and
`__Host-`/`__Secure-` prefix violations. Multiple cookies are handled
independently. The command exits `1` when it reports a finding.

## `method-check <url|host:port> [options]`

Sends bounded `OPTIONS`, `HEAD`, and `TRACE` requests and audits the server's
advertised method policy without issuing state-changing requests.

```sh
ddos method-check http://127.0.0.1:3030/api/users
ddos method-check https://client.example --scope scope.txt --output json
```

The report includes the `Allow` header, a normalized list of advertised
methods, and the status and latency of each probe. Findings cover a missing
`Allow` header (informational), advertised `PUT`/`DELETE`/`PATCH`/`CONNECT`
methods, and `TRACE` returning HTTP 200. Text output shows each probe; JSON,
JSONL, and CSV are supported. Non-loopback targets require `--scope`, and the
command exits `1` when it reports a medium-or-higher finding.

## Authorization scope and audit log

Use `--scope <file>` during authorized engagements to enforce an explicit
target allowlist. Every network command fails closed when the target is outside
the scope file:

```text
# scope.txt — one entry per line; # starts a comment
client.example
*.client.example
192.0.2.0/24
2001:db8::/32
198.51.100.7
```

```sh
ddos diagnose https://client.example --scope scope.txt
ddos tls-check api.client.example --scope scope.txt --output json
ddos load-test http://127.0.0.1:3030 --scope scope.txt
```

Entries are exact hostnames, `*.domain` subdomains (not the apex), exact IP
addresses, or CIDR ranges. Hostname scopes authorize the named host; CIDR and
IP scopes are checked against every resolved address. Out-of-scope targets
return exit code `2` before the diagnostic runs. When a scope file is active,
HTTP redirects are not followed, so a redirect cannot leave the authorized
scope.

`--audit-log <path>` appends one JSONL record per invocation with the
timestamp, version, command, target, status, exit code, and error. Credentials
from `--auth` are never logged:

```sh
ddos diagnose https://client.example --scope scope.txt \
  --audit-log engagement-2026-10.jsonl
```

The log is written even when the command fails or the scope rejects the
target, making it useful as an engagement trail.

## Output formats

`--output` accepts `text`, `json`, `jsonl` (one compact JSON document per
line — ideal for `batch` and `repeat`), and `csv`.

```sh
ddos batch targets.txt --output jsonl | jq -c 'select(.ok == false)'
ddos diagnose https://example.com --output csv
```

## `batch <file|-> [options]`

Checks up to 100 non-empty, non-comment lines. `-` reads targets from stdin;
up to eight bounded workers process the list. Results are printed in input
order, and CSV output contains exactly one header row.

```sh
ddos batch targets.txt --output jsonl
printf '%s\n' https://example.com https://example.org | ddos batch - --output jsonl
```

## `repeat <url|host:port> --interval <seconds> --duration <seconds>`

Repeats one bounded diagnostic until the duration expires. The duration is
limited to one hour. It stops at the duration boundary instead of sleeping
past it.

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

Options: `--rotate-user-agent` cycles through the built-in realistic browser
user-agent pool, and `--random-user-agent` chooses one randomly per request,
for testing user-agent-based rules on your own server; standard HTTP
options (`--header`, `--method`, `--expect-status`, ...) apply. Output
`json`, `jsonl`, and `csv` modes report `sent`, `ok`, `failed`, a status
histogram, latency min/avg/max, and the actual request rate.

Sample output:

```text
$ ddos load-test http://localhost:3030 --rate 20 --count 100 --rotate-user-agent --method GET
LOAD-TEST http://localhost:3030 sent 100 ok 100 failed 0 (5041 ms total, 19.8 req/s actual, target 20 req/s)
  statuses: 200x100
  latency min 2 ms avg 3 ms max 55 ms (user agents rotated)
```

Attempting a non-loopback target is refused:

```text
$ ddos load-test example.com
error: load-test refuses non-loopback target "example.com": only localhost, 127.0.0.1, or ::1 are allowed
```

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
verbose = false
quiet = false
audit-headers = false
concurrency = 8
# scope = "/path/to/authorized-scope.txt"
# user-agent = "healthbot/1.0"
# auth-basic = "user:pass"
# header = "X-Trace-Id: 8f14e45f"
# show-header = "server"
# expect-status = 200
# dns-type = "A"
# dns-server = "1.1.1.1"
# payload = "70696e670a"
# ports = "80,443,8000-8100"
# wordlist = "/path/to/paths.txt"
# origin = "https://evil.example"
```

Use `ddos config path` to print the active default path and `ddos config init`
to write a commented starter file. `config init` refuses to overwrite an
existing file.

Precedence: CLI arguments > `DDOS_*` environment variables > config file.
Use `--config <path>` for an alternate file (it must exist) and
`--no-config` to ignore the default file for one run.

`DDOS_*` variables: `DDOS_TIMEOUT`, `DDOS_RETRIES`, `DDOS_OUTPUT`, `DDOS_PATH`,
`DDOS_METHOD`, `DDOS_FAMILY`, `DDOS_EXPECT_STATUS`, `DDOS_REDIRECTS`,
`DDOS_PROXY`, `DDOS_USER_AGENT`, `DDOS_BODY_BYTES`, `DDOS_SHOW_HEADER`
(comma separated), `DDOS_HEADER` (semicolon separated `"Name: value"` items),
`DDOS_AUTH` (`basic:USER:PASS` or `bearer:TOKEN`), `DDOS_DNS_TYPE`,
`DDOS_DNS_SERVER`, `DDOS_PAYLOAD`, `DDOS_VERBOSE`, `DDOS_QUIET`,
`DDOS_AUDIT_HEADERS` (`true`/`false`), `DDOS_SCOPE` (scope file path),
`DDOS_AUDIT_LOG` (JSONL path), `DDOS_RATE`,
`DDOS_COUNT`, `DDOS_ROTATE_USER_AGENT` (`true`/`false`),
`DDOS_RANDOM_USER_AGENT` (`true`/`false`, load-test), `DDOS_CONCURRENCY`,
`DDOS_PORTS`, `DDOS_WORDLIST`, and `DDOS_ORIGIN`.

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
- `--quiet` suppresses human-readable text output; JSON, JSONL, and CSV still
  print.
- `--no-color` is accepted for compatibility; output is always plain text.
- `--scope <file>` enforces an authorized host/IP/CIDR allowlist.
- `--audit-log <path>` appends a JSONL audit record for the invocation.
- `--audit-headers` reports HTTP security headers on HTTP checks, including a
  weighted score and letter grade.
- `--concurrency <1-8>` sets the worker count for `port-scan`.
- `--ports <spec>` sets `port-scan` ports as CSV and inclusive ranges.
- `--wordlist <file>` supplies custom paths for `path-discovery` (max 200).
- `--origin <origin>` sets the `Origin` header for `cors-check`.
- `--config <path>` / `--no-config` control configuration loading (above).

## Shell completions

Completion definitions are provided in [`completions/`](https://github.com/rkriad585/ddos/tree/main/completions)
for Bash, Zsh, Fish, PowerShell, and Nushell. The same scripts are embedded in
the binary:

```sh
ddos completion bash
ddos completion zsh
ddos completion fish
ddos completion powershell
ddos completion nushell
```

For example, install Bash completion for the current user:

```sh
ddos completion bash > ~/.local/share/bash-completion/completions/ddos
```

## Configuration helpers

```sh
ddos config path   # print the default config file path
ddos config init   # write a commented starter config
```

## Maintenance commands

- `ddos self-update` runs the official platform installer.
- `ddos self-uninstall` removes the current executable.
- `ddos --version` prints the Cargo package version.
- `ddos --help` prints usage.

[Back to README](https://github.com/rkriad585/ddos/blob/main/README.md)
