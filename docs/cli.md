# CLI reference

The executable is named `ddos`. Run `ddos --help` for the built-in summary.

## Basic checks

### `resolve <host>`

Resolves a host and prints IPv4/IPv6 addresses. Use `--output json` for a
stable machine-readable result.

```sh
ddos resolve example.com --output json
```

### `tcp-check <host> <port> [options]`

Attempts bounded TCP connections to every resolved address. Timeout values are
1–120 seconds; retries are 0–5.

```sh
ddos tcp-check example.com 443 --timeout 5 --retry 2
```

### `http-check <host> [port] [options]`

Sends one HTTP `HEAD` request. The default port is 80 and the default path is
`/`. Paths must begin with `/`, contain no newlines, and be at most 2048 bytes.

```sh
ddos http-check example.com --path /health --timeout 5
```

## `diagnose <url|host:port> [options]`

Runs bounded DNS, TCP, and optional HTTP/HTTPS checks and reports per-address
results and total timing. HTTPS uses certificate validation through the
Rustls-backed HTTP client. Redirects are limited to five hops.

```sh
ddos diagnose https://example.com/health --timeout 5
ddos diagnose https://example.com/health --output json | jq .
```

JSON output has schema version `1` and includes `target`, `resolved`, `http`,
`ok`, `total_elapsed_ms`, and an optional `error` field. Exit status is `0`
for a successful report, `1` when a diagnostic fails, and `2` for invalid
usage.

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

## Common options

- `--output text|json` selects human or machine-readable output.
- `--timeout <seconds>` sets a 1–120 second operation timeout.
- `--retry <count>` enables 0–5 bounded retries.
- `--verbose` includes failed address details in text output.

## Maintenance commands

- `ddos self-update` runs the official platform installer.
- `ddos self-uninstall` removes the current executable.
- `ddos --version` prints the Cargo package version.
- `ddos --help` prints usage.

[Back to README](https://github.com/rkriad585/ddos/blob/main/README.md)
