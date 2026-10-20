# CLI reference

The executable is named `ddos`. Run `ddos --help` for the built-in summary.

## `resolve <host>`

Resolves a host and prints the resolved IP addresses.

```sh
ddos resolve example.com
```

## `tcp-check <host> <port> [--timeout <seconds>]`

Attempts one TCP connection to each resolved address until one succeeds. The
timeout must be between 1 and 120 seconds and defaults to 5 seconds.

```sh
ddos tcp-check example.com 443 --timeout 5
```

## `http-check <host> [port] [--path <path>] [--timeout <seconds>]`

Sends one HTTP `HEAD` request. The default port is 80 and the default path is
`/`. Paths must begin with `/`, contain no newlines, and be at most 2048 bytes.

```sh
ddos http-check example.com --path /health --timeout 5
```

## Maintenance commands

- `ddos self-update` runs the official platform installer.
- `ddos self-uninstall` removes the current executable.
- `ddos --version` prints the Cargo package version.
- `ddos --help` prints usage.

[Back to README](https://github.com/rkriad585/ddos/blob/main/README.md)
