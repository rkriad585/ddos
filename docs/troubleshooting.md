# Troubleshooting

## `cargo` is not found

Install a Rust toolchain that provides Cargo, or use a published binary from
the release installer.

## DNS resolution fails

Check the hostname, local resolver, and network policy. `resolve` uses the
operating system resolver through Rust's standard library. HTTPS checks also
require a valid certificate chain trusted by the bundled Rustls roots.

## TCP or HTTP checks fail

Confirm the host and port, then retry with a timeout between 1 and 120 seconds.
The CLI performs one bounded check and does not retry indefinitely. Use
`--verbose` to see per-address errors, and remember that plain `http-check`
against a TLS-only port fails — use `diagnose https://...` there. Scheduled
re-checks belong in shell scripts or CI, since there is no daemon mode.

## UDP or DNS checks fail

`udp-check` fails when the target drops the datagram silently; many services
do this for unknown payloads, so send bytes the service recognizes, for
example a small DNS query payload:

```sh
ddos udp-check 1.1.1.1 53 --payload 123401000001000000000000076578616d706c6503636f6d0000010001
# OK 1.1.1.1:53 (34 ms)
```

`dns-check` needs a reachable resolver; pick one explicitly with
`--dns-server 1.1.1.1` (also works on platforms without `/etc/resolv.conf`):

```sh
ddos dns-check example.com --dns-type A --dns-server 1.1.1.1
# OK A example.com via 1.1.1.1 (63 ms)
```

A target can resolve but have no records of the type requested — the tool
reports `no <type> records returned` in that case.

## `load-test` refuses my target

By design, `load-test` only accepts loopback URLs (`localhost`, `127.0.0.1`,
`::1`), with `--rate 1-50` and `--count 1-5000` as hard caps. Testing other
servers is out of scope for this tool; use consent-based dedicated tools
against systems you operate.

## The command is not found after installation

Restart the shell after the installer updates PATH, or export the managed
directory in the current shell.

[Back to README](https://github.com/rkriad585/ddos/blob/main/README.md)
