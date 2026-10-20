# FAQ

## Is this a traffic-flooding tool?

No. The implementation performs bounded DNS, TCP, HTTP, and UDP diagnostics
only. The only request generator is `load-test`, which is sequential, capped
at 50 req/s and 5000 requests, and refuses any target except loopback
(`localhost`, `127.0.0.1`, `::1`).

## Does `diagnose` support HTTPS?

Yes. `diagnose https://...` performs a bounded HTTPS request with certificate
validation and reports certificate metadata (subject, issuer, serial, SANs,
expiry). The lower-level `http-check` command remains a plain HTTP check:
use it for `http://` ports and expect a failure against TLS-only ports.

## Does the CLI read a configuration file?

Yes, per-run: `~/.config/ddos/config.toml` (or
`%APPDATA%\ddos\config.toml` on Windows). CLI arguments override the
`DDOS_*` environment variables, which override the config file. Use
`--config <path>` or `--no-config` for explicit control. See
[Configuration](configuration.md).

## How do I measure request rate rather than latency?

Use `load-test` against a loopback server:

```sh
python3 -m http.server 3030 &
ddos load-test http://localhost:3030 --rate 20 --count 100 --method GET
```

```text
LOAD-TEST http://localhost:3030 sent 100 ok 100 failed 0 (5041 ms total, 19.8 req/s actual, target 20 req/s)
  statuses: 200x100
  latency min 2 ms avg 3 ms max 55 ms (user agents rotated)
```

## Why does a check fail in a restricted environment?

DNS and socket operations can be blocked by a sandbox, firewall, proxy, or
network policy. The CLI reports the underlying error and exits nonzero.

[Back to README](https://github.com/rkriad585/ddos/blob/main/README.md)
