# FAQ

## Is this a traffic-flooding tool?

No. The implementation performs bounded DNS, TCP, and HTTP diagnostics only.

## Does `diagnose` support HTTPS?

Yes. `diagnose https://...` performs a bounded HTTPS request with certificate
validation and reports certificate metadata. The lower-level `http-check`
command remains an HTTP check.

## Does the CLI read a configuration file?

No. See [Configuration](configuration.md).

## Why does a check fail in a restricted environment?

DNS and socket operations can be blocked by a sandbox, firewall, proxy, or
network policy. The CLI reports the underlying error and exits nonzero.

[Back to README](https://github.com/rkriad585/ddos/blob/main/README.md)
