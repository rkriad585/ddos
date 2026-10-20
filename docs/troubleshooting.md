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
The CLI performs one bounded check and does not retry indefinitely.

## The command is not found after installation

Restart the shell after the installer updates PATH, or export the managed
directory in the current shell.

[Back to README](https://github.com/rkriad585/ddos/blob/main/README.md)
