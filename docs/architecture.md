# Architecture

The project is a single Rust binary with a small runtime dependency set for
JSON serialization and Rustls-backed HTTP/HTTPS requests, plus `x509-parser`
for certificate metadata.

```text
.
├── Cargo.toml                 package metadata and binary definition
├── src/main.rs                CLI parsing and diagnostics implementation
│                                (resolve, tcp-check, http-check, diagnose,
│                                report, udp-check, dns-check, tls-check, user-agents,
│                                batch, repeat, load-test, layered config,
│                                completion generation, installers)
├── installer.sh               Unix-like release installer/uninstaller
├── installer.ps1              Windows release installer/uninstaller
├── flake.nix                  Nix package definition
├── .github/workflows/
│   ├── release.yml            cross-platform release artifacts
│   ├── docs.yml               GitHub Pages documentation
│   └── container.yml          GHCR container publishing
└── docs/                      MkDocs source
```

DNS resolution through `ToSocketAddrs` and bounded TCP connections through
`TcpStream` use the Rust standard library. HTTP and HTTPS requests use the
Rustls-backed `ureq` client with certificate validation and bounded redirects.
iperf-check-style UDP probes use `UdpSocket`, `load-test` runs sequential
requests (no worker pool), and `dns-check` speaks a minimal hand-written
DNS-over-UDP message format without external dependencies.

Authorization scope matching is implemented in-process for exact hosts,
`*.domain` subdomains, IP addresses, and IPv4/IPv6 CIDR ranges. Network
commands check the host before work begins and, where DNS is involved, the
resolved addresses too. Audit records are appended as JSONL by the top-level
dispatcher so successes and failures are both captured. HTTP security-header
auditing reuses the existing response object and does not add another request.

[Back to README](https://github.com/rkriad585/ddos/blob/main/README.md)
