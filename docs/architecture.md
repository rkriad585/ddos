# Architecture

The project is a single Rust binary with a small runtime dependency set for
JSON serialization and Rustls-backed HTTP/HTTPS requests.

```text
.
├── Cargo.toml                 package metadata and binary definition
├── src/main.rs                CLI parsing and diagnostics implementation
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

[Back to README](https://github.com/rkriad585/ddos/blob/main/README.md)
