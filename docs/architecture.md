# Architecture

The project is a single Rust binary with no runtime crate dependencies.

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

Network operations use the Rust standard library: DNS resolution through
`ToSocketAddrs`, bounded TCP connections through `TcpStream`, and one HTTP
`HEAD` request over a TCP stream.

[Back to README](https://github.com/rkriad585/ddos/blob/main/README.md)
