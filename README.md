# ddos

`ddos` is a small Rust command-line tool for bounded network diagnostics on
systems you own or are authorized to test. It performs one DNS lookup, one TCP
connection check, or one HTTP `HEAD` request. It does not flood services,
spoof traffic, evade protections, or generate concurrent attack traffic.

## Install

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/rkriad585/ddos/main/install.ps1 | iex
```

Linux/macOS:

```sh
curl -sL https://raw.githubusercontent.com/rkriad585/ddos/main/install.sh | bash
```

With Rust installed:

```sh
cargo install --git https://github.com/rkriad585/ddos.git
```

After installation, open a new shell if your bin directory was not already on
`PATH`.

## Use

```sh

ddos resolve example.com
ddos tcp-check example.com 443 --timeout 5
ddos http-check example.com --path /health --timeout 5
```

Run `ddos --help` for the complete command reference.

## Development

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
```

Tagged releases (`v0.1.0`, for example) are built for Linux, Windows, macOS,
Nix, and Android/Termux by [the release workflow](.github/workflows/release.yml),
with SHA-256 checksums attached to the GitHub release.

Use this software only for authorized diagnostics. Testing third-party systems
without permission may be illegal and disruptive.
