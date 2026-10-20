# ddos

<p align="center">
  <img src="ddos-logos/logo-on-light-mode.svg" alt="ddos logo" height="150">
  <h1 align="center">ddos</h1>
  <p align="center">Bounded network diagnostics for systems you own or are authorized to test.</p>
</p>

<p align="center">
  <a href="https://github.com/rkriad585/ddos/actions/workflows/release.yml"><img src="https://github.com/rkriad585/ddos/actions/workflows/release.yml/badge.svg" alt="Release workflow"></a>
  <a href="https://github.com/rkriad585/ddos/actions/workflows/docs.yml"><img src="https://github.com/rkriad585/ddos/actions/workflows/docs.yml/badge.svg" alt="Documentation workflow"></a>
  <img src="https://img.shields.io/badge/rust-2021-orange?logo=rust" alt="Rust 2021">
  <img src="https://img.shields.io/badge/version-0.0.1--beta-blue" alt="Version 0.0.1-beta">
  <a href="https://github.com/rkriad585/ddos/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-blue" alt="GPL-3.0 license"></a>
  <a href="https://github.com/rkriad585"><img src="https://img.shields.io/badge/made%20by-rkriad585-lightgrey" alt="Made by rkriad585"></a>
</p>

`ddos` is a dependency-free Rust command-line tool for one-shot DNS, TCP, and
HTTP diagnostics. It deliberately avoids flooding, spoofing, evasion, and
unbounded traffic generation.

## Screenshot

The project is a terminal CLI. A generated help screenshot is documented in
[`docs/screenshots.md`](docs/screenshots.md); the source generator is
[`tools/screenshots_gen.py`](tools/screenshots_gen.py).

## Table of contents

- [Key features](#key-features)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Usage examples](#usage-examples)
- [Documentation](#documentation)
- [Interface](#interface)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Prerequisites](#prerequisites)
- [Development](#development)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## Key features

- DNS resolution through the operating system resolver.
- One bounded TCP connection check with a configurable 1–120 second timeout.
- One HTTP `HEAD` request with an optional path and timeout.
- Self-update through the official platform installer.
- Self-uninstall of the current executable.
- Release binaries for Linux, Windows, macOS, Android/Termux, and Nix.

## Installation

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/rkriad585/ddos/main/installer.ps1 | iex
```

Linux, macOS, and Termux:

```sh
curl -fsSL https://raw.githubusercontent.com/rkriad585/ddos/main/installer.sh | sh
```

Cargo:

```sh
cargo install --git https://github.com/rkriad585/ddos.git
```

Release installers use `~/.config/peekstore/ddos/` on Unix-like systems and
`%USERPROFILE%\\.config\\peekstore\\ddos\\` on Windows.

## Quick start

```sh
ddos resolve localhost
ddos tcp-check example.com 443 --timeout 5
ddos http-check example.com --path / --timeout 5
```

## Usage examples

```text
ddos 0.0.1-beta — bounded network diagnostics

Usage:
  ddos resolve <host>
  ddos tcp-check <host> <port> [--timeout <seconds>]
  ddos http-check <host> [port] [--path <path>] [--timeout <seconds>]
  ddos self-update
  ddos self-uninstall
  ddos --version
  ddos --help
```

Maintenance commands:

```sh
ddos self-update
ddos --selfuninstall
```

The installer-based uninstall command also removes the managed PATH entries:

```sh
curl -fsSL https://raw.githubusercontent.com/rkriad585/ddos/main/installer.sh | sh -s -- --selfuninstall
```

## Documentation

| Topic | Document |
| --- | --- |
| Home | [docs/index.md](docs/index.md) |
| Getting started | [docs/getting-started.md](docs/getting-started.md) |
| Installation | [docs/installation.md](docs/installation.md) |
| CLI | [docs/cli.md](docs/cli.md) |
| Architecture | [docs/architecture.md](docs/architecture.md) |
| Configuration | [docs/configuration.md](docs/configuration.md) |
| Development | [docs/development.md](docs/development.md) |
| Deployment | [docs/deployment.md](docs/deployment.md) |
| FAQ | [docs/faq.md](docs/faq.md) |
| Screenshots | [docs/screenshots.md](docs/screenshots.md) |
| Troubleshooting | [docs/troubleshooting.md](docs/troubleshooting.md) |

## Interface

The interface is a command-line binary named `ddos`. It writes human-readable
results to standard output, errors to standard error, and returns a nonzero
exit status for invalid input or failed checks. See the [CLI reference](docs/cli.md).

## Architecture

```text
src/main.rs
├── argument dispatch
├── DNS resolution (ToSocketAddrs)
├── TCP checks (TcpStream)
├── HTTP HEAD checks (TcpStream)
└── installer maintenance commands
```

The binary has no Cargo dependencies; all runtime networking uses the Rust
standard library.

## Requirements

- Rust edition 2021 and Cargo for source builds.
- `curl`, `sha256sum`, and a POSIX shell for `installer.sh`.
- PowerShell for `installer.ps1`.
- Docker for container builds.
- Python and MkDocs for documentation builds.

## Prerequisites

No application configuration or environment variables are required. Network
checks require DNS and socket access to the target system, with authorization
from its owner.

## Development

```sh
git clone https://github.com/rkriad585/ddos.git
cd ddos
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
```

Build a release binary with `cargo build --locked --release`. Build the docs
with `python3 -m pip install -r requirements-docs.txt && mkdocs build --strict`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md). Use this software only for authorized
diagnostics.

## License

This project is distributed under the [GNU GPL v3.0](LICENSE).
