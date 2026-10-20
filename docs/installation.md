# Installation

The release workflow publishes binaries named by operating system and
architecture. The installer selects the latest release and verifies its
`SHA256SUMS` entry.

## One-line installers

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/rkriad585/ddos/main/installer.ps1 | iex
```

Linux, macOS, and Termux:

```sh
curl -fsSL https://raw.githubusercontent.com/rkriad585/ddos/main/installer.sh | sh
```

The managed install directory is `~/.config/peekstore/ddos/` on Unix-like
systems and `%USERPROFILE%\\.config\\peekstore\\ddos\\` on Windows.

## Cargo

```sh
cargo install --git https://github.com/rkriad585/ddos.git
```

## Uninstall

```sh
curl -fsSL https://raw.githubusercontent.com/rkriad585/ddos/main/installer.sh | sh -s -- --selfuninstall
```

On Windows, run the installer script with `--selfuninstall` through a
PowerShell script block. The installed binary also accepts
`ddos --selfuninstall`.

[Back to README](https://github.com/rkriad585/ddos/blob/main/README.md)
