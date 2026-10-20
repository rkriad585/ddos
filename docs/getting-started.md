# Getting started

This guide gets the Rust CLI running locally and performs a harmless DNS
lookup.

## Build

```sh
cargo build --release
```

The executable is `target/release/ddos`.

## Run

```sh
cargo run -- resolve localhost
cargo run -- tcp-check example.com 443 --timeout 5
cargo run -- http-check example.com --path / --timeout 5
```

All checks are bounded. The program does not flood, spoof, randomize targets,
or create concurrent traffic.

[Back to README](https://github.com/rkriad585/ddos/blob/main/README.md)
