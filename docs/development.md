# Development

## Requirements

- Rust toolchain with Cargo
- Git

## Checks

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
```

Documentation builds with:

```sh
python3 -m pip install -r requirements-docs.txt
mkdocs build --strict
```

Container builds with:

```sh
docker build -t ddos .
```

[Contributing](https://github.com/rkriad585/ddos/blob/main/CONTRIBUTING.md) contains the contribution workflow.

[Back to README](https://github.com/rkriad585/ddos/blob/main/README.md)
