# Contributing

## Workflow

1. Fork or clone the repository.
2. Make a focused change.
3. Run the formatting, test, and lint commands below.
4. Update documentation when behavior changes.
5. Open a pull request describing the change and its verification.

## Checks

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
```

Changes must preserve the tool's bounded, authorized-diagnostics scope. Do not
add flooding, spoofing, evasion, or unbounded scanning behavior.

[Back to README](README.md)
