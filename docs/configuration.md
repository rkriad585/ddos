# Configuration

Settings resolve in layers; later sources override earlier ones:

```text
defaults → config file → DDOS_* environment variables → CLI arguments
```

## Config file

The default config file is `$XDG_CONFIG_HOME/ddos/config.toml`
(usually `~/.config/ddos/config.toml`); on Windows:
`%APPDATA%\ddos\config.toml`. It uses `key = value` lines; `#` starts a
comment. Unknown keys are an error, so misspelled settings fail fast.

```toml
# ~/.config/ddos/config.toml
timeout = 5
retries = 1
output = "text"        # text | json | jsonl | csv
family = "any"         # any | ipv4 | ipv6
method = "HEAD"        # HEAD | GET
# path = "/health"
# expect-status = 200
# redirects = 5
```

Supported keys: `timeout`, `retries`, `output`, `family`, `path`, `method`,
`redirects`, `proxy`, `user-agent`, `auth-basic`, `auth-bearer`, `header`,
`show-header`, `expect-status`, `body-bytes`, `rate`, `count`,
`rotate-user-agent`.

```sh
# Use an alternate config file (must exist)
ddos diagnose https://example.com --config ./staging.toml

# Ignore the default file for one run
ddos diagnose https://example.com --no-config
```

## Environment variables

Each config key has a `DDOS_*` variable:
`DDOS_TIMEOUT`, `DDOS_RETRIES`, `DDOS_OUTPUT`, `DDOS_PATH`, `DDOS_METHOD`,
`DDOS_FAMILY`, `DDOS_EXPECT_STATUS`, `DDOS_REDIRECTS`, `DDOS_PROXY`,
`DDOS_USER_AGENT`, `DDOS_BODY_BYTES`, `DDOS_SHOW_HEADER` (comma separated),
`DDOS_HEADER` (semicolon separated `"Name: value"` items), `DDOS_AUTH`
(`"basic:USER:PASS"` or `"bearer:TOKEN"`), `DDOS_RATE`, `DDOS_COUNT`,
`DDOS_ROTATE_USER_AGENT` (`true`/`false`).

```sh
DDOS_OUTPUT=json DDOS_TIMEOUT=10 ddos diagnose https://example.com
```

## Precedence example

```sh
# config sets output = "csv"; env sets json; CLI wins with jsonl
DDOS_OUTPUT=json ddos tcp-check example.com 443 --output jsonl
```

Precedence: CLI arguments > `DDOS_*` environment variables > config file.
Use `--config <path>` for an alternate path (must exist) and `--no-config`
to skip the default file in one run.

The installers manage only their own executable directory and the PATH entries
they add for that directory. The release and documentation workflows use
GitHub Actions configuration in `.github/workflows/`.

## Documentation site

The documentation is configured in
[`mkdocs.yml`](https://github.com/rkriad585/ddos/blob/main/mkdocs.yml) with the
Void theme. The site has both `slate` and `default` palettes; use the palette
control in the header to switch between dark and light mode. Void swaps the
header logo at the same time using the project assets
[`logo-dark.svg`](assets/logo-dark.svg) and
[`logo-light.svg`](assets/logo-light.svg).

The configuration also enables Void's documented glass surface, dot-matrix
background, animated transitions, code-copy buttons, search suggestions,
image lightbox, reading mode, focus timer, AI-readable page mirrors, social
cards, metadata bar, and installable PWA manifest. These are build-time site
features; they do not change the Rust CLI or its runtime behavior.

For the complete theme reference, see the
[official mkdocs-void documentation](https://rkriad585.github.io/mkdocs-void/).

[Back to README](https://github.com/rkriad585/ddos/blob/main/README.md)
