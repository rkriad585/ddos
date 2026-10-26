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
# audit-headers = true
# scope = "/path/to/authorized-scope.txt"
# path = "/health"
# expect-status = 200
# redirects = 5
```

Supported keys: `timeout`, `retries`, `output`, `family`, `path`, `method`,
`redirects`, `proxy`, `user-agent`, `auth-basic`, `auth-bearer`, `header`,
`show-header`, `expect-status`, `body-bytes`, `rate`, `count`,
`rotate-user-agent`, `random-user-agent`, `audit-headers`, `scope`,
`dns-type`, `dns-server`, `payload`, `verbose`, `quiet`.

`scope` is a path to an authorization file. `audit-headers` is a boolean for
HTTP header auditing. `--audit-log` is not a config key; set it per run or via
`DDOS_AUDIT_LOG`.

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
(`"basic:USER:PASS"` or `"bearer:TOKEN"`), `DDOS_DNS_TYPE`,
`DDOS_DNS_SERVER`, `DDOS_PAYLOAD`, `DDOS_VERBOSE`, `DDOS_QUIET`,
`DDOS_AUDIT_HEADERS`, `DDOS_SCOPE`, `DDOS_AUDIT_LOG`, `DDOS_RATE`,
`DDOS_COUNT`, `DDOS_ROTATE_USER_AGENT`, and `DDOS_RANDOM_USER_AGENT`
(`true`/`false`).

## Authorization scope

Create a scope file when working under an engagement or authorization letter:

```text
# scope.txt
client.example
*.client.example
192.0.2.0/24
2001:db8::/32
198.51.100.7
```

Entries are exact hosts, `*.domain` subdomains, IP addresses, or CIDR ranges.
Comments start with `#`. `--scope scope.txt` makes every network command fail
closed (exit code `2`) if the target is not listed. HTTP redirects are not
followed while a scope file is active.

```sh
DDOS_SCOPE=scope.txt ddos diagnose https://client.example
```

## Audit log

`--audit-log engagement.jsonl` or `DDOS_AUDIT_LOG=engagement.jsonl` appends one
JSON object per run:

```json
{"command":"diagnose","error":null,"exit_code":0,"status":"ok","target":"https://client.example","timestamp_unix":1792507843,"version":"0.0.3-beta"}
```

The record contains the command, target, status, exit code, and optional error.
Credentials passed with `--auth` are never written to the audit log.

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
