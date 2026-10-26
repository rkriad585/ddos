# Changelog

## 0.0.3-beta

- Bumped the package, container, and documentation version to `0.0.3-beta`.
- Fixed the container build by including the embedded completion scripts.
- Added `tls-check` for certificate metadata and `user-agents` for inspecting
  the built-in browser user-agent pool.
- Added `--random-user-agent` and expanded the realistic browser user-agent
  pool used by loopback `load-test`.
- Added embedded `completion <shell>` output and `config path` / `config init`
  helpers.
- Added `--quiet` and `--no-color`, plus config/env support for DNS type,
  DNS server, UDP payload, verbose, and quiet settings.
- Added `--scope` authorization files for exact hosts, `*.domain` subdomains,
  IP addresses, and CIDR ranges; out-of-scope targets fail closed.
- Added `--audit-log` JSONL records for command, target, status, exit code, and
  error, without logging credentials.
- Added `--audit-headers` for HTTP security-header review, including weighted
  A–F grading.
- Added bounded `port-scan`, `path-discovery`, `cors-check`, `cookie-check`,
  and `method-check` recon commands.
- Added `report <url|host:port>` for Markdown assessment reports covering
  DNS/TCP/HTTP/TLS results and security-header findings.
- `--expect-status` now matches 4xx/5xx responses instead of treating them as
  transport failures.
- `tls-check` and HTTPS reports now include the negotiated TLS protocol and
  cipher suite.
- `http-check` now defaults to port 80 when the port is omitted.
- Batch output preserves input order and emits one CSV header; repeat stops at
  the duration boundary.
- Added local TCP and HTTP integration tests.
- Documented the new commands, flags, and environment variables.

## 0.0.2-beta

- Fixed Nix packaging to build from the committed Cargo lockfile.
- Bumped the project version for the next beta release.

## 0.0.1-beta

- Replaced the original flooding script with a bounded Rust diagnostics CLI.
- Added DNS resolution, TCP connectivity, and HTTP `HEAD` checks.
- Added cross-platform release installers and release artifacts.

[Back to README](README.md)
