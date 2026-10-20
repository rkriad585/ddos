# ddos Improvement Plan

This plan is based on the current Rust source, release workflow, installers,
documentation, and a comparison with established network command-line tools.
It is updated alongside implementation so completed work and remaining work
stay explicit.

## 1. Research summary

### What the project is today

`ddos` is a Rust 2021 binary with bounded DNS, TCP, HTTP, HTTPS, batch, and
repeat diagnostic paths:

- `resolve <host>` uses the operating system resolver and prints IP addresses.
- `tcp-check <host> <port>` attempts bounded TCP connections to resolved
  addresses.
- `http-check <host> [port]` sends one HTTP `HEAD` request.
- `diagnose`, `batch`, and `repeat` combine bounded checks for operators and
  automation.
- `self-update` and `self-uninstall` manage the installed executable.

Single-target commands intentionally perform bounded operations. Batch mode
uses at most eight workers for explicitly provided targets; it does not flood,
spoof, randomize targets, or scan ranges. Releases provide native binaries for the
platforms declared in `.github/workflows/release.yml`, and the installers
verify release checksums before installing into the managed user directory.

### Why someone would use it

The project can be useful for an operator who needs a small diagnostic binary
without installing a large scanner or runtime. Its current value is:

1. A single portable executable with a small Rustls/JSON runtime dependency set.
2. A simple install/update/uninstall path for Linux, macOS, Windows, Termux,
   and the published Nix package.
3. Bounded checks that are safer and easier to explain than an open-ended
   scanner.
4. A useful building block for shell scripts, health checks, and deployment
   troubleshooting once its output contract becomes stable.

Comparable tools set a higher user expectation for diagnostics. `curl` offers
many transport controls and output formats; Nmap documents host discovery,
service detection, and explicit output modes; GitHub CLI exposes structured
JSON output and field selection. These are useful patterns to adopt without
adopting their unrestricted scanning scope.

Research references:

- [curl tutorial](https://curl.se/docs/tutorial.html)
- [Nmap host discovery](https://nmap.org/book/man-host-discovery.html)
- [Nmap service and version detection](https://nmap.org/book/man-version-detection.html)
- [GitHub CLI JSON output](https://cli.github.com/manual/gh_repo_view)

## 2. Current adoption blockers

These findings are verified from `src/main.rs`, the repository metadata, and
the current documentation.

### High impact

- The name `ddos` suggests traffic flooding even though the implementation is
  deliberately bounded. This can confuse operators, security reviewers,
  package indexes, and first-time users.
- `http-check` remains plain HTTP; HTTPS is available through `diagnose`, but
  certificate metadata and advanced request controls are still limited.
- Errors do not consistently expose the address family, elapsed time, phase,
  or a stable error category. This makes failures harder to compare and
  troubleshoot.

### Medium impact

- DNS output does not identify IPv4 versus IPv6 or preserve resolver details.
- TCP checks stop after the first successful address and do not provide a
  summary of every attempted address.
- HTTP checks use the first resolved address only and do not support explicit
  IPv4/IPv6 selection.
- Advanced request controls, certificate metadata, proxy support, and shell
  completions are now available.
- The CLI parser is handwritten and does not provide shell completions,
  consistent option help, or a global option model.
- There is no configuration file or environment-variable override for common
  defaults such as timeout, output format, or user agent.

### Correctness and trust issues to resolve first

- License metadata is aligned to GPL-3.0-only, matching `LICENSE` and the
  README badge.
- `self-update` executes a downloaded installer through `curl | bash` or
  PowerShell. The installer verifies the release checksum, but the update
  path should be documented and hardened before being promoted as a trusted
  automation feature.
- The project has no integration-test suite for malformed input, IPv4/IPv6
  behavior, timeout boundaries, HTTP parsing, installer asset selection, or
  update/uninstall behavior.
- The public command name, release asset names, and installer paths must stay
  synchronized; these should be generated or checked in CI rather than
  maintained in several independent places.

## 3. Recommended product direction

Keep the product as a bounded diagnostics tool for systems the user owns or
is authorized to test. Do not add unrestricted port-range scanning, evasion,
spoofing, amplification, packet flooding, or stealth features.

The central feature should be a new bounded `diagnose` command that combines
the existing checks into one explainable report:

```text
ddos diagnose https://example.com/health --timeout 5
```

The exact syntax is a design decision for implementation; the URL form above
is a proposal, not a current command. The command should execute only the
explicitly requested target and a small, fixed sequence of checks:

1. Parse and validate the target.
2. Resolve all addresses.
3. Attempt bounded TCP connectivity per eligible address.
4. For HTTPS, perform a bounded TLS handshake and certificate summary.
5. Send one HTTP request and report status, headers selected by the user, and
   timing phases.
6. Return a stable summary and an actionable failure reason.

## 4. Prioritized implementation roadmap

### Phase 0 — correctness and contract cleanup (complete)

- `Cargo.toml`, `LICENSE`, badges, and documentation now agree on GPL-3.0-only.
- Decide whether `ddos` remains the public binary name. If it remains, add a
  clear safety-oriented description everywhere; do not silently rename release
  assets.
- Introduce shared typed models for target, address result, timing, status,
  and error category.
- Add integration tests around the current commands using local test servers,
  including success, refused connection, timeout, malformed options, and IPv4
  plus IPv6 cases.
- Define exit-code meanings and document them before adding output formats.

### Phase 1 — scriptable diagnostics (mostly complete)

- Add `--output text|json` with JSON written to stdout and diagnostics written
  to stderr.
- Add `--quiet`, `--verbose`, and `--no-color`, with color disabled when stdout
  is not a terminal.
- Include stable fields: target, resolved addresses, selected address,
  operation, phase timings, result, error category, and exit code.
- Add shell completion generation for Bash, Zsh, Fish, PowerShell, and
  Nushell if the chosen argument parser supports it.
- Add examples for CI, monitoring, and `jq` consumption.

### Phase 2 — one powerful bounded command (complete)

- Add `diagnose` as the unified workflow for one host or URL.
- Keep limits explicit: one target per invocation, bounded timeout, bounded
  retries, and a small maximum for parallel address attempts.
- Add `--retry <count>` and bounded exponential backoff only after the basic
  result model is stable.
- Report per-phase timing: DNS, connect, TLS, request, and total.
- Make the command usable both interactively and in CI with the same result
  model.

### Phase 3 — modern HTTP and TLS support (complete)

- Add HTTPS with certificate validation enabled by default.
- Report certificate subject, issuer, expiry, and verification result without
  exposing private data.
- Support request method selection from a safe allowlist, defaulting to
  `HEAD`, with an explicit bounded body-read option for health checks.
- Add redirect policy, status-code expectations, selected response headers,
  and host-header handling with strict input validation.
- Support explicit HTTP/HTTPS proxies and the standard proxy environment
  variables through the HTTP client.

### Phase 4 — operational workflows (complete)

- Add bounded batch input from a file or stdin, with a documented maximum
  target count and no implicit network expansion.
- Add repeat mode with an explicit interval and total duration limit.
- Add bounded concurrency with a conservative default and a hard upper limit.
- Add summary formats suitable for CI annotations and monitoring systems.
- Consider a local-only `serve` or export feature only if a concrete user
  workflow requires it; it is not needed for the core tool.

### Phase 5 — distribution and trust (complete for current scope)

- Add reproducible-build metadata and verify release artifacts in CI.
- Add integration tests for each installer architecture mapping and checksum
  failure path.
- Make self-update use a clear version-selection policy and fail closed when
  the release metadata or checksum is unavailable.
- Publish completion scripts and package-manager recipes only after the
  license and binary naming decisions are finalized.

## 5. Proposed user experience

The final CLI should make the common path obvious:

```text
ddos diagnose https://service.example/health
ddos diagnose https://service.example/health --output json
ddos diagnose service.example:443 --timeout 10 --retry 2
```

These examples are planned interfaces and must not be documented as working
until implemented and tested.

Interactive output should answer:

- What target was parsed?
- Which addresses were resolved?
- Which address was tested?
- Which phases succeeded or failed?
- How long did each phase take?
- What should the operator do next?

JSON output should be stable enough for scripts and should never require
parsing human-oriented text.

## 6. Safety requirements

- Preserve the current one-target, bounded-operation model by default.
- Require explicit flags for retries, repeat mode, batch input, and
  concurrency.
- Enforce hard upper bounds in code, not only in help text.
- Reject malformed host, URL, path, header, and target-file input before any
  network operation.
- Never add spoofing, evasion, amplification, flooding, or stealth behavior.
- Include an authorization reminder in the help text and documentation.
- Add tests proving that limits are enforced.

## 7. Definition of done

The first implementation milestone is complete when:

- The license metadata conflict is resolved.
- `diagnose` supports DNS, TCP, HTTP, and HTTPS with bounded timing.
- Text and JSON output describe the same typed result.
- Exit codes are stable and documented.
- Local integration tests cover success, refusal, timeout, TLS failure, bad
  input, and mixed IPv4/IPv6 results.
- README and `docs/cli.md` contain only verified commands.
- Release builds, installers, Docker, Nix, and self-update continue to work.
- CI runs formatting, tests, Clippy, documentation build, and installer
  contract checks.

## 8. Open decisions / TODOs

- TODO: Decide whether to keep the `ddos` name or introduce a safer product
  name while preserving a compatibility alias.

[Back to README](README.md)
