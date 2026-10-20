# Configuration

The CLI has no configuration file and reads no environment variables.

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
