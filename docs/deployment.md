# Deployment

## Releases

Pushing a tag matching `v*.*.*` runs `.github/workflows/release.yml`. The
workflow builds Linux, Windows, macOS, Android/Termux, and Nix artifacts, then
publishes the artifacts and checksums to a GitHub release.

## Documentation

Changes to `docs/`, `mkdocs.yml`, or the documentation dependency file on
`main` run `.github/workflows/docs.yml` and deploy the MkDocs site to GitHub
Pages.

## Container

Pushes to `main` and version tags run `.github/workflows/container.yml` and
publish `ghcr.io/rkriad585/ddos`.

[Back to README](https://github.com/rkriad585/ddos/blob/main/README.md)
