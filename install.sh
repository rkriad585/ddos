#!/usr/bin/env bash
set -euo pipefail

repo="rkriad585/ddos"
os="$(uname -s)"
arch="$(uname -m)"

case "$os:$arch" in
  Linux:x86_64) asset="ddos-linux-x86_64" ;;
  Linux:aarch64) asset="ddos-linux-aarch64" ;;
  Darwin:arm64) asset="ddos-macos-aarch64" ;;
  Darwin:x86_64) asset="ddos-macos-x86_64" ;;
  *)
    echo "Unsupported platform: $os/$arch" >&2
    echo "Install with: cargo install --git https://github.com/$repo.git" >&2
    exit 1
    ;;
esac

command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "sha256sum is required" >&2; exit 1; }

api="https://api.github.com/repos/$repo/releases/latest"
url="$(curl -fsSL "$api" | sed -n 's/.*"browser_download_url": "\([^"]*\/$asset\)".*/\1/p' | head -n 1)"
[ -n "$url" ] || { echo "No release asset found. Try the Cargo install command instead." >&2; exit 1; }

bin_dir="${XDG_BIN_HOME:-$HOME/.local/bin}"
mkdir -p "$bin_dir"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
curl -fL "$url" -o "$tmp"

checksums="$(curl -fsSL "$api" | sed -n 's/.*"browser_download_url": "\([^"]*\/SHA256SUMS\)".*/\1/p' | head -n 1)"
if [ -n "$checksums" ]; then
  expected="$(curl -fsSL "$checksums" | awk -v name="$asset" '$2 == name {print $1}')"
  actual="$(sha256sum "$tmp" | awk '{print $1}')"
  [ "$expected" = "$actual" ] || { echo "Checksum verification failed" >&2; exit 1; }
fi

install -m 0755 "$tmp" "$bin_dir/ddos"
echo "Installed ddos to $bin_dir/ddos"
case ":${PATH}:" in
  *:"$bin_dir":*) ;;
  *) echo "Add $bin_dir to PATH to run ddos from any shell." ;;
esac
