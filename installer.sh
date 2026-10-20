#!/usr/bin/env bash
set -euo pipefail

PROJECT="ddos"
REPOSITORY="rkriad585/ddos"
CONFIG_DIR="${HOME}/.config/peekstore/${PROJECT}"
BINARY_PATH="${CONFIG_DIR}/${PROJECT}"
API_URL="https://api.github.com/repos/${REPOSITORY}/releases/latest"
PATH_MARKER="# ddos installer PATH"

profiles=("${HOME}/.bashrc" "${HOME}/.zshrc" "${HOME}/.profile" "${HOME}/.bash_profile")

clean_profile() {
    local profile="$1" temporary
    [ -f "$profile" ] || return 0
    temporary="$(mktemp)"
    awk -v marker="$PATH_MARKER" -v config="$CONFIG_DIR" '!index($0, marker) && !index($0, config)' "$profile" > "$temporary"
    mv "$temporary" "$profile"
}

add_profile_path() {
    local profile="$1"
    touch "$profile"
    grep -Fq "$PATH_MARKER" "$profile" 2>/dev/null || {
        {
            printf '\n%s: begin\n' "$PATH_MARKER"
            printf 'export PATH="$HOME/.config/peekstore/ddos:$PATH"\n'
            printf '%s: end\n' "$PATH_MARKER"
        } >> "$profile"
    }
}

if [[ " ${*:-} " == *" --selfuninstall "* || " ${*:-} " == *" --uninstall "* || " ${*:-} " == *" -u "* ]]; then
    rm -f "$BINARY_PATH"
    rmdir "$CONFIG_DIR" 2>/dev/null || true
    for profile in "${profiles[@]}"; do clean_profile "$profile"; done
    printf 'ddos was uninstalled from %s\n' "$CONFIG_DIR"
    printf 'Restart your shell or run: hash -r\n'
    exit 0
fi

command -v curl >/dev/null 2>&1 || { echo "error: curl is required" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "error: sha256sum is required" >&2; exit 1; }

os="$(uname -s)"
arch="$(uname -m)"
case "${os}:${arch}" in
    Linux:x86_64|Linux:amd64) asset="ddos-linux-x86_64" ;;
    Linux:aarch64|Linux:arm64) asset="ddos-linux-aarch64" ;;
    Darwin:x86_64|Darwin:amd64) asset="ddos-macos-x86_64" ;;
    Darwin:arm64|Darwin:aarch64) asset="ddos-macos-aarch64" ;;
    *) echo "error: unsupported platform ${os}/${arch}" >&2; exit 1 ;;
esac

tag="$(curl -fsSL "$API_URL" | sed -n 's/.*"tag_name": "\([^"]*\)".*/\1/p' | head -n 1)"
[ -n "$tag" ] || { echo "error: no published GitHub release found" >&2; exit 1; }
download_url="https://github.com/${REPOSITORY}/releases/download/${tag}/${asset}"
checksum_url="https://github.com/${REPOSITORY}/releases/download/${tag}/SHA256SUMS"

mkdir -p "$CONFIG_DIR"
temporary="$(mktemp)"
trap 'rm -f "$temporary"' EXIT
curl -fL --progress-bar "$download_url" -o "$temporary"
expected="$(curl -fsSL "$checksum_url" | awk -v name="$asset" '$2 == name { print $1; exit }')"
actual="$(sha256sum "$temporary" | awk '{print $1}')"
[ -n "$expected" ] && [ "$expected" = "$actual" ] || { echo "error: checksum verification failed" >&2; exit 1; }
install -m 0755 "$temporary" "$BINARY_PATH"

shell_name="$(basename "${SHELL:-}")"
case "$shell_name" in
    bash) add_profile_path "${HOME}/.bashrc" ;;
    zsh) add_profile_path "${HOME}/.zshrc" ;;
    *) add_profile_path "${HOME}/.profile" ;;
esac

"$BINARY_PATH" --version
printf 'Installed %s to %s\n' "$PROJECT" "$BINARY_PATH"
printf 'Restart your shell or run: export PATH="%s:$PATH"\n' "$CONFIG_DIR"
