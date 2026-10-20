#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$script_dir/installer.sh" ]]; then exec bash "$script_dir/installer.sh" "$@"; fi
exec bash <(curl -fsSL https://raw.githubusercontent.com/rkriad585/ddos/main/installer.sh) "$@"
