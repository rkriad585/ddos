_ddos() {
    local commands="resolve tcp-check http-check diagnose batch repeat self-update self-uninstall"
    local current="${COMP_WORDS[COMP_CWORD]}"
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=($(compgen -W "$commands --help --version" -- "$current"))
    else
        COMPREPLY=($(compgen -W "--timeout --retry --output --path --method --expect-status --show-header --redirects --proxy --interval --duration --verbose" -- "$current"))
    fi
}
complete -F _ddos ddos
