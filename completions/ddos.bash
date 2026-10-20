_ddos() {
    local commands="resolve tcp-check http-check diagnose udp-check dns-check batch repeat load-test self-update self-uninstall"
    local options="--timeout --retry --output --path --method --expect-status --show-header --redirects --proxy --interval --duration --header --auth --user-agent --body-bytes --family --config --no-config --payload --dns-type --dns-server --rate --count --rotate-user-agent --verbose --help --version"
    local current="${COMP_WORDS[COMP_CWORD]}"
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=($(compgen -W "$commands" -- "$current"))
    else
        COMPREPLY=($(compgen -W "$options" -- "$current"))
    fi
}
complete -F _ddos ddos
