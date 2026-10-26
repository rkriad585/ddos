#compdef ddos

_arguments '1:command:(resolve tcp-check http-check diagnose report udp-check dns-check tls-check user-agents batch repeat load-test port-scan path-discovery cors-check cookie-check method-check completion config self-update self-uninstall)' \
  '*::option:(--timeout --retry --output --path --method --expect-status --show-header --redirects --proxy --interval --duration --header --auth --user-agent --body-bytes --family --config --no-config --payload --dns-type --dns-server --scope --audit-log --audit-headers --rate --count --concurrency --ports --wordlist --origin --rotate-user-agent --random-user-agent --quiet --no-color --verbose --help --version)'
