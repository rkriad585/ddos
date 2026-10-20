#compdef ddos

_arguments '1:command:(resolve tcp-check http-check diagnose batch repeat self-update self-uninstall)' \
  '*::option:(--timeout --retry --output --path --method --expect-status --show-header --redirects --proxy --interval --duration --verbose --help --version)'
