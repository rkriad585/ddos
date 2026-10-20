#compdef ddos

_arguments '1:command:(resolve tcp-check http-check diagnose udp-check dns-check batch repeat load-test self-update self-uninstall)' \
  '*::option:(--timeout --retry --output --path --method --expect-status --show-header --redirects --proxy --interval --duration --header --auth --user-agent --body-bytes --family --config --no-config --payload --dns-type --dns-server --rate --count --rotate-user-agent --verbose --help --version)'
