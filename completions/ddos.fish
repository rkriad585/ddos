complete -c ddos -f -n '__fish_use_subcommand' -a 'resolve tcp-check http-check diagnose batch repeat self-update self-uninstall'
complete -c ddos -l timeout -r -d 'Timeout in seconds (1-120)'
complete -c ddos -l retry -r -d 'Retry count (0-5)'
complete -c ddos -l output -r -a 'text json'
complete -c ddos -l path -r
complete -c ddos -l method -r -a 'HEAD GET'
complete -c ddos -l expect-status -r
complete -c ddos -l show-header -r
complete -c ddos -l redirects -r
complete -c ddos -l proxy -r
complete -c ddos -l interval -r
complete -c ddos -l duration -r
complete -c ddos -l verbose
