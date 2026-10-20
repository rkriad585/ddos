complete -c ddos -f -n '__fish_use_subcommand' -a 'resolve tcp-check http-check diagnose udp-check dns-check batch repeat load-test self-update self-uninstall'
complete -c ddos -l timeout -r -d 'Timeout in seconds (1-120)'
complete -c ddos -l retry -r -d 'Retry count (0-5)'
complete -c ddos -l output -r -a 'text json jsonl csv'
complete -c ddos -l path -r
complete -c ddos -l method -r -a 'HEAD GET'
complete -c ddos -l expect-status -r
complete -c ddos -l show-header -r
complete -c ddos -l redirects -r
complete -c ddos -l proxy -r
complete -c ddos -l interval -r
complete -c ddos -l duration -r
complete -c ddos -l header -r -d 'Custom request header (Name: value)'
complete -c ddos -l auth -r -d 'Auth (basic or bearer)'
complete -c ddos -l user-agent -r
complete -c ddos -l body-bytes -r -d 'Read up to N body bytes with GET'
complete -c ddos -l family -r -a 'any ipv4 ipv6'
complete -c ddos -l config -r
complete -c ddos -l no-config
complete -c ddos -l payload -r -d 'Hex bytes for udp-check'
complete -c ddos -l dns-type -r -a 'A AAAA CNAME TXT MX NS'
complete -c ddos -l dns-server -r
complete -c ddos -l rate -r -d 'Requests per second (1-50, load-test)'
complete -c ddos -l count -r -d 'Total requests (1-5000, load-test)'
complete -c ddos -l rotate-user-agent -d 'Rotate user agents per request (load-test)'
complete -c ddos -l verbose
