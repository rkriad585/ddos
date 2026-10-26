def "nu-complete ddos commands" [] {
    [resolve tcp-check http-check diagnose report udp-check dns-check tls-check user-agents batch repeat load-test port-scan path-discovery cors-check cookie-check method-check completion config self-update self-uninstall]
}

export extern ddos [
    command?: string@"nu-complete ddos commands"
    --timeout: int
    --retry: int
    --output: string
    --path: string
    --method: string
    --expect-status: int
    --show-header: string
    --redirects: int
    --proxy: string
    --interval: int
    --duration: int
    --header: string
    --auth: string
    --user-agent: string
    --body-bytes: int
    --family: string
    --config: string
    --no-config
    --payload: string
    --dns-type: string
    --dns-server: string
    --scope: string
    --audit-log: string
    --audit-headers
    --rate: int
    --count: int
    --concurrency: int
    --ports: string
    --wordlist: string
    --origin: string
    --rotate-user-agent
    --random-user-agent
    --quiet
    --no-color
    --verbose
]
