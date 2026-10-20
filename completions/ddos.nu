def "nu-complete ddos commands" [] {
    [resolve tcp-check http-check diagnose udp-check dns-check batch repeat load-test self-update self-uninstall]
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
    --rate: int
    --count: int
    --rotate-user-agent
    --verbose
]
