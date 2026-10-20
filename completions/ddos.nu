def "nu-complete ddos commands" [] {
    [resolve tcp-check http-check diagnose batch repeat self-update self-uninstall]
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
    --verbose
]
