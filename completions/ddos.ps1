Register-ArgumentCompleter -CommandName ddos -ScriptBlock {
    param($commandName, $wordToComplete, $cursorPosition)
    $values = @('resolve','tcp-check','http-check','diagnose','report','udp-check','dns-check','tls-check','user-agents','batch','repeat','load-test','port-scan','path-discovery','cors-check','cookie-check','method-check','completion','config','self-update','self-uninstall','--help','--version','--timeout','--retry','--output','--path','--method','--expect-status','--show-header','--redirects','--proxy','--interval','--duration','--header','--auth','--user-agent','--body-bytes','--family','--config','--no-config','--payload','--dns-type','--dns-server','--scope','--audit-log','--audit-headers','--rate','--count','--concurrency','--ports','--wordlist','--origin','--rotate-user-agent','--random-user-agent','--quiet','--no-color','--verbose')
    $values | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
