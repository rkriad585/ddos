Register-ArgumentCompleter -CommandName ddos -ScriptBlock {
    param($commandName, $wordToComplete, $cursorPosition)
    $values = @('resolve','tcp-check','http-check','diagnose','udp-check','dns-check','batch','repeat','load-test','self-update','self-uninstall','--help','--version','--timeout','--retry','--output','--path','--method','--expect-status','--show-header','--redirects','--proxy','--interval','--duration','--header','--auth','--user-agent','--body-bytes','--family','--config','--no-config','--payload','--dns-type','--dns-server','--rate','--count','--rotate-user-agent','--verbose')
    $values | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
