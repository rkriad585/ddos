Register-ArgumentCompleter -CommandName ddos -ScriptBlock {
    param($commandName, $wordToComplete, $cursorPosition)
    $values = @('resolve','tcp-check','http-check','diagnose','batch','repeat','self-update','self-uninstall','--help','--version','--timeout','--retry','--output','--path','--method','--expect-status','--show-header','--redirects','--proxy','--interval','--duration','--verbose')
    $values | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
