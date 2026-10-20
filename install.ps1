param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
$script = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/rkriad585/ddos/main/installer.ps1"
& ([scriptblock]::Create($script)) @Arguments
