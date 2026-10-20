[CmdletBinding()]
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)

$ErrorActionPreference = "Stop"
$Project = "ddos"
$Repository = "rkriad585/ddos"
$ConfigDir = Join-Path $HOME ".config\peekstore\$Project"
$BinaryPath = Join-Path $ConfigDir "$Project.exe"
$ApiUrl = "https://api.github.com/repos/$Repository/releases/latest"
$isUninstall = $Arguments -contains "--selfuninstall" -or $Arguments -contains "--uninstall" -or $Arguments -contains "-u"

function Remove-PathEntry {
    $current = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($null -eq $current) { return }
    $entries = @($current -split ';' | Where-Object { $_ -and $_.TrimEnd('\') -ine $ConfigDir.TrimEnd('\') })
    [Environment]::SetEnvironmentVariable("Path", ($entries -join ';'), "User")
}

if ($isUninstall) {
    if (Test-Path -LiteralPath $BinaryPath) { Remove-Item -LiteralPath $BinaryPath -Force }
    if (Test-Path -LiteralPath $ConfigDir) {
        $children = @(Get-ChildItem -LiteralPath $ConfigDir -Force)
        if ($children.Count -eq 0) { Remove-Item -LiteralPath $ConfigDir -Force }
    }
    Remove-PathEntry
    Write-Host "ddos was uninstalled from $ConfigDir"
    Write-Host "Restart PowerShell to refresh PATH."
    exit 0
}

$release = Invoke-RestMethod -Uri $ApiUrl
$tag = [string]$release.tag_name
if ([string]::IsNullOrWhiteSpace($tag)) { throw "No published GitHub release found." }
$arch = if ($env:PROCESSOR_ARCHITEW6432 -eq "ARM64" -or $env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "aarch64" } else { "x86_64" }
$asset = "ddos-windows-$arch.exe"
$downloadUrl = "https://github.com/$Repository/releases/download/$tag/$asset"
$checksumUrl = "https://github.com/$Repository/releases/download/$tag/SHA256SUMS"

New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
$temporary = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $temporary
    $expected = ((Invoke-WebRequest -Uri $checksumUrl).Content -split "`n" | Where-Object { $_ -match "\s+$([regex]::Escape($asset))\s*$" } | ForEach-Object { ($_ -split '\s+')[0] } | Select-Object -First 1)
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $temporary).Hash.ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($expected) -or $expected.ToLowerInvariant() -ne $actual) { throw "Checksum verification failed for $asset." }
    Move-Item -LiteralPath $temporary -Destination $BinaryPath -Force
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$entries = @($userPath -split ';' | Where-Object { $_ })
if ($entries -notcontains $ConfigDir) { [Environment]::SetEnvironmentVariable("Path", (($entries + $ConfigDir) -join ';'), "User") }
& $BinaryPath --version
Write-Host "Installed $Project to $BinaryPath"
Write-Host "Restart PowerShell to refresh PATH."
