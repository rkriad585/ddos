$ErrorActionPreference = "Stop"

$repo = "rkriad585/ddos"
$release = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest"
$assetName = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "ddos-windows-aarch64.exe" } else { "ddos-windows-x86_64.exe" }
$asset = $release.assets | Where-Object { $_.name -eq $assetName } | Select-Object -First 1
if (-not $asset) {
    throw "No Windows release asset found. Install with: cargo install --git https://github.com/$repo.git"
}

$binDir = Join-Path $HOME ".local\bin"
New-Item -ItemType Directory -Force -Path $binDir | Out-Null
$destination = Join-Path $binDir "ddos.exe"
$temporary = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())

try {
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $temporary
    Move-Item -Force $temporary $destination
} finally {
    if (Test-Path $temporary) { Remove-Item -Force $temporary }
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$pathEntries = @($userPath -split ';' | Where-Object { $_ })
if ($pathEntries -notcontains $binDir) {
    [Environment]::SetEnvironmentVariable("Path", (($pathEntries + $binDir) -join ';'), "User")
}

Write-Host "Installed ddos to $destination"
Write-Host "Restart PowerShell or add $binDir to PATH before running ddos."
