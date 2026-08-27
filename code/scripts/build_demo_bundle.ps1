[CmdletBinding()]
param(
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Source = Join-Path $RepoRoot "sentinel_agent\samples\vulnerable_project"
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $RepoRoot "tmp\SC-SENTINEL-demo.zip"
}
$ResolvedParent = [System.IO.Path]::GetFullPath((Split-Path -Parent $OutputPath))
if (-not $ResolvedParent.StartsWith([System.IO.Path]::GetFullPath($RepoRoot), [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "OutputPath must remain inside the repository"
}
New-Item -ItemType Directory -Path $ResolvedParent -Force | Out-Null
if (Test-Path -LiteralPath $OutputPath) { Remove-Item -LiteralPath $OutputPath -Force }
Compress-Archive -Path (Join-Path $Source "*") -DestinationPath $OutputPath -CompressionLevel Optimal
Write-Host "Demo bundle created: $OutputPath" -ForegroundColor Green
