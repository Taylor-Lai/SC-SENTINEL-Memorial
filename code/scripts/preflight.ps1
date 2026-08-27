[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Failures = [System.Collections.Generic.List[string]]::new()

function Check([bool]$Condition, [string]$Success, [string]$Failure) {
    if ($Condition) { Write-Host "[OK] $Success" -ForegroundColor Green }
    else { Write-Host "[FAIL] $Failure" -ForegroundColor Red; $Failures.Add($Failure) }
}

Write-Host "SC-SENTINEL competition preflight" -ForegroundColor Cyan
Check ($null -ne (Get-Command docker -ErrorAction SilentlyContinue)) "Docker CLI is available" "Docker CLI was not found"

$EnvFile = Join-Path $RepoRoot ".env"
Check (Test-Path -LiteralPath $EnvFile) ".env exists" "Copy .env.example to .env and configure it"
if (Test-Path -LiteralPath $EnvFile) {
    $Configured = @{}
    Get-Content -LiteralPath $EnvFile -Encoding utf8 | ForEach-Object {
        if ($_ -match '^\s*([A-Z0-9_]+)\s*=\s*(.*)$') { $Configured[$Matches[1]] = $Matches[2].Trim() }
    }
    Check (-not [string]::IsNullOrWhiteSpace($Configured.POSTGRES_PASSWORD)) "Database password is configured" "POSTGRES_PASSWORD is empty"
    if ([string]::IsNullOrWhiteSpace($Configured.LLM_API_KEY)) {
        Write-Host "[WARN] LLM_API_KEY is empty; the audit runs in rule-fallback mode" -ForegroundColor Yellow
    } else {
        Check (-not [string]::IsNullOrWhiteSpace($Configured.LLM_BASE_URL)) "LLM endpoint is configured" "LLM_BASE_URL is empty"
        Check (-not [string]::IsNullOrWhiteSpace($Configured.LLM_MODEL)) "LLM model is configured" "LLM_MODEL is empty"
    }
}

try {
    $ServerOs = docker info --format '{{.OSType}}' 2>$null
    Check ($LASTEXITCODE -eq 0) "Docker engine is reachable" "Docker engine is not running or cannot be reached"
    Check ($ServerOs -eq 'linux') "Docker is using Linux containers" "Switch Docker Desktop to Linux containers"
} catch {
    $Failures.Add("Docker engine preflight failed")
}

if ($Failures.Count -gt 0) {
    Write-Host "`nPreflight failed with $($Failures.Count) blocking issue(s)." -ForegroundColor Red
    exit 1
}

Write-Host "`nPreflight passed. Run: docker compose --profile sandbox build; docker compose up -d" -ForegroundColor Green
