[CmdletBinding()]
param(
    [switch]$SkipFrontend
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
$python = if (Test-Path $venvPython) { $venvPython } else { (Get-Command python).Source }

function Invoke-Checked {
    param(
        [Parameter(Mandatory)]
        [string]$Label,
        [Parameter(Mandatory)]
        [scriptblock]$Command
    )

    Write-Host "`n==> $Label" -ForegroundColor Cyan
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE."
    }
}

Push-Location $repoRoot
try {
    Invoke-Checked "Python lint" { & $python -m ruff check . }
    Invoke-Checked "Python format check" { & $python -m ruff format --check . }
    Invoke-Checked "Python type check" { & $python -m mypy }
    Invoke-Checked "Backend tests and coverage" {
        & $python -m pytest `
            --cov=data_incident_investigator `
            --cov-branch `
            --cov-report=term-missing `
            --cov-fail-under=80
    }

    if (-not $SkipFrontend) {
        Push-Location (Join-Path $repoRoot "web")
        try {
            if (-not (Test-Path "node_modules")) {
                Invoke-Checked "Frontend dependency install" { & npm ci }
            }
            Invoke-Checked "Frontend tests" { & npm test }

            $previousApiMode = $env:VITE_API_MODE
            try {
                $env:VITE_API_MODE = "live"
                Invoke-Checked "Live frontend build" { & npm run build }
            }
            finally {
                $env:VITE_API_MODE = $previousApiMode
            }
        }
        finally {
            Pop-Location
        }
    }
}
finally {
    Pop-Location
}
