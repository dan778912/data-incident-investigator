[CmdletBinding()]
param(
    [ValidateRange(1, 65535)]
    [int]$ApiPort = 8000,
    [ValidateRange(1, 65535)]
    [int]$WebPort = 5173
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$webRoot = Join-Path $repoRoot "web"
$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
$isWindowsHost = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
$python = if (Test-Path $venvPython) { $venvPython } else { (Get-Command python).Source }
$npm = if ($isWindowsHost) { (Get-Command npm.cmd).Source } else { (Get-Command npm).Source }
$logRoot = Join-Path $repoRoot "tmp\dev"
New-Item -ItemType Directory -Force $logRoot | Out-Null

if (-not (Test-Path (Join-Path $webRoot "node_modules"))) {
    Push-Location $webRoot
    try {
        & $npm ci
        if ($LASTEXITCODE -ne 0) {
            throw "Frontend dependency installation failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}

$env:APP_ENV = "development"
$env:APP_HOST = "127.0.0.1"
$env:APP_PORT = $ApiPort.ToString()
$env:VITE_API_MODE = "live"
$env:VITE_API_TARGET = "http://127.0.0.1:$ApiPort"

$startArguments = @{
    FilePath = $python
    ArgumentList = @(
        "-m", "uvicorn",
        "data_incident_investigator.api.main:app",
        "--host", "127.0.0.1",
        "--port", $ApiPort.ToString()
    )
    WorkingDirectory = $repoRoot
    PassThru = $true
    RedirectStandardOutput = (Join-Path $logRoot "api.stdout.log")
    RedirectStandardError = (Join-Path $logRoot "api.stderr.log")
}
if ($isWindowsHost) {
    $startArguments.WindowStyle = "Hidden"
}

$apiProcess = Start-Process @startArguments
try {
    $healthUri = "http://127.0.0.1:$ApiPort/api/health"
    $ready = $false
    for ($attempt = 1; $attempt -le 40; $attempt++) {
        if ($apiProcess.HasExited) {
            throw "The API exited during startup. See $logRoot for details."
        }
        try {
            $response = Invoke-WebRequest -Uri $healthUri -TimeoutSec 1 -UseBasicParsing
            if ($response.StatusCode -eq 200) {
                $ready = $true
                break
            }
        }
        catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if (-not $ready) {
        throw "The API did not become healthy at $healthUri. See $logRoot for details."
    }

    Write-Host "API ready at http://127.0.0.1:$ApiPort" -ForegroundColor Green
    Write-Host "API logs: $logRoot" -ForegroundColor DarkGray
    Write-Host "Starting the web app at http://127.0.0.1:$WebPort" -ForegroundColor Green

    Push-Location $webRoot
    try {
        & $npm run dev -- "--host=127.0.0.1" "--port=$WebPort"
        if ($LASTEXITCODE -ne 0) {
            throw "The frontend exited with code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}
finally {
    if (-not $apiProcess.HasExited) {
        Stop-Process -Id $apiProcess.Id -Force
    }
    $apiProcess.Dispose()
}
