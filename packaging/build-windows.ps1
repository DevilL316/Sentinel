<#
.SYNOPSIS
  Builds dist\Sentinel.exe, a single self-contained executable, on Windows.

.DESCRIPTION
  Creates an isolated virtual environment (.build-venv), installs the pinned build requirements,
  then runs packaging\build.py (unit tests -> PyInstaller -> start the exe and smoke-test it -> SHA-256).
  Needs Python 3.10+ (3.12 recommended) on PATH and internet access to PyPI. Does not need Administrator rights.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File packaging\build-windows.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File packaging\build-windows.ps1 -SkipTests
#>
param(
    [switch]$SkipTests,
    [switch]$SkipSmoke
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

function Invoke-Checked {
    param([string]$Exe, [string[]]$Arguments)
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $Exe $($Arguments -join ' ')"
    }
}

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python was not found on PATH. Install Python 3.12 from python.org (tick 'Add python.exe to PATH') and retry."
}
$ver = & python -c "import sys; print('%d.%d' % sys.version_info[:2])"
if ([version]$ver -lt [version]"3.10") {
    throw "Python $ver found, but 3.10 or newer is required (3.12 recommended)."
}
Write-Host "Using Python $ver"

$venv = Join-Path (Get-Location) ".build-venv"
$py = Join-Path $venv "Scripts\python.exe"
if (-not (Test-Path $py)) {
    Invoke-Checked "python" @("-m", "venv", $venv)
}
Invoke-Checked $py @("-m", "pip", "install", "--upgrade", "pip")
Invoke-Checked $py @("-m", "pip", "install", "-r", "requirements-build.txt")

$buildArgs = @("packaging\build.py")
if ($SkipTests) { $buildArgs += "--skip-tests" }
if ($SkipSmoke) { $buildArgs += "--skip-smoke" }
Invoke-Checked $py $buildArgs

Write-Host ""
Write-Host "Done: $(Join-Path (Get-Location) 'dist\Sentinel.exe')"
Write-Host "Optional: sign it with your own code-signing certificate to avoid SmartScreen warnings."
