param(
  [switch]$InstallTshark,
  [string]$PythonVersion = "-3.11"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step($Message) {
  Write-Host ""
  Write-Host "==> $Message" -ForegroundColor Cyan
}

function Get-PythonLauncher {
  $py = Get-Command py -ErrorAction SilentlyContinue
  if ($py) {
    return @("py", $PythonVersion)
  }
  $python = Get-Command python -ErrorAction SilentlyContinue
  if ($python) {
    return @("python")
  }
  throw "Python was not found. Install Python 3.11+ and rerun this script."
}

function Resolve-TShark {
  $cmd = Get-Command tshark -ErrorAction SilentlyContinue
  if ($cmd) {
    return $cmd.Source
  }
  $candidates = @(
    "$env:ProgramFiles\Wireshark\tshark.exe",
    "${env:ProgramFiles(x86)}\Wireshark\tshark.exe"
  )
  foreach ($candidate in $candidates) {
    if ($candidate -and (Test-Path $candidate)) {
      return $candidate
    }
  }
  return $null
}

Write-Step "Checking repository"
if (-not (Test-Path "requirements.txt")) {
  throw "Run this script from the TraceMAP repository root."
}

Write-Step "Preparing Python virtual environment"
$launcher = Get-PythonLauncher
if (-not (Test-Path ".venv")) {
  $launcherArgs = @()
  if ($launcher.Count -gt 1) {
    $launcherArgs = $launcher[1..($launcher.Count - 1)]
  }
  & $launcher[0] @launcherArgs -m venv .venv
}

$pythonExe = Join-Path $PWD ".venv\Scripts\python.exe"
if (-not (Test-Path $pythonExe)) {
  throw "Virtual environment is missing $pythonExe"
}

Write-Step "Installing Python dependencies"
& $pythonExe -m pip install --upgrade pip
& $pythonExe -m pip install -r requirements.txt

if ($InstallTshark) {
  $existing = Resolve-TShark
  if (-not $existing) {
    Write-Step "Installing Wireshark/tshark"
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if ($winget) {
      winget install --id WiresharkFoundation.Wireshark --silent --accept-package-agreements --accept-source-agreements
    } elseif ($choco) {
      choco install wireshark -y --no-progress
    } else {
      Write-Warning "Neither winget nor choco is available. Install Wireshark manually."
    }
  }
}

$tshark = Resolve-TShark
if ($tshark) {
  $env:TC_RCA__TSHARK__BINARY = $tshark
  Write-Host "Using tshark: $tshark" -ForegroundColor Green
} else {
  Write-Warning "tshark was not found. Upload parsing will fail until Wireshark/tshark is installed."
}

Write-Step "Running TraceMAP preflight"
& $pythonExe scripts\preflight.py

Write-Host ""
Write-Host "Setup complete. Start the app with:" -ForegroundColor Green
Write-Host "  .\scripts\run_windows.ps1"
