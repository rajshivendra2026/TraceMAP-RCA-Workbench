param(
  [int]$Port = 5050,
  [switch]$SkipPreflight
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

if (-not (Test-Path "requirements.txt")) {
  throw "Run this script from the TraceMAP repository root."
}

$pythonExe = Join-Path $PWD ".venv\Scripts\python.exe"
if (-not (Test-Path $pythonExe)) {
  throw "Virtual environment not found. Run .\scripts\setup_windows.ps1 first."
}

$tshark = Resolve-TShark
if ($tshark) {
  $env:TC_RCA__TSHARK__BINARY = $tshark
}

$env:TC_RCA__SERVER__PORT = [string]$Port
$env:MPLCONFIGDIR = Join-Path $PWD ".cache\matplotlib"

if (-not $SkipPreflight) {
  & $pythonExe scripts\preflight.py
  if ($LASTEXITCODE -ne 0) {
    throw "Preflight failed. Fix the reported issue or rerun with -SkipPreflight for local debugging only."
  }
}

Write-Host "Starting TraceMAP RCA Workbench on http://localhost:$Port" -ForegroundColor Green
& $pythonExe main.py
