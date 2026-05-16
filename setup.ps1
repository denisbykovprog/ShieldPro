# ShieldPro Build Script v2.0
$ErrorActionPreference = "Stop"
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ShieldPro AntiVirus Build Script v2" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$DistDir = Join-Path $ProjectRoot "dist"
$BuildDir = Join-Path $ProjectRoot "build"

Write-Host "`n[1/3] Checking Python..." -ForegroundColor Yellow
$PythonVersion = & python --version 2>&1
if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: Python not found!"; exit 1 }
Write-Host "Found: $PythonVersion" -ForegroundColor Green

Write-Host "`n[2/3] Installing dependencies..." -ForegroundColor Yellow
pip install -r (Join-Path $ProjectRoot "requirements.txt") --quiet 2>&1 | Out-Null
Write-Host "Dependencies installed" -ForegroundColor Green

Write-Host "`n[3/3] Building executable..." -ForegroundColor Yellow
Push-Location $ProjectRoot
pyinstaller --onefile --name ShieldPro --distpath $DistDir --workpath $BuildDir --add-data "data;data" --noconsole "src\gui\shieldpro.py"
Pop-Location

$ExePath = Join-Path $DistDir "ShieldPro.exe"
if (Test-Path $ExePath) {
    $Size = [math]::Round((Get-Item $ExePath).Length / 1MB, 2)
    Write-Host "`nBUILD SUCCESSFUL!" -ForegroundColor Green
    Write-Host "Executable: $ExePath ($Size MB)" -ForegroundColor Cyan
} else { Write-Host "Build failed!" -ForegroundColor Red; exit 1 }
