# ShieldPro Build Script
# AntiVirus by RuGuard
# Uses Tkinter (included with Python) - no external dependencies required

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ShieldPro AntiVirus Build Script" -ForegroundColor Cyan
Write-Host "  Company: RuGuard" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$DistDir = Join-Path $ProjectRoot "dist"
$BuildDir = Join-Path $ProjectRoot "build"

Write-Host "`n[1/4] Checking Python..." -ForegroundColor Yellow
$PythonVersion = & python --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Python not found!" -ForegroundColor Red
    Write-Host "Install from: https://www.python.org/" -ForegroundColor Yellow
    exit 1
}
Write-Host "Found: $PythonVersion" -ForegroundColor Green

Write-Host "`n[2/4] Installing build tools..." -ForegroundColor Yellow
pip install pyinstaller --quiet 2>&1 | Out-Null
Write-Host "PyInstaller installed" -ForegroundColor Green

Write-Host "`n[3/4] Building executable..." -ForegroundColor Yellow
Push-Location $ProjectRoot

pyinstaller --onefile --name ShieldPro --distpath $DistDir --workpath $BuildDir --add-data "data;data" "src\gui\shieldpro_tk.py"

Pop-Location

Write-Host "`n[4/4] Verifying build..." -ForegroundColor Yellow
$ExePath = Join-Path $DistDir "ShieldPro.exe"
if (Test-Path $ExePath) {
    $Size = [math]::Round((Get-Item $ExePath).Length / 1MB, 2)
    Write-Host "Build successful!" -ForegroundColor Green
    Write-Host "Executable: $ExePath ($Size MB)" -ForegroundColor Cyan
} else {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  BUILD COMPLETE!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Run: $ExePath" -ForegroundColor Yellow
Write-Host ""
Write-Host "Test EICAR virus detection:" -ForegroundColor Cyan
Write-Host "  Create file with: X5O!P%@AP[4\PZX54(P^)7CC)7}\`$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\`$H+H*" -ForegroundColor White
Write-Host ""