# scripts/deploy_board_two_phase.ps1 - P1-6 board two-phase deploy regression (FW 0.1.274).
# Phase A (test bit): FACTORY_INIT -> capture wrapped blob -> build/deploy_blob.bin.
# Phase B (deploy bit): SEED_LOAD/FACTORY_INIT/INJECT_TAG rejections + BOOT unwrap +
#   0x67/0x66/0x56 self-consistent loop.
# Usage:
#   powershell -File scripts/deploy_board_two_phase.ps1
#   powershell -File scripts/deploy_board_two_phase.ps1 -Phase A
param(
    [string]$Phase = "both",
    [string]$TestBit = "build/bitstreams/shake_fw0274_20260816.bit",
    [string]$DeployBit = "build/bitstreams/shake_deploy_fw0274_20260816.bit"
)
$ErrorActionPreference = 'Continue'
Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONIOENCODING = 'utf-8'
$outdir = "build/board0274"
New-Item -ItemType Directory -Force -Path $outdir | Out-Null

function Flash-Bit([string]$bit, [string]$log) {
    Get-Process | Where-Object { $_.ProcessName -match 'vivado|hw_server|cs_server' } | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    cmd /c "D:\code\Vivado\Vivado\2020.2\bin\vivado.bat -mode batch -source flow\program_bit.tcl -tclargs $bit > $log 2>&1"
    if (-not (Select-String -Path $log -Pattern "PROGRAMMED" -Quiet)) {
        throw "FLASH FAILED for $bit (see $log)"
    }
}

function Run-Py([string[]]$argsList, [string]$log) {
    $proc = Start-Process -FilePath ".\python" -ArgumentList $argsList `
        -NoNewWindow -Wait -PassThru -RedirectStandardOutput $log -RedirectStandardError "$log.err"
    if ($proc.ExitCode -ne 0) {
        throw "python exit=$($proc.ExitCode) (see $log)"
    }
}

if ($Phase -in @("A", "both")) {
    Write-Host "==== Phase A: factory on test bit ===="
    Flash-Bit $TestBit "$outdir/flash_A.log"
    Run-Py @("tests/board/test_lms_uart.py", "--port", "COM5", "--hash", "shake256",
             "--w", "4", "--h", "5", "--deploy-factory") "$outdir/deploy_factory.log"
    if (-not (Test-Path "build/deploy_blob.bin")) { throw "phase A did not produce build/deploy_blob.bin" }
    Write-Host "== Phase A PASS (wrapped blob captured)"
}

if ($Phase -in @("B", "both")) {
    Write-Host "==== Phase B: deploy loop on deploy bit ===="
    Flash-Bit $DeployBit "$outdir/flash_B.log"
    Run-Py @("tests/board/test_lms_uart.py", "--port", "COM5", "--hash", "shake256",
             "--w", "4", "--h", "5", "--deploy-test") "$outdir/deploy_test.log"
    Write-Host "== Phase B PASS (deploy closed loop)"
}

Write-Host "================ DEPLOY TWO-PHASE SUMMARY ================"
Write-Host "logs in $outdir"
