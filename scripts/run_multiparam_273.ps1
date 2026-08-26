# scripts/run_multiparam_273.ps1 - FW 0.1.273 board 9-param sweep (no W8, same scope as 0.1.271 gate).
# Per combo: reflash board (reset hits) -> full KAT+LM-OTS+LMS suite -> archive log.
# Usage:
#   powershell -File scripts/run_multiparam_273.ps1
#   powershell -File scripts/run_multiparam_273.ps1 -Combos W4_H5,W1_H10
param(
    [string]$Combos = "W1_H5,W1_H10,W1_H15,W2_H5,W2_H10,W2_H15,W4_H5,W4_H10,W4_H15"
)
$ErrorActionPreference = 'Continue'
Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONIOENCODING = 'utf-8'

$bit = "build/bitstreams/shake_fw0273_20260816.bit"
$platform = "shake256"
$outdir = "build/multiparam_273"
New-Item -ItemType Directory -Force -Path $outdir | Out-Null

$summary = @()
foreach ($combo in $Combos.Split(',')) {
    if ($combo -notmatch '^W(\d+)_H(\d+)$') { Write-Host "skip bad combo: $combo"; continue }
    $w = [int]$Matches[1]; $h = [int]$Matches[2]
    $tag = "$platform`_$combo"
    $flashLog = "$outdir/flash_$tag.log"
    $testLog  = "$outdir/$tag.log"

    # kill stale hw tools before each flash (reliable reflash, per session notes)
    Get-Process | Where-Object { $_.ProcessName -match 'vivado|hw_server|cs_server' } | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    Write-Host "==== [$tag] flash $bit ===="
    cmd /c "D:\code\Vivado\Vivado\2020.2\bin\vivado.bat -mode batch -source flow\program_bit.tcl -tclargs $bit > $flashLog 2>&1"
    $flashOk = Select-String -Path $flashLog -Pattern "PROGRAMMED" -Quiet
    if (-not $flashOk) {
        Write-Host "!! [$tag] FLASH FAILED (see $flashLog)"
        $summary += "$tag`tFLASH_FAIL"
        continue
    }

    Write-Host "==== [$tag] test (w=$w h=$h) ===="
    $pyArgs = @(
        "tests/board/test_lms_uart.py", "--port", "COM5", "--hash", $platform,
        "--w", "$w", "--h", "$h",
        "--insecure-lmots-test", "--insecure-keygen-test", "--insecure-sign-test",
        "--keygen-timeout", "900", "--sign-timeout", "300",
        "--verify-timeout", "300", "--lmots-timeout", "300"
    )
    $proc = Start-Process -FilePath ".\python" -ArgumentList $pyArgs `
        -NoNewWindow -Wait -PassThru -RedirectStandardOutput $testLog -RedirectStandardError "$testLog.err"
    $code = $proc.ExitCode
    if ($code -eq 0) {
        $summary += "$tag`tPASS"
        Write-Host "== [$tag] PASS"
    } else {
        $summary += "$tag`tFAIL($code)"
        Write-Host "!! [$tag] FAIL exit=$code (see $testLog)"
    }
}

Write-Host ""
Write-Host "================ SUMMARY ($platform) ================"
foreach ($s in $summary) { Write-Host $s }
$summary | Out-File "$outdir/summary_$platform.txt" -Encoding utf8
Write-Host "logs in $outdir"
