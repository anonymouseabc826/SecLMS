# scripts/run_multiparam_270.ps1 - FW 0.1.270 dual-platform 12-param board sweep.
# Per combo: reflash board (reset hits) -> full KAT+LM-OTS+LMS suite -> archive log.
# Usage:
#   powershell -File scripts/run_multiparam_270.ps1 -Platform shake256
#   powershell -File scripts/run_multiparam_270.ps1 -Platform sha256 -Combos W1_H5,W4_H15
param(
    [string]$Platform = "shake256",
    [string]$Combos = "W1_H5,W1_H10,W1_H15,W2_H5,W2_H10,W2_H15,W4_H5,W4_H10,W4_H15,W8_H5,W8_H10,W8_H15"
)
$ErrorActionPreference = 'Continue'
Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONIOENCODING = 'utf-8'

$bits = @{
    shake256 = "build/bitstreams/shake_fw0270_fwfix_20260815.bit"
    sha256   = "build/bitstreams/sha256_fw0270_20260815.bit"
}
$bit = $bits[$Platform]
if (-not $bit) { throw "unknown platform: $Platform" }

$outdir = "build/multiparam_270"
New-Item -ItemType Directory -Force -Path $outdir | Out-Null

$summary = @()
foreach ($combo in $Combos.Split(',')) {
    if ($combo -notmatch '^W(\d+)_H(\d+)$') { Write-Host "skip bad combo: $combo"; continue }
    $w = [int]$Matches[1]; $h = [int]$Matches[2]
    $tag = "$Platform`_$combo"
    $flashLog = "$outdir\flash_$tag.log"
    $testLog  = "$outdir\$tag.log"

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
        "tests/board/test_lms_uart.py", "--port", "COM5", "--hash", $Platform,
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
Write-Host "================ SUMMARY ($Platform) ================"
foreach ($s in $summary) { Write-Host $s }
$summary | Out-File "$outdir\summary_$Platform.txt" -Encoding utf8
Write-Host "logs in $outdir"
