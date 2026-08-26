# scripts/run_multiparam_cw305.ps1 - CW305 board 9-param sweep (W1/W2/W4 x H5/10/15).
# Per combo: reflash board via ChipWhisperer (reset hits) -> full KAT+LM-OTS+LMS suite -> archive log.
# CW305 ported version: 0.275 Da Vinci script adapted for CW305 (flash via prog_cw305.py, test via --transport cw305).
# Usage:
#   powershell -File scripts/run_multiparam_cw305.ps1
#   powershell -File scripts/run_multiparam_cw305.ps1 -Combos W4_H5,W1_H10
param(
    [string]$Bit = "build/vivado_lms_cw305/lms_cw305.bit",
    [string]$Hash = "shake256",
    [string]$Combos = "W1_H5,W1_H10,W1_H15,W2_H5,W2_H10,W2_H15,W4_H5,W4_H10,W4_H15"
)
$ErrorActionPreference = 'Continue'
Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONIOENCODING = 'utf-8'
$env:TMP = Join-Path (Split-Path -Parent $PSScriptRoot) 'build\cw305\tmp'
$env:TEMP = Join-Path (Split-Path -Parent $PSScriptRoot) 'build\cw305\tmp'
$env:PYTHONPATH = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts'

$bit = $Bit
$platform = $Hash
$outdir = "build/multiparam_cw305_$platform"
New-Item -ItemType Directory -Force -Path $outdir | Out-Null

$summary = @()
foreach ($combo in $Combos.Split(',')) {
    if ($combo -notmatch '^W(\d+)_H(\d+)$') { Write-Host "skip bad combo: $combo"; continue }
    $w = [int]$Matches[1]; $h = [int]$Matches[2]
    $tag = "$platform`_$combo"
    $flashLog = "$outdir/flash_$tag.log"
    $testLog  = "$outdir/$tag.log"

    Write-Host "==== [$tag] flash $bit ===="
    & ".\python" "scripts/prog_cw305.py" $bit *> $flashLog
    if ($LASTEXITCODE -ne 0) {
        Write-Host "!! [$tag] FLASH FAILED (see $flashLog)"
        $summary += "$tag`tFLASH_FAIL"
        continue
    }

    Write-Host "==== [$tag] test (w=$w h=$h) ===="
    $pyArgs = @(
        "tests/board/test_lms_uart.py", "--transport", "cw305", "--hash", $platform,
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
