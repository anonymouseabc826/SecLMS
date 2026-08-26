# scripts/run_perf_sweep.ps1 - CW305 performance sweep (generic).
# Usage:
#   powershell -File scripts/run_perf_sweep.ps1 -Platform shake256 -Bit build/cw305/xxx.bit
#       [-PureSoftware] [-Combos W1_H5,W4_H10] [-OutDir build/perf_shake_hw]
# -Platform: shake256|sha256 (vector/oracle selection)
# -Bit: bitstream to flash per combo (hardware or pure-software bit)
# -PureSoftware: add --pure-software (NO_HW_ACCEL firmware expectations: hw=0, hits frozen)
# -Combos: default 9-param hardware set (W1/2/4 x H5/10/15); for software baseline pass
#          the specific combos (e.g. W4_H5,W4_H10)
# Each combo: flash bit (resets hits) -> insecure LM-OTS + LMS suite -> archive log.
param(
    [string]$Platform = "shake256",
    [string]$Bit = "build/vivado_lms_cw305/lms_cw305.bit",
    [switch]$PureSoftware,
    [string]$Combos = "W1_H5,W1_H10,W1_H15,W2_H5,W2_H10,W2_H15,W4_H5,W4_H10,W4_H15",
    [string]$OutDir = ""
)
$ErrorActionPreference = 'Continue'
Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONIOENCODING = 'utf-8'
$env:TMP = Join-Path (Split-Path -Parent $PSScriptRoot) 'build\cw305\tmp'
$env:TEMP = Join-Path (Split-Path -Parent $PSScriptRoot) 'build\cw305\tmp'
$env:PYTHONPATH = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts'

if ($OutDir -eq "") {
    $suffix = if ($PureSoftware) { "sw" } else { "hw" }
    $OutDir = "build/perf_${Platform}_${suffix}"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
if (-not (Test-Path $Bit)) { Write-Host "ERROR: bit not found: $Bit"; exit 1 }

$summary = @()
foreach ($combo in $Combos.Split(',')) {
    if ($combo -notmatch '^W(\d+)_H(\d+)$') { Write-Host "skip bad combo: $combo"; continue }
    $w = [int]$Matches[1]; $h = [int]$Matches[2]
    $tag = "$Platform`_$combo"
    $flashLog = "$OutDir/flash_$tag.log"
    $testLog  = "$OutDir/$tag.log"

    Write-Host "==== [$tag] flash $Bit ===="
    & ".\python" "scripts/prog_cw305.py" $Bit *> $flashLog
    if ($LASTEXITCODE -ne 0) {
        Write-Host "!! [$tag] FLASH FAILED (see $flashLog)"
        $summary += "$tag`tFLASH_FAIL"
        continue
    }

    Write-Host "==== [$tag] test (w=$w h=$h) ===="
    $pyArgs = @(
        "tests/board/test_lms_uart.py", "--transport", "cw305", "--hash", $Platform,
        "--w", "$w", "--h", "$h",
        "--insecure-lmots-test", "--insecure-keygen-test", "--insecure-sign-test",
        "--keygen-timeout", "1800", "--sign-timeout", "900",
        "--verify-timeout", "900", "--lmots-timeout", "900"
    )
    if ($PureSoftware) { $pyArgs += "--pure-software" }
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
Write-Host "================ SUMMARY ($Platform, pure=$PureSoftware) ================"
foreach ($s in $summary) { Write-Host $s }
$summary | Out-File "$OutDir/summary_$Platform.txt" -Encoding utf8
