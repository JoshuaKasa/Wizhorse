Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$sourcePath = Join-Path $projectRoot "benign_suspicious_plus.c"
$outputDir = Join-Path $projectRoot "bin"
$outputPath = Join-Path $outputDir "benign_suspicious_plus.exe"

if (-not (Test-Path -LiteralPath $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

$compiler = Get-Command clang -ErrorAction SilentlyContinue
if (-not $compiler) {
    $compiler = Get-Command gcc -ErrorAction SilentlyContinue
}
if (-not $compiler) {
    throw "No supported compiler found. Install clang or gcc."
}

& $compiler.Source `
    -Wall `
    -Wextra `
    -O2 `
    -municode `
    $sourcePath `
    -o $outputPath `
    -ladvapi32 `
    -liphlpapi

if ($LASTEXITCODE -ne 0) {
    throw "Compilation failed with exit code $LASTEXITCODE."
}

Write-Host "Built $outputPath"
