# Builds cvalt.exe with the MSYS2 UCRT64 toolchain (static libsodium, no DLLs).
$ErrorActionPreference = 'Stop'

$msys   = 'C:\msys64\ucrt64'
$gpp    = Join-Path $msys 'bin\g++.exe'
$outDir = Join-Path $PSScriptRoot 'build'

if (-not (Test-Path $gpp)) { throw "g++ not found at $gpp" }

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

& $gpp -std=c++20 -Wall -Wextra -Wpedantic -O2 `
    -I (Join-Path $msys 'include') `
    (Join-Path $PSScriptRoot 'kdf.cpp') `
    (Join-Path $PSScriptRoot 'vault_file.cpp') `
    (Join-Path $PSScriptRoot 'main.cpp') `
    -o (Join-Path $outDir 'cvalt.exe') `
    -L (Join-Path $msys 'lib') -lsodium -static -static-libgcc -static-libstdc++

if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }

Write-Host "built $outDir\cvalt.exe"
