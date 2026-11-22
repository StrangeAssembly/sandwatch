<#
.SYNOPSIS
  Build, test and run Sandwatch inside a Docker Rust toolchain (no local Rust install needed).
.EXAMPLE
  .\scripts\dev.ps1 build
  .\scripts\dev.ps1 test
  .\scripts\dev.ps1 sandwatch eval recordings -v
  .\scripts\dev.ps1 sandwatch replay recordings\full-chain-s1.swrec.gz
#>
param([Parameter(Mandatory = $true, Position = 0)][string]$Command,
      [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest)
$ErrorActionPreference = "Continue"
$Root = Split-Path $PSScriptRoot -Parent
$Image = "sandwatch-dev:0.3"
$common = @("run", "--rm", "-v", "${Root}:/src", "-w", "/src",
            "-v", "sandwatch-cargo-registry:/usr/local/cargo/registry",
            "-v", "sandwatch-target:/target", "-e", "CARGO_TARGET_DIR=/target")
# Windows paths in arguments (recordings\x) -> forward slashes for the Linux container
$args2 = @($Rest | ForEach-Object { $_ -replace '\\', '/' })
switch ($Command) {
  "build"     { docker @common $Image cargo build --release @args2 }
  "test"      { docker @common $Image cargo test --release @args2 }
  "clippy"    { docker @common $Image bash -c "rustup component add clippy >/dev/null 2>&1; cargo clippy --release --all-targets -- -D warnings" }
  "sandwatch" { docker @common $Image bash -c "cargo build --release -q && /target/release/sandwatch $($args2 -join ' ')" }
  default     { docker @common $Image @($Command) @args2 }
}
exit $LASTEXITCODE
