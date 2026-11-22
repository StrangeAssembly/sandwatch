<#
.SYNOPSIS
  Records every scenario in lab/scenarios/manifest.json into recordings/*.swrec.gz (Windows / Docker Desktop).
.EXAMPLE
  .\lab\record-all.ps1                 # build images, record everything
  .\lab\record-all.ps1 -Only "escape*" # only matching scenario ids
  .\lab\record-all.ps1 -NoBuild        # skip image build
#>
param([string]$Only = "", [switch]$NoBuild, [switch]$ConvertOnly)
# Not "Stop": docker writes progress to stderr, which Windows PowerShell 5.1 would treat as
# a terminating error. Failures are checked through $LASTEXITCODE instead.
$ErrorActionPreference = "Continue"
$Lab  = $PSScriptRoot
$Root = Split-Path $Lab -Parent
$manifest = Get-Content (Join-Path $Lab "scenarios\manifest.json") -Raw | ConvertFrom-Json

Push-Location $Lab
try {
  if (-not $NoBuild -and -not $ConvertOnly) {
    docker compose --profile run build
    if ($LASTEXITCODE -ne 0) { throw "image build failed" }
  }
  New-Item -ItemType Directory -Force (Join-Path $Lab "out\raw") | Out-Null
  New-Item -ItemType Directory -Force (Join-Path $Root "recordings") | Out-Null
  docker compose up -d labsvc 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "could not start labsvc" }

  foreach ($s in $manifest.scenarios) {
    if ($Only -and ($s.id -notlike $Only)) { continue }
    foreach ($seed in $s.seeds) {
      $rid = "$($s.id)-s$seed"
      $envArgs = @("-e", "SANDWATCH_SEED=$seed")
      if ($s.env) { foreach ($p in $s.env.PSObject.Properties) { $envArgs += @("-e", "$($p.Name)=$($p.Value)") } }
      if (-not $ConvertOnly) {
        docker compose run --rm @envArgs agent bash /lab/harness/record.sh $s.script $rid
        if ($LASTEXITCODE -ne 0) { throw "recording $rid failed" }
      }
      docker run --rm --network none -v "${Root}:/work" sandwatch-lab-agent:0.1 `
        python3 /work/tools/swrec_convert.py `
          --raw "/work/lab/out/raw/$rid.strace" --env "/work/lab/out/raw/$rid.env.json" `
          --manifest /work/lab/scenarios/manifest.json --scenario $s.id --seed $seed `
          --out "/work/recordings/$rid.swrec.gz"
      if ($LASTEXITCODE -ne 0) { throw "conversion of $rid failed" }
    }
  }
  docker compose down 2>&1 | Out-Null
}
finally { Pop-Location }

docker run --rm --network none -v "${Root}:/work" -w /work sandwatch-lab-agent:0.1 `
  bash -c "python3 tools/swrec_verify.py recordings/*.swrec.gz && echo && python3 tools/swrec_stats.py recordings/*.swrec.gz"
