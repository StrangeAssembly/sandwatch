<#
.SYNOPSIS
  Runs every lab scenario under the LIVE eBPF sensor and writes recordings/live/*.swrec.gz.
  The sensor runs in its own privileged container, outside the agent's container: the
  workload cannot see or touch it.
.EXAMPLE
  .\lab\live-all.ps1                      # build sensor image, run everything, evaluate
  .\lab\live-all.ps1 -Only "full-chain"   # one scenario
  .\lab\live-all.ps1 -Only "full-chain" -FreezeOn chain   # freeze the agent when a chain fires
#>
param([string]$Only = "", [switch]$NoBuild, [string]$FreezeOn = "")
$ErrorActionPreference = "Continue"
$Lab  = $PSScriptRoot
$Root = Split-Path $Lab -Parent
$manifest = Get-Content (Join-Path $Lab "scenarios\manifest.json") -Raw | ConvertFrom-Json

if (-not $NoBuild) {
  docker build -q -t sandwatch-sensor:0.3 -f (Join-Path $Root "docker\sensor.Dockerfile") $Root | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "sensor image build failed" }
}
Push-Location $Lab
try {
  docker compose up -d labsvc 2>&1 | Out-Null
  # Freeze runs stop the attack midway, so they are kept apart from the evaluation set.
  $outDir = if ($FreezeOn) { "recordings/live-freeze" } else { "recordings/live" }
  New-Item -ItemType Directory -Force (Join-Path $Root $outDir) | Out-Null
  foreach ($s in $manifest.scenarios) {
    if ($Only -and ($s.id -notlike $Only)) { continue }
    foreach ($seed in $s.seeds) {
      $rid = "$($s.id)-s$seed"
      $agent = "sw-agent-$rid"; $sensor = "sw-sensor-$rid"
      docker rm -f $agent $sensor 2>&1 | Out-Null
      docker compose run -d --name $agent agent sleep infinity 2>&1 | Out-Null
      $cid = (docker inspect -f '{{.Id}}' $agent).Trim()

      $sensorArgs = @("watch", "--container", $cid, "--out", "$outDir/$rid.swrec.gz",
                      "--session-id", $rid, "--manifest", "lab/scenarios/manifest.json",
                      "--scenario", $s.id, "--seed", "$seed")
      if ($FreezeOn) { $sensorArgs += @("--freeze-on", $FreezeOn) }
      docker run -d --name $sensor --privileged --pid=host --cgroupns=host `
        -v /sys/fs/cgroup:/sys/fs/cgroup -v "${Root}:/work" -w /work sandwatch-sensor:0.3 @sensorArgs | Out-Null

      $ready = $false
      for ($i = 0; $i -lt 80; $i++) {
        if ((docker logs $sensor 2>&1 | Out-String) -match 'watching ') { $ready = $true; break }
        Start-Sleep -Milliseconds 250
      }
      if (-not $ready) {
        docker logs $sensor 2>&1 | ForEach-Object { "$_" }
        docker rm -f $agent $sensor 2>&1 | Out-Null
        throw "sensor for $rid did not start"
      }

      $envArgs = @("-e", "SANDWATCH_SEED=$seed")
      if ($s.env) { foreach ($p in $s.env.PSObject.Properties) { $envArgs += @("-e", "$($p.Name)=$($p.Value)") } }
      $t = [Diagnostics.Stopwatch]::StartNew()
      # Run the scenario as a job: if Sandwatch freezes the agent, `docker exec` blocks
      # forever, so give up after a timeout (the container is removed below anyway).
      $job = Start-Job -ScriptBlock { param($a, $e, $sc) docker exec @e $a bash /lab/scenarios/$sc 2>&1 | Out-Null } `
                       -ArgumentList $agent, $envArgs, $s.script
      $limit = if ($FreezeOn) { 45 } else { 300 }
      if (-not (Wait-Job $job -Timeout $limit)) { "    (scenario still blocked after ${limit}s: workload frozen)" }
      Remove-Job $job -Force
      $secs = [math]::Round($t.Elapsed.TotalSeconds, 1)
      Start-Sleep -Milliseconds 700
      docker stop -t 15 $sensor 2>&1 | Out-Null
      $log = docker logs $sensor 2>&1 | ForEach-Object { "$_" }
      $alerts = ($log | Select-String -Pattern '^\s+\d\d:\d\d\.\d{3}\s').Count
      $summary = ($log | Select-String -Pattern 'events recorded').Line
      "{0,-26} {1,6}s  {2} alert lines  |{3}" -f $rid, $secs, $alerts, $summary
      if ($log -match 'FROZE') { $log | Select-String 'FROZE' | ForEach-Object { "    $($_.Line)" } }
      if ($FreezeOn) {
        $uploads = (docker compose logs labsvc 2>&1 | Select-String 'collector:.*POST').Count
        "    exfiltration uploads seen by the decoy collector so far: $uploads"
      }
      docker rm -f $agent $sensor 2>&1 | Out-Null
    }
  }
  docker compose down 2>&1 | Out-Null
}
finally { Pop-Location }

""
if (-not $FreezeOn) { & (Join-Path $Root "scripts\dev.ps1") sandwatch eval recordings/live --verbose }
