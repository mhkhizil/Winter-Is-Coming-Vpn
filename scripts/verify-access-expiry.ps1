# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#
# Proves that paid access lapsing at the DATA PLANE takes effect immediately for a
# client that already has its configuration (ADR-0010). A control plane that only
# refuses to hand out new configs would leave every existing tunnel running.
#
#   pwsh -File scripts/verify-access-expiry.ps1
param([int]$BasePort = 51845)

# The Python client prints to stderr in the expired case by design, so a Stop
# preference would abort the test instead of asserting the expected failure.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$dp = Join-Path $root 'out/build-dp/server/vpn-dp.exe'
$py = Join-Path $root 'scripts/interop_client.py'
if (-not (Test-Path $dp)) { Write-Host "SKIP: $dp not found (build with -DVPN_BUILD_DATAPLANE=ON)"; exit 2 }

Get-Process vpn-dp -ErrorAction SilentlyContinue | Stop-Process -Force

$client = & python $py --genkey
$clientPriv = (($client -split "`n") | Select-String 'private_key').ToString().Split('=')[1].Trim()
$clientPub = (($client -split "`n") | Select-String 'public_key').ToString().Split('=')[1].Trim()
$server = & $dp '--genkey'
$serverPriv = (($server -split "`n") | Select-String 'private_key').ToString().Split('=')[1].Trim()
$serverPub = (($server -split "`n") | Select-String 'public_key').ToString().Split('=')[1].Trim()
if (-not $clientPub -or -not $serverPub) { throw 'key generation failed' }

$now = [int](& python -c 'import time; print(int(time.time()))')

function Invoke-Case([string]$label, $expires, [bool]$expectReject, [int]$listenPort) {
  $conf = Join-Path $env:TEMP ("dp-expiry-" + [guid]::NewGuid().ToString('N').Substring(0, 6) + '.toml')
  $log = "$conf.log"
  $body = @"
[interface]
private_key = "$serverPriv"
listen = "127.0.0.1:$listenPort"
tun = "none"

[[peer]]
name = "customer"
public_key = "$clientPub"
allowed_ips = ["10.66.0.1/32"]
"@
  if ($null -ne $expires) { $body += "`nexpires_at = $expires`n" }
  [IO.File]::WriteAllText($conf, $body, (New-Object System.Text.UTF8Encoding($false)))

  Start-Process -FilePath 'cmd.exe' -WindowStyle Hidden -ArgumentList ('/c ""' + $dp + '" --config "' + $conf + '" > "' + $log + '" 2>&1"')

  # Wait for our own daemon to be listening before talking to it. Each case uses a
  # different port so a socket in TIME_WAIT cannot make a case fail spuriously.
  for ($i = 0; $i -lt 60; $i++) {
    if (Get-Content $log -ErrorAction SilentlyContinue | Select-String "listening on 127.0.0.1:$listenPort") { break }
    Start-Sleep -Milliseconds 100
  }

  $out = & python $py --connect --server-pub $serverPub --client-priv $clientPriv --port $listenPort --packets 1 2>&1
  $clientExit = $LASTEXITCODE
  Start-Sleep -Milliseconds 400
  $serverLog = Get-Content $log -ErrorAction SilentlyContinue
  Get-Process vpn-dp -ErrorAction SilentlyContinue | Stop-Process -Force

  $rejected = [bool]($serverLog | Select-String 'access expired')
  Write-Host ("{0,-20} client_exit={1} server_says_expired={2}" -f $label, $clientExit, $rejected)
  if ($expectReject) { return ($clientExit -ne 0) -and $rejected }
  return ($clientExit -eq 0) -and (-not $rejected)
}

$expiredOk = Invoke-Case 'expired (t-1h)' ($now - 3600) $true $BasePort
$activeOk = Invoke-Case 'active (t+30d)' ($now + 2592000) $false ($BasePort + 1)
$staffOk = Invoke-Case 'no expiry' $null $false ($BasePort + 2)

if ($expiredOk -and $activeOk -and $staffOk) {
  Write-Host ''
  Write-Host 'PASS: a lapsed peer cannot handshake; paid-up and staff peers can'
  exit 0
}
Write-Host 'FAIL: see the per-case output above'
exit 1
