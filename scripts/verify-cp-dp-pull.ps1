# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#
# End-to-end proof of the control-plane -> data-plane channel (ADR-0011):
# a data plane with NO peers in its own config file gets its whole peer table over
# HTTP, and an independent WireGuard implementation then completes a handshake
# against it. Nobody hand-copies keys.
#
#   pwsh -File scripts/verify-cp-dp-pull.ps1
param([int]$ApiPort = 8091, [int]$MetricsPort = 9191, [int]$WirePort = 51851)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$vpnd = Join-Path $root 'out/build-release/server/vpnd.exe'
$ctl = Join-Path $root 'out/build-release/server/vpnctl.exe'
$dp = Join-Path $root 'out/build-dp/server/vpn-dp.exe'
$py = Join-Path $root 'scripts/interop_client.py'
foreach ($exe in @($vpnd, $ctl, $dp)) {
  if (-not (Test-Path $exe)) { Write-Host "SKIP: $exe not built"; exit 2 }
}

Get-Process vpnd, vpn-dp -ErrorAction SilentlyContinue | Stop-Process -Force
$work = Join-Path $env:TEMP ("vpn-pull-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force $work | Out-Null

# An administrator account in the store (the operator's own bootstrap account).
$hash = (& python -c "import hmac,hashlib; print(hmac.new(b'vpn-dev-pepper', b'admin-password', hashlib.blake2s).hexdigest())").Trim()
$tab = [char]9
$store = Join-Path $work 'control.log'
[IO.File]::WriteAllText($store, "U$tab" + "usr_admin$tab" + "ten_default$tab" + "admin@example.invalid$tab" + "$hash$tab" + "admin`n", (New-Object System.Text.UTF8Encoding($false)))

$client = & python $py --genkey
$clientPriv = (($client -split "`n") | Select-String 'private_key').ToString().Split('=')[1].Trim()
$clientPub = (($client -split "`n") | Select-String 'public_key').ToString().Split('=')[1].Trim()
$server = & $dp '--genkey'
$serverPriv = (($server -split "`n") | Select-String 'private_key').ToString().Split('=')[1].Trim()
$serverPub = (($server -split "`n") | Select-String 'public_key').ToString().Split('=')[1].Trim()

$env:VPN_STORE_PATH = $store
$env:VPN_API = "http://127.0.0.1:$ApiPort"
$adminToken = Join-Path $work 'admin.token'
$customerToken = Join-Path $work 'customer.token'

$vpndLog = Join-Path $work 'vpnd.log'
Start-Process -FilePath 'cmd.exe' -WindowStyle Hidden -ArgumentList ('/c ""' + $vpnd + '" --bind 127.0.0.1:' + $ApiPort + ' --metrics-bind 127.0.0.1:' + $MetricsPort + ' > "' + $vpndLog + '" 2>&1"')
Start-Sleep -Seconds 2

$env:VPN_TOKEN_FILE = $adminToken
& $ctl login --email admin@example.invalid --password admin-password | Out-Null
& $ctl nodes add --host "127.0.0.1:$WirePort" --public-key $serverPub | Out-Null
& $ctl admin users add --email ali@example.invalid --password cust-password --months 1 | Out-Null

$env:VPN_TOKEN_FILE = $customerToken
& $ctl login --email ali@example.invalid --password cust-password | Out-Null
$device = (& $ctl devices create --name laptop).Trim()
& $ctl devices set-key $device --key $clientPub | Out-Null
$peer = & $ctl peers create --device $device
Write-Host ("peer allocated: " + $peer)

# The node's own config has an interface block and NOT ONE [[peer]].
$base = Join-Path $work 'datad.toml'
$config = @"
[interface]
private_key = "$serverPriv"
listen = "127.0.0.1:$WirePort"
tun = "none"
"@
[IO.File]::WriteAllText($base, $config, (New-Object System.Text.UTF8Encoding($false)))

$token = (Get-Content $adminToken).Trim()
$dpLog = Join-Path $work 'dp.log'
Start-Process -FilePath 'cmd.exe' -WindowStyle Hidden -ArgumentList ('/c ""' + $dp + '" --config "' + $base + '" --config-url http://127.0.0.1:' + $ApiPort + '/api/v1/dp/config --token ' + $token + ' --refresh 0 > "' + $dpLog + '" 2>&1"')
Start-Sleep -Seconds 3

$pulled = (Get-Content $dpLog -ErrorAction SilentlyContinue | Select-String 'peers pulled') -ne $null
$listening = (Get-Content $dpLog -ErrorAction SilentlyContinue | Select-String "listening on 127.0.0.1:$WirePort.*peers=1") -ne $null
$out = & python $py --connect --server-pub $serverPub --client-priv $clientPriv --port $WirePort --packets 2 2>&1
$clientExit = $LASTEXITCODE
Start-Sleep -Milliseconds 500
$established = (Get-Content $dpLog -ErrorAction SilentlyContinue | Select-String 'established') -ne $null
$transport = (Get-Content $dpLog -ErrorAction SilentlyContinue | Select-String 'transport packet accepted') -ne $null

Write-Host ("pulled={0} listening_with_1_peer={1} handshake={2} transport={3}" -f $pulled, $listening, $established, $transport)
Get-Process vpnd, vpn-dp -ErrorAction SilentlyContinue | Stop-Process -Force

if ($pulled -and $listening -and ($clientExit -eq 0) -and $established -and $transport) {
  Write-Host ''
  Write-Host 'PASS: vpn-dp fetched its peer table from vpnd and served a real handshake'
  exit 0
}
Write-Host 'FAIL'; Get-Content $dpLog -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  dp: $_" }
Get-Content $vpndLog -ErrorAction SilentlyContinue | Select-Object -Last 5 | ForEach-Object { Write-Host "  vpnd: $_" }
exit 1
