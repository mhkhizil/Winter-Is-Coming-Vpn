# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#
# Interop harness for machines without TUN/wireguard-tools (Windows, CI):
# drives the INDEPENDENT Python client (scripts/interop_client.py, which uses
# Python's `cryptography` for X25519/ChaCha20-Poly1305) against a real vpn-dp.
#
#   pwsh -File scripts/interop-local.ps1
#   pwsh -File scripts/interop-local.ps1 -DataPlane out/build-dp/server/vpn-dp.exe
#
# Exit code 0 only if the handshake completes AND a transport packet is accepted
# by the server. The Linux/official-client harness is scripts/interop-test.sh.
param(
    [string]$DataPlane = "",
    [int]$Port = 51830
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrEmpty($DataPlane)) { $DataPlane = Join-Path $root 'out/build-dp/server/vpn-dp.exe' }
if (-not (Test-Path $DataPlane)) {
    Write-Host "SKIP: $DataPlane not found (build with -DVPN_BUILD_DATAPLANE=ON)"
    exit 2
}

$py = Join-Path $root 'scripts/interop_client.py'
$work = Join-Path $env:TEMP ("vpn-interop-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $work | Out-Null
$conf = Join-Path $work 'datad.toml'
$log = Join-Path $work 'server.log'

Get-Process vpn-dp -ErrorAction SilentlyContinue | Stop-Process -Force

# 1. keys: client from the independent implementation, server from our binary
$client = & python $py --genkey
$clientPriv = (($client -split "`n") | Select-String 'private_key').ToString().Split('=')[1].Trim()
$clientPub = (($client -split "`n") | Select-String 'public_key').ToString().Split('=')[1].Trim()
$server = & $DataPlane --genkey
$serverPriv = (($server -split "`n") | Select-String 'private_key').ToString().Split('=')[1].Trim()
$serverPub = (($server -split "`n") | Select-String 'public_key').ToString().Split('=')[1].Trim()

if (-not $clientPub -or -not $serverPub) { throw "key generation failed" }

# 2. server config (tun disabled: this box has no TUN, handshake+transport still work)
@"
[interface]
private_key = "$serverPriv"
listen = "127.0.0.1:$Port"
tun = "none"

[[peer]]
name = "interop-client"
public_key = "$clientPub"
allowed_ips = ["10.66.0.1/32"]
"@ | Set-Content -Path $conf -Encoding ascii

# 3. start the server. cmd.exe handles the quoting: Start-Process does not, and the
#    repo path contains spaces.
$cmd = '/c ""' + $DataPlane + '" --config "' + $conf + '" > "' + $log + '" 2>&1"'
Start-Process -FilePath 'cmd.exe' -ArgumentList $cmd -WindowStyle Hidden
Start-Sleep -Seconds 2

if (-not (Get-Content $log -ErrorAction SilentlyContinue | Select-String 'listening on')) {
    Write-Host "FAIL: the data plane did not start"; Get-Content $log -ErrorAction SilentlyContinue; exit 1
}

# 4. run the independent client
$output = & python $py --connect --server-pub $serverPub --client-priv $clientPriv --port $Port --packets 4
$clientExit = $LASTEXITCODE
$output | ForEach-Object { Write-Host "  client: $_" }
Start-Sleep -Seconds 1
$serverLog = Get-Content $log -ErrorAction SilentlyContinue
Get-Process vpn-dp -ErrorAction SilentlyContinue | Stop-Process -Force

# 5. assertions
$okHandshake = $clientExit -eq 0 -and ($output -match 'handshake ok')
$okEstablished = $serverLog | Select-String 'established'
$okTransport = $serverLog | Select-String 'first transport packet accepted'

if ($okHandshake -and $okEstablished -and $okTransport) {
    Write-Host ''
    Write-Host 'PASS: independent implementation handshake + transport against vpn-dp'
    Write-Host ($serverLog | Select-String 'established|transport packet' | Out-String).Trim()
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
    exit 0
}

Write-Host 'FAIL:'
if (-not $okHandshake) { Write-Host '  - the client did not complete the handshake' }
if (-not $okEstablished) { Write-Host '  - the server did not log an established peer' }
if (-not $okTransport) { Write-Host '  - no transport packet was accepted (keys or padding disagree)' }
Write-Host '--- server log ---'; $serverLog | ForEach-Object { Write-Host $_ }
exit 1
