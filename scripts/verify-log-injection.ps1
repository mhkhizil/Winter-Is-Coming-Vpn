# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#
# Regression test for a privilege escalation that was real: the store is a
# tab-separated, newline-terminated log, and a device name is user input. A name
# containing a newline and tabs rewrote the log into a forged `U ... admin` record,
# which replay then honoured - any authenticated user could become an administrator,
# permanently.
#
# The fix escapes '%', TAB, LF and CR on write and reverses it per field on read, and
# rejects control characters in names/emails at the API boundary. This script proves
# three things that matter:
#   1. the attack is now refused,
#   2. no forged account survives a restart,
#   3. legitimate names still round-trip, including one containing '%'.
#
#   pwsh -File scripts/verify-log-injection.ps1
param([int]$ApiPort = 8077, [int]$MetricsPort = 9177)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$vpnd = Join-Path $root 'out/build-release/server/vpnd.exe'
if (-not (Test-Path $vpnd)) { Write-Host "SKIP: $vpnd not built"; exit 2 }

Get-Process vpnd -ErrorAction SilentlyContinue | Stop-Process -Force
$work = Join-Path $env:TEMP ("vpn-inject-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force $work | Out-Null
$store = Join-Path $work 'control.log'

$env:VPN_STORE_PATH = $store
$env:VPN_BOOTSTRAP_EMAIL = 'alice@example.invalid'
$env:VPN_BOOTSTRAP_PASSWORD = 'alice-password'

function Start-Daemon([string]$logName) {
    Start-Process -FilePath 'cmd.exe' -WindowStyle Hidden -ArgumentList (
        '/c ""' + $vpnd + '" --bind 127.0.0.1:' + $ApiPort +
        ' --metrics-bind 127.0.0.1:' + $MetricsPort + ' > "' + (Join-Path $work $logName) + '" 2>&1"'
    )
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Milliseconds 100
        try { Invoke-WebRequest -Uri "http://127.0.0.1:$ApiPort/healthz" -UseBasicParsing -TimeoutSec 1 | Out-Null; return $true } catch { }
    }
    return $false
}

function Stop-Daemon { Get-Process vpnd -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Sleep -Milliseconds 400 }

function Invoke-Api([string]$method, [string]$path, $body, [string]$token) {
    $headers = @{}
    if ($token) { $headers['Authorization'] = "Bearer $token" }
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$ApiPort$path" -Method $method -Body $body `
            -Headers $headers -ContentType 'application/json' -UseBasicParsing
        return @{ status = $r.StatusCode; body = $r.Content }
    } catch {
        $code = 0
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        return @{ status = $code; body = '' }
    }
}

if (-not (Start-Daemon 'first.log')) { Write-Host 'FAIL: daemon did not start'; exit 1 }

$login = Invoke-Api 'POST' '/api/v1/auth/login' '{"email":"alice@example.invalid","password":"alice-password"}' $null
$token = ($login.body | ConvertFrom-Json).access_token
if (-not $token) { Write-Host 'FAIL: bootstrap login failed'; Stop-Daemon; exit 1 }

# --- 1. the attack ------------------------------------------------------------
$hash = (& python -c "import hmac,hashlib; print(hmac.new(b'vpn-dev-pepper', b'pwn-password', hashlib.blake2s).hexdigest())").Trim()
$payload = 'innocent' + "`n" + 'U' + "`t" + 'usr_pwn' + "`t" + 'ten_default' + "`t" + 'pwn@evil.invalid' + "`t" + $hash + "`t" + 'admin'
$injected = Invoke-Api 'POST' '/api/v1/devices' ('{"name":"' + $payload + '","platform":"linux"}') $token
Write-Host ("attack: HTTP " + $injected.status)

# --- 2. legitimate names, one of them containing '%' --------------------------
$ok1 = Invoke-Api 'POST' '/api/v1/devices' '{"name":"Pixel 8 Pro","platform":"android"}' $token
$ok2 = Invoke-Api 'POST' '/api/v1/devices' '{"name":"100% phone","platform":"android"}' $token
Write-Host ("legit names: HTTP " + $ok1.status + " / " + $ok2.status)

$rawLog = Get-Content $store -Raw
$forgedBeforeRestart = $rawLog.Contains('pwn@evil.invalid')
Stop-Daemon

# --- 3. restart, then check nothing forged survived ---------------------------
if (-not (Start-Daemon 'second.log')) { Write-Host 'FAIL: daemon did not restart'; exit 1 }

$forged = Invoke-Api 'POST' '/api/v1/auth/login' '{"email":"pwn@evil.invalid","password":"pwn-password"}' $null
$escalation = Invoke-Api 'GET' '/api/v1/admin/users' $null $token
$login2 = Invoke-Api 'POST' '/api/v1/auth/login' '{"email":"alice@example.invalid","password":"alice-password"}' $null
$token2 = ($login2.body | ConvertFrom-Json).access_token
$devices = Invoke-Api 'GET' '/api/v1/devices' $null $token2
$namesOk = ($devices.body -like '*Pixel 8 Pro*') -and ($devices.body -like '*100% phone*')

Write-Host ("after restart: forged login=" + $forged.status + " admin-endpoint=" + $escalation.status + " names-intact=" + $namesOk)
Write-Host ("forged account in raw log before restart: " + $forgedBeforeRestart)
Stop-Daemon

$pass = ($injected.status -eq 400) -and
        ($forged.status -eq 401) -and
        ($escalation.status -eq 403) -and
        ($ok1.status -eq 201) -and
        ($ok2.status -eq 201) -and
        $namesOk

if ($pass) {
    Write-Host ''
    Write-Host 'PASS: injection refused, no forged admin, legitimate names (including %) survive a restart'
    exit 0
}
Write-Host 'FAIL'
if ($injected.status -ne 400) { Write-Host '  - the injected name was accepted; expected 400' }
if ($forged.status -ne 401) { Write-Host '  - a forged admin account exists and can log in' }
if ($escalation.status -ne 403) { Write-Host '  - a non-admin reached an admin endpoint' }
if (-not $namesOk) { Write-Host '  - legitimate device names did not survive the restart' }
exit 1
