# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#
# Proves the renewal-reminder path end to end against a capture-only SMTP server:
# one mail per account per reminder bucket, correct recipient and text, and no
# duplicate on the second run (cron safety).
#
#   pwsh -File scripts/verify-reminders.ps1
param([int]$ApiPort = 8092, [int]$MetricsPort = 9192, [int]$SmtpPort = 2526)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$vpnd = Join-Path $root 'out/build-release/server/vpnd.exe'
$ctl = Join-Path $root 'out/build-release/server/vpnctl.exe'
if (-not (Test-Path $vpnd) -or -not (Test-Path $ctl)) { Write-Host 'SKIP: vpnd/vpnctl not built'; exit 2 }

Get-Process vpnd -ErrorAction SilentlyContinue | Stop-Process -Force
$work = Join-Path $env:TEMP ("vpn-remind-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
$maildir = Join-Path $work 'mail'
New-Item -ItemType Directory -Force $maildir | Out-Null

$hash = (& python -c "import hmac,hashlib; print(hmac.new(b'vpn-dev-pepper', b'admin-password', hashlib.blake2s).hexdigest())").Trim()
$tab = [char]9
$store = Join-Path $work 'control.log'
[IO.File]::WriteAllText($store, "U$tab" + "usr_admin$tab" + "ten_default$tab" + "admin@example.invalid$tab" + "$hash$tab" + "admin`n", (New-Object System.Text.UTF8Encoding($false)))

# vpnd config: plain HTTP on loopback, SMTP pointed at the capture server.
$conf = Join-Path $work 'vpnd.toml'
@"
environment = "development"
[http]
bind = "127.0.0.1:$ApiPort"
[metrics]
bind = "127.0.0.1:$MetricsPort"
[smtp]
host = "127.0.0.1"
port = $SmtpPort
from = "vpn@example.invalid"
"@ | Set-Content -Path $conf -Encoding ascii

$sinkLog = Join-Path $work 'sink.log'
$sinkErr = Join-Path $work 'sink.err'
$sink = Start-Process -FilePath 'python' -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput $sinkLog -RedirectStandardError $sinkErr `
    -ArgumentList ('"' + (Join-Path $root 'scripts/fake_smtp.py') + '" --port ' + $SmtpPort + ' --outdir "' + $maildir + '"')

# Wait for the capture server to actually be listening instead of sleeping a fixed
# second: a slow start used to leave vpnd talking to nothing.
$listening = $false
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 100
    if (Get-NetTCPConnection -LocalPort $SmtpPort -State Listen -ErrorAction SilentlyContinue) {
        $listening = $true
        break
    }
    if ($sink.HasExited) { break }
}
if (-not $listening) {
    Write-Host 'FAIL: the SMTP capture server never listened'
    if (Test-Path $sinkErr) { Get-Content $sinkErr | Select-Object -First 5 | ForEach-Object { Write-Host "  $_" } }
    if (-not $sink.HasExited) { Stop-Process -Id $sink.Id -Force }
    exit 1
}
$env:VPN_STORE_PATH = $store
$env:VPN_API = "http://127.0.0.1:$ApiPort"
$env:VPN_TOKEN_FILE = Join-Path $work 'admin.token'
Start-Process -FilePath 'cmd.exe' -WindowStyle Hidden -ArgumentList ('/c ""' + $vpnd + '" --config "' + $conf + '" > "' + (Join-Path $work 'vpnd.log') + '" 2>&1"')
Start-Sleep -Seconds 2

& $ctl login --email admin@example.invalid --password admin-password | Out-Null
# An account that lapses inside the 7-day window.
& $ctl admin users add --email ali@example.invalid --password cust-password --days 3 | Out-Null

$first = & $ctl admin remind --days 7
$second = & $ctl admin remind --days 7
Write-Host "first run : $first"
Write-Host "second run: $second"

$mails = @()
for ($i = 0; $i -lt 30; $i++) {
    $mails = @(Get-ChildItem $maildir -Filter '*.eml' -ErrorAction SilentlyContinue)
    if ($mails.Count -gt 0) { break }
    Start-Sleep -Milliseconds 100
}
$body = if ($mails.Count -gt 0) { Get-Content $mails[0].FullName -Raw } else { '' }
$addressed = $body -match 'To: ali@example\.invalid'
$textOk = $body -match 'ends in 7 day\(s\)'
Write-Host ("mails={0} addressed={1} text_ok={2}" -f $mails.Count, $addressed, $textOk)
if ($mails.Count -eq 0 -and (Test-Path $sinkLog)) {
    # When nothing was captured, the sink's own log is the only evidence of whether it
    # was ever contacted.
    Write-Host 'sink log:'
    Get-Content $sinkLog | Select-Object -Last 5 | ForEach-Object { Write-Host "  $_" }
    Get-Content $sinkErr -ErrorAction SilentlyContinue | Select-Object -Last 5 | ForEach-Object { Write-Host "  $_" }
}

Get-Process vpnd -ErrorAction SilentlyContinue | Stop-Process -Force
# Only the sink this script started: the previous version killed every python.exe on the
# machine, which is a nasty thing for a verification script to do.
if (-not $sink.HasExited) { Stop-Process -Id $sink.Id -Force -ErrorAction SilentlyContinue }

$sentOnce = $first -match '"sent":1'
$idempotent = $second -match '"sent":0'
if ($sentOnce -and $idempotent -and $mails.Count -eq 1 -and $addressed -and $textOk) {
  Write-Host ''
  Write-Host 'PASS: one reminder per account per bucket, with the right recipient and text'
  exit 0
}
Write-Host 'FAIL'
if ($mails.Count -gt 0) { Write-Host $body }
exit 1
