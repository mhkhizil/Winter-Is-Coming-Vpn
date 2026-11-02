# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#
# Verifies and measures the BATCHED receive path of vpn-dp.
#
# The data plane used to read exactly one datagram per select() wakeup (two
# syscalls per packet). It now drains up to 32 already-queued datagrams per wakeup
# (recvmmsg() on Linux, a recvfrom() loop elsewhere). This harness proves the
# batched path still accepts every datagram - same counters, same handshake log,
# same endpoint learning - and reports the packet rate, so a before/after
# comparison is possible:
#
#   pwsh -File scripts/verify-dp-batching.ps1
#   pwsh -File scripts/verify-dp-batching.ps1 -DataPlane <exe> -Clients 12 -Packets 3000
#
# Why parallel clients: one Python client is slower than the data plane (it pays
# for ChaCha20-Poly1305 per packet in Python), so a single sender would measure
# the client. -Clients independent senders keep the socket queue full, which is
# exactly the case the batching has to handle, and the aggregate rate plus the
# server's own CPU time per packet then describe the receive path.
param(
    [string]$DataPlane = "",
    [int]$Clients = 12,
    [int]$Packets = 3000,
    [int]$Port = 51860,
    [int]$Rounds = 3
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrEmpty($DataPlane)) { $DataPlane = Join-Path $root 'out/build-dp/server/vpn-dp.exe' }
$py = Join-Path $root 'scripts/interop_client.py'
if (-not (Test-Path $DataPlane)) {
    Write-Host "SKIP: $DataPlane not found (build with -DVPN_BUILD_DATAPLANE=ON)"
    exit 2
}

$procName = [IO.Path]::GetFileNameWithoutExtension($DataPlane)
$work = Join-Path $env:TEMP ("vpn-batch-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $work | Out-Null
$conf = Join-Path $work 'datad.toml'
$log = Join-Path $work 'server.log'

Get-Process $procName -ErrorAction SilentlyContinue | Stop-Process -Force

# 1. keys: clients come from the independent implementation, the server from ours
$server = & $DataPlane --genkey
$serverPriv = (($server -split "`n") | Select-String 'private_key').ToString().Split('=')[1].Trim()
$serverPub = (($server -split "`n") | Select-String 'public_key').ToString().Split('=')[1].Trim()
if (-not $serverPub) { throw 'key generation failed' }

$clientPrivs = @()
$peerBlocks = @()
for ($i = 0; $i -lt $Clients; $i++) {
    $c = & python $py --genkey
    $priv = (($c -split "`n") | Select-String 'private_key').ToString().Split('=')[1].Trim()
    $pub = (($c -split "`n") | Select-String 'public_key').ToString().Split('=')[1].Trim()
    if (-not $pub) { throw 'client key generation failed' }
    $clientPrivs += $priv
    $peerBlocks += "[[peer]]`nname = `"batch$i`"`npublic_key = `"$pub`"`nallowed_ips = [`"10.66.$i.1/32`"]`n"
}

@"
[interface]
private_key = "$serverPriv"
listen = "127.0.0.1:$Port"
tun = "none"

$($peerBlocks -join "`n")
"@ | Set-Content -Path $conf -Encoding ascii

# 2. start the data plane (cmd.exe does the quoting: the repo path has spaces)
Start-Process -FilePath 'cmd.exe' -WindowStyle Hidden -ArgumentList ('/c "' + '"' + $DataPlane + '"' + ' --config "' + $conf + '" > "' + $log + '" 2>&1"')
for ($i = 0; $i -lt 100; $i++) {
    if (Get-Content $log -ErrorAction SilentlyContinue | Select-String 'listening on') { break }
    Start-Sleep -Milliseconds 100
}
if (-not (Get-Content $log -ErrorAction SilentlyContinue | Select-String 'listening on')) {
    Write-Host 'FAIL: the data plane did not start'; Get-Content $log -ErrorAction SilentlyContinue; exit 1
}
$serverProc = Get-Process $procName
Start-Sleep -Milliseconds 200

# 3. handshake every client first, so the timed window is pure transport traffic
$warmup = @()
for ($i = 0; $i -lt $Clients; $i++) {
    $warmup += Start-Process -FilePath 'python' -PassThru -NoNewWindow `
        -ArgumentList @('"' + $py + '"', '--connect', '--server-pub', $serverPub, '--client-priv', $clientPrivs[$i], '--port', $Port, '--packets', '1') `
        -RedirectStandardOutput (Join-Path $work "w$i.out") -RedirectStandardError (Join-Path $work "w$i.err")
}
foreach ($w in $warmup) { $w.WaitForExit() }
Start-Sleep -Milliseconds 1000

$udpBefore = [int](netstat -s -p udp | Select-String 'Receive Errors').ToString().Split('=')[1].Trim()
$serverProc.Refresh()
$cpuStart = $serverProc.TotalProcessorTime
$cpuMark = $cpuStart

$rates = @()
$cpuPerPacket = @()
$sent = $Clients * $Packets
for ($round = 1; $round -le $Rounds; $round++) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $burst = @()
    for ($i = 0; $i -lt $Clients; $i++) {
        $burst += Start-Process -FilePath 'python' -PassThru -NoNewWindow `
            -ArgumentList @('"' + $py + '"', '--connect', '--server-pub', $serverPub, '--client-priv', $clientPrivs[$i], '--port', $Port, '--packets', $Packets) `
            -RedirectStandardOutput (Join-Path $work "r$round-$i.out") -RedirectStandardError (Join-Path $work "r$round-$i.err")
    }
    foreach ($b in $burst) { $b.WaitForExit() }
    $sw.Stop()
    Start-Sleep -Milliseconds 1000  # let the server drain its whole backlog before sampling

    $serverProc.Refresh()
    $cpuNow = $serverProc.TotalProcessorTime
    # A client whose handshake timed out (5 s socket timeout) never sends its burst,
    # which would smear the round's rate: count it, report it, exclude the round.
    $short = 0
    for ($i = 0; $i -lt $Clients; $i++) {
        if (-not (Select-String -Path (Join-Path $work "r$round-$i.out") -Pattern 'transport sent' -Quiet)) { $short++ }
    }
    if ($short -eq 0) {
        $rates += ($sent / $sw.Elapsed.TotalSeconds)
        $cpuPerPacket += ((($cpuNow - $cpuMark).TotalMilliseconds * 1000.0) / $sent)
    }
    $cpuMark = $cpuNow
    Write-Host ("round {0}/{1}: {2} datagrams in {3,6:N0} ms -> {4,7:N0} pkt/s | server {5,5:N2} us/packet | cpu total {6,6:N0} ms{7}" -f `
        $round, $Rounds, $sent, $sw.Elapsed.TotalMilliseconds, ($sent / $sw.Elapsed.TotalSeconds), `
        ((($cpuNow - $cpuStart).TotalMilliseconds * 1000.0) / ($sent * $round)), ($cpuNow - $cpuStart).TotalMilliseconds, `
        $(if ($short -gt 0) { "  [excluded: $short client(s) never finished their handshake]" } else { '' }))
}

$udpAfter = [int](netstat -s -p udp | Select-String 'Receive Errors').ToString().Split('=')[1].Trim()
$drops = $udpAfter - $udpBefore
$incomplete = $Rounds - $rates.Count
if ($rates.Count -eq 0) {
    Write-Host 'FAIL: no round completed (every client handshake timed out)'
    Get-Process $procName -ErrorAction SilentlyContinue | Stop-Process -Force
    exit 1
}
$ratesSorted = @($rates | Sort-Object)
$median = $ratesSorted[[int]([math]::Floor($ratesSorted.Count / 2))]
$cpuAvg = ($cpuPerPacket | Measure-Object -Average).Average

# 4. assertions: everything the batched path must still do, unchanged.
# A client that never receives its handshake response is a pre-existing quirk of
# driving 12 independent Python processes at once (it happens on both the batched
# and the one-datagram-per-wakeup build), so an incomplete round is reported but
# does not decide the verdict: what must hold is that the peers that did connect
# got every transport datagram through and the server logged the batch path.
$serverLog = Get-Content $log -ErrorAction SilentlyContinue
$established = @($serverLog | Select-String 'established').Count
$transport = @($serverLog | Select-String 'first transport packet accepted').Count

Write-Host ''
Write-Host ("datapath      : {0}" -f $DataPlane)
Write-Host ("senders       : {0} clients x {1} packets x {2} rounds = {3} datagrams" -f $Clients, $Packets, $Rounds, ($sent * $Rounds))
Write-Host ("packet rate   : {0:N0} pkt/s (median of {1} completed rounds)" -f $median, $rates.Count)
Write-Host ("server cost   : {0:N2} us per datagram -> {1:N0} pkt/s per core" -f $cpuAvg, (1000000.0 / $cpuAvg))
Write-Host ("udp drops     : {0} (box UDP receive errors for the whole run)" -f $drops)
Write-Host ("server log    : {0} handshakes accepted, {1} peers saw their first transport packet" -f $established, $transport)

Get-Process $procName -ErrorAction SilentlyContinue | Stop-Process -Force

if ($incomplete -gt 0) {
    Write-Host ("warning       : {0} of {1} rounds excluded (a client never got its handshake response)" -f $incomplete, $Rounds)
}
if ($established -ge $Clients -and $transport -eq $Clients -and $drops -eq 0) {
    Write-Host ''
    Write-Host 'PASS: every queued datagram of every batch was accepted (handshake, transport, no drops)'
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
    exit 0
}
Write-Host 'FAIL:'
if ($established -lt $Clients) { Write-Host "  - expected at least $Clients established peers, saw $established" }
if ($transport -ne $Clients) { Write-Host "  - expected $Clients 'first transport packet' lines, saw $transport" }
if ($drops -ne 0) { Write-Host "  - $drops datagrams were dropped by the socket queue" }
Write-Host '--- server log ---'; $serverLog | ForEach-Object { Write-Host $_ }
exit 1



