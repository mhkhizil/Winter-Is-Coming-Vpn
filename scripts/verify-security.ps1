# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
#
# Independent verification of the credential-hardening work (PBKDF2 password
# hashing, login throttling, token rotation, admin audit trail).
#
# Written against docs/API.md and the ADR set, NOT against the implementation:
# nothing below imports, includes or greps server/ code. If an endpoint is
# missing the case is reported as SKIP with the exact request it expected,
# never as a crash.
#
#   pwsh -File scripts/verify-security.ps1
#   powershell -File scripts/verify-security.ps1 -ApiPort 8095 -KeepWork
#   powershell -File scripts/verify-security.ps1 -FailedLoginAttempts 12 -KeepWork
#
# Cases
#   1  password change:    POST /api/v1/me/password (correct current) -> 204,
#                          old password 401, new password 200
#   2  wrong current pw:   POST /api/v1/me/password (wrong current) -> 401 and the
#                          password is unchanged (old still logs in)
#   3  login throttle:     12 failed logins for one email, then the CORRECT
#                          password must be refused (429/423), and a different
#                          account must be unaffected
#   4  token rotation:     POST /api/v1/auth/rotate -> new token, old token 401,
#                          new token works
#   5  audit trail:        an admin action (POST /api/v1/admin/users) is recorded
#                          against the acting admin, read from
#                          GET /api/v1/admin/audit or (until that exists) the
#                          append-only store log
#
# How accounts are provisioned without hardcoding a hash
# -------------------------------------------------------
# Passwords used to be stored as HMAC-BLAKE2s-256(pepper, password) and are being
# replaced by pbkdf2-sha256$<iterations>$<salt-hex>$<derived-hex>. A verification
# script that embedded one hash would be testing last week's format. Instead:
#
#   * the ordinary account under test is created through the documented bootstrap
#     path (VPN_BOOTSTRAP_EMAIL / VPN_BOOTSTRAP_PASSWORD), and
#   * the administrator account - which bootstrap cannot create, because
#     /api/v1/admin/* needs role "admin" and bootstrap always creates an owner -
#     is seeded with a hash computed AT RUNTIME by Python, once per candidate
#     storage format. The harness then logs in to find out which format the
#     binary accepts.
#
# So no hash is hardcoded, both the old and the new format work, and a successful
# pbkdf2 login is itself an independent check that the C++ PBKDF2 agrees with
# Python's hashlib byte for byte (it can only match if the KDF is identical).
#
# Case 2 is executed (and printed) before case 1, on the same account, so a
# successful change cannot mask the "nothing changed" assertion.
#
# Exit codes: 0 = every non-skipped assertion passed, 1 = at least one FAIL,
#             2 = could not run (no binary, no python, daemon did not start).
#
# The script kills any stray vpnd process and writes only under %TEMP%, so it
# does not touch the working tree.
#
# Bearer tokens appear in failure reports as $TOKEN: each is single-use per run
# and the store that holds them is deleted at the end.
param(
  [int]$ApiPort = 8094,
  [int]$MetricsPort = 9194,
  [string]$VpndPath = '',
  # Failed logins before the correct one in case 3.
  [int]$FailedLoginAttempts = 12,
  # Delay between requests. The control plane also has a per-IP token bucket
  # (20 rps, burst 40) and case 3 must not be satisfied by IP rate limiting, so
  # the harness paces itself and checks the unaffected account at the end.
  [int]$PacingMs = 40,
  [string]$Pepper = 'verify-security-pepper',
  [int]$SeedIterations = 120000,
  [switch]$KeepWork
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Off

$script:Root = Split-Path -Parent $PSScriptRoot
$script:Vpnd = if ($VpndPath -ne '') { $VpndPath } else { Join-Path $script:Root 'out/build-release/server/vpnd.exe' }
$script:BaseUrl = "http://127.0.0.1:$ApiPort"
$script:PacingMs = $PacingMs
$script:SeedIterations = $SeedIterations
$script:Pepper = $Pepper
$script:CaseResults = @()

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
function Write-CaseResult {
  param(
    [int]$Id,
    [string]$Name,
    [string]$Verdict,      # PASS | FAIL | SKIP
    [string]$Detail,
    [string[]]$Requests = @()
  )
  $script:CaseResults += [pscustomobject]@{
    Id = $Id; Name = $Name; Verdict = $Verdict; Detail = $Detail; Requests = $Requests
  }
  Write-Host ('{0,-6} {1}  {2,-16} {3}' -f "[$Verdict]", $Id, $Name, $Detail)
  if ($Verdict -ne 'PASS') {
    foreach ($request in $Requests) { Write-Host ('         request: ' + $request) }
  }
}

function Format-Curl {
  param([string]$Method, [string]$Path, [string]$Body, [string]$Token)
  $parts = @('curl -sS -X ' + $Method + ' "' + $script:BaseUrl + $Path + '"')
  $hasBody = $false
  if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body -and $Body -ne '') {
    $hasBody = $true
  }
  if ($hasBody) { $parts += '-H "Content-Type: application/json"' }
  if ($PSBoundParameters.ContainsKey('Token') -and $null -ne $Token -and $Token -ne '') {
    $parts += '-H "Authorization: Bearer $TOKEN"'
  }
  if ($hasBody) { $parts += '--data ''' + $Body + '''' }
  $parts += '-w "\nHTTP %{http_code}\n"'
  return ($parts -join ' ')
}

function Get-ProblemCode {
  param([string]$Text)
  if ($null -eq $Text -or $Text -eq '') { return '' }
  $match = [regex]::Match($Text, '"code"\s*:\s*"([^"]+)"')
  if ($match.Success) { return $match.Groups[1].Value }
  return ''
}


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
Add-Type -AssemblyName System.Net.Http

function New-HttpClient {
  $client = [System.Net.Http.HttpClient]::new()
  $client.Timeout = [TimeSpan]::FromSeconds(20)
  return $client
}

# Every call returns one object so a case can assert on the status, the problem
# `code` and the parsed body without exceptions getting in the way.
function Invoke-Api {
  param(
    [string]$Method,
    [string]$Path,
    [string]$Body = $null,
    [string]$Token = $null,
    [switch]$NoPace
  )
  $url = $script:BaseUrl + $Path
  $curl = Format-Curl -Method $Method -Path $Path -Body $Body -Token $Token
  $result = [pscustomobject]@{
    Method = $Method; Path = $Path; Status = 0; Body = ''; Json = $null
    Code = ''; RetryAfter = ''; Curl = $curl; Error = ''
  }
  try {
    $request = [System.Net.Http.HttpRequestMessage]::new(
      [System.Net.Http.HttpMethod]::new($Method), $url)
    if ($null -ne $Token -and $Token -ne '') {
      $request.Headers.Add('Authorization', 'Bearer ' + $Token)
    }
    if ($null -ne $Body -and $Body -ne '') {
      $request.Content = [System.Net.Http.StringContent]::new(
        $Body, [System.Text.Encoding]::UTF8, 'application/json')
    }
    if (-not $NoPace -and $script:PacingMs -gt 0) { Start-Sleep -Milliseconds $script:PacingMs }
    $response = $script:Http.SendAsync($request).Result
    $result.Status = [int]$response.StatusCode
    $result.Body = $response.Content.ReadAsStringAsync().Result
    $retry = $response.Headers.RetryAfter
    if ($null -ne $retry) { $result.RetryAfter = $retry.ToString() }
    $request.Dispose()
    $response.Dispose()
  } catch {
    $result.Error = $_.Exception.Message
    if ($null -ne $_.Exception.InnerException) {
      $result.Error = $result.Error + ' / ' + $_.Exception.InnerException.Message
    }
  }
  $result.Code = Get-ProblemCode -Text $result.Body
  if ($result.Body -ne '') {
    try { $result.Json = $result.Body | ConvertFrom-Json } catch { $result.Json = $null }
  }
  return $result
}

# Login returns the whole response; the caller decides what to assert.
function Invoke-Login {
  param([string]$Email, [string]$Password, [switch]$NoPace)
  $body = '{"email":"' + $Email + '","password":"' + $Password + '"}'
  return Invoke-Api -Method POST -Path '/api/v1/auth/login' -Body $body -NoPace:$NoPace
}

function Get-Token {
  param($Login)
  if ($null -ne $Login.Json -and $null -ne $Login.Json.access_token) {
    return [string]$Login.Json.access_token
  }
  return ''
}

function Format-Status {
  param($Response)
  if ($Response.Status -eq 0) { return 'transport-error(' + $Response.Error + ')' }
  if ($Response.Code -ne '') { return [string]$Response.Status + ' ' + $Response.Code }
  return [string]$Response.Status
}

# ---------------------------------------------------------------------------
# Daemon lifecycle
# ---------------------------------------------------------------------------
function Stop-Vpnd {
  Get-Process vpnd -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 350
}

function Write-VpndConfig {
  param([string]$Path)
  $text = @"
environment = "development"
[http]
bind = "127.0.0.1:$ApiPort"
[metrics]
bind = "127.0.0.1:$MetricsPort"
"@
  [IO.File]::WriteAllText($Path, $text, (New-Object System.Text.UTF8Encoding($false)))
}

# Starting the daemon the same way scripts/verify-reminders.ps1 does: a config
# file for the bind addresses, VPN_STORE_PATH for the record log.
function Start-Vpnd {
  param([string]$ConfigPath, [string]$LogPath, [string]$StorePath)
  Stop-Vpnd
  $env:VPN_STORE_PATH = $StorePath
  $env:VPN_PASSWORD_PEPPER = $script:Pepper
  $env:VPN_LOG_LEVEL = 'info'
  Start-Process -FilePath 'cmd.exe' -WindowStyle Hidden -ArgumentList (
    '/c ""' + $script:Vpnd + '" --config "' + $ConfigPath + '" > "' + $LogPath + '" 2>&1"') | Out-Null
  for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Milliseconds 200
    $health = Invoke-Api -Method GET -Path '/api/v1/health' -NoPace
    # Any answer means the listener is up; the exact path may not be mounted yet.
    if ($health.Status -ne 0) { return $true }
    if ($null -eq (Get-Process vpnd -ErrorAction SilentlyContinue) -and $i -gt 5) { break }
  }
  return $false
}

# ---------------------------------------------------------------------------
# Seeding: hashes are computed at runtime, never hardcoded.
#
# Two candidate storage formats are supported, one line per account:
#   legacy  <32 hex>                                     HMAC-BLAKE2s(pepper, pw)
#   pbkdf2  pbkdf2-sha256$<iters>$<salt hex>$<dk hex>    per-password salt
# The harness starts the daemon with both sets and logs in until one works.
# ---------------------------------------------------------------------------
$script:SeedScript = @'
import hashlib
import hmac
import os
import sys

fmt, pepper, iterations, blob = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
for record in blob.split(";"):
    if record.strip() == "":
        continue
    uid, email, password, role = record.split("|")
    if fmt == "legacy":
        digest = hmac.new(pepper.encode("utf-8"), password.encode("utf-8"),
                          hashlib.blake2s).hexdigest()
    elif fmt == "pbkdf2":
        salt = os.urandom(16)
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        digest = "pbkdf2-sha256$%d$%s$%s" % (iterations, salt.hex(), derived.hex())
    else:
        sys.stderr.write("unknown seed format\n")
        raise SystemExit(2)
    sys.stdout.write("U\t%s\tten_default\t%s\t%s\t%s\n" % (uid, email, digest, role))
'@

function Get-SeedLines {
  param([string]$Format, [object[]]$Accounts)
  $blob = ($Accounts | ForEach-Object {
    $_.Id + '|' + $_.Email + '|' + $_.Password + '|' + $_.Role
  }) -join ';'
  $output = & python $script:SeedScriptPath $Format $script:Pepper ([string]$script:SeedIterations) $blob 2>&1
  $text = (($output -join "`n") -replace "`r`n", "`n")
  if ($LASTEXITCODE -ne 0) {
    throw ('seed helper failed (' + $Format + '): ' + $text)
  }
  # Only accept record lines: anything the interpreter writes on stdout or stderr
  # that is not a store record must never land in the store file.
  $records = @($text -split "`n" | Where-Object { $_ -match "^U`t" })
  if ($records.Count -ne $Accounts.Count) {
    throw ('seed helper produced ' + $records.Count + ' record(s) for ' +
           $Accounts.Count + ' account(s): ' + $text)
  }
  return (($records -join "`n") + "`n")
}

function Add-SeedLines {
  param([string]$StorePath, [string]$Text)
  if ($Text -eq '') { return }
  $existing = ''
  if (Test-Path $StorePath) { $existing = [IO.File]::ReadAllText($StorePath) }
  if ($existing -ne '' -and -not $existing.EndsWith("`n")) { $existing += "`n" }
  [IO.File]::WriteAllText($StorePath, $existing + $Text,
    (New-Object System.Text.UTF8Encoding($false)))
}


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host 'verify-security: PBKDF2 / throttle / token rotation / audit trail'
Write-Host ''

if (-not (Test-Path $script:Vpnd)) {
  Write-Host ('SKIP  cannot run: ' + $script:Vpnd + ' is not built')
  Write-Host '      build it with: cmake --build out/build-release --target vpnd'
  exit 2
}
$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
if ($null -eq $pythonCommand) {
  Write-Host 'SKIP  cannot run: python is required to compute seed hashes and PBKDF2 vectors'
  exit 2
}
Write-Host ('binary : ' + $script:Vpnd)
Write-Host ('python : ' + $pythonCommand.Source)

$runId = [guid]::NewGuid().ToString('N').Substring(0, 8)
$work = Join-Path $env:TEMP ('vpn-sec-' + $runId)
if (Test-Path $work) { Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force $work | Out-Null
$store = Join-Path $work 'control.log'
$configPath = Join-Path $work 'vpnd.toml'
$daemonLog = Join-Path $work 'vpnd.log'
$script:SeedScriptPath = Join-Path $work 'seed_account.py'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($script:SeedScriptPath, $script:SeedScript, $utf8NoBom)
Write-VpndConfig -Path $configPath
$script:Http = New-HttpClient
Write-Host ('work   : ' + $work)
Write-Host ''

# ---------------------------------------------------------------------------
# Provisioning
#   1. empty store + VPN_BOOTSTRAP_EMAIL/PASSWORD -> the ordinary account
#   2. append admin + throttle candidates in both candidate hash formats
#   3. log in to discover which format this binary accepts
# ---------------------------------------------------------------------------
$bootstrapEmail = 'boot-' + $runId + '@verify.invalid'
$bootstrapPassword = 'Boot-' + $runId + '-pw'
$env:VPN_BOOTSTRAP_EMAIL = $bootstrapEmail
$env:VPN_BOOTSTRAP_PASSWORD = $bootstrapPassword

$failedToRun = $false
$diagnostic = ''
$userRole = ''
$userId = ''
$bootLogin = $null

$started = Start-Vpnd -ConfigPath $configPath -LogPath $daemonLog -StorePath $store
if ($started) { $bootLogin = Invoke-Login $bootstrapEmail $bootstrapPassword -NoPace }
if (-not $started -or $bootLogin.Status -ne 200) {
  $failedToRun = $true
  if (-not $started) {
    $diagnostic = 'vpnd did not become healthy on ' + $script:BaseUrl
  } else {
    $diagnostic = 'the bootstrap account could not log in: ' + (Format-Status $bootLogin)
  }
} else {
  $bootstrapToken = Get-Token $bootLogin
  $me = Invoke-Api -Method GET -Path '/api/v1/me' -Token $bootstrapToken
  if ($null -ne $me.Json -and $null -ne $me.Json.role) { $userRole = [string]$me.Json.role }
  if ($null -ne $me.Json -and $null -ne $me.Json.user_id) { $userId = [string]$me.Json.user_id }
  Write-Host ('bootstrap account: ' + $bootstrapEmail + ' role=' + $userRole + ' id=' + $userId)
}
Stop-Vpnd


$candidates = @()
if (-not $failedToRun) {
  foreach ($format in @('legacy', 'pbkdf2')) {
    $candidates += [pscustomobject]@{
      Format = $format; Role = 'admin'
      Id = 'usr_ver' + $format + 'adm'
      Email = 'admin-' + $format + '-' + $runId + '@verify.invalid'
      Password = 'Admin-' + $format + '-' + $runId + '-pw'
    }
    $candidates += [pscustomobject]@{
      Format = $format; Role = 'user'
      Id = 'usr_ver' + $format + 'thr'
      Email = 'throttle-' + $format + '-' + $runId + '@verify.invalid'
      Password = 'Throttle-' + $format + '-' + $runId + '-pw'
    }
  }
  try {
    foreach ($format in @('legacy', 'pbkdf2')) {
      $subset = @($candidates | Where-Object { $_.Format -eq $format })
      Add-SeedLines -StorePath $store -Text (Get-SeedLines -Format $format -Accounts $subset)
    }
    Write-Host ('seeded  : ' + $candidates.Count +
                ' candidate accounts (legacy and pbkdf2 storage formats)')
  } catch {
    $failedToRun = $true
    $diagnostic = 'seed helper failed: ' + $_.Exception.Message
  }
}

$adminCandidate = $null
$throttleCandidate = $null
$seedFormat = ''
if (-not $failedToRun) {
  # The store is not empty any more, so the bootstrap account is not re-created:
  # the two daemon starts leave one store holding an account of each origin.
  if (-not (Start-Vpnd -ConfigPath $configPath -LogPath $daemonLog -StorePath $store)) {
    $failedToRun = $true
    $diagnostic = 'vpnd did not become healthy after seeding on ' + $script:BaseUrl
  } else {
    # The new storage format is probed first so a passing run also proves that
    # the PBKDF2 verifier agrees with Python's hashlib; the legacy format is
    # tried second, for a binary that has not switched over yet.
    foreach ($format in @('pbkdf2', 'legacy')) {
      $probe = @($candidates | Where-Object { $_.Format -eq $format -and $_.Role -eq 'admin' })[0]
      $attempt = Invoke-Login $probe.Email $probe.Password
      if ($attempt.Status -eq 200) {
        $seedFormat = $format
        $adminCandidate = $probe
        if ($format -eq 'pbkdf2') {
          Write-Host ('pbkdf2  : the C++ KDF accepted a hash computed by python hashlib (' +
                      $script:SeedIterations + ' iterations) - cross-implementation match')
        }
        break
      }
    }
    if ($null -eq $adminCandidate) {
      $failedToRun = $true
      $diagnostic = ('no seeded hash format was accepted: tried legacy HMAC-BLAKE2s and ' +
                     'pbkdf2-sha256$<iters>$<salt>$<dk>, so the stored password format changed')
    } else {
      $throttleCandidate = @($candidates | Where-Object {
        $_.Format -eq $seedFormat -and $_.Role -eq 'user' })[0]
    }
  }
}

if ($failedToRun) {
  Write-Host ''
  Write-Host ('PROVISIONING FAILED: ' + $diagnostic)
  Write-Host ('     daemon log: ' + $daemonLog)
  if (Test-Path $daemonLog) {
    Get-Content $daemonLog -Tail 12 | ForEach-Object { Write-Host ('     ' + $_) }
  }
  $provisionRequests = @()
  if ($null -ne $bootLogin) { $provisionRequests += $bootLogin.Curl }
  foreach ($caseId in 1..5) {
    Write-CaseResult -Id $caseId -Name 'not-run' -Verdict 'FAIL' `
      -Detail ('provisioning failed: ' + $diagnostic) -Requests $provisionRequests
  }
  Stop-Vpnd
  if (-not $KeepWork) { Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue }
  Write-Host ''
  Write-Host 'summary: 0 passed, 5 failed, 0 skipped (harness could not run)'
  exit 1
}

$adminToken = ''
$adminId = ''
$adminLogin = Invoke-Login $adminCandidate.Email $adminCandidate.Password
if ($adminLogin.Status -eq 200) {
  $adminToken = Get-Token $adminLogin
  if ($null -ne $adminLogin.Json -and $null -ne $adminLogin.Json.user_id) {
    $adminId = [string]$adminLogin.Json.user_id
  }
}
if ($adminId -eq '') { $adminId = $adminCandidate.Id }
Write-Host ('admin   : ' + $adminCandidate.Email + ' id=' + $adminId + ' (seeded, ' + $seedFormat + ')')
Write-Host ''

# Password of record for the ordinary account. Case 2 runs before case 1 so the
# "nothing changed" assertion cannot be masked by a successful change.
$script:PasswordOfRecord = $bootstrapPassword
# Every password this account has had. Cases that only need *a* token (not a
# password assertion) walk this list, so one failing case cannot cascade into the
# next: after a failed assertion in case 1 the old password may no longer work.
$script:KnownPasswords = @($bootstrapPassword)

function Set-PasswordOfRecord {
  param([string]$Password)
  if ($Password -eq '') { return }
  $script:PasswordOfRecord = $Password
  if ($script:KnownPasswords -notcontains $Password) {
    $script:KnownPasswords = @($Password) + $script:KnownPasswords
  }
}

# Login for a case that needs a token rather than a password assertion.
function Invoke-LoginRecovered {
  param([string]$Email)
  $last = $null
  foreach ($candidate in $script:KnownPasswords) {
    $last = Invoke-Login -Email $Email -Password $candidate
    if ($last.Status -eq 200) {
      Set-PasswordOfRecord $candidate
      return $last
    }
  }
  return $last
}


# ---------------------------------------------------------------------------
# Case 2: a wrong current password is refused and changes nothing
#         POST /api/v1/me/password {current_password,new_password} -> 401
# ---------------------------------------------------------------------------
$login = Invoke-LoginRecovered -Email $bootstrapEmail
$userToken = Get-Token $login
if ($userToken -eq '') {
  Write-CaseResult -Id 2 -Name 'wrong-current' -Verdict 'FAIL' `
    -Detail ('cannot log in as ' + $bootstrapEmail + ': ' + (Format-Status $login)) `
    -Requests @($login.Curl)
} else {
  $attemptedPassword = 'Attempted-' + $runId + '-pw'
  $wrongBody = '{"current_password":"definitely-not-the-password","new_password":"' +
               $attemptedPassword + '"}'
  $wrong = Invoke-Api -Method POST -Path '/api/v1/me/password' -Body $wrongBody -Token $userToken
  $stillOld = Invoke-Login -Email $bootstrapEmail -Password $script:PasswordOfRecord
  $attemptedLogin = Invoke-Login -Email $bootstrapEmail -Password $attemptedPassword
  $reqs = @($wrong.Curl, $stillOld.Curl, $attemptedLogin.Curl)
  if ($wrong.Status -eq 404 -or $wrong.Status -eq 405) {
    Write-CaseResult -Id 2 -Name 'wrong-current' -Verdict 'SKIP' `
      -Detail ('expected POST /api/v1/me/password, got ' + (Format-Status $wrong)) `
      -Requests @($wrong.Curl)
  } elseif ($wrong.Status -ne 401) {
    Write-CaseResult -Id 2 -Name 'wrong-current' -Verdict 'FAIL' `
      -Detail ('a wrong current password returned ' + (Format-Status $wrong) + ', expected 401') `
      -Requests $reqs
  } elseif ($stillOld.Status -ne 200) {
    Write-CaseResult -Id 2 -Name 'wrong-current' -Verdict 'FAIL' `
      -Detail ('the old password stopped working after a refused change (' +
               (Format-Status $stillOld) + ')') -Requests $reqs
  } elseif ($attemptedLogin.Status -eq 200) {
    Write-CaseResult -Id 2 -Name 'wrong-current' -Verdict 'FAIL' `
      -Detail 'the refused request still changed the password: the attempted new one works' `
      -Requests $reqs
  } else {
    Write-CaseResult -Id 2 -Name 'wrong-current' -Verdict 'PASS' `
      -Detail ('wrong current ' + (Format-Status $wrong) + ', old still ' +
               (Format-Status $stillOld) + ', attempted new ' + (Format-Status $attemptedLogin))
  }
}

# ---------------------------------------------------------------------------
# Case 1: the password change works end to end
#         POST /api/v1/me/password (correct current) -> 204
# ---------------------------------------------------------------------------
$newPassword = 'Changed-' + $runId + '-pw'
$login = Invoke-LoginRecovered -Email $bootstrapEmail
$userToken = Get-Token $login
if ($userToken -eq '') {
  Write-CaseResult -Id 1 -Name 'password-change' -Verdict 'FAIL' `
    -Detail ('cannot log in as ' + $bootstrapEmail + ': ' + (Format-Status $login)) `
    -Requests @($login.Curl)
} else {
  $previousPassword = $script:PasswordOfRecord
  $wantChangeStatus = 204
  $changeBody = '{"current_password":"' + $previousPassword + '","new_password":"' +
                $newPassword + '"}'
  $change = Invoke-Api -Method POST -Path '/api/v1/me/password' -Body $changeBody -Token $userToken
  $oldLogin = Invoke-Login -Email $bootstrapEmail -Password $previousPassword
  $newLogin = Invoke-Login -Email $bootstrapEmail -Password $newPassword
  $reqs = @($change.Curl, $oldLogin.Curl, $newLogin.Curl)
  # The password of record follows an *accepted* change (any 2xx) whether or not
  # this harness expected that status, so a failed assertion in this case cannot
  # throw off cases 3 and 4.
  if ($change.Status -ge 200 -and $change.Status -lt 300) { Set-PasswordOfRecord $newPassword }
  if ($change.Status -eq 404 -or $change.Status -eq 405) {
    Write-CaseResult -Id 1 -Name 'password-change' -Verdict 'SKIP' `
      -Detail ('expected POST /api/v1/me/password, got ' + (Format-Status $change)) `
      -Requests @($change.Curl)
  } elseif ($change.Status -ne $wantChangeStatus) {
    Write-CaseResult -Id 1 -Name 'password-change' -Verdict 'FAIL' `
      -Detail ('change returned ' + (Format-Status $change) + ', expected ' + $wantChangeStatus) `
      -Requests $reqs
  } elseif ($oldLogin.Status -ne 401) {
    Write-CaseResult -Id 1 -Name 'password-change' -Verdict 'FAIL' `
      -Detail ('the old password still logs in after the change (' +
               (Format-Status $oldLogin) + '), expected 401') -Requests $reqs
  } elseif ($newLogin.Status -ne 200) {
    Write-CaseResult -Id 1 -Name 'password-change' -Verdict 'FAIL' `
      -Detail ('the new password does not log in (' + (Format-Status $newLogin) +
               '), expected 200') -Requests $reqs
  } else {
    Write-CaseResult -Id 1 -Name 'password-change' -Verdict 'PASS' `
      -Detail ('change ' + (Format-Status $change) + ', old ' + (Format-Status $oldLogin) +
               ', new ' + (Format-Status $newLogin))
  }
}


# ---------------------------------------------------------------------------
# Case 3: login throttle
#   N failed logins for one email, then the CORRECT password must be refused
#   (429 or 423) instead of accepted, and a different account must be unaffected.
#
#   The control plane also has a per-IP token bucket, so a bare 429 proves
#   nothing: the refusal only counts if the problem code is not `rate_limited`
#   and another account still logs in from the same address afterwards.
# ---------------------------------------------------------------------------
$throttleName = 'login-throttle'
if ($null -eq $throttleCandidate) {
  Write-CaseResult -Id 3 -Name $throttleName -Verdict 'SKIP' `
    -Detail 'needs a second provisionable account to show the throttle is account-scoped'
} else {
  $baseline = Invoke-Login -Email $throttleCandidate.Email -Password $throttleCandidate.Password
  $badStatuses = @()
  $firstBadCurl = ''
  $ipShed = $false
  for ($i = 1; $i -le $FailedLoginAttempts; $i++) {
    $bad = Invoke-Login -Email $throttleCandidate.Email -Password ('wrong-' + $i + '-' + $runId)
    $badStatuses += $bad.Status
    if ($firstBadCurl -eq '') { $firstBadCurl = $bad.Curl }
    if ($bad.Status -eq 429 -and $bad.Code -eq 'rate_limited') { $ipShed = $true }
  }
  $after = Invoke-Login -Email $throttleCandidate.Email -Password $throttleCandidate.Password
  $other = Invoke-LoginRecovered -Email $bootstrapEmail
  $reqs = @($firstBadCurl, $after.Curl, $other.Curl)

  $histogram = (@($badStatuses | Group-Object | ForEach-Object {
    [string]$_.Count + 'x' + $_.Name }) -join ', ')
  $verdict = ''
  $detail = ''
  if ($baseline.Status -ne 200) {
    $verdict = 'FAIL'
    $detail = ('the throttle account could not log in before the test: ' +
               (Format-Status $baseline))
  } elseif ($after.Status -eq 200) {
    $verdict = 'FAIL'
    $detail = ('the correct password was still accepted after ' + $FailedLoginAttempts +
               ' failures (' + (Format-Status $after) + '): logins are not throttled')
  } elseif ($after.Status -ne 429 -and $after.Status -ne 423) {
    $verdict = 'FAIL'
    $detail = ('after ' + $FailedLoginAttempts + ' failures the correct password returned ' +
               (Format-Status $after) + ', expected 429 or 423')
  } elseif ($after.Code -eq 'rate_limited') {
    $verdict = 'FAIL'
    $detail = ('refused by the per-IP rate limiter (code=rate_limited), not by an account ' +
               'throttle; the request never reached the password check')
  } elseif ($other.Status -ne 200) {
    $verdict = 'FAIL'
    $detail = ('a different account was affected too (' + (Format-Status $other) +
               '): the refusal is not account-scoped')
  } else {
    $verdict = 'PASS'
    $detail = ('' + $FailedLoginAttempts + ' bad attempts [' + $histogram + '], then the ' +
               'correct password was refused with ' + (Format-Status $after) +
               '; another account still logs in (200)')
    # "recovers or is clearly rate-limited": if the server told us to come back
    # soon, verify the recovery so the throttle cannot be a permanent lockout.
    $waitSeconds = 0
    if ($after.RetryAfter -ne '' -and $after.RetryAfter -match '^\d+$') {
      $waitSeconds = [int]$after.RetryAfter
    }
    if ($waitSeconds -gt 0 -and $waitSeconds -le 10) {
      Start-Sleep -Seconds $waitSeconds
      $recovery = Invoke-Login -Email $throttleCandidate.Email -Password $throttleCandidate.Password
      $reqs += $recovery.Curl
      if ($recovery.Status -eq 200) {
        $detail += ('; recovered after ' + $waitSeconds + 's (Retry-After)')
      } else {
        $detail += ('; still refused after Retry-After ' + $waitSeconds + 's (' +
                    (Format-Status $recovery) + ')')
      }
    } elseif ($after.RetryAfter -ne '') {
      $detail += ('; Retry-After ' + $after.RetryAfter)
    }
    if ($ipShed) { $detail += '; note: the per-IP bucket shed at least one attempt' }
  }
  Write-CaseResult -Id 3 -Name $throttleName -Verdict $verdict -Detail $detail -Requests $reqs
}


# ---------------------------------------------------------------------------
# Case 4: token rotation
#   POST /api/v1/auth/rotate -> new token, the old token now 401, the new one works.
#   docs/API.md also names POST /api/v1/auth/refresh for rotation, so if /rotate
#   is absent the documented alternative is used (with refresh semantics: only
#   the returned token is asserted to work).
# ---------------------------------------------------------------------------
$rotateName = 'token-rotation'
$login = Invoke-LoginRecovered -Email $bootstrapEmail
$tokenA = Get-Token $login
$rotateCurl = Format-Curl -Method POST -Path '/api/v1/auth/rotate' -Body '{}' -Token $tokenA
$refreshCurl = Format-Curl -Method POST -Path '/api/v1/auth/refresh' -Body '{}' -Token $tokenA
if ($tokenA -eq '') {
  Write-CaseResult -Id 4 -Name $rotateName -Verdict 'FAIL' `
    -Detail ('cannot obtain a token to rotate: ' + (Format-Status $login)) `
    -Requests @($login.Curl)
} else {
  $endpoint = '/api/v1/auth/rotate'
  $rotate = Invoke-Api -Method POST -Path $endpoint -Body '{}' -Token $tokenA
  $strict = $true
  if ($rotate.Status -eq 404 -or $rotate.Status -eq 405) {
    $endpoint = '/api/v1/auth/refresh'
    $rotate = Invoke-Api -Method POST -Path $endpoint -Body '{}' -Token $tokenA
    $strict = $false
  }
  if ($rotate.Status -eq 404 -or $rotate.Status -eq 405) {
    Write-CaseResult -Id 4 -Name $rotateName -Verdict 'SKIP' `
      -Detail ('expected POST /api/v1/auth/rotate (or /api/v1/auth/refresh): both return ' +
               (Format-Status $rotate)) -Requests @($rotateCurl, $refreshCurl)
  } else {
    $tokenB = ''
    if ($null -ne $rotate.Json) {
      if ($null -ne $rotate.Json.access_token) { $tokenB = [string]$rotate.Json.access_token }
      elseif ($null -ne $rotate.Json.token) { $tokenB = [string]$rotate.Json.token }
    }
    $oldCheck = Invoke-Api -Method GET -Path '/api/v1/me' -Token $tokenA
    $newCheck = Invoke-Api -Method GET -Path '/api/v1/me' -Token $tokenB
    $reqs = @($rotate.Curl, $oldCheck.Curl, $newCheck.Curl)
    if ($rotate.Status -ne 200 -and $rotate.Status -ne 201) {
      Write-CaseResult -Id 4 -Name $rotateName -Verdict 'FAIL' `
        -Detail ('POST ' + $endpoint + ' returned ' + (Format-Status $rotate) +
                 ', expected 200 with a new token') -Requests $reqs
    } elseif ($tokenB -eq '') {
      Write-CaseResult -Id 4 -Name $rotateName -Verdict 'FAIL' `
        -Detail ('POST ' + $endpoint + ' returned 200 but no access_token/token field: ' +
                 $rotate.Body) -Requests $reqs
    } elseif ($tokenB -eq $tokenA) {
      Write-CaseResult -Id 4 -Name $rotateName -Verdict 'FAIL' `
        -Detail 'the rotated token is identical to the old one: no rotation' -Requests $reqs
    } elseif ($newCheck.Status -ne 200) {
      Write-CaseResult -Id 4 -Name $rotateName -Verdict 'FAIL' `
        -Detail ('the new token does not work (' + (Format-Status $newCheck) + ')') `
        -Requests $reqs
    } elseif ($strict -and $oldCheck.Status -ne 401) {
      Write-CaseResult -Id 4 -Name $rotateName -Verdict 'FAIL' `
        -Detail ('the old token is still valid after rotation (' + (Format-Status $oldCheck) +
                 '), expected 401') -Requests $reqs
    } else {
      $oldDetail = 'old ' + (Format-Status $oldCheck)
      if (-not $strict) { $oldDetail += ' (refresh semantics: not asserted)' }
      Write-CaseResult -Id 4 -Name $rotateName -Verdict 'PASS' `
        -Detail ('POST ' + $endpoint + ' 200, new token works, ' + $oldDetail)
    }
  }
}


# ---------------------------------------------------------------------------
# Audit helpers (case 5)
# ---------------------------------------------------------------------------
# The store is append-only and fsync'ed, so "everything past this byte offset" is
# exactly what the daemon wrote during the admin action.
function Get-AppendedText {
  param([string]$Path, [long]$Offset)
  if (-not (Test-Path $Path)) { return '' }
  $stream = $null
  try {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
                              [IO.FileShare]::ReadWrite)
    if ($Offset -lt 0 -or $Offset -gt $stream.Length) { $Offset = 0 }
    [void]$stream.Seek($Offset, [IO.SeekOrigin]::Begin)
    $reader = New-Object System.IO.StreamReader($stream, [Text.Encoding]::UTF8)
    return $reader.ReadToEnd()
  } catch {
    return ''
  } finally {
    if ($null -ne $stream) { $stream.Dispose() }
  }
}

# One record must name the acting administrator AND the action. Records are
# separated by newlines in the store log and by '}' in a JSON body; a JSON body
# that is pretty-printed still has one object per chunk.
function Find-AuditRecord {
  param([string]$Text, [string]$Actor, [string[]]$ActionTokens, [switch]$JsonChunks)
  if ($Text -eq '' -or $Actor -eq '') { return '' }
  $chunks = @()
  if ($JsonChunks) { $chunks = $Text -split '\}' } else { $chunks = $Text -split "`r?`n" }
  foreach ($chunk in $chunks) {
    if ($chunk -eq '') { continue }
    if ($chunk.IndexOf($Actor, [StringComparison]::Ordinal) -lt 0) { continue }
    foreach ($token in $ActionTokens) {
      if ($chunk.IndexOf($token, [StringComparison]::Ordinal) -ge 0) { return $chunk.Trim() }
    }
  }
  return ''
}

# ---------------------------------------------------------------------------
# Case 5: the admin audit trail records who did what
#   POST /api/v1/admin/users, then GET /api/v1/admin/audit (or, until that
#   exists, the appended store log) must name the acting admin and the action.
# ---------------------------------------------------------------------------
$auditName = 'audit-trail'
$actionTokens = @('user.create', 'admin.users.create', 'users.create', 'admin.users')
if ($adminToken -eq '') {
  Write-CaseResult -Id 5 -Name $auditName -Verdict 'FAIL' `
    -Detail ('no administrator token: login as ' + $adminCandidate.Email + ' gave ' +
             (Format-Status $adminLogin)) -Requests @($adminLogin.Curl)
} else {
  $marker = 0
  if (Test-Path $store) { $marker = (Get-Item $store).Length }
  $createdEmail = 'audit-' + $runId + '@verify.invalid'
  $createBody = '{"email":"' + $createdEmail + '","password":"Audit-' + $runId +
                '-pw","days":30}'
  $action = Invoke-Api -Method POST -Path '/api/v1/admin/users' -Body $createBody -Token $adminToken
  $endpointUsed = '/api/v1/admin/users'
  $reqs = @($action.Curl)

  if ($action.Status -eq 404 -or $action.Status -eq 405) {
    # Another documented administrator action, so the audit trail is still
    # exercised end to end when account creation is not mounted yet.
    $endpointUsed = '/api/v1/admin/users/' + $userId + '/access'
    $actionTokens = @('user.grant', 'admin.access', 'access.grant')
    $action = Invoke-Api -Method POST -Path $endpointUsed -Body '{"days":1}' -Token $adminToken
    $reqs = @($action.Curl)
  }

  $createdId = ''
  if ($null -ne $action.Json -and $null -ne $action.Json.id) {
    $createdId = [string]$action.Json.id
  }

  if ($action.Status -eq 404 -or $action.Status -eq 405) {
    Write-CaseResult -Id 5 -Name $auditName -Verdict 'SKIP' `
      -Detail ('expected POST /api/v1/admin/users (or /api/v1/admin/users/{id}/access); ' +
               'both return ' + (Format-Status $action)) -Requests $reqs
  } elseif ($action.Status -ne 200 -and $action.Status -ne 201) {
    Write-CaseResult -Id 5 -Name $auditName -Verdict 'FAIL' `
      -Detail ('the admin action ' + $endpointUsed + ' returned ' + (Format-Status $action) +
               ', expected 200/201') -Requests $reqs
  } else {
    $audit = Invoke-Api -Method GET -Path '/api/v1/admin/audit' -Token $adminToken
    $reqs += $audit.Curl
    $haystack = ''
    $source = ''
    $isJson = $false
    if ($audit.Status -eq 200) {
      $haystack = $audit.Body
      $source = 'GET /api/v1/admin/audit'
      $isJson = $true
    } else {
      $appended = Get-AppendedText -Path $store -Offset $marker
      $lineCount = @($appended -split "`r?`n" | Where-Object { $_ -ne '' }).Count
      $haystack = $appended
      $source = ('store log fallback (' + $lineCount + ' new line(s); GET ' +
                 '/api/v1/admin/audit is ' + (Format-Status $audit) + ')')
    }
    $hit = Find-AuditRecord -Text $haystack -Actor $adminId -ActionTokens $actionTokens `
      -JsonChunks:$isJson
    $targetNote = ''
    if ($createdId -ne '') { $targetNote = ', target ' + $createdId }
    if ($hit -ne '') {
      $snippet = $hit
      if ($snippet.Length -gt 120) { $snippet = $snippet.Substring(0, 120) + '...' }
      Write-CaseResult -Id 5 -Name $auditName -Verdict 'PASS' `
        -Detail ('record found in ' + $source + ' naming actor ' + $adminId + $targetNote +
                 ': ' + $snippet)
    } else {
      Write-CaseResult -Id 5 -Name $auditName -Verdict 'FAIL' `
        -Detail ('no record naming actor ' + $adminId + ' and action ' +
                 ($actionTokens -join '|') + ' found in ' + $source) -Requests $reqs
    }
  }
}


# ---------------------------------------------------------------------------
# Summary and cleanup
# ---------------------------------------------------------------------------
Stop-Vpnd
if ($null -ne $script:Http) { $script:Http.Dispose() }

$passed = @($script:CaseResults | Where-Object { $_.Verdict -eq 'PASS' }).Count
$failed = @($script:CaseResults | Where-Object { $_.Verdict -eq 'FAIL' }).Count
$skipped = @($script:CaseResults | Where-Object { $_.Verdict -eq 'SKIP' }).Count

Write-Host ''
Write-Host ('summary: ' + $passed + ' passed, ' + $failed + ' failed, ' + $skipped + ' skipped')
if ($failed -gt 0) {
  $names = @($script:CaseResults | Where-Object { $_.Verdict -eq 'FAIL' } | ForEach-Object {
    [string]$_.Id + ' (' + $_.Name + ')' })
  Write-Host ('failed : ' + ($names -join ', '))
}
if ($skipped -gt 0) {
  $names = @($script:CaseResults | Where-Object { $_.Verdict -eq 'SKIP' } | ForEach-Object {
    [string]$_.Id + ' (' + $_.Name + ')' })
  Write-Host ('skipped: ' + ($names -join ', ') + '  -- endpoint not implemented yet')
}
if (Test-Path $daemonLog) {
  Write-Host ('log    : ' + $daemonLog)
}
if ($KeepWork) {
  Write-Host ('work   : kept at ' + $work + ' (store, config, seed helper)')
} else {
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
  Write-Host ('work   : removed ' + $work + ' (-KeepWork keeps it for inspection)')
}

if ($failed -gt 0) { exit 1 }
exit 0
