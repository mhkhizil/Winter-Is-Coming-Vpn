# ADR-0011: Reminders by plain SMTP, and peers pulled over HTTP

**Status:** accepted (2026-11-02)
**Related:** ADR-0009 (TLS at the edge), ADR-0010 (administrator-granted access).

## Context

Two gaps were left after the access work:

1. **Nobody tells the customer their plan is ending.** Access expires silently, and
   the first the customer hears of it is a dead tunnel. The operator wanted
   automatic reminders, without adding a mail provider SDK.
2. **Somebody has to hand-write each node's peer table.** `vpn-dp` reads peers from
   a config file, so every new customer meant an operator editing `datad.toml` on
   the node and sending `SIGHUP` — tolerable for 5 users, not for 500. The ROADMAP
   called for gRPC CP→DP; gRPC needs protobuf codegen, HTTP/2 and a large
   dependency, for a payload of a few kilobytes.

## Decision

### Reminders: SMTP to a relay, no TLS in the binary

`vpnd` speaks **plain SMTP to a local relay** (postfix/exim/msmtp/mailhog on
loopback, or a provider's submission port behind `stunnel`). The relay does TLS
upstream. This is the same reasoning as ADR-0009: certificate validation and cipher
configuration belong in software that does it for a living, and the alternative is
a hand-written TLS client with no certificate store. `vpn-dp`/`vpnd` therefore still
contain no TLS code.

- `POST /api/v1/admin/reminders/run?days=7,1[&dry_run=1]` sends one mail per
  account per bucket and returns `{"sent":n,"failed":n,"dry_run":bool}`.
- **Idempotent by construction**: each send is recorded as an `R <user> <bucket>
  <sent-at>` record, so a daily cron never mails the same person twice for the same
  bucket. Re-granting access does not re-arm an old bucket.
- `dry_run` renders the message and skips the network, so the whole path is
  testable (and `scripts/fake_smtp.py` captures real messages for
  `scripts/verify-reminders.ps1`).
- Failure is visible: a send that fails leaves the account unmarked (it will be
  retried tomorrow) and the endpoint returns `502` with the SMTP error per
  recipient.

### Peers: pull over HTTP, in the format the daemon already speaks

`vpn-dp --config-url http://... --token ... --refresh 60` fetches
`GET /api/v1/dp/config`, which returns **the same TOML subset `vpn-dp` already
parses**. There is no second schema, no JSON parser in the data plane, and no
protobuf toolchain.

- Only `[[peer]]` blocks come from the control plane. The node's `[interface]`
  block (`private_key`, `listen`, `tun`) stays local: a node's private key must
  never travel. The merged file is written next to the local config and applied
  through the existing in-place reload path, so established sessions survive.
- Each peer carries `expires_at`, which is how ADR-0010's expiry reaches the node.
  Revoked accounts are omitted entirely; expired ones are included with a past
  timestamp so extending access takes effect on the next refresh without touching
  the node.
- **A failed pull keeps the last good table** and logs a warning: losing the control
  plane must never drop live tunnels.
- `http://` only, deliberately. TLS is terminated by a local relay or the control
  plane is reached over a private network (ADR-0009). The error message says so.

## Consequences

**Positive**

- No new runtime dependency in either binary; both features are testable on a
  laptop with no mail account and no second host.
- The pull is a plain `GET` of a few kilobytes, cheap enough at `--refresh 60` and
  trivial to debug with `curl` or `vpnctl admin dp-config`.
- Idempotency lives in the store, so it survives restarts and multiple app
  instances racing a cron.

**Negative**

- Reminders are only as reliable as the local relay; if it is down, mail is delayed
  (retried next run) but access still expires on time. That asymmetry is
  deliberate: the tunnel is the product, the mail is a courtesy.
- A pull is not a push: config changes reach a node within `--refresh` seconds
  rather than immediately. Acceptable for an operator-driven service; a real push
  channel can be added later without changing the payload format.
- The operator must keep a relay running. It is one line in
  `deploy/compose/compose.yaml`.

## Alternatives rejected

- **gRPC CP→DP (the ROADMAP plan).** HTTP/2 + protobuf + a codegen step, for a
  payload we already render as text, and a dependency that would break the
  single-static-binary property. Revisit only if the channel needs bidirectional
  streaming.
- **TLS inside `vpn-dp`.** See ADR-0009; same conclusion.
- **A mail provider HTTP API** (SES/Sendgrid/Postmark). Adds an SDK or hand-rolled
  request signing, plus an API key in the operator's config, to send three lines of
  text. SMTP to a local relay is one config block.
