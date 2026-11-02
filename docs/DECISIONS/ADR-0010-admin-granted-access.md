# ADR-0010: Access is granted by an administrator, paid for out of band

**Status:** accepted (2026-11-02)
**Supersedes:** the planned Stripe/billing integration (ROADMAP M4 "subscriptions").

## Context

The service needs a way to sell access. Two models were on the table:

1. **Payment processor (Stripe).** Card forms, webhooks, signature verification,
   invoices, refunds, tax, disputes — and PCI scope, even with Stripe Checkout.
   It needs an account, API keys, a public HTTPS endpoint for webhooks and a
   business entity that Stripe will accept. That is a lot of machinery, and it is
   machinery that breaks (failed webhooks silently leaving accounts active or
   inactive are a classic).
2. **Administrator-granted access.** The operator collects money the way they
   actually want to (bank transfer, cash, mobile money, PayPal invoice) and
   records the result in one place: *this email, on this plan, until this
   timestamp*.

The operator for this deployment sells in months (1, 6, 12) to individual
customers, and wants the VPN to stop working when the time is up.

## Decision

**Access is a per-account expiry, granted and extended by an administrator. There
is no payment integration and no card data anywhere in the system.**

- `POST /api/v1/admin/users` creates an account for an email with a duration
  (`months` or `days`) and an initial password. `months` are 30-day months, which
  is how this is sold. Administrators are staff: their own accounts never expire.
- `POST /api/v1/admin/users/{id}/access` extends. Extension adds to whatever is
  **left** (`max(now, current expiry) + duration`), so paying early never loses
  days and paying late starts from today.
- `POST /api/v1/admin/users/{id}/revoke` is an immediate lockout that keeps the
  record; granting again re-enables it. An administrator cannot revoke themselves.
- `GET /api/v1/me` returns the account's own view: `plan`, `status`
  (`active|expired|disabled`), `expires_at`, `days_left`.
- Storage is a new `E` record in the append-only log:
  `E <user-id> <expires-unix> <plan> <status>`. Logs written before this exists
  have no `E` line for a user; those accounts are treated as never-expiring
  (`plan = "legacy"`) so an upgrade never locks the operator out. Compaction
  rewrites `E` lines like every other record kind.

**Enforcement happens in two places, because one is not enough:**

| Where | Effect |
|---|---|
| Control plane (`create_peer`, `render_client_conf`) | `403 access_expired` — an expired account cannot obtain a new peer or re-download its configuration, so a new device cannot be onboarded |
| Data plane (`vpn-dp`) | handshake refused (`peer … rejected: access expired`) and transport packets for a lapsed peer are dropped — so a client that **already** has a working configuration stops passing traffic the moment the subscription ends |

The data-plane half is the important one: without it, expiry would only be
advisory, and a customer who installed their config last month would keep using
the service indefinitely. Each peer entry in `datad.toml` therefore carries
`expires_at = <unix>` (0 or absent = never), and the control plane is the source
of that value.
`scripts/verify-access-expiry.ps1` proves all three cases (lapsed, paid-up, staff)
against a real `vpn-dp` and a real handshake.

## Consequences

**Positive**

- No PCI scope, no card storage, no webhook endpoint, no third-party account, and
  no dependency that can fail silently. Money movement stays outside the code.
- The whole model is one timestamp per account, so it is auditable in the log
  ("who extended whom, until when") and trivially operator-driven.
- Works for any payment method the operator already accepts, including cash.

**Negative**

- Renewal is manual: nobody is charged automatically, and nothing reminds the
  customer. Mitigation: `GET /api/v1/admin/users` reports `days_left` per account,
  so the operator can see who is about to lapse (a cron + `vpnctl admin users`
  is enough); a future increment can add email reminders without changing this
  model.
- The initial password is set by the administrator and must be delivered out of
  band. A password-change endpoint is the natural next increment.
- Revenue is not reconciled automatically. This is a deliberate trade: the
  operator reconciles against their own bank/cash records.

## Alternatives rejected

- **Stripe (or any processor).** Rejected by the operator's explicit request: too
  much machinery for a service sold in months against manual payment.
- **Expiry enforced only in the control plane.** Cheap, but leaves
  already-installed clients working forever (see table above).
- **Deleting the peer at expiry.** Works, but loses history, burns an address from
  the pool, and makes "renew" a re-enrolment rather than a single click.
- **A cron that deletes expired users.** Destructive and hard to reverse; an
  expiry timestamp is reversible and inspectable.
