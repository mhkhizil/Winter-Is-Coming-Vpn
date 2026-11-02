# ADR-0009: TLS is terminated by an edge proxy, not by vpnd

**Status:** accepted (2026-11-02)
**Supersedes:** the `[tls] cert_file`/`key_file` plan in ADR-0002, which assumed an
in-process TLS stack.

## Context

The control plane must be reachable over authenticated, encrypted transport on the
public internet. Three options were on the table:

1. **Terminate TLS inside vpnd.** This requires a TLS 1.3 stack plus X.509 parsing
   and signature verification (RSA-PSS and ECDSA-P256). Our only crypto is what we
   wrote ourselves for WireGuard: X25519, ChaCha20-Poly1305, BLAKE2s and SHA-256.
   There is no ECDSA, no RSA, no ASN.1, and no certificate parsing. Writing those
   to interoperate with public CAs and every client on the internet is a
   multi-month project with a very bad bug profile — certificate and ASN.1 parsers
   are among the most exploited code paths in existence.
2. **Take an OpenSSL/mbedTLS dependency.** Gets us TLS, but breaks the project's
   defining property (one static binary, no third-party runtime deps), adds a
   supply-chain and CVE-tracking burden, and still leaves us owning the
   configuration that is easy to get subtly wrong (OCSP, session tickets, cipher
   suites).
3. **Terminate TLS at an edge proxy** that we deploy next to vpnd: nginx or Caddy
   on the same host, or the cloud load balancer.

## Decision

**vpnd speaks plain HTTP/1.1 on a private interface; TLS 1.3 is terminated by a
proxy in front of it.** Because vpnd can then no longer tell whether a request
arrived over TLS, the proxy's claim (`X-Forwarded-Proto`) is made *trustworthy*
instead of *assumed*:

- `tls.terminated_by_proxy = true` declares the topology.
- `tls.trusted_proxies = [...]` lists the CIDRs allowed to assert
  `X-Forwarded-Proto`. The header is ignored when the peer is not in this list, so
  a client that connects straight to the socket cannot claim `https`. A wildcard
  entry (`0.0.0.0/0`) is rejected at startup, because it would silently make the
  header forgeable.
- `tls.require_https = true` makes any request that did not arrive through a
  trusted proxy a `403 HTTPS Required` (problem+json) instead of serving the API
  in cleartext. `/healthz`, `/readyz` and `/metrics` are exempt so Kubernetes
  probes and Prometheus scrapes keep working over the private network.
- `tls.hsts = true` adds `Strict-Transport-Security` to responses that did arrive
  over TLS (never to cleartext ones, where it is meaningless).
- `validate()` refuses to start in `production` unless either
  `terminated_by_proxy` or certificate files are configured, so "I forgot TLS" is
  a startup failure rather than a silent cleartext deployment.

Reference proxy configurations ship in `deploy/nginx/vpn.conf` (TLS 1.3 only, OCSP
stapling, HTTP/2, login rate limit) and `deploy/caddy/Caddyfile` (automatic
certificates, HTTP/3).

## Consequences

**Positive**

- Every client sees an ordinary TLS 1.3 endpoint — browsers, curl, official SDKs,
  mobile HTTP stacks. Compatibility is complete because it *is* the same TLS
  everyone else uses.
- The handshake runs in the proxy's event loop with session resumption and
  (kernel 5.19+) kTLS, so vpnd's worker threads never spend time on asymmetric
  crypto. Measured effect: zero TLS code on vpnd's request path, and request
  handling stays at the cost of a plaintext HTTP parse.
- vpnd contains no X.509 or ASN.1 parser, so it inherits none of that CVE surface.
- HTTP/2 and HTTP/3 come for free from the proxy; our HTTP/1.1 server is enough
  behind it.

**Negative**

- Two processes to deploy and monitor. Mitigated: both ship in
  `deploy/compose/compose.yaml`, and the proxy configs are versioned here.
- A misconfigured proxy is now a security failure mode, which is exactly why
  `require_https` exists and why the wildcard check is a startup error.
- vpnd must bind a private interface. The compose and systemd units do this;
  `deploy/nginx/vpn.conf` assumes `127.0.0.1:8080`.

## Alternatives rejected

- **A self-signed in-process TLS stack.** Not compatible: no public client would
  trust it, and TLS without certificate verification is worse than cleartext.
- **WireGuard as the only transport for the API.** Fast and we already have it,
  but it requires every API consumer to install a VPN client, which excludes
  browsers and third-party integrations.
- **Terminate in the cloud LB and skip the trusted-proxy check.** Then anyone who
  can reach the pod directly bypasses TLS. The check costs one CIDR comparison per
  request.
