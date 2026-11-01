# vpn — documentation index

Read in this order. Everything here is normative unless it says "draft".

| # | Document | What it answers |
|---|---|---|
| 1 | [DECISIONS/](DECISIONS/) | **Start here.** Every locked decision, with the rejected options and why. |
| 2 | [ARCHITECTURE.md](ARCHITECTURE.md) | Process model, module boundaries, threading, data flow. |
| 3 | [PROTOCOL.md](PROTOCOL.md) | The exact bytes on the wire, timers, counters, replay rules. |
| 4 | [THREAT_MODEL.md](THREAT_MODEL.md) | What we defend against, what we explicitly do not, key hygiene. |
| 5 | [DATA_MODEL.md](DATA_MODEL.md) | PostgreSQL schema, IPAM, tenancy isolation, retention. |
| 6 | [API.md](API.md) + [api/openapi.yaml](api/openapi.yaml) | The control-plane HTTP contract, spec-first. |
| 7 | [CLIENT_INTEGRATION.md](CLIENT_INTEGRATION.md) | Exactly what the Kotlin and Swift clients must implement. |
| 8 | [DEPLOYMENT.md](DEPLOYMENT.md) | compose → systemd edge nodes → multi-region. |
| 9 | [RUNBOOK.md](RUNBOOK.md) | On-call procedures: drain, rotate keys, restore, incident classes. |
| 10 | [CAPACITY.md](CAPACITY.md) | Sizing table, cost model, measured-vs-modelled numbers. |
| 11 | [BUILDING.md](BUILDING.md) | Toolchain bootstrap from a bare Windows 11 machine. |
| 12 | [CPP_CONVENTIONS.md](CPP_CONVENTIONS.md) | C++ rules enforced by clang-tidy and review. |
| 13 | [ROADMAP.md](ROADMAP.md) | M0–M6 with acceptance gates and what is *not* built yet. |
| 14 | [CONTRIBUTING.md](../CONTRIBUTING.md) | Branch, commit, review and CI expectations. |
| 15 | [SECURITY.md](../SECURITY.md) | Vulnerability disclosure policy. |

## Documentation rules

1. **A decision without an ADR does not exist.** If code changes a number in
   `vpn/wire/constants.hpp`, the PR must add or amend an ADR.
2. **No marketing language.** Superlatives are forbidden in these docs; state the
   property, the mechanism and the residual risk instead. The enforced term list
   is in `.github/workflows/docs-lint.yml` (`docs-lint` job, "Forbidden marketing
   terms" step) — that step is what makes this rule real, so add new terms there.
3. **Numbers carry their measurement conditions** ("10 Gbps IMIX on 16 vCPU
   with two egress NICs"), never bare claims.
4. **Every runbook step is copy-pasteable** and names the exact binary, flag and
   expected output. Steps that depend on a milestone that is not implemented yet
   must be tagged `[M2]`, `[M3]`, … — an untagged step is a bug.
5. Docs are reviewed like code: `.github/workflows/docs-lint.yml` fails the build
   on a broken relative link, a tab character, a missing required document, a
   malformed ADR filename, or a forbidden marketing term. The canonical term list
   lives in that workflow — add a term there, not here.
