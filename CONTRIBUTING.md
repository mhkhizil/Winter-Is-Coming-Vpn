# Contributing

## Before you start

* Read [`docs/DECISIONS/`](docs/DECISIONS/) — every locked decision lives there.
* Read [`docs/CPP_CONVENTIONS.md`](docs/CPP_CONVENTIONS.md) — the rules are
  enforced, not advisory.
* Bootstrap a toolchain with [`docs/BUILDING.md`](docs/BUILDING.md).

## Workflow

```sh
git switch -c feat/wire-mac1-verification
# ... edit ...
cmake --preset default && cmake --build --preset default --parallel
ctest --preset default            # or: ./build/default/server/vpn_unit_tests
cmake --build --preset default --target format-check
git commit -m "feat(wire): verify mac1 before any DH"
```

Conventional commits: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `chore`,
`build`, `ci`. Scope is the module (`wire`, `crypto`, `dp`, `cp`, `api`, `deploy`).

## Pull request checklist

- [ ] Builds with `-Werror` on GCC 13 **and** Clang 18
- [ ] `vpn_unit_tests` green (and new tests for new behaviour)
- [ ] `cmake --build --preset default --target format-check` clean (CI gate)
- [ ] No new `clang-tidy` findings (`clang-tidy` is not run in CI yet — run it locally)
- [ ] Docs updated if behaviour or a constant changed — and no claim added that the
      code does not implement (`docs/README.md` rules 1–5)
- [ ] ADR added/amended if a decision changed
- [ ] No secret, key, token or customer data in the diff (`git diff --stat` review)
- [ ] If `wire/` or `crypto/` changed: **two approvals**, one from the crypto owner,
      plus a 24 h fuzz run linked in the description

## What gets rejected immediately

* Exceptions thrown across a module boundary, or `catch (...)` swallowing errors.
* `memcmp`/`==` on secret material, `memset` on keys.
* Any code path that stores a client private key (ADR-0007).
* A hard-coded IP, key, token or tenant id.
* A performance claim without a benchmark attached.
* A new dependency without an ADR.

## Testing expectations

| Layer | Tool | Required | Exists today |
|---|---|---|---|
| Unit (pure logic) | `vpn_unit_tests` (built-in harness, zero deps) | every new function | **yes** — 6 translation units including `test_ct.cpp` |
| Golden vectors | `server/tests/golden/` — Python verifiers + standalone C++ drivers + `work/*.json` | every crypto/protocol change | **partial** — verifiers and drivers exist, but nothing wires them into `ctest`, and `VERIFICATION_REPORT.md` (cited by the tests) is missing |
| Fuzzing | libFuzzer targets in `server/tests/fuzz/` | every parser | empty (`.gitkeep` only) |
| Integration | docker compose + real Postgres | every API change (M3+) | empty (`.gitkeep` only) |
| Benchmarks | `server/tests/bench/` | every data-plane change | **does not exist** |

"Required" means required once the layer exists. Do not add a test directory
without wiring it into `server/tests/CMakeLists.txt` and `ctest` — the golden
harness is the current example of what happens when you skip that step.

## Current state you will hit on day one

`ctest --preset default` is **red**. `wire.cookie_is_bound_to_address_and_port`
fails because `compute_cookie()` does not include the source port for IPv4
(`docs/PROTOCOL.md` §2.1). Do not "fix" the test; fix `compute_cookie()`.

Two more defects are recorded but currently invisible: the replay window is one
counter too narrow (§4.1) and `ct::select()` is inverted (§4.2). Their
`KNOWN-BUG` tests are gated behind `-DVPN_ENABLE_KNOWN_BUG_TESTS`, which no build
defines — and in `test_replay_window.cpp` that block does not even compile when
enabled. Do not treat "the gate is green" as "these are not real".

`make demo-m1` fails: `scripts/demo/m1.sh` does not exist.
`make lint` exits 0 without running clang-tidy.

## Reviewing

Reviewers check, in order: correctness of the security property, tests, failure
behaviour, then style. A reviewer may block on "this is not covered by a test"
even if the code looks right.
