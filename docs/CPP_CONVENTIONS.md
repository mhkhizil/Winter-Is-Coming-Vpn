# C++ conventions

Status: **normative**. Enforced by `.clang-format`, `.clang-tidy`, `-Werror` and
review. If a rule must be broken, the PR says which rule and why.

## 1. Language level and dependencies

* C++20 minimum; the `default` preset compiles as **C++23** (`VPN_USE_CXX23=ON`).
  `vpn::Result<T>` / `Status` (`server/include/vpn/common/result.hpp`) is a
  hand-written type used unconditionally — nothing in the tree uses
  `std::expected`, so `-DVPN_USE_CXX23=OFF` only lowers the language standard; it
  changes no code path.
* **No exceptions across module boundaries.** `vpn::Result<T>` / `Status` only.
  Exceptions may be caught at the outermost layer (`main`) as a last resort.
* **No RTTI in `vpn-dp`**, no `dynamic_cast`. Virtual dispatch only at startup
  seams (config, sinks), never per packet.
* Standard library only in `vpn_core`. Every third-party dependency is an ADR.

## 2. Naming

| Entity | Style | Example |
|---|---|---|
| Types, enums, concepts | `CamelCase` | `ReplayWindow`, `MessageType` |
| Functions, variables, namespaces | `snake_case` | `compute_mac1`, `sender_index` |
| Private members | trailing underscore | `highest_`, `listen_fd_` |
| Constants (`constexpr`) | `kCamelCase` | `kHandshakeInitiationSize` |
| Enum values | `kCamelCase` | `MessageType::kTransportData` |
| Macros | `VPN_SCREAMING_SNAKE` | `VPN_TRY` |

Files: `snake_case.hpp` / `snake_case.cpp`, header guard is `#pragma once`.

## 3. Values and ownership

* Pass byte buffers as `ByteSpan` / `MutableByteSpan` (`std::span`). Never
  `const std::vector<uint8_t>&` for binary data.
* Return `Result<T>`; mark it `[[nodiscard]]` (it already is).
* `noexcept` on every function that can fail without throwing — which is all of
  `vpn_core`.
* Prefer `std::array` for fixed sizes; `std::vector` only for genuinely dynamic
  data and never inside the packet path.

## 4. Error handling

```cpp
Result<Endpoint> parse_endpoint(std::string_view text);   // value or Status
Status validate(const ServerConfig& cfg);                 // status only
VPN_TRY(auto cfg, load_config(path));                      // propagate
```

* Error codes are stable identifiers (`ErrorCode`), messages are for humans and
  may change. Never branch on message text.
* Never `assert()` on input from the network; assert only on internal invariants.
* Every `catch` must either translate to `Status` or rethrow with context.

## 5. Security rules (intended CI-enforced greps)

| Banned | Use instead | Actually enforced today? |
|---|---|---|
| `memcmp` / `==` on key material | `vpn::ct::equal` | **partly** — `ci-server.yml` greps `server/{src,include}` for `memcmp (`; it does not catch `==` on spans (use `vpn::ct::equal`) and is trivially bypassed by `std::memcmp` |
| `memset` on secrets | `vpn::ct::cleanse` | **no** — there is no gate, and `server/src/crypto/blake2s.cpp:58,62,130` uses `std::memset`/`std::memcpy` on key-derived state |
| `strcpy`, `sprintf`, `gets` | `snprintf`, `std::string` | no |
| `reinterpret_cast` of packet buffers to structs | field-by-field `load_le32` etc. | no |
| logging a key, PSK, token or password | log an id + a hash prefix | no |
| `rand()` / `std::random_device` for crypto | `getrandom(2)` via `crypto::random` (M1) | no |

The three "no" rows are review rules, not gates. Do not describe them as
"CI-enforced" until a gate exists — several other documents currently do, which
is why this table is explicit.

## 6. Performance discipline (data plane)

* Zero heap allocations per packet, zero locks on ingress, one coarse clock read
  per batch. Proven by the `alloc_guard` test build at M2.
* Per-worker state is `alignas(64)` and padded to avoid false sharing.
* No `std::function` on the packet path; templates or function pointers.
* Measure before optimising: `bench/` results are attached to the PR.

## 7. Formatting and static analysis

```sh
cmake --build --preset default --target format        # clang-format in place
cmake --build --preset default --target format-check  # CI gate (runs in ci-server.yml)
clang-tidy -p build/default server/src/**/*.cpp       # must be run manually today
```

`format-check` **is** a real CI gate. `clang-tidy` is **not** wired into CI yet,
and `cmake --build --preset default --target lint` only prints a reminder — it
always exits 0 without analysing anything. `.clang-tidy` therefore describes the
intended rule set, not an enforced one.

clang-tidy enables `bugprone-*, cert-*, concurrency-*, clang-analyzer-*,
cppcoreguidelines-*, modernize-*, performance-*, portability-*, readability-*`
with `bugprone-*, cert-*, concurrency-*, clang-analyzer-*` as **errors**.

## 8. Commits and reviews

* Conventional commits: `feat(wire): add mac1 verification`, `fix(dp): …`,
  `docs(adr): …`, `test(crypto): …`.
* Every PR: build green on GCC 13 and Clang 18, unit tests green, no new
  clang-tidy findings, docs updated if behaviour changed.
* Anything touching `wire/` or `crypto/` needs **two** approvals, one of them
  from the crypto owner, plus a fuzz run in the description.
