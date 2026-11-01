// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// vpn::Result<T> - the one error-propagation type used across the server.
//
// Rules (see docs/CPP_CONVENTIONS.md):
//   * No exceptions cross a module boundary, ever.
//   * Errors are values: `Status` carries a stable machine code + human message.
//   * Callers must handle or explicitly discard a Result ([[nodiscard]]).
//
// WHY NOT std::expected
// std::expected<T,E> cannot be constructed from a bare E - it requires
// std::unexpected. That makes `return make_error(...)`, the single most common
// line in this codebase, ill-formed, and it would drag C++23 into every
// translation unit. This header therefore ships a tiny, dependency-free
// implementation covering the subset of the std API we use (`has_value`,
// `value`, `error`, `operator*`, `operator->`, `value_or`) and constructing
// directly from E. It compiles unchanged on every C++20 toolchain. See ADR-0003.
#pragma once

#include <cstdint>
#include <string>
#include <type_traits>
#include <utility>

namespace vpn {

// Stable, machine-readable error codes. Never parse Status::message; branch on
// ErrorCode. Values are part of the CLI/API contract - do not renumber.
enum class ErrorCode : std::uint8_t {
  kNone = 0,
  kInvalidArgument = 1,
  kMalformed = 2,
  kUnsupported = 3,
  kOutOfRange = 4,
  kWouldBlock = 5,
  kNotFound = 6,
  kAlreadyExists = 7,
  kPermissionDenied = 8,
  kUnauthenticated = 9,
  kResourceExhausted = 10,
  kUnavailable = 11,
  kCancelled = 12,
  kInternal = 13,
};

[[nodiscard]] constexpr const char* to_string(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::kNone: return "ok";
    case ErrorCode::kInvalidArgument: return "invalid_argument";
    case ErrorCode::kMalformed: return "malformed";
    case ErrorCode::kUnsupported: return "unsupported";
    case ErrorCode::kOutOfRange: return "out_of_range";
    case ErrorCode::kWouldBlock: return "would_block";
    case ErrorCode::kNotFound: return "not_found";
    case ErrorCode::kAlreadyExists: return "already_exists";
    case ErrorCode::kPermissionDenied: return "permission_denied";
    case ErrorCode::kUnauthenticated: return "unauthenticated";
    case ErrorCode::kResourceExhausted: return "resource_exhausted";
    case ErrorCode::kUnavailable: return "unavailable";
    case ErrorCode::kCancelled: return "cancelled";
    case ErrorCode::kInternal: return "internal";
  }
  return "unknown";
}

// Maps to the closest gRPC status code so the control plane can translate
// internal failures into stable API errors (docs/api/openapi.yaml).
[[nodiscard]] constexpr int to_grpc_status(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::kNone: return 0;               // OK
    case ErrorCode::kInvalidArgument: return 3;    // INVALID_ARGUMENT
    case ErrorCode::kMalformed: return 3;          // INVALID_ARGUMENT
    case ErrorCode::kUnsupported: return 12;       // UNIMPLEMENTED
    case ErrorCode::kOutOfRange: return 11;        // OUT_OF_RANGE
    case ErrorCode::kWouldBlock: return 4;         // DEADLINE_EXCEEDED
    case ErrorCode::kNotFound: return 5;           // NOT_FOUND
    case ErrorCode::kAlreadyExists: return 6;      // ALREADY_EXISTS
    case ErrorCode::kPermissionDenied: return 7;   // PERMISSION_DENIED
    case ErrorCode::kUnauthenticated: return 16;   // UNAUTHENTICATED
    case ErrorCode::kResourceExhausted: return 8;  // RESOURCE_EXHAUSTED
    case ErrorCode::kUnavailable: return 14;       // UNAVAILABLE
    case ErrorCode::kCancelled: return 1;          // CANCELLED
    case ErrorCode::kInternal: return 13;          // INTERNAL
  }
  return 2;  // UNKNOWN
}

class Status {
 public:
  Status() noexcept = default;
  Status(ErrorCode code, std::string message) : code_(code), message_(std::move(message)) {}

  [[nodiscard]] bool ok() const noexcept { return code_ == ErrorCode::kNone; }
  [[nodiscard]] ErrorCode code() const noexcept { return code_; }
  [[nodiscard]] const std::string& message() const noexcept { return message_; }

  // "not_found: peer 42 does not exist"
  [[nodiscard]] std::string to_string() const {
    if (ok()) return "ok";
    std::string out{::vpn::to_string(code_)};
    if (!message_.empty()) {
      out += ": ";
      out += message_;
    }
    return out;
  }

 private:
  ErrorCode code_{ErrorCode::kNone};
  std::string message_{};
};

// --- Result / VoidResult ----------------------------------------------------
namespace detail {

template <class T>
class ExpectedStorage {
 public:
  ExpectedStorage(const T& value) : has_(true), value_(value) {}
  ExpectedStorage(T&& value) : has_(true), value_(std::move(value)) {}
  ExpectedStorage(const Status& status) : has_(false), status_(status) {}
  ExpectedStorage(Status&& status) : has_(false), status_(std::move(status)) {}

  [[nodiscard]] bool has_value() const noexcept { return has_; }
  explicit operator bool() const noexcept { return has_; }

  T& value() & { return value_; }
  const T& value() const& { return value_; }
  T&& value() && { return std::move(value_); }
  const T& operator*() const& noexcept { return value_; }
  T& operator*() & noexcept { return value_; }
  T&& operator*() && noexcept { return std::move(value_); }
  const T* operator->() const noexcept { return &value_; }
  T* operator->() noexcept { return &value_; }

  [[nodiscard]] const Status& error() const& noexcept { return status_; }
  [[nodiscard]] Status& error() & noexcept { return status_; }

  template <class U>
  [[nodiscard]] T value_or(U&& fallback) const& {
    return has_ ? value_ : static_cast<T>(std::forward<U>(fallback));
  }

 private:
  bool has_;
  T value_{};
  Status status_{};
};

class ExpectedVoid {
 public:
  ExpectedVoid() noexcept = default;
  ExpectedVoid(const Status& status) : status_(status) {}
  ExpectedVoid(Status&& status) : status_(std::move(status)) {}

  [[nodiscard]] bool has_value() const noexcept { return status_.ok(); }
  explicit operator bool() const noexcept { return status_.ok(); }
  [[nodiscard]] const Status& error() const noexcept { return status_; }

 private:
  Status status_{};
};

}  // namespace detail

template <class T>
using Result = detail::ExpectedStorage<T>;
using VoidResult = detail::ExpectedVoid;

}  // namespace vpn
