// Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
//
// Constant-time primitive gates. server/src/crypto/ct.cpp had no unit test at
// all before this file (verification report 2026-02, FINDING C-1):
// every primitive here is a place where a "clever" rewrite silently becomes a
// timing oracle, so each one gets an exhaustive small-domain truth table.
#include <cstddef>
#include <cstdint>

#include "test_support.hpp"
#include "vpn/common/bytes.hpp"
#include "vpn/crypto/ct.hpp"

namespace {

using vpn::Byte;
using vpn::ByteSpan;
using vpn::MutableByteSpan;
using namespace vpn::ct;

ByteSpan span(const Byte* p, std::size_t n) { return ByteSpan{p, n}; }

}  // namespace

TEST(ct, equal_accepts_identical_spans) {
  const Byte a[5] = {1, 2, 3, 4, 5};
  const Byte b[5] = {1, 2, 3, 4, 5};
  CHECK(equal(span(a, 5), span(b, 5)));
  CHECK(equal(ByteSpan{}, ByteSpan{}));            // empty == empty
}

TEST(ct, equal_rejects_any_single_bit_difference) {
  Byte base[32] = {};
  for (std::size_t i = 0; i < 32; ++i) base[i] = static_cast<Byte>(i * 7 + 1);
  const ByteSpan a = span(base, 32);

  for (std::size_t byte = 0; byte < 32; ++byte) {
    for (int bit = 0; bit < 8; ++bit) {
      Byte other[32];
      for (std::size_t i = 0; i < 32; ++i) other[i] = base[i];
      other[byte] = static_cast<Byte>(other[byte] ^ (1U << bit));
      CHECK_MSG(!equal(a, span(other, 32)),
                "a single flipped bit must not compare equal");
    }
  }
}

TEST(ct, equal_rejects_length_mismatch) {
  const Byte a[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  CHECK(!equal(span(a, 4), span(a, 8)));
  CHECK(!equal(span(a, 8), span(a, 4)));
  CHECK(!equal(span(a, 8), ByteSpan{}));
  // Same prefix, different length: must not be equal even though the shared
  // prefix matches (a length-insensitive comparison would say "equal").
  const Byte b[4] = {0, 0, 0, 0};
  CHECK(!equal(span(a, 8), span(b, 4)));
}

TEST(ct, equal_handles_zero_filled_spans) {
  // diff == 0 is the interesting case for the (diff - 1) >> 31 fold: it relies
  // on the 0 -> 0xFFFFFFFF unsigned wrap.
  const Byte zeros[16] = {};
  CHECK(equal(span(zeros, 16), span(zeros, 16)));
  const Byte ones[16] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
  CHECK(!equal(span(zeros, 16), span(ones, 16)));
}

TEST(ct, is_nonzero_u8_truth_table) {
  CHECK_EQ(static_cast<unsigned>(is_nonzero_u8(0)), 0x00U);
  CHECK_EQ(static_cast<unsigned>(is_nonzero_u8(1)), 0xFFU);
  CHECK_EQ(static_cast<unsigned>(is_nonzero_u8(2)), 0xFFU);
  CHECK_EQ(static_cast<unsigned>(is_nonzero_u8(0x80U)), 0xFFU);
  CHECK_EQ(static_cast<unsigned>(is_nonzero_u8(0x7FFFFFFFU)), 0xFFU);
  CHECK_EQ(static_cast<unsigned>(is_nonzero_u8(0x80000000U)), 0xFFU);
  CHECK_EQ(static_cast<unsigned>(is_nonzero_u8(0xFFFFFFFFU)), 0xFFU);
  // Exhaustive over the byte range (each byte value in a 32-bit word).
  for (std::uint32_t v = 0; v < 256; ++v) {
    const std::uint8_t expected = v == 0 ? 0x00 : 0xFF;
    CHECK_EQ(static_cast<unsigned>(is_nonzero_u8(v)),
             static_cast<unsigned>(expected));
  }
}

TEST(ct, cleanse_zeroes_exactly_the_requested_span) {
  Byte buf[16];
  for (std::size_t i = 0; i < 16; ++i) buf[i] = 0xAA;
  cleanse(MutableByteSpan{buf + 4, 8});
  for (std::size_t i = 0; i < 4; ++i) CHECK_EQ(buf[i], Byte{0xAA});
  for (std::size_t i = 4; i < 12; ++i) CHECK_EQ(buf[i], Byte{0x00});
  for (std::size_t i = 12; i < 16; ++i) CHECK_EQ(buf[i], Byte{0xAA});
  cleanse(MutableByteSpan{});  // must be a no-op, not UB
  CHECK_EQ(buf[0], Byte{0xAA});
}

TEST(ct, select_stays_within_the_shortest_span) {
  // Documented precondition: equally sized spans. With unequal spans the
  // implementation clamps to min(dst, a, b); the only property we may assert
  // unconditionally is that it neither over-reads nor over-writes.
  // (What it *writes* under an unequal-span precondition is unspecified.)
  const Byte a[4] = {1, 1, 1, 1};
  const Byte b[2] = {2, 2};
  Byte dst[4] = {0xEE, 0xEE, 0xEE, 0xEE};
  select(MutableByteSpan{dst, 4}, span(a, 4), span(b, 2), false);
  CHECK_EQ(dst[2], Byte{0xEE});  // untouched: beyond min(a, b)
  CHECK_EQ(dst[3], Byte{0xEE});
  select(MutableByteSpan{dst, 4}, span(a, 2), span(b, 4), true);
  CHECK_EQ(dst[2], Byte{0xEE});
  CHECK_EQ(dst[3], Byte{0xEE});
}

// ---------------------------------------------------------------------------
// ct::select contract (FINDING C-1, fixed in src/crypto/ct.cpp):
//   dst = cond ? a : b
// These were previously compiled out behind a "known bug" define; the defect is
// fixed, so the contract is asserted unconditionally and a regression fails the
// default gate.
// ---------------------------------------------------------------------------
TEST(ct, select_honours_the_documented_contract) {
  const Byte a[4] = {0xA0, 0xA1, 0xA2, 0xA3};
  const Byte b[4] = {0xB0, 0xB1, 0xB2, 0xB3};
  Byte dst[4] = {};

  select(MutableByteSpan{dst, 4}, span(a, 4), span(b, 4), true);
  CHECK(vpn::equals(span(dst, 4), span(a, 4)));

  select(MutableByteSpan{dst, 4}, span(a, 4), span(b, 4), false);
  CHECK(vpn::equals(span(dst, 4), span(b, 4)));
}

TEST(ct, select_is_a_full_byte_mask) {
  const Byte a[8] = {0x00, 0xFF, 0x55, 0xAA, 0x0F, 0xF0, 0x01, 0x80};
  const Byte b[8] = {0xFF, 0x00, 0xAA, 0x55, 0xF0, 0x0F, 0x80, 0x01};
  Byte dst[8] = {};

  select(MutableByteSpan{dst, 8}, span(a, 8), span(b, 8), true);
  CHECK(vpn::equals(span(dst, 8), span(a, 8)));
  select(MutableByteSpan{dst, 8}, span(a, 8), span(b, 8), false);
  CHECK(vpn::equals(span(dst, 8), span(b, 8)));
}

TEST(ct, select_is_identity_when_both_inputs_are_equal) {
  const Byte a[4] = {0x11, 0x22, 0x33, 0x44};
  Byte dst[4] = {};
  select(MutableByteSpan{dst, 4}, span(a, 4), span(a, 4), true);
  CHECK(vpn::equals(span(dst, 4), span(a, 4)));
  select(MutableByteSpan{dst, 4}, span(a, 4), span(a, 4), false);
  CHECK(vpn::equals(span(dst, 4), span(a, 4)));
}
