#!/usr/bin/env python3
# Copyright 2026 The vpn authors. SPDX-License-Identifier: Apache-2.0
"""Fail if a source file uses std::uintN_t / std::intN_t without including <cstdint>.

Why this exists: libc++ (what `zig c++` ships, and what the local cross-compile gate
uses) transitively includes <cstdint> from <string> and <cstring>. libstdc++ (what
gcc-13 in CI uses) does not. So `std::uint16_t` compiles here and fails there with
"`uint16_t` in namespace 'std' does not name a type", plus a cascade of confusing
"has no member named 'port'" errors in every struct that used it.

That is exactly what broke the gcc-13 release job. Requiring a direct include is the
only portable answer: <cstdint> guarantees these names, transitive includes never do.

  python scripts/check_includes.py            # exit 1 on any finding
"""
import pathlib
import re
import sys

TYPE_USE = re.compile(r"\bstd::(?:u?int(?:8|16|32|64)_t)\b")
HAS_CSTDINT = re.compile(r"^\s*#\s*include\s*<cstdint>", re.MULTILINE)
ROOT = pathlib.Path(__file__).resolve().parent.parent
SEARCH = ("server/src", "server/cli", "server/include")


def main() -> int:
    findings = []
    for directory in SEARCH:
        for path in sorted((ROOT / directory).rglob("*")):
            if path.suffix not in (".cpp", ".hpp"):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if TYPE_USE.search(text) and not HAS_CSTDINT.search(text):
                findings.append(path.relative_to(ROOT).as_posix())
    if findings:
        print("error: these files use std::int*_t/std::uint*_t without #include <cstdint>:")
        for name in findings:
            print(f"  {name}")
        print("\nlibc++ hides the omission; libstdc++ (gcc in CI) does not.")
        return 1
    print(f"ok: every file using std::int*/std::uint* includes <cstdint>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
