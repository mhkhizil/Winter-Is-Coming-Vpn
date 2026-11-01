# vpn server - libraries and executables.
#
# Layering (enforced by review, see docs/ARCHITECTURE.md):
#   vpn_core      : pure, dependency-free logic (crypto primitives, wire codec,
#                   config, metrics). No sockets, no threads, no globals.
#   vpnd          : control-plane process; owns sockets, signals, lifecycle.
#   vpn-dp        : data-plane process (M2); must never link the control plane.

add_library(vpn_core STATIC
  src/common/endpoint.cpp
  src/common/log.cpp
  src/crypto/blake2s.cpp
  src/crypto/chacha20poly1305.cpp
  src/crypto/ct.cpp
  src/crypto/kdf.cpp
  src/crypto/random.cpp
  src/crypto/x25519.cpp
  src/wire/message.cpp
  src/wire/noise.cpp
  src/wire/replay_window.cpp
  src/config/config.cpp
  src/obs/metrics.cpp
)

target_include_directories(vpn_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_features(vpn_core PUBLIC cxx_std_20)

# BCryptGenRandom is the CSPRNG behind vpn::crypto::fill_random on Windows.
if(WIN32)
  target_link_libraries(vpn_core PUBLIC bcrypt)
endif()
set_target_properties(vpn_core PROPERTIES
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN ON)

if(VPN_BUILD_CONTROLPLANE)
  add_executable(vpnd
    src/controlplane/main.cpp
    src/controlplane/http_server.cpp)
  target_link_libraries(vpnd PRIVATE vpn_core)

  if(WIN32)
    target_link_libraries(vpnd PRIVATE ws2_32)
  else()
    find_package(Threads REQUIRED)
    target_link_libraries(vpnd PRIVATE Threads::Threads)
  endif()

  # PIE + full RELRO on ELF; the release pipeline additionally strips and signs.
  if(UNIX AND NOT APPLE)
    target_link_options(vpnd PRIVATE -Wl,-z,relro,-z,now)
  endif()
endif()

if(VPN_BUILD_DATAPLANE)
  add_executable(vpn-dp src/dataplane/main.cpp)
  target_link_libraries(vpn-dp PRIVATE vpn_core)
  if(WIN32)
    target_link_libraries(vpn-dp PRIVATE ws2_32)
  else()
    find_package(Threads REQUIRED)
    target_link_libraries(vpn-dp PRIVATE Threads::Threads)
    if(UNIX AND NOT APPLE)
      target_link_options(vpn-dp PRIVATE -Wl,-z,relro,-z,now)
    endif()
  endif()
endif()

if(VPN_BUILD_TESTS)
  add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Developer tooling targets (format / format-check / lint)
# ---------------------------------------------------------------------------
find_program(VPN_CLANG_FORMAT NAMES clang-format clang-format-19 clang-format-18
             clang-format-17 clang-format-16)
if(VPN_CLANG_FORMAT)
  file(GLOB_RECURSE VPN_FORMAT_FILES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.hpp")

  add_custom_target(format
    COMMAND "${VPN_CLANG_FORMAT}" -i --style=file ${VPN_FORMAT_FILES}
    COMMENT "clang-format (in place)"
    VERBATIM)

  add_custom_target(format-check
    COMMAND "${VPN_CLANG_FORMAT}" --dry-run --Werror --style=file ${VPN_FORMAT_FILES}
    COMMENT "clang-format (check only)"
    VERBATIM)
else()
  add_custom_target(format
    COMMAND ${CMAKE_COMMAND} -E echo "clang-format not found; skipping")
  add_custom_target(format-check
    COMMAND ${CMAKE_COMMAND} -E echo "clang-format not found; skipping")
endif()

find_program(VPN_CLANG_TIDY NAMES clang-tidy clang-tidy-18 clang-tidy-17)
# NOTE: the variable must be expanded as ${VPN_CLANG_TIDY}. A literal "$(" in a
# COMMAND is not a valid Ninja escape: cmake writes it verbatim and the generated
# build.ninja fails to parse ("bad $-escape"), which breaks every target.
if(VPN_CLANG_TIDY)
  add_custom_target(lint
    COMMAND ${CMAKE_COMMAND} -E echo "lint: run '${VPN_CLANG_TIDY}' via CI; see docs/CPP_CONVENTIONS.md"
    COMMENT "clang-tidy is executed in CI (needs compile_commands.json)"
    VERBATIM)
else()
  add_custom_target(lint
    COMMAND ${CMAKE_COMMAND} -E echo "clang-tidy not found; skipping")
endif()
