cmake_minimum_required(VERSION 3.28)

# Serialize language so the version below applies before project().
project(vpn
  VERSION 0.1.0
  DESCRIPTION "Multi-tenant, WireGuard-compatible VPN backend"
  HOMEPAGE_URL "https://example.invalid/vpn"
  LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(VPN_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(VPN_ENABLE_SANITIZERS  "Build with ASan+UBSan (debug presets only)" OFF)
option(VPN_ENABLE_COVERAGE    "Instrument for gcov/llvm-cov coverage" OFF)
option(VPN_BUILD_TESTS        "Build the unit test suite" ON)
option(VPN_BUILD_CONTROLPLANE "Build the vpnd control-plane daemon" ON)
option(VPN_BUILD_DATAPLANE    "Build the vpn-dp data-plane daemon (Linux only)" OFF)
option(VPN_USE_CXX23          "Compile in C++23 mode (enables std::expected)" ON)

set(CMAKE_CXX_STANDARD 20)
if(VPN_USE_CXX23)
  set(CMAKE_CXX_STANDARD 23)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# ---------------------------------------------------------------------------
# Global compile settings
# ---------------------------------------------------------------------------
add_compile_definitions(
  VPN_VERSION="${PROJECT_VERSION}"
  $<$<CONFIG:Debug>:VPN_DEBUG=1>
)

if(MSVC)
  add_compile_options(/W4 /permissive- /Zc:__cplusplus /utf-8)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
                      -Wcast-align -Wunused -Woverloaded-virtual -Wdouble-promotion
                      -Wformat=2 -Wimplicit-fallthrough -Wnull-dereference)
  add_compile_options(-fno-omit-frame-pointer)
  add_compile_options($<$<CONFIG:Release>:-O2>)
  # One genex per option: an unquoted argument is split on whitespace, so
  # "$<$<CONFIG:Debug>:-O0 -g3>" arrives as the two malformed tokens
  # "$<0:-O0" and "-g3>", which every compiler rejects (and which silently
  # removed the debug flags in Debug builds).
  add_compile_options($<$<CONFIG:Debug>:-O0> $<$<CONFIG:Debug>:-g3>)
endif()

if(VPN_WARNINGS_AS_ERRORS)
  if(MSVC)
    add_compile_options(/WX)
  else()
    add_compile_options(-Werror)
  endif()
endif()

if(VPN_ENABLE_COVERAGE AND NOT MSVC)
  add_compile_options(--coverage -O0 -g)
  add_link_options(--coverage)
endif()

# ---------------------------------------------------------------------------
# Sanitizers
# ---------------------------------------------------------------------------
if(VPN_ENABLE_SANITIZERS AND NOT MSVC)
  add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=undefined
                      -fno-sanitize=vptr)
  add_link_options(-fsanitize=address,undefined)
endif()

# ---------------------------------------------------------------------------
# Subprojects
# ---------------------------------------------------------------------------
if(VPN_BUILD_TESTS)
  # Must be called in the top-level directory, otherwise `ctest` in the build
  # root finds no tests (add_test in server/tests would be invisible).
  enable_testing()
endif()

add_subdirectory(server)

message(STATUS "vpn ${PROJECT_VERSION} | C++${CMAKE_CXX_STANDARD} | ${CMAKE_BUILD_TYPE}"
               " | tests=${VPN_BUILD_TESTS} | controlplane=${VPN_BUILD_CONTROLPLANE}"
               " | dataplane=${VPN_BUILD_DATAPLANE}")
