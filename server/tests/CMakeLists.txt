# Unit tests for the dependency-free core.
#
# One binary, zero third-party dependencies: a fresh clone can run the whole
# suite offline, which is what makes the CI gate fast and trustworthy.

add_executable(vpn_unit_tests
  unit/test_main.cpp
  unit/test_aead.cpp
  unit/test_blake2s.cpp
  unit/test_wire_message.cpp
  unit/test_replay_window.cpp
  unit/test_ct.cpp
  unit/test_config.cpp
  unit/test_kdf.cpp
  unit/test_metrics.cpp)

target_link_libraries(vpn_unit_tests PRIVATE vpn_core)
target_include_directories(vpn_unit_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/unit")

if(NOT WIN32)
  find_package(Threads REQUIRED)
  target_link_libraries(vpn_unit_tests PRIVATE Threads::Threads)
endif()

add_test(NAME vpn_unit_tests COMMAND vpn_unit_tests)

# Timeout so a hung test cannot wedge CI.
set_tests_properties(vpn_unit_tests PROPERTIES TIMEOUT 120)

# The HTTP server is compiled into `vpnd`, not into a library, so its tests build
# their own binary from the same source file. Keeping them separate preserves the
# "vpn_unit_tests has no sockets" property of the core suite.
if(VPN_BUILD_CONTROLPLANE)
  add_executable(vpn_http_tests
    unit/test_main.cpp
    unit/test_http_server.cpp
    ../src/controlplane/http_server.cpp)

  target_link_libraries(vpn_http_tests PRIVATE vpn_core)
  target_include_directories(vpn_http_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/unit")

  if(WIN32)
    target_link_libraries(vpn_http_tests PRIVATE ws2_32)
  else()
    find_package(Threads REQUIRED)
    target_link_libraries(vpn_http_tests PRIVATE Threads::Threads)
  endif()

  add_test(NAME vpn_http_tests COMMAND vpn_http_tests)
  set_tests_properties(vpn_http_tests PROPERTIES TIMEOUT 120)
endif()

if(VPN_ENABLE_COVERAGE)
  add_custom_target(coverage
    COMMAND gcovr --root "${CMAKE_SOURCE_DIR}" --filter "${CMAKE_SOURCE_DIR}/server/src"
            --print-summary --xml-pretty -o "${CMAKE_BINARY_DIR}/coverage.xml"
    DEPENDS vpn_unit_tests
    COMMENT "gcovr coverage report")
endif()
