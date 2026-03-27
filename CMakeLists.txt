cmake_minimum_required(VERSION 3.22)

project(encryp_base VERSION 0.1.0 LANGUAGES C)

include(CTest)
find_package(PkgConfig REQUIRED)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(ENCSQLITE_SQLITE_VERSION_TOKEN "3510300")
set(ENCSQLITE_SQLITE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/sqlite/${ENCSQLITE_SQLITE_VERSION_TOKEN}")

pkg_check_modules(OPENSSL_PC REQUIRED IMPORTED_TARGET openssl)
pkg_check_modules(LIBSODIUM_PC REQUIRED IMPORTED_TARGET libsodium)
find_path(ARGON2_INCLUDE_DIR
  NAMES argon2.h
  HINTS
    /opt/homebrew/include
    /usr/local/include
)
find_library(ARGON2_LIBRARY
  NAMES argon2
  HINTS
    /opt/homebrew/lib
    /usr/local/lib
)

if(NOT EXISTS "${ENCSQLITE_SQLITE_SOURCE_DIR}/sqlite3.c")
  message(FATAL_ERROR "Vendored SQLite amalgamation is missing: ${ENCSQLITE_SQLITE_SOURCE_DIR}")
endif()
if(NOT ARGON2_INCLUDE_DIR OR NOT ARGON2_LIBRARY)
  message(FATAL_ERROR "Argon2 development files are missing. Install the argon2 package.")
endif()

add_library(encsqlite_base STATIC
  src/encsqlite_build_info.c
  src/encsqlite_api.c
  src/encsqlite_codec.c
  src/encsqlite_connection.c
  src/encsqlite_crypto.c
  src/encsqlite_page_format.c
)

target_include_directories(encsqlite_base
  PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
  PRIVATE
    "${ENCSQLITE_SQLITE_SOURCE_DIR}"
    "${ARGON2_INCLUDE_DIR}"
)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
  target_compile_options(encsqlite_base PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_library(sqlite3_vendor STATIC
  "${ENCSQLITE_SQLITE_SOURCE_DIR}/sqlite3.c"
)

target_include_directories(sqlite3_vendor
  PUBLIC
    "${ENCSQLITE_SQLITE_SOURCE_DIR}"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_compile_definitions(sqlite3_vendor
  PUBLIC
    SQLITE_THREADSAFE=1
    SQLITE_TEMP_STORE=3
    SQLITE_DEFAULT_FOREIGN_KEYS=1
    SQLITE_OMIT_LOAD_EXTENSION=1
)

target_link_libraries(encsqlite_base
  PUBLIC
    sqlite3_vendor
    PkgConfig::OPENSSL_PC
    PkgConfig::LIBSODIUM_PC
    "${ARGON2_LIBRARY}"
)

if(BUILD_TESTING)
  add_executable(encsqlite_smoke_test
    tests/test_build.c
  )

  add_executable(encsqlite_crypto_test
    tests/test_crypto.c
  )

  add_executable(encsqlite_codec_test
    tests/test_codec.c
  )

  add_executable(encsqlite_connection_test
    tests/test_connection.c
  )

  add_executable(encsqlite_api_test
    tests/test_api.c
  )

  add_executable(encsqlite_differential_test
    tests/test_differential.c
  )

  add_executable(encsqlite_corruption_test
    tests/test_corruption.c
  )

  add_executable(encsqlite_benchmark
    tests/test_benchmark.c
  )

  add_executable(encsqlite_policy_test
    tests/test_policy.c
  )

  add_executable(encsqlite_page_format_test
    tests/test_page_format.c
  )

  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    target_compile_options(encsqlite_smoke_test PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(encsqlite_crypto_test PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(encsqlite_codec_test PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(encsqlite_connection_test PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(encsqlite_api_test PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(encsqlite_differential_test PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(encsqlite_corruption_test PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(encsqlite_benchmark PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(encsqlite_policy_test PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(encsqlite_page_format_test PRIVATE -Wall -Wextra -Wpedantic)
  endif()

  target_link_libraries(encsqlite_smoke_test
    PRIVATE
      encsqlite_base
  )

  target_link_libraries(encsqlite_crypto_test
    PRIVATE
      encsqlite_base
  )

  target_link_libraries(encsqlite_codec_test
    PRIVATE
      encsqlite_base
  )

  target_link_libraries(encsqlite_connection_test
    PRIVATE
      encsqlite_base
  )

  target_link_libraries(encsqlite_api_test
    PRIVATE
      encsqlite_base
  )

  target_link_libraries(encsqlite_differential_test
    PRIVATE
      encsqlite_base
  )

  target_link_libraries(encsqlite_corruption_test
    PRIVATE
      encsqlite_base
  )

  target_link_libraries(encsqlite_benchmark
    PRIVATE
      encsqlite_base
  )

  target_link_libraries(encsqlite_policy_test
    PRIVATE
      encsqlite_base
  )

  target_link_libraries(encsqlite_page_format_test
    PRIVATE
      encsqlite_base
  )

  add_test(NAME encsqlite_smoke_test COMMAND encsqlite_smoke_test)
  add_test(NAME encsqlite_crypto_test COMMAND encsqlite_crypto_test)
  add_test(NAME encsqlite_codec_test COMMAND encsqlite_codec_test)
  add_test(NAME encsqlite_connection_test COMMAND encsqlite_connection_test)
  add_test(NAME encsqlite_api_test COMMAND encsqlite_api_test)
  add_test(NAME encsqlite_differential_test COMMAND encsqlite_differential_test)
  add_test(NAME encsqlite_corruption_test COMMAND encsqlite_corruption_test)
  add_test(NAME encsqlite_benchmark COMMAND encsqlite_benchmark)
  add_test(NAME encsqlite_policy_test COMMAND encsqlite_policy_test)
  add_test(NAME encsqlite_page_format_test COMMAND encsqlite_page_format_test)
endif()
