cmake_minimum_required(VERSION 3.22)

project(encryp_base VERSION 0.1.0 LANGUAGES C)

include(CTest)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(ENCSQLITE_SQLITE_VERSION_TOKEN "3510300")
set(ENCSQLITE_SQLITE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/sqlite/${ENCSQLITE_SQLITE_VERSION_TOKEN}")

if(NOT EXISTS "${ENCSQLITE_SQLITE_SOURCE_DIR}/sqlite3.c")
  message(FATAL_ERROR "Vendored SQLite amalgamation is missing: ${ENCSQLITE_SQLITE_SOURCE_DIR}")
endif()

add_library(encsqlite_base STATIC
  src/encsqlite_build_info.c
)

target_include_directories(encsqlite_base
  PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
  PRIVATE
    "${ENCSQLITE_SQLITE_SOURCE_DIR}"
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
)

if(BUILD_TESTING)
  add_executable(encsqlite_smoke_test
    tests/test_build.c
  )

  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    target_compile_options(encsqlite_smoke_test PRIVATE -Wall -Wextra -Wpedantic)
  endif()

  target_link_libraries(encsqlite_smoke_test
    PRIVATE
      encsqlite_base
  )

  add_test(NAME encsqlite_smoke_test COMMAND encsqlite_smoke_test)
endif()
