cmake_minimum_required(VERSION 3.22)

project(encsqlite_android LANGUAGES C)

option(ENCSQLITE_ANDROID_BUILD_NATIVE_BRIDGE "Build the JNI bridge target" OFF)

set(ENCSQLITE_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../..")
set(ENCSQLITE_SQLITE_VERSION_TOKEN "3510300")
set(ENCSQLITE_SQLITE_SOURCE_DIR "${ENCSQLITE_REPO_ROOT}/third_party/sqlite/${ENCSQLITE_SQLITE_VERSION_TOKEN}")

if(NOT ENCSQLITE_ANDROID_BUILD_NATIVE_BRIDGE)
  message(STATUS "Android native bridge is disabled; Kotlin sources remain buildable without JNI.")
  return()
endif()

if(NOT EXISTS "${ENCSQLITE_SQLITE_SOURCE_DIR}/sqlite3.c")
  message(FATAL_ERROR "Vendored SQLite amalgamation is missing: ${ENCSQLITE_SQLITE_SOURCE_DIR}")
endif()

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(OPENSSL_PC QUIET openssl)
  pkg_check_modules(LIBSODIUM_PC QUIET libsodium)
endif()

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

if(NOT OPENSSL_PC_FOUND OR NOT LIBSODIUM_PC_FOUND OR NOT ARGON2_INCLUDE_DIR OR NOT ARGON2_LIBRARY)
  message(WARNING "Android native bridge sources are enabled, but crypto backends are incomplete. The shared library target is skipped.")
  return()
endif()

set(ENCSQLITE_ANDROID_CORE_SOURCES
  "${ENCSQLITE_REPO_ROOT}/src/encsqlite_api.c"
  "${ENCSQLITE_REPO_ROOT}/src/encsqlite_build_info.c"
  "${ENCSQLITE_REPO_ROOT}/src/encsqlite_codec.c"
  "${ENCSQLITE_REPO_ROOT}/src/encsqlite_connection.c"
  "${ENCSQLITE_REPO_ROOT}/src/encsqlite_crypto.c"
  "${ENCSQLITE_REPO_ROOT}/src/encsqlite_page_format.c"
)

add_library(sqlite3_vendor STATIC
  "${ENCSQLITE_SQLITE_SOURCE_DIR}/sqlite3.c"
)

target_include_directories(sqlite3_vendor
  PUBLIC
    "${ENCSQLITE_SQLITE_SOURCE_DIR}"
  PRIVATE
    "${ENCSQLITE_REPO_ROOT}/include"
)

target_compile_definitions(sqlite3_vendor
  PUBLIC
    SQLITE_THREADSAFE=1
    SQLITE_TEMP_STORE=3
    SQLITE_DEFAULT_FOREIGN_KEYS=1
    SQLITE_OMIT_LOAD_EXTENSION=1
)

add_library(encsqlite_base STATIC
  ${ENCSQLITE_ANDROID_CORE_SOURCES}
)

target_include_directories(encsqlite_base
  PUBLIC
    "${ENCSQLITE_REPO_ROOT}/include"
  PRIVATE
    "${ENCSQLITE_SQLITE_SOURCE_DIR}"
)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
  target_compile_options(encsqlite_base PRIVATE -Wall -Wextra -Wpedantic)
endif()

target_link_libraries(encsqlite_base
  PUBLIC
    sqlite3_vendor
)

add_library(encsqlite_android_jni SHARED
  "${CMAKE_CURRENT_LIST_DIR}/src/main/cpp/encsqlite_jni.c"
)

target_include_directories(encsqlite_android_jni
  PRIVATE
    "${ENCSQLITE_REPO_ROOT}/include"
    "${ENCSQLITE_SQLITE_SOURCE_DIR}"
    "${CMAKE_CURRENT_LIST_DIR}/src/main/cpp"
    "${ARGON2_INCLUDE_DIR}"
    ${OPENSSL_PC_INCLUDE_DIRS}
    ${LIBSODIUM_PC_INCLUDE_DIRS}
)

target_compile_options(encsqlite_android_jni PRIVATE
  ${OPENSSL_PC_CFLAGS_OTHER}
  ${LIBSODIUM_PC_CFLAGS_OTHER}
)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
  target_compile_options(encsqlite_android_jni PRIVATE -Wall -Wextra -Wpedantic)
endif()

target_link_directories(encsqlite_android_jni PRIVATE
  ${OPENSSL_PC_LIBRARY_DIRS}
  ${LIBSODIUM_PC_LIBRARY_DIRS}
)

target_link_libraries(encsqlite_android_jni
  PRIVATE
    encsqlite_base
    ${OPENSSL_PC_LIBRARIES}
    ${LIBSODIUM_PC_LIBRARIES}
    ${ARGON2_LIBRARY}
)
