#include "encsqlite/encsqlite_build_info.h"

#include "sqlite3.h"

const char *encsqlite_build_sqlite_version(void) {
  return SQLITE_VERSION;
}

int encsqlite_build_sqlite_version_number(void) {
  return SQLITE_VERSION_NUMBER;
}

const char *encsqlite_build_sqlite_source_id(void) {
  return SQLITE_SOURCE_ID;
}

const char *encsqlite_build_sqlite_import_method(void) {
  return "vendored amalgamation (sqlite-amalgamation-3510300.zip)";
}
