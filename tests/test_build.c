#include <assert.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "encsqlite/encsqlite_build_info.h"

static int count_rows(void *out, int argc, char **argv, char **col_names) {
  (void)argc;
  (void)col_names;
  if (argv[0] == NULL) {
    return SQLITE_ERROR;
  }
  *(int *)out = atoi(argv[0]);
  return SQLITE_OK;
}

static void smoke_test_sqlite(void) {
  sqlite3 *db = NULL;
  char *error_message = NULL;
  int rc = sqlite3_open(":memory:", &db);
  assert(rc == SQLITE_OK);
  assert(db != NULL);

  rc = sqlite3_exec(db,
                    "CREATE TABLE t(id INTEGER PRIMARY KEY, value TEXT);"
                    "INSERT INTO t(value) VALUES ('ok');",
                    NULL,
                    NULL,
                    &error_message);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_exec failed: %s\n", error_message ? error_message : "(null)");
    sqlite3_free(error_message);
  }
  assert(rc == SQLITE_OK);

  int row_count = 0;
  rc = sqlite3_exec(db, "SELECT count(*) FROM t;", count_rows, &row_count, &error_message);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "count query failed: %s\n", error_message ? error_message : "(null)");
    sqlite3_free(error_message);
  }
  assert(rc == SQLITE_OK);
  assert(row_count == 1);

  rc = sqlite3_close(db);
  assert(rc == SQLITE_OK);
}

static void check_build_info(void) {
  assert(strcmp(encsqlite_build_sqlite_version(), SQLITE_VERSION) == 0);
  assert(encsqlite_build_sqlite_version_number() == SQLITE_VERSION_NUMBER);
  assert(strcmp(encsqlite_build_sqlite_source_id(), SQLITE_SOURCE_ID) == 0);
  assert(strcmp(encsqlite_build_sqlite_import_method(), "vendored amalgamation (sqlite-amalgamation-3510300.zip)") == 0);
}

int main(void) {
  check_build_info();
  smoke_test_sqlite();
  return 0;
}
