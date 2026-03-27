#include <sqlite3.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "encsqlite/api.h"

typedef struct {
  int id;
  char name[32];
  int qty;
} parent_row;

typedef struct {
  int id;
  int parent_id;
  char note[32];
} child_row;

static void fail(const char *message) {
  fprintf(stderr, "%s\n", message);
  abort();
}

static void check_true(int condition, const char *message) {
  if (!condition) {
    fail(message);
  }
}

static void check_sqlite_ok(int rc, const char *message) {
  if (rc != SQLITE_OK) {
    fail(message);
  }
}

static void fill_sequence(uint8_t *buffer, size_t len, uint8_t base) {
  for (size_t i = 0; i < len; ++i) {
    buffer[i] = (uint8_t)(base + i);
  }
}

static void make_temp_path(char *path, size_t path_len, const char *suffix) {
  int fd;

  snprintf(path, path_len, "/tmp/encryp-base-diff-%s-XXXXXX", suffix);
  fd = mkstemp(path);
  if (fd < 0) {
    fail("mkstemp failed");
  }
  close(fd);
  unlink(path);
}

static int exec_sql(sqlite3 *db, const char *sql) {
  char *error_message = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &error_message);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_exec failed: %s\n", error_message ? error_message : "(null)");
    sqlite3_free(error_message);
  }
  return rc;
}

static int query_int(sqlite3 *db, const char *sql, int *out_value) {
  sqlite3_stmt *stmt = NULL;
  int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    return rc;
  }

  rc = sqlite3_step(stmt);
  if (rc == SQLITE_ROW) {
    *out_value = sqlite3_column_int(stmt, 0);
    rc = SQLITE_OK;
  }

  sqlite3_finalize(stmt);
  return rc;
}

static void copy_sql_text(char *dest, size_t dest_len, const unsigned char *text) {
  if (text == NULL) {
    fail("sqlite text column was null");
  }
  snprintf(dest, dest_len, "%s", text);
}

static void collect_parent_rows(sqlite3 *db, parent_row *rows, size_t max_rows, size_t *out_count) {
  sqlite3_stmt *stmt = NULL;
  int rc = sqlite3_prepare_v2(db, "SELECT id, name, qty FROM parent ORDER BY id;", -1, &stmt, NULL);
  size_t count = 0;

  if (rc != SQLITE_OK) {
    fail("prepare parent query failed");
  }

  while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
    const unsigned char *name = sqlite3_column_text(stmt, 1);

    check_true(count < max_rows, "parent row buffer overflow");
    rows[count].id = sqlite3_column_int(stmt, 0);
    copy_sql_text(rows[count].name, sizeof(rows[count].name), name);
    rows[count].qty = sqlite3_column_int(stmt, 2);
    count++;
  }

  if (rc != SQLITE_DONE) {
    sqlite3_finalize(stmt);
    fail("parent row query failed");
  }

  sqlite3_finalize(stmt);
  *out_count = count;
}

static void collect_child_rows(sqlite3 *db, child_row *rows, size_t max_rows, size_t *out_count) {
  sqlite3_stmt *stmt = NULL;
  int rc = sqlite3_prepare_v2(db, "SELECT id, parent_id, note FROM child ORDER BY id;", -1, &stmt, NULL);
  size_t count = 0;

  if (rc != SQLITE_OK) {
    fail("prepare child query failed");
  }

  while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
    const unsigned char *note = sqlite3_column_text(stmt, 2);

    check_true(count < max_rows, "child row buffer overflow");
    rows[count].id = sqlite3_column_int(stmt, 0);
    rows[count].parent_id = sqlite3_column_int(stmt, 1);
    copy_sql_text(rows[count].note, sizeof(rows[count].note), note);
    count++;
  }

  if (rc != SQLITE_DONE) {
    sqlite3_finalize(stmt);
    fail("child row query failed");
  }

  sqlite3_finalize(stmt);
  *out_count = count;
}

static void compare_parent_rows(const parent_row *lhs, const parent_row *rhs, size_t count) {
  for (size_t i = 0; i < count; ++i) {
    if (lhs[i].id != rhs[i].id ||
        lhs[i].qty != rhs[i].qty ||
        strcmp(lhs[i].name, rhs[i].name) != 0) {
      fail("parent row mismatch");
    }
  }
}

static void compare_child_rows(const child_row *lhs, const child_row *rhs, size_t count) {
  for (size_t i = 0; i < count; ++i) {
    if (lhs[i].id != rhs[i].id ||
        lhs[i].parent_id != rhs[i].parent_id ||
        strcmp(lhs[i].note, rhs[i].note) != 0) {
      fail("child row mismatch");
    }
  }
}

static void run_workload(sqlite3 *db) {
  int rc = exec_sql(
      db,
      "CREATE TABLE parent(id INTEGER PRIMARY KEY, name TEXT NOT NULL, qty INTEGER NOT NULL);"
      "CREATE TABLE child("
      "  id INTEGER PRIMARY KEY,"
      "  parent_id INTEGER NOT NULL REFERENCES parent(id),"
      "  note TEXT NOT NULL"
      ");"
      "INSERT INTO parent(id, name, qty) VALUES"
      "  (1, 'alpha', 10),"
      "  (2, 'beta', 20),"
      "  (3, 'gamma', 30);"
      "INSERT INTO child(id, parent_id, note) VALUES"
      "  (1, 1, 'one'),"
      "  (2, 1, 'two'),"
      "  (3, 2, 'three');"
      "BEGIN IMMEDIATE;"
      "UPDATE parent SET qty = qty + 5 WHERE id IN (1, 3);"
      "DELETE FROM child WHERE id = 2;"
      "INSERT INTO parent(id, name, qty) VALUES (4, 'delta', 40);"
      "INSERT INTO child(id, parent_id, note) VALUES (4, 4, 'four');"
      "COMMIT;"
      "BEGIN;"
      "INSERT INTO parent(id, name, qty) VALUES (5, 'rollback', 50);"
      "INSERT INTO child(id, parent_id, note) VALUES (5, 5, 'rollback');"
      "ROLLBACK;"
      "CREATE INDEX idx_parent_qty ON parent(qty);");
  check_sqlite_ok(rc, "workload execution failed");
}

static void checkpoint_plain(sqlite3 *db) {
  char *error_message = NULL;
  int rc = sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE);", NULL, NULL, &error_message);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "wal checkpoint failed: %s\n", error_message ? error_message : "(null)");
    sqlite3_free(error_message);
  }
  check_sqlite_ok(rc, "plain wal checkpoint failed");
}

static void close_plain(sqlite3 *db) {
  int rc = sqlite3_close(db);
  check_sqlite_ok(rc, "sqlite3_close failed");
}

static void remove_sqlite_sidecars(const char *path) {
  char wal_path[256];
  char shm_path[256];
  char journal_path[256];

  snprintf(wal_path, sizeof(wal_path), "%s-wal", path);
  snprintf(shm_path, sizeof(shm_path), "%s-shm", path);
  snprintf(journal_path, sizeof(journal_path), "%s-journal", path);
  unlink(wal_path);
  unlink(shm_path);
  unlink(journal_path);
}

static void test_plain_and_encrypted_workloads_match(void) {
  char plain_path[128];
  char encrypted_path[128];
  sqlite3 *plain_db = NULL;
  encsqlite_connection *encrypted_connection = NULL;
  sqlite3 *encrypted_db = NULL;
  sqlite3 *plain_reopen_db = NULL;
  encsqlite_connection *encrypted_reopen_connection = NULL;
  sqlite3 *encrypted_reopen_db = NULL;
  encsqlite_key_material key_material;
  encsqlite_open_options options;
  uint8_t raw_secret[ENCSQLITE_CODEC_KEY_BYTES];
  parent_row plain_parent_rows[8];
  parent_row encrypted_parent_rows[8];
  child_row plain_child_rows[8];
  child_row encrypted_child_rows[8];
  size_t plain_parent_count = 0;
  size_t encrypted_parent_count = 0;
  size_t plain_child_count = 0;
  size_t encrypted_child_count = 0;
  int value = -1;
  int rc;

  make_temp_path(plain_path, sizeof(plain_path), "plain");
  make_temp_path(encrypted_path, sizeof(encrypted_path), "encrypted");

  fill_sequence(raw_secret, sizeof(raw_secret), 0x11);
  key_material.type = ENCSQLITE_KEY_RAW_32;
  key_material.data = raw_secret;
  key_material.data_len = sizeof(raw_secret);

  options.create_if_missing = 1;
  options.read_only = 0;
  options.expect_application_id = 1;
  options.application_id = 0x454E4353U;
  options.journal_mode_wal = 1;

  rc = sqlite3_open(plain_path, &plain_db);
  check_sqlite_ok(rc, "plain sqlite3_open failed");
  check_true(plain_db != NULL, "plain db missing");
  run_workload(plain_db);
  rc = query_int(plain_db, "SELECT COUNT(*) FROM parent;", &value);
  check_sqlite_ok(rc, "plain parent count query failed");
  check_true(value == 4, "plain parent count mismatch");
  rc = query_int(plain_db, "SELECT SUM(qty) FROM parent;", &value);
  check_sqlite_ok(rc, "plain parent sum query failed");
  check_true(value == 110, "plain parent sum mismatch");
  checkpoint_plain(plain_db);
  close_plain(plain_db);
  plain_db = NULL;

  rc = encsqlite_open_v2(&encrypted_connection, encrypted_path, &key_material, &options);
  check_sqlite_ok(rc, "encrypted open failed");
  check_true(encrypted_connection != NULL, "encrypted connection missing");
  encrypted_db = encsqlite_connection_sqlite3(encrypted_connection);
  check_true(encrypted_db != NULL, "encrypted sqlite handle missing");
  run_workload(encrypted_db);
  rc = query_int(encrypted_db, "SELECT COUNT(*) FROM parent;", &value);
  check_sqlite_ok(rc, "encrypted parent count query failed");
  check_true(value == 4, "encrypted parent count mismatch");
  rc = query_int(encrypted_db, "SELECT SUM(qty) FROM parent;", &value);
  check_sqlite_ok(rc, "encrypted parent sum query failed");
  check_true(value == 110, "encrypted parent sum mismatch");
  rc = encsqlite_checkpoint(encrypted_connection, 1);
  check_sqlite_ok(rc, "encrypted checkpoint failed");
  rc = encsqlite_close_secure(encrypted_connection);
  check_sqlite_ok(rc, "encrypted close failed");
  encrypted_connection = NULL;

  rc = sqlite3_open(plain_path, &plain_reopen_db);
  check_sqlite_ok(rc, "plain reopen failed");
  check_true(plain_reopen_db != NULL, "plain reopen db missing");

  rc = encsqlite_open_v2(&encrypted_reopen_connection, encrypted_path, &key_material, &options);
  check_sqlite_ok(rc, "encrypted reopen failed");
  check_true(encrypted_reopen_connection != NULL, "encrypted reopen connection missing");
  encrypted_reopen_db = encsqlite_connection_sqlite3(encrypted_reopen_connection);
  check_true(encrypted_reopen_db != NULL, "encrypted reopen sqlite handle missing");

  memset(plain_parent_rows, 0, sizeof(plain_parent_rows));
  memset(encrypted_parent_rows, 0, sizeof(encrypted_parent_rows));
  memset(plain_child_rows, 0, sizeof(plain_child_rows));
  memset(encrypted_child_rows, 0, sizeof(encrypted_child_rows));

  collect_parent_rows(plain_reopen_db, plain_parent_rows, 8, &plain_parent_count);
  collect_parent_rows(encrypted_reopen_db, encrypted_parent_rows, 8, &encrypted_parent_count);
  collect_child_rows(plain_reopen_db, plain_child_rows, 8, &plain_child_count);
  collect_child_rows(encrypted_reopen_db, encrypted_child_rows, 8, &encrypted_child_count);

  check_true(plain_parent_count == encrypted_parent_count, "parent row count mismatch");
  check_true(plain_child_count == encrypted_child_count, "child row count mismatch");
  compare_parent_rows(plain_parent_rows, encrypted_parent_rows, plain_parent_count);
  compare_child_rows(plain_child_rows, encrypted_child_rows, plain_child_count);

  rc = sqlite3_close(plain_reopen_db);
  check_sqlite_ok(rc, "plain reopen close failed");
  rc = encsqlite_close_secure(encrypted_reopen_connection);
  check_sqlite_ok(rc, "encrypted reopen close failed");

  unlink(plain_path);
  unlink(encrypted_path);
  remove_sqlite_sidecars(plain_path);
  remove_sqlite_sidecars(encrypted_path);
}

int main(void) {
  test_plain_and_encrypted_workloads_match();
  return 0;
}
