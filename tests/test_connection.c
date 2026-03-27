#include <sqlite3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "encsqlite/connection.h"

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

static void make_temp_path(char *path, size_t path_len) {
  int fd;

  snprintf(path, path_len, "/tmp/encryp-base-connection-XXXXXX");
  fd = mkstemp(path);
  if (fd < 0) {
    fail("mkstemp failed");
  }
  close(fd);
  unlink(path);
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

static int query_text(sqlite3 *db, const char *sql, char *buffer, size_t buffer_len) {
  sqlite3_stmt *stmt = NULL;
  int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    return rc;
  }

  rc = sqlite3_step(stmt);
  if (rc == SQLITE_ROW) {
    const unsigned char *text = sqlite3_column_text(stmt, 0);
    if (text == NULL) {
      sqlite3_finalize(stmt);
      return SQLITE_ERROR;
    }
    snprintf(buffer, buffer_len, "%s", text);
    rc = SQLITE_OK;
  }

  sqlite3_finalize(stmt);
  return rc;
}

static void test_connection_policy(void) {
  char path[128];
  encsqlite_connection *connection = NULL;
  sqlite3 *db = NULL;
  encsqlite_key_material key_material;
  encsqlite_open_options options;
  uint8_t raw_secret[ENCSQLITE_CODEC_KEY_BYTES];
  char *error_message = NULL;
  int rc;
  int value = -1;
  char text[32];

  make_temp_path(path, sizeof(path));
  fill_sequence(raw_secret, sizeof(raw_secret), 0x11);
  key_material.type = ENCSQLITE_KEY_RAW_32;
  key_material.data = raw_secret;
  key_material.data_len = sizeof(raw_secret);
  options.create_if_missing = 1;
  options.read_only = 0;
  options.expect_application_id = 1;
  options.application_id = 0x454E4353U;
  options.journal_mode_wal = 1;

  rc = encsqlite_open_v2(&connection, path, &key_material, &options);
  check_sqlite_ok(rc, "encsqlite_open_v2 failed");
  check_true(connection != NULL, "connection missing");

  db = encsqlite_connection_sqlite3(connection);
  check_true(db != NULL, "sqlite handle missing");
  check_true(encsqlite_connection_codec(connection) != NULL, "codec context missing");

  rc = sqlite3_exec(
      db,
      "CREATE TABLE t(id INTEGER PRIMARY KEY, value TEXT);"
      "INSERT INTO t(value) VALUES ('ok');",
      NULL,
      NULL,
      &error_message);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_exec failed: %s\n", error_message ? error_message : "(null)");
    sqlite3_free(error_message);
    fail("basic SQL failed");
  }

  rc = query_int(db, "PRAGMA foreign_keys;", &value);
  check_sqlite_ok(rc, "foreign_keys query failed");
  check_true(value == 1, "foreign_keys should be ON");

  rc = query_int(db, "PRAGMA trusted_schema;", &value);
  check_sqlite_ok(rc, "trusted_schema query failed");
  check_true(value == 0, "trusted_schema should be OFF");

  rc = query_int(db, "PRAGMA mmap_size;", &value);
  check_sqlite_ok(rc, "mmap_size query failed");
  check_true(value == 0, "mmap_size should be 0");

  rc = query_int(db, "PRAGMA application_id;", &value);
  check_sqlite_ok(rc, "application_id query failed");
  check_true((uint32_t)value == options.application_id, "application_id mismatch");

  rc = query_text(db, "PRAGMA journal_mode;", text, sizeof(text));
  check_sqlite_ok(rc, "journal_mode query failed");
  check_true(strcmp(text, "wal") == 0, "journal_mode should be WAL");

  rc = encsqlite_checkpoint(connection, 0);
  check_sqlite_ok(rc, "checkpoint failed");

  rc = encsqlite_checkpoint(connection, 1);
  check_sqlite_ok(rc, "truncate checkpoint failed");

  rc = sqlite3_exec(db, "PRAGMA journal_mode=DELETE;", NULL, NULL, &error_message);
  check_true(rc == SQLITE_AUTH, "changing journal_mode should be rejected");
  sqlite3_free(error_message);
  error_message = NULL;

  rc = sqlite3_exec(db, "PRAGMA foreign_keys=OFF;", NULL, NULL, &error_message);
  check_true(rc == SQLITE_AUTH, "changing foreign_keys should be rejected");
  sqlite3_free(error_message);
  error_message = NULL;

  rc = sqlite3_exec(db, "ATTACH 'other.db' AS aux;", NULL, NULL, &error_message);
  check_true(rc == SQLITE_AUTH, "ATTACH should be rejected");
  sqlite3_free(error_message);
  error_message = NULL;

  rc = sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, -1, &value);
  check_sqlite_ok(rc, "load_extension db_config query failed");
  check_true(value == 0, "load_extension should be disabled");

  rc = encsqlite_close_secure(connection);
  check_sqlite_ok(rc, "close failed");

  unlink(path);
  {
    char wal_path[256];
    char shm_path[256];
    snprintf(wal_path, sizeof(wal_path), "%s-wal", path);
    snprintf(shm_path, sizeof(shm_path), "%s-shm", path);
    unlink(wal_path);
    unlink(shm_path);
  }
}

int main(void) {
  test_connection_policy();
  return 0;
}
