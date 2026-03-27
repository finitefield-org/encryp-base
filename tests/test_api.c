#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "encsqlite/api.h"

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

  snprintf(path, path_len, "/tmp/encryp-base-api-%s-XXXXXX", suffix);
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

static int exec_sql(sqlite3 *db, const char *sql) {
  char *error_message = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &error_message);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_exec failed: %s\n", error_message ? error_message : "(null)");
    sqlite3_free(error_message);
  }
  return rc;
}

static void read_file_prefix(const char *path, uint8_t *buffer, size_t len) {
  FILE *file = fopen(path, "rb");
  size_t bytes_read;

  if (file == NULL) {
    fail("fopen failed");
  }

  bytes_read = fread(buffer, 1, len, file);
  fclose(file);
  if (bytes_read != len) {
    fail("fread failed");
  }
}

static void write_text_file(const char *path, const char *contents) {
  FILE *file = fopen(path, "wb");

  if (file == NULL) {
    fail("fopen failed");
  }
  if (fputs(contents, file) == EOF) {
    fclose(file);
    fail("fputs failed");
  }
  if (fclose(file) != 0) {
    fail("fclose failed");
  }
}

static void make_sidecar_path(char *path, size_t path_len, const char *base_path, const char *suffix) {
  snprintf(path, path_len, "%s%s", base_path, suffix);
}

static void expect_missing_path(const char *path, const char *message) {
  check_true(access(path, F_OK) != 0, message);
}

static void create_plaintext_database(const char *path) {
  sqlite3 *db = NULL;
  int rc;

  rc = sqlite3_open(path, &db);
  check_sqlite_ok(rc, "sqlite3_open failed");
  check_true(db != NULL, "plaintext db missing");

  rc = exec_sql(
      db,
      "PRAGMA page_size=4096;"
      "PRAGMA application_id=0x454E4353;"
      "VACUUM;"
      "CREATE TABLE t(id INTEGER PRIMARY KEY, value TEXT);"
      "INSERT INTO t(value) VALUES ('plain');");
  if (rc != SQLITE_OK) {
    fail("create plaintext database failed");
  }

  rc = sqlite3_close(db);
  check_sqlite_ok(rc, "sqlite3_close failed");
}

static void verify_encrypted_database(
    const char *path,
    const encsqlite_key_material *key_material,
    int expected_row_count) {
  encsqlite_connection *connection = NULL;
  sqlite3 *db = NULL;
  encsqlite_open_options options;
  int rc;
  int value = -1;

  memset(&options, 0, sizeof(options));
  options.create_if_missing = 0;
  options.read_only = 1;
  options.expect_application_id = 1;
  options.application_id = 0x454E4353U;
  options.journal_mode_wal = 0;

  rc = encsqlite_open_v2(&connection, path, key_material, &options);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "encsqlite_open_v2 failed: %d (%s)\n", rc, sqlite3_errstr(rc));
  }
  check_sqlite_ok(rc, "encsqlite_open_v2 failed");
  check_true(connection != NULL, "connection missing");

  db = encsqlite_connection_sqlite3(connection);
  check_true(db != NULL, "sqlite handle missing");

  rc = query_int(db, "SELECT COUNT(*) FROM t;", &value);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "row count query failed: %d (%s)\n", rc, sqlite3_errstr(rc));
  }
  check_sqlite_ok(rc, "row count query failed");
  check_true(value == expected_row_count, "row count mismatch");

  rc = encsqlite_close_secure(connection);
  check_sqlite_ok(rc, "close failed");
}

static void test_migrate_rekey_and_export(void) {
  static const uint8_t sqlite_header[ENCSQLITE_SQLITE_HEADER_BYTES] = {
      'S', 'Q', 'L', 'i', 't', 'e', ' ', 'f',
      'o', 'r', 'm', 'a', 't', ' ', '3', '\0'};
  char source_path[128];
  char rekey_path[128];
  char export_path[128];
  char stale_temp_path[192];
  char stale_bak_path[192];
  char stale_marker_path[192];
  uint8_t key_one[ENCSQLITE_CODEC_KEY_BYTES];
  uint8_t key_two[ENCSQLITE_CODEC_KEY_BYTES];
  encsqlite_key_material source_key;
  encsqlite_key_material destination_key;
  encsqlite_open_options options;
  encsqlite_codec_context codec;
  uint8_t header[ENCSQLITE_SQLITE_HEADER_BYTES];
  uint8_t physical_page[ENCSQLITE_PAGE_SIZE_BYTES];
  uint8_t logical_page[ENCSQLITE_PAGE_SIZE_BYTES];
  int rc;

  make_temp_path(source_path, sizeof(source_path), "source");
  make_temp_path(rekey_path, sizeof(rekey_path), "rekey");
  make_temp_path(export_path, sizeof(export_path), "export");

  fill_sequence(key_one, sizeof(key_one), 0x11);
  fill_sequence(key_two, sizeof(key_two), 0x51);
  source_key.type = ENCSQLITE_KEY_RAW_32;
  source_key.data = key_one;
  source_key.data_len = sizeof(key_one);
  destination_key.type = ENCSQLITE_KEY_RAW_32;
  destination_key.data = key_two;
  destination_key.data_len = sizeof(key_two);

  memset(&options, 0, sizeof(options));
  options.expect_application_id = 1;
  options.application_id = 0x454E4353U;

  create_plaintext_database(source_path);

  make_sidecar_path(stale_temp_path, sizeof(stale_temp_path), source_path, ".encsqlite-stale");
  make_sidecar_path(stale_bak_path, sizeof(stale_bak_path), source_path, ".encsqlite.bak");
  make_sidecar_path(stale_marker_path, sizeof(stale_marker_path), source_path, ".encsqlite.recovery");
  write_text_file(stale_temp_path, "stale temp\n");
  write_text_file(stale_bak_path, "stale backup\n");
  write_text_file(stale_marker_path, "phase=1\n");

  rc = encsqlite_migrate_plaintext(source_path, source_path, &source_key, &options);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "migrate_plaintext failed: %d (%s)\n", rc, sqlite3_errstr(rc));
  }
  check_sqlite_ok(rc, "migrate_plaintext failed");

  expect_missing_path(stale_temp_path, "stale temp path should be removed");
  expect_missing_path(stale_bak_path, "stale backup path should be removed");
  expect_missing_path(stale_marker_path, "stale recovery marker should be removed");

  read_file_prefix(source_path, header, sizeof(header));
  check_true(memcmp(header, sqlite_header, sizeof(sqlite_header)) != 0,
             "migrated file should not start with plaintext SQLite header");

  check_sqlite_ok(
      encsqlite_codec_init(&codec, key_one, header, 1U),
      "codec init for migrated file failed");
  read_file_prefix(source_path, physical_page, sizeof(physical_page));
  rc = encsqlite_codec_decrypt_page(&codec, 1U, physical_page, logical_page);
  if (rc != ENCSQLITE_CODEC_OK) {
    fprintf(stderr, "decrypt migrated page1 failed: %d\n", rc);
  }
  check_true(rc == ENCSQLITE_CODEC_OK, "migrated page1 decrypt failed");
  check_true(encsqlite_page1_has_sqlite_header(logical_page) == 1,
             "migrated page1 header missing");
  encsqlite_codec_clear(&codec);

  verify_encrypted_database(source_path, &source_key, 1);

  make_sidecar_path(stale_temp_path, sizeof(stale_temp_path), rekey_path, ".encsqlite-stale");
  make_sidecar_path(stale_bak_path, sizeof(stale_bak_path), rekey_path, ".encsqlite.bak");
  make_sidecar_path(stale_marker_path, sizeof(stale_marker_path), rekey_path, ".encsqlite.recovery");
  write_text_file(stale_temp_path, "stale temp\n");
  write_text_file(stale_bak_path, "stale backup\n");
  write_text_file(stale_marker_path, "phase=2\n");

  rc = encsqlite_rekey_copy_swap(
      source_path,
      rekey_path,
      &source_key,
      &destination_key,
      &options);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "rekey_copy_swap failed: %d (%s)\n", rc, sqlite3_errstr(rc));
  }
  check_sqlite_ok(rc, "rekey_copy_swap failed");
  verify_encrypted_database(rekey_path, &destination_key, 1);
  verify_encrypted_database(source_path, &source_key, 1);

  expect_missing_path(stale_temp_path, "stale rekey temp path should be removed");
  expect_missing_path(stale_bak_path, "stale rekey backup path should be removed");
  expect_missing_path(stale_marker_path, "stale rekey recovery marker should be removed");

  make_sidecar_path(stale_temp_path, sizeof(stale_temp_path), export_path, ".encsqlite-stale");
  make_sidecar_path(stale_bak_path, sizeof(stale_bak_path), export_path, ".encsqlite.bak");
  make_sidecar_path(stale_marker_path, sizeof(stale_marker_path), export_path, ".encsqlite.recovery");
  write_text_file(stale_temp_path, "stale temp\n");
  write_text_file(stale_bak_path, "stale backup\n");
  write_text_file(stale_marker_path, "phase=2\n");

  rc = encsqlite_export(rekey_path, export_path, &destination_key, &options);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "export failed: %d (%s)\n", rc, sqlite3_errstr(rc));
  }
  check_sqlite_ok(rc, "export failed");
  verify_encrypted_database(export_path, &destination_key, 1);

  expect_missing_path(stale_temp_path, "stale export temp path should be removed");
  expect_missing_path(stale_bak_path, "stale export backup path should be removed");
  expect_missing_path(stale_marker_path, "stale export recovery marker should be removed");

  unlink(source_path);
  unlink(rekey_path);
  unlink(export_path);
}

int main(void) {
  test_migrate_rekey_and_export();
  return 0;
}
