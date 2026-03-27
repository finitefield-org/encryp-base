#include <sqlite3.h>

#include <stdint.h>
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

  snprintf(path, path_len, "/tmp/encryp-base-corruption-%s-XXXXXX", suffix);
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

static void expect_path_exists(const char *path, const char *message) {
  check_true(access(path, F_OK) == 0, message);
}

static void expect_missing_path(const char *path, const char *message) {
  check_true(access(path, F_OK) != 0, message);
}

static void make_sidecar_path(char *path, size_t path_len, const char *base_path, const char *suffix) {
  snprintf(path, path_len, "%s%s", base_path, suffix);
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

static void copy_file(const char *source_path, const char *destination_path) {
  FILE *source = fopen(source_path, "rb");
  FILE *destination = NULL;
  uint8_t buffer[4096];
  size_t bytes_read;

  if (source == NULL) {
    fail("copy source fopen failed");
  }

  destination = fopen(destination_path, "wb");
  if (destination == NULL) {
    fclose(source);
    fail("copy destination fopen failed");
  }

  while ((bytes_read = fread(buffer, 1, sizeof(buffer), source)) != 0) {
    if (fwrite(buffer, 1, bytes_read, destination) != bytes_read) {
      fclose(source);
      fclose(destination);
      fail("copy fwrite failed");
    }
  }

  if (ferror(source) != 0) {
    fclose(source);
    fclose(destination);
    fail("copy fread failed");
  }

  if (fflush(destination) != 0) {
    fclose(source);
    fclose(destination);
    fail("copy fflush failed");
  }
  if (fsync(fileno(destination)) != 0) {
    fclose(source);
    fclose(destination);
    fail("copy fsync failed");
  }

  if (fclose(source) != 0) {
    fclose(destination);
    fail("copy source fclose failed");
  }
  if (fclose(destination) != 0) {
    fail("copy destination fclose failed");
  }
}

static void expect_encrypted_row_count(
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
  check_sqlite_ok(rc, "encrypted database open failed");
  check_true(connection != NULL, "encrypted database connection missing");

  db = encsqlite_connection_sqlite3(connection);
  check_true(db != NULL, "encrypted database sqlite handle missing");

  rc = query_int(db, "SELECT COUNT(*) FROM t;", &value);
  check_sqlite_ok(rc, "encrypted row count query failed");
  check_true(value == expected_row_count, "encrypted row count mismatch");

  rc = encsqlite_close_secure(connection);
  check_sqlite_ok(rc, "encrypted database close failed");
}

static void corrupt_byte(const char *path, long offset, uint8_t mask) {
  FILE *file = fopen(path, "r+b");
  int value;

  if (file == NULL) {
    fail("fopen failed");
  }
  if (fseek(file, offset, SEEK_SET) != 0) {
    fclose(file);
    fail("fseek failed");
  }
  value = fgetc(file);
  if (value == EOF) {
    fclose(file);
    fail("fgetc failed");
  }
  if (fseek(file, offset, SEEK_SET) != 0) {
    fclose(file);
    fail("fseek rewind failed");
  }
  if (fputc(value ^ mask, file) == EOF) {
    fclose(file);
    fail("fputc failed");
  }
  if (fflush(file) != 0) {
    fclose(file);
    fail("fflush failed");
  }
  if (fsync(fileno(file)) != 0) {
    fclose(file);
    fail("fsync failed");
  }
  if (fclose(file) != 0) {
    fail("fclose failed");
  }
}

static void build_encrypted_fixture(
    const char *path,
    const encsqlite_key_material *key_material) {
  encsqlite_connection *connection = NULL;
  sqlite3 *db = NULL;
  encsqlite_open_options options;
  int rc;
  int value = -1;

  memset(&options, 0, sizeof(options));
  options.create_if_missing = 1;
  options.read_only = 0;
  options.expect_application_id = 1;
  options.application_id = 0x454E4353U;
  options.journal_mode_wal = 1;

  rc = encsqlite_open_v2(&connection, path, key_material, &options);
  check_sqlite_ok(rc, "fixture open failed");
  check_true(connection != NULL, "fixture connection missing");

  db = encsqlite_connection_sqlite3(connection);
  check_true(db != NULL, "fixture sqlite handle missing");

  rc = exec_sql(db, "CREATE TABLE t(id INTEGER PRIMARY KEY, value TEXT NOT NULL);");
  check_sqlite_ok(rc, "fixture table creation failed");

  rc = exec_sql(db, "BEGIN IMMEDIATE;");
  check_sqlite_ok(rc, "fixture begin failed");
  for (int i = 0; i < 64; ++i) {
    char sql[128];
    int written;

    written = snprintf(
        sql,
        sizeof(sql),
        "INSERT INTO t(id, value) VALUES (%d, 'row-%02d');",
        i + 1,
        i + 1);
    if (written < 0 || (size_t)written >= sizeof(sql)) {
      fail("fixture insert statement truncated");
    }
    rc = exec_sql(db, sql);
    check_sqlite_ok(rc, "fixture insert failed");
  }
  rc = exec_sql(db, "COMMIT;");
  check_sqlite_ok(rc, "fixture commit failed");

  rc = query_int(db, "SELECT COUNT(*) FROM t;", &value);
  check_sqlite_ok(rc, "fixture row count query failed");
  check_true(value == 64, "fixture row count mismatch");

  rc = query_int(db, "PRAGMA page_count;", &value);
  check_sqlite_ok(rc, "fixture page_count query failed");
  check_true(value > 1, "fixture should span more than one page");

  rc = encsqlite_checkpoint(connection, 1);
  check_sqlite_ok(rc, "fixture checkpoint failed");

  rc = encsqlite_close_secure(connection);
  check_sqlite_ok(rc, "fixture close failed");
}

static void open_corrupt_database_and_expect_failure(
    const char *path,
    const encsqlite_key_material *key_material,
    int expected_rc) {
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
  if (rc == SQLITE_OK) {
    check_true(connection != NULL, "corrupt open connection missing");
    db = encsqlite_connection_sqlite3(connection);
    check_true(db != NULL, "corrupt open sqlite handle missing");

    rc = query_int(db, "SELECT COUNT(*) FROM t;", &value);
    check_true(rc == expected_rc, "corruption was not detected");

    rc = encsqlite_close_secure(connection);
    check_sqlite_ok(rc, "corrupt close failed");
    return;
  }

  check_true(rc == expected_rc, "corrupt open returned unexpected code");
}

static void test_page1_corruption_is_detected(void) {
  char path[128];
  uint8_t raw_secret[ENCSQLITE_CODEC_KEY_BYTES];
  encsqlite_key_material key_material;

  make_temp_path(path, sizeof(path), "page1");
  fill_sequence(raw_secret, sizeof(raw_secret), 0x11);
  key_material.type = ENCSQLITE_KEY_RAW_32;
  key_material.data = raw_secret;
  key_material.data_len = sizeof(raw_secret);

  build_encrypted_fixture(path, &key_material);
  corrupt_byte(path, ENCSQLITE_PAGE1_CIPHERTEXT_OFFSET + 32L, 0x01U);
  open_corrupt_database_and_expect_failure(path, &key_material, SQLITE_NOTADB);

  unlink(path);
  remove_sqlite_sidecars(path);
}

static void test_page_n_corruption_is_detected(void) {
  char path[128];
  uint8_t raw_secret[ENCSQLITE_CODEC_KEY_BYTES];
  encsqlite_key_material key_material;

  make_temp_path(path, sizeof(path), "pagen");
  fill_sequence(raw_secret, sizeof(raw_secret), 0x21);
  key_material.type = ENCSQLITE_KEY_RAW_32;
  key_material.data = raw_secret;
  key_material.data_len = sizeof(raw_secret);

  build_encrypted_fixture(path, &key_material);
  corrupt_byte(path, ENCSQLITE_PAGE_SIZE_BYTES + 0L, 0x01U);
  open_corrupt_database_and_expect_failure(path, &key_material, SQLITE_CORRUPT);

  unlink(path);
  remove_sqlite_sidecars(path);
}

static void test_stale_wal_is_replayed(void) {
  char path[128];
  char wal_path[192];
  char wal_snapshot_path[192];
  uint8_t raw_secret[ENCSQLITE_CODEC_KEY_BYTES];
  encsqlite_key_material key_material;
  encsqlite_open_options options;
  encsqlite_connection *connection = NULL;
  sqlite3 *db = NULL;
  int rc;
  int value = -1;

  make_temp_path(path, sizeof(path), "wal");
  make_sidecar_path(wal_path, sizeof(wal_path), path, "-wal");
  make_sidecar_path(wal_snapshot_path, sizeof(wal_snapshot_path), path, "-wal-snapshot");

  fill_sequence(raw_secret, sizeof(raw_secret), 0x31);
  key_material.type = ENCSQLITE_KEY_RAW_32;
  key_material.data = raw_secret;
  key_material.data_len = sizeof(raw_secret);

  memset(&options, 0, sizeof(options));
  options.create_if_missing = 1;
  options.read_only = 0;
  options.expect_application_id = 1;
  options.application_id = 0x454E4353U;
  options.journal_mode_wal = 1;

  rc = encsqlite_open_v2(&connection, path, &key_material, &options);
  check_sqlite_ok(rc, "stale WAL fixture open failed");
  check_true(connection != NULL, "stale WAL connection missing");

  db = encsqlite_connection_sqlite3(connection);
  check_true(db != NULL, "stale WAL sqlite handle missing");

  rc = exec_sql(db, "CREATE TABLE t(id INTEGER PRIMARY KEY, value TEXT NOT NULL);");
  check_sqlite_ok(rc, "stale WAL table creation failed");
  rc = exec_sql(
      db,
      "INSERT INTO t(value) VALUES ('one');"
      "INSERT INTO t(value) VALUES ('two');"
      "INSERT INTO t(value) VALUES ('three');");
  check_sqlite_ok(rc, "stale WAL insert failed");

  rc = query_int(db, "SELECT COUNT(*) FROM t;", &value);
  check_sqlite_ok(rc, "stale WAL row count query failed");
  check_true(value == 3, "stale WAL row count mismatch before close");

  expect_path_exists(wal_path, "WAL file should exist before close");
  copy_file(wal_path, wal_snapshot_path);

  rc = encsqlite_close_secure(connection);
  check_sqlite_ok(rc, "stale WAL close failed");
  connection = NULL;

  unlink(wal_path);
  copy_file(wal_snapshot_path, wal_path);
  unlink(wal_snapshot_path);

  options.create_if_missing = 0;
  options.read_only = 0;
  rc = encsqlite_open_v2(&connection, path, &key_material, &options);
  check_sqlite_ok(rc, "stale WAL reopen failed");
  check_true(connection != NULL, "stale WAL reopen connection missing");

  db = encsqlite_connection_sqlite3(connection);
  check_true(db != NULL, "stale WAL reopen sqlite handle missing");

  rc = query_int(db, "SELECT COUNT(*) FROM t;", &value);
  check_sqlite_ok(rc, "stale WAL recovery query failed");
  check_true(value == 3, "stale WAL replay did not restore committed rows");

  rc = encsqlite_checkpoint(connection, 1);
  check_sqlite_ok(rc, "stale WAL checkpoint failed");

  rc = encsqlite_close_secure(connection);
  check_sqlite_ok(rc, "stale WAL reopen close failed");

  expect_missing_path(wal_path, "checkpoint should remove stale WAL");

  unlink(path);
  remove_sqlite_sidecars(path);
}

static void test_copy_swap_interruptions_are_recovered(void) {
  char source_path[128];
  char prepared_dest_path[128];
  char backed_up_dest_path[128];
  char prepared_temp_path[192];
  char prepared_marker_path[192];
  char backed_up_temp_path[192];
  char backed_up_backup_path[192];
  char backed_up_marker_path[192];
  uint8_t source_secret[ENCSQLITE_CODEC_KEY_BYTES];
  uint8_t destination_secret[ENCSQLITE_CODEC_KEY_BYTES];
  uint8_t wrong_source_secret[ENCSQLITE_CODEC_KEY_BYTES];
  encsqlite_key_material source_key;
  encsqlite_key_material destination_key;
  encsqlite_key_material wrong_source_key;
  encsqlite_open_options options;
  int rc;

  make_temp_path(source_path, sizeof(source_path), "interrupt-source");
  make_temp_path(prepared_dest_path, sizeof(prepared_dest_path), "interrupt-prepared");
  make_temp_path(backed_up_dest_path, sizeof(backed_up_dest_path), "interrupt-backed-up");

  fill_sequence(source_secret, sizeof(source_secret), 0x41);
  fill_sequence(destination_secret, sizeof(destination_secret), 0x51);
  fill_sequence(wrong_source_secret, sizeof(wrong_source_secret), 0x61);
  source_key.type = ENCSQLITE_KEY_RAW_32;
  source_key.data = source_secret;
  source_key.data_len = sizeof(source_secret);
  destination_key.type = ENCSQLITE_KEY_RAW_32;
  destination_key.data = destination_secret;
  destination_key.data_len = sizeof(destination_secret);
  wrong_source_key.type = ENCSQLITE_KEY_RAW_32;
  wrong_source_key.data = wrong_source_secret;
  wrong_source_key.data_len = sizeof(wrong_source_secret);

  memset(&options, 0, sizeof(options));
  options.expect_application_id = 1;
  options.application_id = 0x454E4353U;

  build_encrypted_fixture(source_path, &source_key);
  build_encrypted_fixture(prepared_dest_path, &destination_key);
  build_encrypted_fixture(backed_up_dest_path, &destination_key);

  make_sidecar_path(prepared_temp_path, sizeof(prepared_temp_path), prepared_dest_path, ".encsqlite-stale");
  make_sidecar_path(prepared_marker_path, sizeof(prepared_marker_path), prepared_dest_path, ".encsqlite.recovery");
  make_sidecar_path(backed_up_temp_path, sizeof(backed_up_temp_path), backed_up_dest_path, ".encsqlite-stale");
  make_sidecar_path(backed_up_backup_path, sizeof(backed_up_backup_path), backed_up_dest_path, ".encsqlite.bak");
  make_sidecar_path(backed_up_marker_path, sizeof(backed_up_marker_path), backed_up_dest_path, ".encsqlite.recovery");

  write_text_file(prepared_temp_path, "prepared temp\n");
  write_text_file(prepared_marker_path, "phase=1\n");
  write_text_file(backed_up_temp_path, "backed up temp\n");
  copy_file(backed_up_dest_path, backed_up_backup_path);
  write_text_file(backed_up_marker_path, "phase=2\n");
  unlink(backed_up_dest_path);

  rc = encsqlite_rekey_copy_swap(
      source_path,
      prepared_dest_path,
      &wrong_source_key,
      &destination_key,
      &options);
  check_true(rc != SQLITE_OK, "prepared interruption recovery should fail after cleanup");
  expect_missing_path(prepared_temp_path, "prepared temp should be removed");
  expect_missing_path(prepared_marker_path, "prepared recovery marker should be removed");
  expect_encrypted_row_count(prepared_dest_path, &destination_key, 64);

  rc = encsqlite_rekey_copy_swap(
      source_path,
      backed_up_dest_path,
      &wrong_source_key,
      &destination_key,
      &options);
  check_true(rc != SQLITE_OK, "backed up interruption recovery should fail after cleanup");
  expect_missing_path(backed_up_temp_path, "backed up temp should be removed");
  expect_missing_path(backed_up_backup_path, "backed up backup should be consumed");
  expect_missing_path(backed_up_marker_path, "backed up recovery marker should be removed");
  expect_encrypted_row_count(backed_up_dest_path, &destination_key, 64);

  unlink(source_path);
  unlink(prepared_dest_path);
  unlink(backed_up_dest_path);
  remove_sqlite_sidecars(source_path);
  remove_sqlite_sidecars(prepared_dest_path);
  remove_sqlite_sidecars(backed_up_dest_path);
}

int main(void) {
  test_page1_corruption_is_detected();
  test_page_n_corruption_is_detected();
  test_stale_wal_is_replayed();
  test_copy_swap_interruptions_are_recovered();
  return 0;
}
