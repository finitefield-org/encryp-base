#include <sqlite3.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "encsqlite/api.h"

enum {
  BENCHMARK_FIXTURE_ROWS = 128,
  BENCHMARK_OPEN_ITERATIONS = 100,
  BENCHMARK_UPDATE_ITERATIONS = 50,
  BENCHMARK_UPDATES_PER_TRANSACTION = 16
};

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

static double now_seconds(void) {
  struct timeval tv;

  if (gettimeofday(&tv, NULL) != 0) {
    fail("gettimeofday failed");
  }
  return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}

static void make_temp_path(char *path, size_t path_len) {
  int fd;

  snprintf(path, path_len, "/tmp/encryp-base-benchmark-XXXXXX");
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

static void create_fixture_database(
    const char *path,
    const encsqlite_key_material *key_material) {
  encsqlite_connection *connection = NULL;
  sqlite3 *db = NULL;
  encsqlite_open_options options;
  int rc;

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
  for (int i = 0; i < BENCHMARK_FIXTURE_ROWS; ++i) {
    char sql[128];
    int written;

    written = snprintf(
        sql,
        sizeof(sql),
        "INSERT INTO t(id, value) VALUES (%d, 'seed-%03d');",
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

  rc = encsqlite_checkpoint(connection, 1);
  check_sqlite_ok(rc, "fixture checkpoint failed");

  rc = encsqlite_close_secure(connection);
  check_sqlite_ok(rc, "fixture close failed");
}

static double benchmark_open_read_close(
    const char *path,
    const encsqlite_key_material *key_material) {
  encsqlite_connection *connection = NULL;
  sqlite3 *db = NULL;
  encsqlite_open_options options;
  int rc;
  int value = -1;
  double start;
  double end;

  memset(&options, 0, sizeof(options));
  options.create_if_missing = 0;
  options.read_only = 1;
  options.expect_application_id = 1;
  options.application_id = 0x454E4353U;
  options.journal_mode_wal = 0;

  start = now_seconds();
  for (int i = 0; i < BENCHMARK_OPEN_ITERATIONS; ++i) {
    rc = encsqlite_open_v2(&connection, path, key_material, &options);
    check_sqlite_ok(rc, "benchmark open failed");
    check_true(connection != NULL, "benchmark connection missing");

    db = encsqlite_connection_sqlite3(connection);
    check_true(db != NULL, "benchmark sqlite handle missing");

    rc = query_int(db, "SELECT SUM(id) FROM t;", &value);
    check_sqlite_ok(rc, "benchmark sum query failed");
    check_true(value == (BENCHMARK_FIXTURE_ROWS * (BENCHMARK_FIXTURE_ROWS + 1)) / 2,
               "benchmark sum mismatch");

    rc = encsqlite_close_secure(connection);
    check_sqlite_ok(rc, "benchmark close failed");
    connection = NULL;
  }
  end = now_seconds();

  return end - start;
}

static double benchmark_update_transactions(
    const char *path,
    const encsqlite_key_material *key_material) {
  encsqlite_connection *connection = NULL;
  sqlite3 *db = NULL;
  sqlite3_stmt *stmt = NULL;
  encsqlite_open_options options;
  int rc;
  int value = -1;
  double start;
  double end;

  memset(&options, 0, sizeof(options));
  options.create_if_missing = 0;
  options.read_only = 0;
  options.expect_application_id = 1;
  options.application_id = 0x454E4353U;
  options.journal_mode_wal = 1;

  rc = encsqlite_open_v2(&connection, path, key_material, &options);
  check_sqlite_ok(rc, "benchmark update open failed");
  check_true(connection != NULL, "benchmark update connection missing");

  db = encsqlite_connection_sqlite3(connection);
  check_true(db != NULL, "benchmark update sqlite handle missing");

  rc = sqlite3_prepare_v2(db, "UPDATE t SET value = ?1 WHERE id = ?2;", -1, &stmt, NULL);
  check_sqlite_ok(rc, "benchmark update prepare failed");

  start = now_seconds();
  for (int iter = 0; iter < BENCHMARK_UPDATE_ITERATIONS; ++iter) {
    rc = exec_sql(db, "BEGIN IMMEDIATE;");
    check_sqlite_ok(rc, "benchmark update begin failed");

    for (int row = 0; row < BENCHMARK_UPDATES_PER_TRANSACTION; ++row) {
      char value_text[32];
      int row_id = ((iter * BENCHMARK_UPDATES_PER_TRANSACTION) + row) % BENCHMARK_FIXTURE_ROWS + 1;
      int written;

      written = snprintf(value_text, sizeof(value_text), "bench-%03d-%02d", iter, row);
      if (written < 0 || (size_t)written >= sizeof(value_text)) {
        fail("benchmark update value truncated");
      }

      rc = sqlite3_bind_text(stmt, 1, value_text, -1, SQLITE_TRANSIENT);
      check_sqlite_ok(rc, "benchmark update bind text failed");
      rc = sqlite3_bind_int(stmt, 2, row_id);
      check_sqlite_ok(rc, "benchmark update bind int failed");

      rc = sqlite3_step(stmt);
      check_true(rc == SQLITE_DONE, "benchmark update step failed");
      rc = sqlite3_reset(stmt);
      check_sqlite_ok(rc, "benchmark update reset failed");
      rc = sqlite3_clear_bindings(stmt);
      check_sqlite_ok(rc, "benchmark update clear bindings failed");
    }

    rc = exec_sql(db, "COMMIT;");
    check_sqlite_ok(rc, "benchmark update commit failed");
  }
  end = now_seconds();

  rc = sqlite3_finalize(stmt);
  check_sqlite_ok(rc, "benchmark update finalize failed");

  rc = query_int(db, "SELECT COUNT(*) FROM t;", &value);
  check_sqlite_ok(rc, "benchmark update count query failed");
  check_true(value == BENCHMARK_FIXTURE_ROWS, "benchmark update count mismatch");

  rc = encsqlite_checkpoint(connection, 1);
  check_sqlite_ok(rc, "benchmark update checkpoint failed");

  rc = encsqlite_close_secure(connection);
  check_sqlite_ok(rc, "benchmark update close failed");

  return end - start;
}

static void print_result(const char *label, int iterations, double elapsed_seconds) {
  double per_iteration_ms = (elapsed_seconds * 1000.0) / (double)iterations;

  printf("%s: %d iterations, %.3f sec total, %.3f ms/iter\n",
         label,
         iterations,
         elapsed_seconds,
         per_iteration_ms);
}

int main(void) {
  char path[128];
  uint8_t raw_secret[ENCSQLITE_CODEC_KEY_BYTES];
  encsqlite_key_material key_material;
  double open_elapsed;
  double update_elapsed;

  make_temp_path(path, sizeof(path));
  fill_sequence(raw_secret, sizeof(raw_secret), 0x71);
  key_material.type = ENCSQLITE_KEY_RAW_32;
  key_material.data = raw_secret;
  key_material.data_len = sizeof(raw_secret);

  create_fixture_database(path, &key_material);
  open_elapsed = benchmark_open_read_close(path, &key_material);
  update_elapsed = benchmark_update_transactions(path, &key_material);

  puts("encsqlite benchmark");
  print_result("open/read/close", BENCHMARK_OPEN_ITERATIONS, open_elapsed);
  print_result("update transactions", BENCHMARK_UPDATE_ITERATIONS, update_elapsed);

  unlink(path);
  remove_sqlite_sidecars(path);
  return 0;
}
