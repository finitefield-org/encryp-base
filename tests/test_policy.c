#include <sqlite3.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "encsqlite/connection.h"

enum {
  POLICY_LOG_MESSAGE_BYTES = 256,
  POLICY_LOG_MESSAGE_LIMIT = 32
};

typedef struct {
  char messages[POLICY_LOG_MESSAGE_LIMIT][POLICY_LOG_MESSAGE_BYTES];
  size_t count;
  int overflow;
} policy_log_capture;

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

  snprintf(path, path_len, "/tmp/encryp-base-policy-XXXXXX");
  fd = mkstemp(path);
  if (fd < 0) {
    fail("mkstemp failed");
  }
  close(fd);
  unlink(path);
}

static int exec_sql(sqlite3 *db, const char *sql, char **out_error_message) {
  char *error_message = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &error_message);

  if (out_error_message != NULL) {
    *out_error_message = error_message;
  } else {
    sqlite3_free(error_message);
  }
  return rc;
}

static void policy_log_callback(void *user_data, int err_code, const char *message) {
  policy_log_capture *capture = (policy_log_capture *)user_data;
  size_t index;

  (void)err_code;

  if (capture == NULL) {
    return;
  }
  if (capture->count >= POLICY_LOG_MESSAGE_LIMIT) {
    capture->overflow = 1;
    return;
  }

  index = capture->count++;
  snprintf(capture->messages[index], sizeof(capture->messages[index]), "%s", message ? message : "(null)");
}

static void assert_no_leak_in_text(const char *text, const char *needle, const char *message) {
  if (text != NULL && needle != NULL && strstr(text, needle) != NULL) {
    fprintf(stderr, "%s\ntext: %s\nneedle: %s\n", message, text, needle);
    fflush(stderr);
    fail(message);
  }
}

static void assert_denied_statement_is_generic(
    sqlite3 *db,
    const char *sql,
    const char *needle) {
  char *error_message = NULL;
  const char *errmsg;
  int rc;

  rc = exec_sql(db, sql, &error_message);
  check_true(rc == SQLITE_AUTH, "statement should be rejected");
  assert_no_leak_in_text(error_message, needle, "error_message leaked sensitive text");
  sqlite3_free(error_message);

  errmsg = sqlite3_errmsg(db);
  assert_no_leak_in_text(errmsg, needle, "sqlite3_errmsg leaked sensitive text");
}

static void assert_ignored_statement_is_generic(
    sqlite3 *db,
    const char *sql,
    const char *needle) {
  char *error_message = NULL;
  const char *errmsg;
  int rc;

  rc = exec_sql(db, sql, &error_message);
  check_true(rc == SQLITE_OK, "statement should be ignored");
  check_true(error_message == NULL, "ignored statement should not allocate error text");
  sqlite3_free(error_message);

  errmsg = sqlite3_errmsg(db);
  assert_no_leak_in_text(errmsg, needle, "sqlite3_errmsg leaked sensitive text");
}

static void test_policy_rejects_sensitive_pragmas_without_logging_them(void) {
  char path[128];
  char secret_token[64];
  char attach_path[128];
  uint8_t raw_secret[ENCSQLITE_CODEC_KEY_BYTES];
  encsqlite_connection *connection = NULL;
  sqlite3 *db = NULL;
  encsqlite_key_material key_material;
  encsqlite_open_options options;
  policy_log_capture capture;
  int rc;

  memset(&capture, 0, sizeof(capture));
  rc = sqlite3_config(SQLITE_CONFIG_LOG, policy_log_callback, &capture);
  check_sqlite_ok(rc, "sqlite3_config(LOG) failed");

  sqlite3_log(SQLITE_WARNING, "policy log probe");
  check_true(capture.count >= 1, "log callback probe did not fire");

  make_temp_path(path, sizeof(path));
  fill_sequence(raw_secret, sizeof(raw_secret), 0x11);
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
  check_sqlite_ok(rc, "encsqlite_open_v2 failed");
  check_true(connection != NULL, "connection missing");

  db = encsqlite_connection_sqlite3(connection);
  check_true(db != NULL, "sqlite handle missing");

  rc = exec_sql(db, "CREATE TABLE t(id INTEGER PRIMARY KEY, value TEXT);", NULL);
  check_sqlite_ok(rc, "table creation failed");

  snprintf(secret_token, sizeof(secret_token), "leak-token-%08x", 0x454E4353U);
  snprintf(attach_path, sizeof(attach_path), "%s-attach.db", path);

  {
    char sql[256];
    int written;

    written = snprintf(sql, sizeof(sql), "PRAGMA key='%s';", secret_token);
    if (written < 0 || (size_t)written >= sizeof(sql)) {
      fail("key pragma statement truncated");
    }
    assert_ignored_statement_is_generic(db, sql, secret_token);
  }

  {
    char sql[256];
    int written;

    written = snprintf(sql, sizeof(sql), "ATTACH '%s' AS aux;", attach_path);
    if (written < 0 || (size_t)written >= sizeof(sql)) {
      fail("attach statement truncated");
    }
    assert_denied_statement_is_generic(db, sql, secret_token);
  }

  assert_denied_statement_is_generic(db, "PRAGMA journal_mode=DELETE;", "DELETE");
  assert_denied_statement_is_generic(db, "PRAGMA writable_schema=ON;", "writable_schema");

  rc = sqlite3_exec(db, "PRAGMA foreign_keys=OFF;", NULL, NULL, NULL);
  check_true(rc == SQLITE_AUTH, "foreign_keys pragma should be rejected");

  rc = encsqlite_close_secure(connection);
  check_sqlite_ok(rc, "close failed");

  for (size_t i = 0; i < capture.count; ++i) {
    assert_no_leak_in_text(capture.messages[i], secret_token, "log callback leaked sensitive text");
  }
  check_true(capture.overflow == 0, "log capture overflowed");

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
  test_policy_rejects_sensitive_pragmas_without_logging_them();
  return 0;
}
