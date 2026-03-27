#include "encsqlite/connection.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "encsqlite/crypto.h"
#include "sqlite3.h"

struct encsqlite_connection {
  struct sqlite3 *db;
  encsqlite_open_options options;
  uint8_t root_secret[ENCSQLITE_CODEC_KEY_BYTES];
  int has_root_secret;
  encsqlite_codec_context codec;
  int has_codec;
};

static void connection_zeroize_material(encsqlite_connection *connection) {
  if (connection == NULL) {
    return;
  }

  encsqlite_zeroize(connection->root_secret, sizeof(connection->root_secret));
  encsqlite_codec_clear(&connection->codec);
  connection->has_root_secret = 0;
  connection->has_codec = 0;
}

static int ascii_ieq(const char *lhs, const char *rhs) {
  while (*lhs != '\0' && *rhs != '\0') {
    unsigned char a = (unsigned char)*lhs++;
    unsigned char b = (unsigned char)*rhs++;
    if (tolower(a) != tolower(b)) {
      return 0;
    }
  }
  return *lhs == '\0' && *rhs == '\0';
}

static int ascii_iprefix(const char *value, const char *prefix) {
  while (*prefix != '\0') {
    unsigned char a = (unsigned char)*value++;
    unsigned char b = (unsigned char)*prefix++;
    if (a == '\0' || tolower(a) != tolower(b)) {
      return 0;
    }
  }
  return 1;
}

static int pragma_is_mutable_policy(const char *pragma_name) {
  if (pragma_name == NULL) {
    return 0;
  }
  if (ascii_ieq(pragma_name, "journal_mode")) {
    return 1;
  }
  if (ascii_ieq(pragma_name, "mmap_size")) {
    return 1;
  }
  if (ascii_ieq(pragma_name, "trusted_schema")) {
    return 1;
  }
  if (ascii_ieq(pragma_name, "foreign_keys")) {
    return 1;
  }
  if (ascii_ieq(pragma_name, "cell_size_check")) {
    return 1;
  }
  if (ascii_ieq(pragma_name, "secure_delete")) {
    return 1;
  }
  if (ascii_ieq(pragma_name, "temp_store")) {
    return 1;
  }
  if (ascii_ieq(pragma_name, "writable_schema")) {
    return 1;
  }
  if (ascii_ieq(pragma_name, "schema_version")) {
    return 1;
  }
  return ascii_ieq(pragma_name, "key") || ascii_iprefix(pragma_name, "cipher_");
}

static int connection_authorizer(
    void *user_data,
    int action_code,
    const char *param1,
    const char *param2,
    const char *db_name,
    const char *trigger_or_view) {
  (void)user_data;
  (void)db_name;
  (void)trigger_or_view;

  switch (action_code) {
    case SQLITE_ATTACH:
    case SQLITE_DETACH:
      return SQLITE_DENY;
    case SQLITE_FUNCTION:
      if (param2 != NULL && ascii_ieq(param2, "load_extension")) {
        return SQLITE_DENY;
      }
      return SQLITE_OK;
    case SQLITE_PRAGMA:
      if (param1 != NULL && pragma_is_mutable_policy(param1) && param2 != NULL) {
        return SQLITE_DENY;
      }
      return SQLITE_OK;
    default:
      return SQLITE_OK;
  }
}

static int exec_sql(struct sqlite3 *db, const char *sql) {
  char *error_message = NULL;
  int rc = sqlite3_exec(db, sql, NULL, NULL, &error_message);
  if (rc != SQLITE_OK) {
    sqlite3_free(error_message);
  }
  return rc;
}

static int query_pragma_int(struct sqlite3 *db, const char *sql, int *out_value) {
  sqlite3_stmt *stmt = NULL;
  int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    return rc;
  }

  rc = sqlite3_step(stmt);
  if (rc == SQLITE_ROW) {
    *out_value = sqlite3_column_int(stmt, 0);
    rc = SQLITE_OK;
  } else if (rc == SQLITE_DONE) {
    rc = SQLITE_ERROR;
  }

  sqlite3_finalize(stmt);
  return rc;
}

static int query_pragma_text(
    struct sqlite3 *db,
    const char *sql,
    const char **out_value,
    char *buffer,
    size_t buffer_len) {
  sqlite3_stmt *stmt = NULL;
  int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    return rc;
  }

  rc = sqlite3_step(stmt);
  if (rc == SQLITE_ROW) {
    const unsigned char *value = sqlite3_column_text(stmt, 0);
    if (value == NULL) {
      sqlite3_finalize(stmt);
      return SQLITE_ERROR;
    }
    if (buffer != NULL && buffer_len > 0) {
      snprintf(buffer, buffer_len, "%s", value);
      *out_value = buffer;
    } else {
      *out_value = (const char *)value;
    }
    rc = SQLITE_OK;
  } else if (rc == SQLITE_DONE) {
    rc = SQLITE_ERROR;
  }

  sqlite3_finalize(stmt);
  return rc;
}

static int set_journal_mode_wal(struct sqlite3 *db) {
  const char *mode = NULL;
  char mode_buffer[16];
  int rc = query_pragma_text(db, "PRAGMA journal_mode=WAL;", &mode, mode_buffer, sizeof(mode_buffer));
  if (rc != SQLITE_OK) {
    return rc;
  }
  if (!ascii_ieq(mode, "wal")) {
    return SQLITE_ERROR;
  }
  return SQLITE_OK;
}

static int checkpoint_database(struct sqlite3 *db, int truncate) {
  int log_frame_count = 0;
  int checkpointed_frame_count = 0;
  int checkpoint_mode = truncate ? SQLITE_CHECKPOINT_TRUNCATE : SQLITE_CHECKPOINT_PASSIVE;

  return sqlite3_wal_checkpoint_v2(
      db,
      NULL,
      checkpoint_mode,
      &log_frame_count,
      &checkpointed_frame_count);
}

static int apply_runtime_policy(struct sqlite3 *db, const encsqlite_open_options *options) {
  int old_value = 0;
  int rc;

  rc = sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_FKEY, 1, &old_value);
  if (rc != SQLITE_OK) {
    return rc;
  }
  rc = sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1, &old_value);
  if (rc != SQLITE_OK) {
    return rc;
  }
  rc = sqlite3_db_config(db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, &old_value);
  if (rc != SQLITE_OK) {
    return rc;
  }
  rc = sqlite3_db_config(db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, &old_value);
  if (rc != SQLITE_OK) {
    return rc;
  }

  rc = exec_sql(
      db,
      "PRAGMA foreign_keys=ON;"
      "PRAGMA temp_store=MEMORY;"
      "PRAGMA mmap_size=0;"
      "PRAGMA secure_delete=FAST;"
      "PRAGMA cell_size_check=ON;"
  );
  if (rc != SQLITE_OK) {
    return rc;
  }

  if (options->journal_mode_wal && !options->read_only) {
    rc = set_journal_mode_wal(db);
    if (rc != SQLITE_OK) {
      return rc;
    }
  }

  if (options->expect_application_id) {
    char sql[64];
    int current_application_id = 0;

    if (!options->read_only) {
      int written = snprintf(sql, sizeof(sql), "PRAGMA application_id=%u;", options->application_id);
      if (written < 0 || (size_t)written >= sizeof(sql)) {
        return SQLITE_ERROR;
      }
      rc = exec_sql(db, sql);
      if (rc != SQLITE_OK) {
        return rc;
      }
    }

    rc = query_pragma_int(db, "PRAGMA application_id;", &current_application_id);
    if (rc != SQLITE_OK) {
      return rc;
    }
    if ((uint32_t)current_application_id != options->application_id) {
      return SQLITE_MISMATCH;
    }
  }

  return SQLITE_OK;
}

static int initialize_codec_context(
    encsqlite_connection *connection,
    const encsqlite_key_material *key_material) {
  uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES];
  int rc;

  if (key_material == NULL) {
    return SQLITE_OK;
  }
  if (key_material->type != ENCSQLITE_KEY_RAW_32) {
    return SQLITE_MISUSE;
  }
  if (key_material->data_len != ENCSQLITE_CODEC_KEY_BYTES || key_material->data == NULL) {
    return SQLITE_MISUSE;
  }

  memcpy(connection->root_secret, key_material->data, ENCSQLITE_CODEC_KEY_BYTES);
  connection->has_root_secret = 1;

  if (!connection->options.create_if_missing || connection->options.read_only) {
    return SQLITE_OK;
  }

  rc = encsqlite_random_bytes(db_salt, sizeof(db_salt));
  if (rc != ENCSQLITE_CRYPTO_OK) {
    return SQLITE_ERROR;
  }
  rc = encsqlite_codec_init(&connection->codec, connection->root_secret, db_salt, 1U);
  if (rc != ENCSQLITE_CODEC_OK) {
    encsqlite_zeroize(db_salt, sizeof(db_salt));
    return SQLITE_ERROR;
  }
  encsqlite_zeroize(db_salt, sizeof(db_salt));
  connection->has_codec = 1;
  return SQLITE_OK;
}

static int default_open_option(int value, int default_value) {
  return value ? value : default_value;
}

int encsqlite_open_v2(
    encsqlite_connection **out_connection,
    const char *filename,
    const encsqlite_key_material *key_material,
    const encsqlite_open_options *options) {
  encsqlite_connection *connection = NULL;
  struct sqlite3 *db = NULL;
  encsqlite_open_options effective_options;
  int flags;
  int rc;

  if (out_connection == NULL || filename == NULL) {
    return SQLITE_MISUSE;
  }
  *out_connection = NULL;

  effective_options.create_if_missing = default_open_option(options != NULL ? options->create_if_missing : 0, 1);
  effective_options.read_only = default_open_option(options != NULL ? options->read_only : 0, 0);
  effective_options.expect_application_id = default_open_option(options != NULL ? options->expect_application_id : 0, 0);
  effective_options.application_id = options != NULL ? options->application_id : 0U;
  effective_options.journal_mode_wal = default_open_option(options != NULL ? options->journal_mode_wal : 0, 1);

  if (effective_options.read_only) {
    flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX;
  } else {
    flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX;
    if (effective_options.create_if_missing) {
      flags |= SQLITE_OPEN_CREATE;
    }
  }

  rc = sqlite3_open_v2(filename, &db, flags, NULL);
  if (rc != SQLITE_OK) {
    if (db != NULL) {
      sqlite3_close(db);
    }
    return rc;
  }

  sqlite3_extended_result_codes(db, 1);

  connection = (encsqlite_connection *)calloc(1, sizeof(*connection));
  if (connection == NULL) {
    sqlite3_close(db);
    return SQLITE_NOMEM;
  }

  connection->db = db;
  connection->options = effective_options;

  rc = initialize_codec_context(connection, key_material);
  if (rc != SQLITE_OK) {
    encsqlite_close_secure(connection);
    return rc;
  }

  rc = apply_runtime_policy(db, &effective_options);
  if (rc != SQLITE_OK) {
    encsqlite_close_secure(connection);
    return rc;
  }

  rc = sqlite3_set_authorizer(db, connection_authorizer, connection);
  if (rc != SQLITE_OK) {
    encsqlite_close_secure(connection);
    return rc;
  }

  *out_connection = connection;
  return SQLITE_OK;
}

struct sqlite3 *encsqlite_connection_sqlite3(const encsqlite_connection *connection) {
  return connection != NULL ? connection->db : NULL;
}

const encsqlite_codec_context *encsqlite_connection_codec(const encsqlite_connection *connection) {
  if (connection == NULL || !connection->has_codec) {
    return NULL;
  }
  return &connection->codec;
}

int encsqlite_checkpoint(encsqlite_connection *connection, int truncate) {
  if (connection == NULL || connection->db == NULL) {
    return SQLITE_MISUSE;
  }
  if (connection->options.read_only) {
    return SQLITE_READONLY;
  }

  return checkpoint_database(connection->db, truncate != 0);
}

int encsqlite_close_secure(encsqlite_connection *connection) {
  int rc;

  if (connection == NULL) {
    return SQLITE_MISUSE;
  }

  rc = sqlite3_close(connection->db);
  if (rc != SQLITE_OK) {
    return rc;
  }

  connection_zeroize_material(connection);
  connection->db = NULL;
  free(connection);
  return SQLITE_OK;
}
