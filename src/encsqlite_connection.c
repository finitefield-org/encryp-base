#include "encsqlite/connection.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "encsqlite/crypto.h"
#include "sqlite3.h"

extern int encsqlite_sqlite3_open_v2(
    const char *filename,
    struct sqlite3 **ppDb,
    int flags,
    const char *zVfs,
    const encsqlite_codec_bridge *bridge);

struct encsqlite_connection {
  struct sqlite3 *db;
  encsqlite_open_options options;
  uint8_t root_secret[ENCSQLITE_CODEC_KEY_BYTES];
  int has_root_secret;
  encsqlite_codec_context codec;
  int has_codec;
  encsqlite_codec_bridge codec_bridge;
};

static void connection_zeroize_material(encsqlite_connection *connection) {
  if (connection == NULL) {
    return;
  }

  encsqlite_zeroize(connection->root_secret, sizeof(connection->root_secret));
  encsqlite_codec_clear(&connection->codec);
  memset(&connection->codec_bridge, 0, sizeof(connection->codec_bridge));
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
        if (ascii_ieq(param1, "key") || ascii_iprefix(param1, "cipher_")) {
          return SQLITE_IGNORE;
        }
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

static int codec_bridge_encrypt_page(
    const void *context,
    uint32_t page_no,
    const uint8_t input_page[ENCSQLITE_PAGE_SIZE_BYTES],
    uint8_t output_page[ENCSQLITE_PAGE_SIZE_BYTES]) {
  return encsqlite_codec_encrypt_page(
      (const encsqlite_codec_context *)context,
      page_no,
      input_page,
      output_page);
}

static int codec_bridge_decrypt_page(
    const void *context,
    uint32_t page_no,
    const uint8_t input_page[ENCSQLITE_PAGE_SIZE_BYTES],
    uint8_t output_page[ENCSQLITE_PAGE_SIZE_BYTES]) {
  return encsqlite_codec_decrypt_page(
      (const encsqlite_codec_context *)context,
      page_no,
      input_page,
      output_page);
}

static int load_db_salt(
    const char *filename,
    const encsqlite_open_options *options,
    uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES]) {
  static const uint8_t sqlite_header[ENCSQLITE_SQLITE_HEADER_BYTES] = {
      'S', 'Q', 'L', 'i', 't', 'e', ' ', 'f',
      'o', 'r', 'm', 'a', 't', ' ', '3', '\0'};
  struct stat st;
  FILE *file = NULL;
  size_t bytes_read;

  if (filename == NULL || options == NULL || db_salt == NULL) {
    return SQLITE_MISUSE;
  }

  if (stat(filename, &st) != 0) {
    if (errno == ENOENT && options->create_if_missing && !options->read_only) {
      int rc = encsqlite_random_bytes(db_salt, ENCSQLITE_DB_SALT_BYTES);
      return rc == ENCSQLITE_CRYPTO_OK ? SQLITE_OK : SQLITE_ERROR;
    }
    return SQLITE_CANTOPEN;
  }

  if (st.st_size == 0) {
    if (options->create_if_missing && !options->read_only) {
      int rc = encsqlite_random_bytes(db_salt, ENCSQLITE_DB_SALT_BYTES);
      return rc == ENCSQLITE_CRYPTO_OK ? SQLITE_OK : SQLITE_ERROR;
    }
    return SQLITE_NOTADB;
  }

  file = fopen(filename, "rb");
  if (file == NULL) {
    return SQLITE_CANTOPEN;
  }

  bytes_read = fread(db_salt, 1, ENCSQLITE_DB_SALT_BYTES, file);
  fclose(file);
  if (bytes_read != ENCSQLITE_DB_SALT_BYTES) {
    return SQLITE_NOTADB;
  }
  if (memcmp(db_salt, sqlite_header, sizeof(sqlite_header)) == 0) {
    return SQLITE_NOTADB;
  }

  return SQLITE_OK;
}

static int initialize_codec_context(
    encsqlite_connection *connection,
    const encsqlite_key_material *key_material,
    const uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES]) {
  int rc;

  if (connection == NULL) {
    return SQLITE_MISUSE;
  }
  if (key_material == NULL) {
    return SQLITE_OK;
  }
  if (key_material->type != ENCSQLITE_KEY_RAW_32) {
    return SQLITE_MISUSE;
  }
  if (key_material->data_len != ENCSQLITE_CODEC_KEY_BYTES || key_material->data == NULL) {
    return SQLITE_MISUSE;
  }
  if (db_salt == NULL) {
    return SQLITE_MISUSE;
  }

  memcpy(connection->root_secret, key_material->data, ENCSQLITE_CODEC_KEY_BYTES);
  connection->has_root_secret = 1;
  rc = encsqlite_codec_init(&connection->codec, connection->root_secret, db_salt, 1U);
  if (rc != ENCSQLITE_CODEC_OK) {
    return SQLITE_ERROR;
  }
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
  uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES];
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

  connection = (encsqlite_connection *)calloc(1, sizeof(*connection));
  if (connection == NULL) {
    return SQLITE_NOMEM;
  }
  connection->options = effective_options;

  if (effective_options.read_only) {
    flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX;
  } else {
    flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX;
    if (effective_options.create_if_missing) {
      flags |= SQLITE_OPEN_CREATE;
    }
  }

  if (key_material != NULL) {
    if (key_material->type != ENCSQLITE_KEY_RAW_32 ||
        key_material->data_len != ENCSQLITE_CODEC_KEY_BYTES ||
        key_material->data == NULL) {
      connection_zeroize_material(connection);
      free(connection);
      return SQLITE_MISUSE;
    }
    rc = load_db_salt(filename, &effective_options, db_salt);
    if (rc != SQLITE_OK) {
      connection_zeroize_material(connection);
      free(connection);
      return rc;
    }
    rc = initialize_codec_context(connection, key_material, db_salt);
    encsqlite_zeroize(db_salt, sizeof(db_salt));
    if (rc != SQLITE_OK) {
      connection_zeroize_material(connection);
      free(connection);
      return rc;
    }
    connection->codec_bridge.context = &connection->codec;
    connection->codec_bridge.encrypt_page = codec_bridge_encrypt_page;
    connection->codec_bridge.decrypt_page = codec_bridge_decrypt_page;
  }

  rc = encsqlite_sqlite3_open_v2(
      filename,
      &db,
      flags,
      NULL,
      connection->has_codec ? &connection->codec_bridge : NULL);
  if (rc != SQLITE_OK) {
    if (db != NULL) {
      sqlite3_close(db);
    }
    connection_zeroize_material(connection);
    free(connection);
    return rc;
  }

  sqlite3_extended_result_codes(db, 1);

  connection->db = db;

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
