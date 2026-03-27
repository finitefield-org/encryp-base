#include <jni.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <encsqlite/api.h>
#include <encsqlite/connection.h>
#include <encsqlite/crypto.h>
#include "sqlite3.h"

enum {
  SQLITE_ROW_CODE = 100,
  SQLITE_DONE_CODE = 101,
  SQLITE_MISUSE_CODE = 21,
  SQLITE_RANGE_CODE = 25,
  SQLITE_READONLY_CODE = 8
};

static encsqlite_connection *connection_from_handle(jlong handle) {
  return (encsqlite_connection *)(intptr_t)handle;
}

static sqlite3_stmt *statement_from_handle(jlong handle) {
  return (sqlite3_stmt *)(intptr_t)handle;
}

static void throw_java_exception(
    JNIEnv *env,
    const char *class_name,
    const char *message) {
  jclass exception_class;

  exception_class = (*env)->FindClass(env, class_name);
  if (exception_class == NULL) {
    return;
  }
  (*env)->ThrowNew(env, exception_class, message);
}

static void throw_illegal_argument(JNIEnv *env, const char *message) {
  throw_java_exception(env, "java/lang/IllegalArgumentException", message);
}

static void throw_illegal_state(JNIEnv *env, const char *message) {
  throw_java_exception(env, "java/lang/IllegalStateException", message);
}

static void throw_sqlite_exception(
    JNIEnv *env,
    sqlite3 *db,
    int rc,
    const char *context) {
  char buffer[256];
  const char *detail;

  detail = db != NULL ? sqlite3_errmsg(db) : sqlite3_errstr(rc);
  if (detail == NULL) {
    detail = "unknown";
  }
  snprintf(buffer, sizeof(buffer), "%s (code %d): %s", context, rc, detail);
  throw_java_exception(env, "android/database/sqlite/SQLiteException", buffer);
}

static jsize utf16_c_string_length(const jchar *text) {
  jsize length = 0;

  if (text == NULL) {
    return 0;
  }

  while (text[length] != 0) {
    length++;
  }
  return length;
}

static jlong open_connection_internal(
    JNIEnv *env,
    jobject thiz,
    jstring file_name,
    jbyteArray key_bytes,
    jboolean create_if_missing,
    jboolean read_only,
    jboolean expect_application_id,
    jint application_id,
    jboolean journal_mode_wal) {
  const char *file_name_chars = NULL;
  jbyte *key_copy = NULL;
  jsize key_len;
  encsqlite_connection *connection = NULL;
  encsqlite_key_material key_material;
  encsqlite_open_options options;
  sqlite3 *db = NULL;
  int rc;
  jlong result = 0;

  (void)thiz;

  if (file_name == NULL || key_bytes == NULL) {
    throw_illegal_argument(env, "file name and key bytes are required");
    return 0;
  }

  key_len = (*env)->GetArrayLength(env, key_bytes);
  if (key_len != ENCSQLITE_CODEC_KEY_BYTES) {
    throw_illegal_argument(env, "key bytes must be exactly 32 bytes");
    return 0;
  }

  file_name_chars = (*env)->GetStringUTFChars(env, file_name, NULL);
  if (file_name_chars == NULL) {
    return 0;
  }

  key_copy = (jbyte *)malloc((size_t)key_len);
  if (key_copy == NULL) {
    (*env)->ReleaseStringUTFChars(env, file_name, file_name_chars);
    throw_java_exception(env, "java/lang/OutOfMemoryError", "out of memory");
    return 0;
  }

  (*env)->GetByteArrayRegion(env, key_bytes, 0, key_len, key_copy);
  if ((*env)->ExceptionCheck(env)) {
    encsqlite_zeroize(key_copy, (size_t)key_len);
    free(key_copy);
    (*env)->ReleaseStringUTFChars(env, file_name, file_name_chars);
    return 0;
  }

  rc = encsqlite_crypto_init();
  if (rc != ENCSQLITE_CRYPTO_OK) {
    throw_illegal_state(env, "crypto backend initialization failed");
    goto cleanup;
  }

  key_material.type = ENCSQLITE_KEY_RAW_32;
  key_material.data = key_copy;
  key_material.data_len = (size_t)key_len;

  options.create_if_missing = create_if_missing ? 1 : 0;
  options.read_only = read_only ? 1 : 0;
  options.expect_application_id = expect_application_id ? 1 : 0;
  options.application_id = (uint32_t)application_id;
  options.journal_mode_wal = journal_mode_wal ? 1 : 0;

  rc = encsqlite_open_v2(&connection, file_name_chars, &key_material, &options);
  if (rc != SQLITE_OK) {
    db = connection != NULL ? encsqlite_connection_sqlite3(connection) : NULL;
    throw_sqlite_exception(env, db, rc, "open failed");
    if (connection != NULL) {
      (void)encsqlite_close_secure(connection);
      connection = NULL;
    }
    goto cleanup;
  }

  result = (jlong)(intptr_t)connection;

cleanup:
  if (key_copy != NULL) {
    encsqlite_zeroize(key_copy, (size_t)key_len);
    free(key_copy);
  }
  if (file_name_chars != NULL) {
    (*env)->ReleaseStringUTFChars(env, file_name, file_name_chars);
  }
  return result;
}

static jint close_connection_internal(encsqlite_connection *connection) {
  if (connection == NULL) {
    return SQLITE_MISUSE;
  }
  return encsqlite_close_secure(connection);
}

static jint checkpoint_connection_internal(encsqlite_connection *connection, jboolean truncate) {
  if (connection == NULL) {
    return SQLITE_MISUSE;
  }
  return encsqlite_checkpoint(connection, truncate ? 1 : 0);
}

static jboolean connection_in_transaction_internal(
    JNIEnv *env,
    encsqlite_connection *connection) {
  sqlite3 *db;

  if (connection == NULL) {
    throw_illegal_state(env, "connection is closed");
    return JNI_FALSE;
  }

  db = encsqlite_connection_sqlite3(connection);
  if (db == NULL) {
    throw_illegal_state(env, "connection is closed");
    return JNI_FALSE;
  }
  return sqlite3_get_autocommit(db) == 0 ? JNI_TRUE : JNI_FALSE;
}

static jint finalize_statement_internal(sqlite3_stmt *statement) {
  if (statement == NULL) {
    return SQLITE_MISUSE;
  }
  return sqlite3_finalize(statement);
}

static jint bind_blob_internal(
    JNIEnv *env,
    sqlite3_stmt *statement,
    jint index,
    jbyteArray value) {
  jbyte *blob = NULL;
  jsize blob_len;
  jint rc;

  if (statement == NULL || value == NULL) {
    throw_illegal_argument(env, "statement and blob value are required");
    return SQLITE_MISUSE;
  }

  blob_len = (*env)->GetArrayLength(env, value);
  blob = (jbyte *)malloc((size_t)blob_len);
  if (blob == NULL) {
    throw_java_exception(env, "java/lang/OutOfMemoryError", "out of memory");
    return SQLITE_MISUSE;
  }

  (*env)->GetByteArrayRegion(env, value, 0, blob_len, blob);
  if ((*env)->ExceptionCheck(env)) {
    encsqlite_zeroize(blob, (size_t)blob_len);
    free(blob);
    return SQLITE_MISUSE;
  }

  rc = sqlite3_bind_blob(statement, index, blob, (int)blob_len, SQLITE_TRANSIENT);
  encsqlite_zeroize(blob, (size_t)blob_len);
  free(blob);
  return rc;
}

static jint bind_long_internal(sqlite3_stmt *statement, jint index, jlong value) {
  if (statement == NULL) {
    return SQLITE_MISUSE;
  }
  return sqlite3_bind_int64(statement, index, (sqlite3_int64)value);
}

static jint bind_double_internal(sqlite3_stmt *statement, jint index, jdouble value) {
  if (statement == NULL) {
    return SQLITE_MISUSE;
  }
  return sqlite3_bind_double(statement, index, (double)value);
}

static jint bind_text_internal(
    JNIEnv *env,
    sqlite3_stmt *statement,
    jint index,
    jstring value) {
  const jchar *chars = NULL;
  jsize char_len;
  jint rc;

  if (statement == NULL || value == NULL) {
    throw_illegal_argument(env, "statement and text value are required");
    return SQLITE_MISUSE;
  }

  chars = (*env)->GetStringChars(env, value, NULL);
  if (chars == NULL) {
    return SQLITE_MISUSE;
  }
  char_len = (*env)->GetStringLength(env, value);
  rc = sqlite3_bind_text16(
      statement,
      index,
      chars,
      (int)(char_len * (jsize)sizeof(jchar)),
      SQLITE_TRANSIENT);
  (*env)->ReleaseStringChars(env, value, chars);
  return rc;
}

static jint bind_null_internal(sqlite3_stmt *statement, jint index) {
  if (statement == NULL) {
    return SQLITE_MISUSE;
  }
  return sqlite3_bind_null(statement, index);
}

static jint clear_bindings_internal(sqlite3_stmt *statement) {
  if (statement == NULL) {
    return SQLITE_MISUSE;
  }
  return sqlite3_clear_bindings(statement);
}

static jint reset_statement_internal(sqlite3_stmt *statement) {
  if (statement == NULL) {
    return SQLITE_MISUSE;
  }
  return sqlite3_reset(statement);
}

static jint step_statement_internal(sqlite3_stmt *statement) {
  if (statement == NULL) {
    return SQLITE_MISUSE;
  }
  return sqlite3_step(statement);
}

static jint get_column_count_internal(sqlite3_stmt *statement) {
  if (statement == NULL) {
    return 0;
  }
  return sqlite3_column_count(statement);
}

static jstring get_column_name_internal(
    JNIEnv *env,
    sqlite3_stmt *statement,
    jint index) {
  const jchar *name;
  jsize name_len;

  if (statement == NULL) {
    throw_illegal_state(env, "statement is closed");
    return NULL;
  }

  name = (const jchar *)sqlite3_column_name16(statement, index);
  if (name == NULL) {
    throw_sqlite_exception(env, sqlite3_db_handle(statement), SQLITE_NOMEM, "column name unavailable");
    return NULL;
  }

  name_len = utf16_c_string_length(name);
  return (*env)->NewString(env, name, name_len);
}

static jint get_column_type_internal(sqlite3_stmt *statement, jint index) {
  if (statement == NULL) {
    return SQLITE_NULL;
  }
  return sqlite3_column_type(statement, index);
}

static jboolean is_column_null_internal(sqlite3_stmt *statement, jint index) {
  if (statement == NULL) {
    return JNI_TRUE;
  }
  return sqlite3_column_type(statement, index) == SQLITE_NULL ? JNI_TRUE : JNI_FALSE;
}

static jlong get_column_long_internal(sqlite3_stmt *statement, jint index) {
  if (statement == NULL) {
    return 0;
  }
  return (jlong)sqlite3_column_int64(statement, index);
}

static jdouble get_column_double_internal(sqlite3_stmt *statement, jint index) {
  if (statement == NULL) {
    return 0.0;
  }
  return (jdouble)sqlite3_column_double(statement, index);
}

static jstring get_column_text_internal(
    JNIEnv *env,
    sqlite3_stmt *statement,
    jint index) {
  const jchar *text;
  jsize text_len;
  int bytes;

  if (statement == NULL) {
    throw_illegal_state(env, "statement is closed");
    return NULL;
  }

  text = (const jchar *)sqlite3_column_text16(statement, index);
  bytes = sqlite3_column_bytes16(statement, index);
  if (sqlite3_errcode(sqlite3_db_handle(statement)) == SQLITE_NOMEM) {
    throw_java_exception(env, "java/lang/OutOfMemoryError", "out of memory");
    return NULL;
  }
  if (text == NULL) {
    if (bytes == 0) {
      static const jchar empty_text[] = {0};
      return (*env)->NewString(env, empty_text, 0);
    }
    throw_sqlite_exception(env, sqlite3_db_handle(statement), sqlite3_errcode(sqlite3_db_handle(statement)), "column text unavailable");
    return NULL;
  }

  text_len = (jsize)(bytes / (int)sizeof(jchar));
  return (*env)->NewString(env, text, text_len);
}

static jbyteArray get_column_blob_internal(
    JNIEnv *env,
    sqlite3_stmt *statement,
    jint index) {
  const void *blob;
  int bytes;
  jbyteArray result;

  if (statement == NULL) {
    throw_illegal_state(env, "statement is closed");
    return NULL;
  }

  blob = sqlite3_column_blob(statement, index);
  bytes = sqlite3_column_bytes(statement, index);
  if (sqlite3_errcode(sqlite3_db_handle(statement)) == SQLITE_NOMEM) {
    throw_java_exception(env, "java/lang/OutOfMemoryError", "out of memory");
    return NULL;
  }
  if (blob == NULL) {
    if (bytes == 0) {
      return (*env)->NewByteArray(env, 0);
    }
    throw_sqlite_exception(
        env,
        sqlite3_db_handle(statement),
        sqlite3_errcode(sqlite3_db_handle(statement)),
        "column blob unavailable");
    return NULL;
  }

  result = (*env)->NewByteArray(env, bytes);
  if (result == NULL) {
    return NULL;
  }
  (*env)->SetByteArrayRegion(env, result, 0, bytes, (const jbyte *)blob);
  return result;
}

JNIEXPORT jlong JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeOpenConnection(
    JNIEnv *env,
    jobject thiz,
    jstring fileName,
    jbyteArray keyBytes,
    jboolean createIfMissing,
    jboolean readOnly,
    jboolean expectApplicationId,
    jint applicationId,
    jboolean journalModeWal) {
  return open_connection_internal(
      env,
      thiz,
      fileName,
      keyBytes,
      createIfMissing,
      readOnly,
      expectApplicationId,
      applicationId,
      journalModeWal);
}

JNIEXPORT jint JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeCloseConnection(
    JNIEnv *env,
    jobject thiz,
    jlong connectionHandle) {
  (void)env;
  (void)thiz;
  return close_connection_internal(connection_from_handle(connectionHandle));
}

JNIEXPORT jboolean JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeConnectionInTransaction(
    JNIEnv *env,
    jobject thiz,
    jlong connectionHandle) {
  (void)thiz;
  return connection_in_transaction_internal(env, connection_from_handle(connectionHandle));
}

JNIEXPORT jint JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeCheckpointConnection(
    JNIEnv *env,
    jobject thiz,
    jlong connectionHandle,
    jboolean truncate) {
  (void)env;
  (void)thiz;
  return checkpoint_connection_internal(connection_from_handle(connectionHandle), truncate);
}

JNIEXPORT jlong JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativePrepareStatement(
    JNIEnv *env,
    jobject thiz,
    jlong connectionHandle,
    jstring sql) {
  const char *sql_chars = NULL;
  encsqlite_connection *connection;
  sqlite3 *db;
  sqlite3_stmt *statement = NULL;
  int rc;
  jlong result = 0;

  (void)thiz;

  if (connectionHandle == 0 || sql == NULL) {
    throw_illegal_argument(env, "connection and SQL are required");
    return 0;
  }

  connection = connection_from_handle(connectionHandle);
  db = encsqlite_connection_sqlite3(connection);
  if (db == NULL) {
    throw_illegal_state(env, "connection is closed");
    return 0;
  }

  sql_chars = (*env)->GetStringUTFChars(env, sql, NULL);
  if (sql_chars == NULL) {
    return 0;
  }

  rc = sqlite3_prepare_v2(db, sql_chars, -1, &statement, NULL);
  (*env)->ReleaseStringUTFChars(env, sql, sql_chars);
  if (rc != SQLITE_OK) {
    if (statement != NULL) {
      (void)sqlite3_finalize(statement);
    }
    throw_sqlite_exception(env, db, rc, "prepare failed");
    return 0;
  }

  result = (jlong)(intptr_t)statement;
  return result;
}

JNIEXPORT jint JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeFinalizeStatement(
    JNIEnv *env,
    jobject thiz,
    jlong statementHandle) {
  (void)env;
  (void)thiz;
  return finalize_statement_internal(statement_from_handle(statementHandle));
}

JNIEXPORT jint JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeBindBlob(
    JNIEnv *env,
    jobject thiz,
    jlong statementHandle,
    jint index,
    jbyteArray value) {
  (void)thiz;
  return bind_blob_internal(env, statement_from_handle(statementHandle), index, value);
}

JNIEXPORT jint JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeBindLong(
    JNIEnv *env,
    jobject thiz,
    jlong statementHandle,
    jint index,
    jlong value) {
  (void)env;
  (void)thiz;
  return bind_long_internal(statement_from_handle(statementHandle), index, value);
}

JNIEXPORT jint JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeBindDouble(
    JNIEnv *env,
    jobject thiz,
    jlong statementHandle,
    jint index,
    jdouble value) {
  (void)env;
  (void)thiz;
  return bind_double_internal(statement_from_handle(statementHandle), index, value);
}

JNIEXPORT jint JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeBindText(
    JNIEnv *env,
    jobject thiz,
    jlong statementHandle,
    jint index,
    jstring value) {
  (void)thiz;
  return bind_text_internal(env, statement_from_handle(statementHandle), index, value);
}

JNIEXPORT jint JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeBindNull(
    JNIEnv *env,
    jobject thiz,
    jlong statementHandle,
    jint index) {
  (void)env;
  (void)thiz;
  return bind_null_internal(statement_from_handle(statementHandle), index);
}

JNIEXPORT jint JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeClearBindings(
    JNIEnv *env,
    jobject thiz,
    jlong statementHandle) {
  (void)env;
  (void)thiz;
  return clear_bindings_internal(statement_from_handle(statementHandle));
}

JNIEXPORT jint JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeResetStatement(
    JNIEnv *env,
    jobject thiz,
    jlong statementHandle) {
  (void)env;
  (void)thiz;
  return reset_statement_internal(statement_from_handle(statementHandle));
}

JNIEXPORT jint JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeStepStatement(
    JNIEnv *env,
    jobject thiz,
    jlong statementHandle) {
  (void)env;
  (void)thiz;
  return step_statement_internal(statement_from_handle(statementHandle));
}

JNIEXPORT jint JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeGetColumnCount(
    JNIEnv *env,
    jobject thiz,
    jlong statementHandle) {
  (void)env;
  (void)thiz;
  return get_column_count_internal(statement_from_handle(statementHandle));
}

JNIEXPORT jstring JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeGetColumnName(
    JNIEnv *env,
    jobject thiz,
    jlong statementHandle,
    jint index) {
  (void)thiz;
  return get_column_name_internal(env, statement_from_handle(statementHandle), index);
}

JNIEXPORT jint JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeGetColumnType(
    JNIEnv *env,
    jobject thiz,
    jlong statementHandle,
    jint index) {
  (void)env;
  (void)thiz;
  return get_column_type_internal(statement_from_handle(statementHandle), index);
}

JNIEXPORT jboolean JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeIsColumnNull(
    JNIEnv *env,
    jobject thiz,
    jlong statementHandle,
    jint index) {
  (void)env;
  (void)thiz;
  return is_column_null_internal(statement_from_handle(statementHandle), index);
}

JNIEXPORT jlong JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeGetColumnLong(
    JNIEnv *env,
    jobject thiz,
    jlong statementHandle,
    jint index) {
  (void)env;
  (void)thiz;
  return get_column_long_internal(statement_from_handle(statementHandle), index);
}

JNIEXPORT jdouble JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeGetColumnDouble(
    JNIEnv *env,
    jobject thiz,
    jlong statementHandle,
    jint index) {
  (void)env;
  (void)thiz;
  return get_column_double_internal(statement_from_handle(statementHandle), index);
}

JNIEXPORT jstring JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeGetColumnText(
    JNIEnv *env,
    jobject thiz,
    jlong statementHandle,
    jint index) {
  (void)thiz;
  return get_column_text_internal(env, statement_from_handle(statementHandle), index);
}

JNIEXPORT jbyteArray JNICALL
Java_io_github_kazuyoshitoshiya_encrypbase_android_EncSQLiteNative_nativeGetColumnBlob(
    JNIEnv *env,
    jobject thiz,
    jlong statementHandle,
    jint index) {
  (void)thiz;
  return get_column_blob_internal(env, statement_from_handle(statementHandle), index);
}
