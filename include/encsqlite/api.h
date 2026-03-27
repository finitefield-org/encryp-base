#ifndef ENCSQLITE_API_H
#define ENCSQLITE_API_H

#include <sqlite3.h>

#include "encsqlite/connection.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  ENCSQLITE_RESULT_OK = SQLITE_OK,
  ENCSQLITE_RESULT_ERROR = SQLITE_ERROR,
  ENCSQLITE_RESULT_NOMEM = SQLITE_NOMEM,
  ENCSQLITE_RESULT_MISUSE = SQLITE_MISUSE,
  ENCSQLITE_RESULT_BUSY = SQLITE_BUSY,
  ENCSQLITE_RESULT_LOCKED = SQLITE_LOCKED,
  ENCSQLITE_RESULT_READONLY = SQLITE_READONLY,
  ENCSQLITE_RESULT_IOERR = SQLITE_IOERR,
  ENCSQLITE_RESULT_CORRUPT = SQLITE_CORRUPT,
  ENCSQLITE_RESULT_CANTOPEN = SQLITE_CANTOPEN,
  ENCSQLITE_RESULT_AUTH = SQLITE_AUTH,
  ENCSQLITE_RESULT_NOTADB = SQLITE_NOTADB,
  ENCSQLITE_RESULT_MISMATCH = SQLITE_MISMATCH
} encsqlite_result;

int encsqlite_migrate_plaintext(
    const char *source_path,
    const char *destination_path,
    const encsqlite_key_material *destination_key,
    const encsqlite_open_options *options);

int encsqlite_rekey_copy_swap(
    const char *source_path,
    const char *destination_path,
    const encsqlite_key_material *source_key,
    const encsqlite_key_material *destination_key,
    const encsqlite_open_options *options);

int encsqlite_export(
    const char *source_path,
    const char *destination_path,
    const encsqlite_key_material *key_material,
    const encsqlite_open_options *options);

#ifdef __cplusplus
}
#endif

#endif
