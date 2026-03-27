#ifndef ENCSQLITE_CONNECTION_H
#define ENCSQLITE_CONNECTION_H

#include <stddef.h>
#include <stdint.h>

#include "encsqlite/codec.h"

#ifdef __cplusplus
extern "C" {
#endif

struct sqlite3;

typedef enum {
  ENCSQLITE_KEY_DEVICE_BOUND = 1,
  ENCSQLITE_KEY_PASSPHRASE = 2,
  ENCSQLITE_KEY_RAW_32 = 3
} encsqlite_key_type;

typedef struct {
  encsqlite_key_type type;
  const void *data;
  size_t data_len;
} encsqlite_key_material;

typedef struct {
  int create_if_missing;
  int read_only;
  int expect_application_id;
  uint32_t application_id;
  int journal_mode_wal;
} encsqlite_open_options;

typedef struct encsqlite_connection encsqlite_connection;

int encsqlite_open_v2(
    encsqlite_connection **out_connection,
    const char *filename,
    const encsqlite_key_material *key_material,
    const encsqlite_open_options *options);

struct sqlite3 *encsqlite_connection_sqlite3(const encsqlite_connection *connection);

const encsqlite_codec_context *encsqlite_connection_codec(const encsqlite_connection *connection);

int encsqlite_checkpoint(encsqlite_connection *connection, int truncate);

int encsqlite_close_secure(encsqlite_connection *connection);

#ifdef __cplusplus
}
#endif

#endif
