#ifndef ENCSQLITE_CODEC_H
#define ENCSQLITE_CODEC_H

#include <stdint.h>

#include "encsqlite/page_format.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
  ENCSQLITE_CODEC_OK = 0,
  ENCSQLITE_CODEC_INVALID_ARGUMENT = -1,
  ENCSQLITE_CODEC_BAD_KEY_OR_FORMAT = -2,
  ENCSQLITE_CODEC_CORRUPT = -3,
  ENCSQLITE_CODEC_BACKEND_ERROR = -4,
  ENCSQLITE_CODEC_KEY_BYTES = 32
};

typedef struct {
  uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES];
  uint8_t page_key[ENCSQLITE_CODEC_KEY_BYTES];
  uint32_t key_epoch;
} encsqlite_codec_context;

typedef int (*encsqlite_codec_page_fn)(
    const void *context,
    uint32_t page_no,
    const uint8_t input_page[ENCSQLITE_PAGE_SIZE_BYTES],
    uint8_t output_page[ENCSQLITE_PAGE_SIZE_BYTES]);

typedef struct {
  const void *context;
  encsqlite_codec_page_fn encrypt_page;
  encsqlite_codec_page_fn decrypt_page;
} encsqlite_codec_bridge;

int encsqlite_codec_init(
    encsqlite_codec_context *ctx,
    const uint8_t root_secret[ENCSQLITE_CODEC_KEY_BYTES],
    const uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES],
    uint32_t key_epoch);

void encsqlite_codec_clear(encsqlite_codec_context *ctx);

int encsqlite_codec_encrypt_page(
    const encsqlite_codec_context *ctx,
    uint32_t page_no,
    const uint8_t logical_page[ENCSQLITE_PAGE_SIZE_BYTES],
    uint8_t physical_page[ENCSQLITE_PAGE_SIZE_BYTES]);

int encsqlite_codec_decrypt_page(
    const encsqlite_codec_context *ctx,
    uint32_t page_no,
    const uint8_t physical_page[ENCSQLITE_PAGE_SIZE_BYTES],
    uint8_t logical_page[ENCSQLITE_PAGE_SIZE_BYTES]);

#ifdef __cplusplus
}
#endif

#endif
