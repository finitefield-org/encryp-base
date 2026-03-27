#ifndef ENCSQLITE_PAGE_FORMAT_H
#define ENCSQLITE_PAGE_FORMAT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  ENCSQLITE_PAGE_SIZE_BYTES = 4096,
  ENCSQLITE_PAGE_RESERVED_BYTES = 36,
  ENCSQLITE_DB_SALT_BYTES = 16,
  ENCSQLITE_GCM_NONCE_BYTES = 16,
  ENCSQLITE_GCM_TAG_BYTES = 16,
  ENCSQLITE_KEY_EPOCH_BYTES = 4,
  ENCSQLITE_PAGE_USABLE_BYTES = ENCSQLITE_PAGE_SIZE_BYTES - ENCSQLITE_PAGE_RESERVED_BYTES,
  ENCSQLITE_SQLITE_HEADER_BYTES = 16,
  ENCSQLITE_PAGE1_CIPHERTEXT_BYTES =
      ENCSQLITE_PAGE_USABLE_BYTES - ENCSQLITE_SQLITE_HEADER_BYTES,
  ENCSQLITE_PAGE_N_CIPHERTEXT_BYTES = ENCSQLITE_PAGE_USABLE_BYTES,
  ENCSQLITE_PAGE1_SALT_OFFSET = 0,
  ENCSQLITE_PAGE1_CIPHERTEXT_OFFSET = ENCSQLITE_DB_SALT_BYTES,
  ENCSQLITE_PAGE1_NONCE_OFFSET =
      ENCSQLITE_PAGE1_CIPHERTEXT_OFFSET + ENCSQLITE_PAGE1_CIPHERTEXT_BYTES,
  ENCSQLITE_PAGE1_TAG_OFFSET =
      ENCSQLITE_PAGE1_NONCE_OFFSET + ENCSQLITE_GCM_NONCE_BYTES,
  ENCSQLITE_PAGE1_EPOCH_OFFSET =
      ENCSQLITE_PAGE1_TAG_OFFSET + ENCSQLITE_GCM_TAG_BYTES,
  ENCSQLITE_PAGEN_CIPHERTEXT_OFFSET = 0,
  ENCSQLITE_PAGEN_NONCE_OFFSET = ENCSQLITE_PAGE_N_CIPHERTEXT_BYTES,
  ENCSQLITE_PAGEN_TAG_OFFSET =
      ENCSQLITE_PAGEN_NONCE_OFFSET + ENCSQLITE_GCM_NONCE_BYTES,
  ENCSQLITE_PAGEN_EPOCH_OFFSET =
      ENCSQLITE_PAGEN_TAG_OFFSET + ENCSQLITE_GCM_TAG_BYTES,
  ENCSQLITE_AAD_V1_BYTES =
      (sizeof("encsqlite-page-v1") - 1) + ENCSQLITE_DB_SALT_BYTES +
      ENCSQLITE_KEY_EPOCH_BYTES + 2 * sizeof(uint32_t)
};

enum {
  ENCSQLITE_PAGE_FORMAT_OK = 0,
  ENCSQLITE_PAGE_FORMAT_INVALID_ARGUMENT = -1
};

int encsqlite_page1_pack(
    uint8_t page[ENCSQLITE_PAGE_SIZE_BYTES],
    const uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES],
    const uint8_t ciphertext[ENCSQLITE_PAGE1_CIPHERTEXT_BYTES],
    const uint8_t nonce[ENCSQLITE_GCM_NONCE_BYTES],
    const uint8_t tag[ENCSQLITE_GCM_TAG_BYTES],
    uint32_t key_epoch);

int encsqlite_page1_unpack(
    const uint8_t page[ENCSQLITE_PAGE_SIZE_BYTES],
    uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES],
    uint8_t ciphertext[ENCSQLITE_PAGE1_CIPHERTEXT_BYTES],
    uint8_t nonce[ENCSQLITE_GCM_NONCE_BYTES],
    uint8_t tag[ENCSQLITE_GCM_TAG_BYTES],
    uint32_t *key_epoch);

int encsqlite_page_n_pack(
    uint8_t page[ENCSQLITE_PAGE_SIZE_BYTES],
    const uint8_t ciphertext[ENCSQLITE_PAGE_N_CIPHERTEXT_BYTES],
    const uint8_t nonce[ENCSQLITE_GCM_NONCE_BYTES],
    const uint8_t tag[ENCSQLITE_GCM_TAG_BYTES],
    uint32_t key_epoch);

int encsqlite_page_n_unpack(
    const uint8_t page[ENCSQLITE_PAGE_SIZE_BYTES],
    uint8_t ciphertext[ENCSQLITE_PAGE_N_CIPHERTEXT_BYTES],
    uint8_t nonce[ENCSQLITE_GCM_NONCE_BYTES],
    uint8_t tag[ENCSQLITE_GCM_TAG_BYTES],
    uint32_t *key_epoch);

int encsqlite_page1_make_logical_plaintext(
    uint8_t logical_page[ENCSQLITE_PAGE_SIZE_BYTES],
    const uint8_t payload[ENCSQLITE_PAGE1_CIPHERTEXT_BYTES]);

int encsqlite_page1_extract_logical_payload(
    const uint8_t logical_page[ENCSQLITE_PAGE_SIZE_BYTES],
    uint8_t payload[ENCSQLITE_PAGE1_CIPHERTEXT_BYTES]);

int encsqlite_page1_has_sqlite_header(
    const uint8_t logical_page[ENCSQLITE_PAGE_SIZE_BYTES]);

int encsqlite_page_aad_v1(
    uint8_t *out,
    size_t out_len,
    const uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES],
    uint32_t page_no,
    uint32_t page_size,
    uint32_t key_epoch);

#ifdef __cplusplus
}
#endif

#endif
