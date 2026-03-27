#include "encsqlite/page_format.h"

#include <string.h>

static const uint8_t k_sqlite_header[ENCSQLITE_SQLITE_HEADER_BYTES] = {
    'S', 'Q', 'L', 'i', 't', 'e', ' ', 'f', 'o', 'r', 'm', 'a', 't', ' ', '3', '\0'};
static const uint8_t k_aad_prefix[] = "encsqlite-page-v1";

static void store_be32(uint8_t out[4], uint32_t value) {
  out[0] = (uint8_t)((value >> 24) & 0xffU);
  out[1] = (uint8_t)((value >> 16) & 0xffU);
  out[2] = (uint8_t)((value >> 8) & 0xffU);
  out[3] = (uint8_t)(value & 0xffU);
}

static uint32_t load_be32(const uint8_t in[4]) {
  return ((uint32_t)in[0] << 24) |
         ((uint32_t)in[1] << 16) |
         ((uint32_t)in[2] << 8) |
         (uint32_t)in[3];
}

int encsqlite_page1_pack(
    uint8_t page[ENCSQLITE_PAGE_SIZE_BYTES],
    const uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES],
    const uint8_t ciphertext[ENCSQLITE_PAGE1_CIPHERTEXT_BYTES],
    const uint8_t nonce[ENCSQLITE_GCM_NONCE_BYTES],
    const uint8_t tag[ENCSQLITE_GCM_TAG_BYTES],
    uint32_t key_epoch) {
  if (page == NULL || db_salt == NULL || ciphertext == NULL || nonce == NULL || tag == NULL) {
    return ENCSQLITE_PAGE_FORMAT_INVALID_ARGUMENT;
  }

  memset(page, 0, ENCSQLITE_PAGE_SIZE_BYTES);
  memcpy(page + ENCSQLITE_PAGE1_SALT_OFFSET, db_salt, ENCSQLITE_DB_SALT_BYTES);
  memcpy(page + ENCSQLITE_PAGE1_CIPHERTEXT_OFFSET, ciphertext, ENCSQLITE_PAGE1_CIPHERTEXT_BYTES);
  memcpy(page + ENCSQLITE_PAGE1_NONCE_OFFSET, nonce, ENCSQLITE_GCM_NONCE_BYTES);
  memcpy(page + ENCSQLITE_PAGE1_TAG_OFFSET, tag, ENCSQLITE_GCM_TAG_BYTES);
  store_be32(page + ENCSQLITE_PAGE1_EPOCH_OFFSET, key_epoch);
  return ENCSQLITE_PAGE_FORMAT_OK;
}

int encsqlite_page1_unpack(
    const uint8_t page[ENCSQLITE_PAGE_SIZE_BYTES],
    uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES],
    uint8_t ciphertext[ENCSQLITE_PAGE1_CIPHERTEXT_BYTES],
    uint8_t nonce[ENCSQLITE_GCM_NONCE_BYTES],
    uint8_t tag[ENCSQLITE_GCM_TAG_BYTES],
    uint32_t *key_epoch) {
  if (page == NULL || db_salt == NULL || ciphertext == NULL || nonce == NULL || tag == NULL || key_epoch == NULL) {
    return ENCSQLITE_PAGE_FORMAT_INVALID_ARGUMENT;
  }

  memcpy(db_salt, page + ENCSQLITE_PAGE1_SALT_OFFSET, ENCSQLITE_DB_SALT_BYTES);
  memcpy(ciphertext, page + ENCSQLITE_PAGE1_CIPHERTEXT_OFFSET, ENCSQLITE_PAGE1_CIPHERTEXT_BYTES);
  memcpy(nonce, page + ENCSQLITE_PAGE1_NONCE_OFFSET, ENCSQLITE_GCM_NONCE_BYTES);
  memcpy(tag, page + ENCSQLITE_PAGE1_TAG_OFFSET, ENCSQLITE_GCM_TAG_BYTES);
  *key_epoch = load_be32(page + ENCSQLITE_PAGE1_EPOCH_OFFSET);
  return ENCSQLITE_PAGE_FORMAT_OK;
}

int encsqlite_page_n_pack(
    uint8_t page[ENCSQLITE_PAGE_SIZE_BYTES],
    const uint8_t ciphertext[ENCSQLITE_PAGE_N_CIPHERTEXT_BYTES],
    const uint8_t nonce[ENCSQLITE_GCM_NONCE_BYTES],
    const uint8_t tag[ENCSQLITE_GCM_TAG_BYTES],
    uint32_t key_epoch) {
  if (page == NULL || ciphertext == NULL || nonce == NULL || tag == NULL) {
    return ENCSQLITE_PAGE_FORMAT_INVALID_ARGUMENT;
  }

  memset(page, 0, ENCSQLITE_PAGE_SIZE_BYTES);
  memcpy(page + ENCSQLITE_PAGEN_CIPHERTEXT_OFFSET, ciphertext, ENCSQLITE_PAGE_N_CIPHERTEXT_BYTES);
  memcpy(page + ENCSQLITE_PAGEN_NONCE_OFFSET, nonce, ENCSQLITE_GCM_NONCE_BYTES);
  memcpy(page + ENCSQLITE_PAGEN_TAG_OFFSET, tag, ENCSQLITE_GCM_TAG_BYTES);
  store_be32(page + ENCSQLITE_PAGEN_EPOCH_OFFSET, key_epoch);
  return ENCSQLITE_PAGE_FORMAT_OK;
}

int encsqlite_page_n_unpack(
    const uint8_t page[ENCSQLITE_PAGE_SIZE_BYTES],
    uint8_t ciphertext[ENCSQLITE_PAGE_N_CIPHERTEXT_BYTES],
    uint8_t nonce[ENCSQLITE_GCM_NONCE_BYTES],
    uint8_t tag[ENCSQLITE_GCM_TAG_BYTES],
    uint32_t *key_epoch) {
  if (page == NULL || ciphertext == NULL || nonce == NULL || tag == NULL || key_epoch == NULL) {
    return ENCSQLITE_PAGE_FORMAT_INVALID_ARGUMENT;
  }

  memcpy(ciphertext, page + ENCSQLITE_PAGEN_CIPHERTEXT_OFFSET, ENCSQLITE_PAGE_N_CIPHERTEXT_BYTES);
  memcpy(nonce, page + ENCSQLITE_PAGEN_NONCE_OFFSET, ENCSQLITE_GCM_NONCE_BYTES);
  memcpy(tag, page + ENCSQLITE_PAGEN_TAG_OFFSET, ENCSQLITE_GCM_TAG_BYTES);
  *key_epoch = load_be32(page + ENCSQLITE_PAGEN_EPOCH_OFFSET);
  return ENCSQLITE_PAGE_FORMAT_OK;
}

int encsqlite_page1_make_logical_plaintext(
    uint8_t logical_page[ENCSQLITE_PAGE_SIZE_BYTES],
    const uint8_t payload[ENCSQLITE_PAGE1_CIPHERTEXT_BYTES]) {
  if (logical_page == NULL || payload == NULL) {
    return ENCSQLITE_PAGE_FORMAT_INVALID_ARGUMENT;
  }

  memset(logical_page, 0, ENCSQLITE_PAGE_SIZE_BYTES);
  memcpy(logical_page, k_sqlite_header, ENCSQLITE_SQLITE_HEADER_BYTES);
  memcpy(logical_page + ENCSQLITE_SQLITE_HEADER_BYTES, payload, ENCSQLITE_PAGE1_CIPHERTEXT_BYTES);
  return ENCSQLITE_PAGE_FORMAT_OK;
}

int encsqlite_page1_extract_logical_payload(
    const uint8_t logical_page[ENCSQLITE_PAGE_SIZE_BYTES],
    uint8_t payload[ENCSQLITE_PAGE1_CIPHERTEXT_BYTES]) {
  if (logical_page == NULL || payload == NULL) {
    return ENCSQLITE_PAGE_FORMAT_INVALID_ARGUMENT;
  }

  memcpy(payload, logical_page + ENCSQLITE_SQLITE_HEADER_BYTES, ENCSQLITE_PAGE1_CIPHERTEXT_BYTES);
  return ENCSQLITE_PAGE_FORMAT_OK;
}

int encsqlite_page1_has_sqlite_header(
    const uint8_t logical_page[ENCSQLITE_PAGE_SIZE_BYTES]) {
  if (logical_page == NULL) {
    return 0;
  }
  return memcmp(logical_page, k_sqlite_header, ENCSQLITE_SQLITE_HEADER_BYTES) == 0;
}

int encsqlite_page_aad_v1(
    uint8_t *out,
    size_t out_len,
    const uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES],
    uint32_t page_no,
    uint32_t page_size,
    uint32_t key_epoch) {
  size_t offset = 0;

  if (out == NULL || db_salt == NULL || page_no == 0 || page_size == 0 || out_len < ENCSQLITE_AAD_V1_BYTES) {
    return ENCSQLITE_PAGE_FORMAT_INVALID_ARGUMENT;
  }
  if (page_size != ENCSQLITE_PAGE_SIZE_BYTES) {
    return ENCSQLITE_PAGE_FORMAT_INVALID_ARGUMENT;
  }

  memcpy(out + offset, k_aad_prefix, sizeof(k_aad_prefix) - 1);
  offset += sizeof(k_aad_prefix) - 1;
  memcpy(out + offset, db_salt, ENCSQLITE_DB_SALT_BYTES);
  offset += ENCSQLITE_DB_SALT_BYTES;
  store_be32(out + offset, page_no);
  offset += sizeof(uint32_t);
  store_be32(out + offset, page_size);
  offset += sizeof(uint32_t);
  store_be32(out + offset, key_epoch);
  offset += sizeof(uint32_t);

  return offset == ENCSQLITE_AAD_V1_BYTES ? ENCSQLITE_PAGE_FORMAT_OK : ENCSQLITE_PAGE_FORMAT_INVALID_ARGUMENT;
}
