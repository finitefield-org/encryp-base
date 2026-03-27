#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "encsqlite/page_format.h"

static void fail(const char *message) {
  fprintf(stderr, "%s\n", message);
  abort();
}

static void check_true(int condition, const char *message) {
  if (!condition) {
    fail(message);
  }
}

static void check_bytes(const uint8_t *lhs, const uint8_t *rhs, size_t len) {
  if (memcmp(lhs, rhs, len) != 0) {
    fail("byte comparison failed");
  }
}

static void fill_sequence(uint8_t *buffer, size_t len, uint8_t base) {
  for (size_t i = 0; i < len; ++i) {
    buffer[i] = (uint8_t)(base + i);
  }
}

static void test_constants(void) {
  check_true(ENCSQLITE_PAGE_SIZE_BYTES == 4096, "page size mismatch");
  check_true(ENCSQLITE_PAGE_RESERVED_BYTES == 36, "reserved bytes mismatch");
  check_true(ENCSQLITE_DB_SALT_BYTES == 16, "salt bytes mismatch");
  check_true(ENCSQLITE_GCM_NONCE_BYTES == 16, "nonce bytes mismatch");
  check_true(ENCSQLITE_GCM_TAG_BYTES == 16, "tag bytes mismatch");
  check_true(ENCSQLITE_PAGE1_CIPHERTEXT_BYTES == 4044, "page1 ciphertext size mismatch");
  check_true(ENCSQLITE_PAGE_N_CIPHERTEXT_BYTES == 4060, "pageN ciphertext size mismatch");
  check_true(ENCSQLITE_AAD_V1_BYTES == 45, "AAD size mismatch");
}

static void test_page1_layout(void) {
  uint8_t page[ENCSQLITE_PAGE_SIZE_BYTES];
  uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES];
  uint8_t ciphertext[ENCSQLITE_PAGE1_CIPHERTEXT_BYTES];
  uint8_t nonce[ENCSQLITE_GCM_NONCE_BYTES];
  uint8_t tag[ENCSQLITE_GCM_TAG_BYTES];
  uint8_t unpack_salt[ENCSQLITE_DB_SALT_BYTES];
  uint8_t unpack_ciphertext[ENCSQLITE_PAGE1_CIPHERTEXT_BYTES];
  uint8_t unpack_nonce[ENCSQLITE_GCM_NONCE_BYTES];
  uint8_t unpack_tag[ENCSQLITE_GCM_TAG_BYTES];
  uint32_t unpack_epoch = 0;

  fill_sequence(db_salt, sizeof(db_salt), 0x10);
  fill_sequence(ciphertext, sizeof(ciphertext), 0x20);
  fill_sequence(nonce, sizeof(nonce), 0x80);
  fill_sequence(tag, sizeof(tag), 0x90);

  check_true(
      encsqlite_page1_pack(page, db_salt, ciphertext, nonce, tag, 0x01020304) == ENCSQLITE_PAGE_FORMAT_OK,
      "page1 pack failed");
  check_bytes(page + ENCSQLITE_PAGE1_SALT_OFFSET, db_salt, sizeof(db_salt));
  check_bytes(page + ENCSQLITE_PAGE1_CIPHERTEXT_OFFSET, ciphertext, sizeof(ciphertext));
  check_bytes(page + ENCSQLITE_PAGE1_NONCE_OFFSET, nonce, sizeof(nonce));
  check_bytes(page + ENCSQLITE_PAGE1_TAG_OFFSET, tag, sizeof(tag));
  check_true(page[ENCSQLITE_PAGE1_EPOCH_OFFSET + 0] == 0x01, "page1 epoch byte 0 mismatch");
  check_true(page[ENCSQLITE_PAGE1_EPOCH_OFFSET + 1] == 0x02, "page1 epoch byte 1 mismatch");
  check_true(page[ENCSQLITE_PAGE1_EPOCH_OFFSET + 2] == 0x03, "page1 epoch byte 2 mismatch");
  check_true(page[ENCSQLITE_PAGE1_EPOCH_OFFSET + 3] == 0x04, "page1 epoch byte 3 mismatch");

  check_true(
      encsqlite_page1_unpack(page, unpack_salt, unpack_ciphertext, unpack_nonce, unpack_tag, &unpack_epoch) ==
          ENCSQLITE_PAGE_FORMAT_OK,
      "page1 unpack failed");
  check_bytes(unpack_salt, db_salt, sizeof(db_salt));
  check_bytes(unpack_ciphertext, ciphertext, sizeof(ciphertext));
  check_bytes(unpack_nonce, nonce, sizeof(nonce));
  check_bytes(unpack_tag, tag, sizeof(tag));
  check_true(unpack_epoch == 0x01020304U, "page1 epoch decode mismatch");

  memset(page, 0xAA, sizeof(page));
  check_true(
      encsqlite_page1_make_logical_plaintext(page, ciphertext) == ENCSQLITE_PAGE_FORMAT_OK,
      "page1 logical plaintext build failed");
  check_true(encsqlite_page1_has_sqlite_header(page) == 1, "logical header missing");
  static const uint8_t expected_header[ENCSQLITE_SQLITE_HEADER_BYTES] = {
      'S', 'Q', 'L', 'i', 't', 'e', ' ', 'f', 'o', 'r', 'm', 'a', 't', ' ', '3', '\0'};
  check_bytes(page, expected_header, sizeof(expected_header));
  check_bytes(page + ENCSQLITE_SQLITE_HEADER_BYTES, ciphertext, sizeof(ciphertext));
  for (size_t i = ENCSQLITE_PAGE1_CIPHERTEXT_BYTES + ENCSQLITE_SQLITE_HEADER_BYTES; i < ENCSQLITE_PAGE_SIZE_BYTES; ++i) {
    check_true(page[i] == 0, "page1 tail bytes should be zero");
  }

  memset(unpack_ciphertext, 0, sizeof(unpack_ciphertext));
  check_true(
      encsqlite_page1_extract_logical_payload(page, unpack_ciphertext) == ENCSQLITE_PAGE_FORMAT_OK,
      "page1 logical payload extraction failed");
  check_bytes(unpack_ciphertext, ciphertext, sizeof(ciphertext));
}

static void test_page_n_layout(void) {
  uint8_t page[ENCSQLITE_PAGE_SIZE_BYTES];
  uint8_t ciphertext[ENCSQLITE_PAGE_N_CIPHERTEXT_BYTES];
  uint8_t nonce[ENCSQLITE_GCM_NONCE_BYTES];
  uint8_t tag[ENCSQLITE_GCM_TAG_BYTES];
  uint8_t unpack_ciphertext[ENCSQLITE_PAGE_N_CIPHERTEXT_BYTES];
  uint8_t unpack_nonce[ENCSQLITE_GCM_NONCE_BYTES];
  uint8_t unpack_tag[ENCSQLITE_GCM_TAG_BYTES];
  uint32_t unpack_epoch = 0;

  fill_sequence(ciphertext, sizeof(ciphertext), 0x30);
  fill_sequence(nonce, sizeof(nonce), 0x40);
  fill_sequence(tag, sizeof(tag), 0x50);

  check_true(
      encsqlite_page_n_pack(page, ciphertext, nonce, tag, 0x55667788) == ENCSQLITE_PAGE_FORMAT_OK,
      "pageN pack failed");
  check_bytes(page + ENCSQLITE_PAGEN_CIPHERTEXT_OFFSET, ciphertext, sizeof(ciphertext));
  check_bytes(page + ENCSQLITE_PAGEN_NONCE_OFFSET, nonce, sizeof(nonce));
  check_bytes(page + ENCSQLITE_PAGEN_TAG_OFFSET, tag, sizeof(tag));
  check_true(page[ENCSQLITE_PAGEN_EPOCH_OFFSET + 0] == 0x55, "pageN epoch byte 0 mismatch");
  check_true(page[ENCSQLITE_PAGEN_EPOCH_OFFSET + 1] == 0x66, "pageN epoch byte 1 mismatch");
  check_true(page[ENCSQLITE_PAGEN_EPOCH_OFFSET + 2] == 0x77, "pageN epoch byte 2 mismatch");
  check_true(page[ENCSQLITE_PAGEN_EPOCH_OFFSET + 3] == 0x88, "pageN epoch byte 3 mismatch");

  check_true(
      encsqlite_page_n_unpack(page, unpack_ciphertext, unpack_nonce, unpack_tag, &unpack_epoch) ==
          ENCSQLITE_PAGE_FORMAT_OK,
      "pageN unpack failed");
  check_bytes(unpack_ciphertext, ciphertext, sizeof(ciphertext));
  check_bytes(unpack_nonce, nonce, sizeof(nonce));
  check_bytes(unpack_tag, tag, sizeof(tag));
  check_true(unpack_epoch == 0x55667788U, "pageN epoch decode mismatch");
}

static void test_aad_layout(void) {
  uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES];
  uint8_t aad[ENCSQLITE_AAD_V1_BYTES];
  static const uint8_t prefix[] = "encsqlite-page-v1";

  fill_sequence(db_salt, sizeof(db_salt), 0xA0);

  check_true(
      encsqlite_page_aad_v1(aad, sizeof(aad), db_salt, 0x01020304, ENCSQLITE_PAGE_SIZE_BYTES, 0x0A0B0C0D) ==
          ENCSQLITE_PAGE_FORMAT_OK,
      "aad generation failed");
  check_bytes(aad, prefix, sizeof(prefix) - 1);
  check_bytes(aad + (sizeof(prefix) - 1), db_salt, sizeof(db_salt));
  check_true(aad[sizeof(prefix) - 1 + sizeof(db_salt) + 0] == 0x01, "aad page number byte 0 mismatch");
  check_true(aad[sizeof(prefix) - 1 + sizeof(db_salt) + 1] == 0x02, "aad page number byte 1 mismatch");
  check_true(aad[sizeof(prefix) - 1 + sizeof(db_salt) + 2] == 0x03, "aad page number byte 2 mismatch");
  check_true(aad[sizeof(prefix) - 1 + sizeof(db_salt) + 3] == 0x04, "aad page number byte 3 mismatch");
  check_true(aad[sizeof(prefix) - 1 + sizeof(db_salt) + 4] == 0x00, "aad page size byte 0 mismatch");
  check_true(aad[sizeof(prefix) - 1 + sizeof(db_salt) + 5] == 0x00, "aad page size byte 1 mismatch");
  check_true(aad[sizeof(prefix) - 1 + sizeof(db_salt) + 6] == 0x10, "aad page size byte 2 mismatch");
  check_true(aad[sizeof(prefix) - 1 + sizeof(db_salt) + 7] == 0x00, "aad page size byte 3 mismatch");
  check_true(aad[sizeof(prefix) - 1 + sizeof(db_salt) + 8] == 0x0A, "aad epoch byte 0 mismatch");
  check_true(aad[sizeof(prefix) - 1 + sizeof(db_salt) + 9] == 0x0B, "aad epoch byte 1 mismatch");
  check_true(aad[sizeof(prefix) - 1 + sizeof(db_salt) + 10] == 0x0C, "aad epoch byte 2 mismatch");
  check_true(aad[sizeof(prefix) - 1 + sizeof(db_salt) + 11] == 0x0D, "aad epoch byte 3 mismatch");
}

int main(void) {
  test_constants();
  test_page1_layout();
  test_page_n_layout();
  test_aad_layout();
  return 0;
}
