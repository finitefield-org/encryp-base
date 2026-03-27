#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "encsqlite/codec.h"

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

static void make_context(encsqlite_codec_context *ctx) {
  uint8_t root_secret[ENCSQLITE_CODEC_KEY_BYTES];
  uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES];

  fill_sequence(root_secret, sizeof(root_secret), 0x11);
  fill_sequence(db_salt, sizeof(db_salt), 0xA0);

  check_true(
      encsqlite_codec_init(ctx, root_secret, db_salt, 1U) == ENCSQLITE_CODEC_OK,
      "codec init failed");
}

static void test_page1_roundtrip(void) {
  encsqlite_codec_context ctx;
  uint8_t logical_page[ENCSQLITE_PAGE_SIZE_BYTES];
  uint8_t physical_page[ENCSQLITE_PAGE_SIZE_BYTES];
  uint8_t recovered_page[ENCSQLITE_PAGE_SIZE_BYTES];
  uint8_t payload[ENCSQLITE_PAGE1_CIPHERTEXT_BYTES];
  uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES];

  fill_sequence(payload, sizeof(payload), 0x20);
  fill_sequence(db_salt, sizeof(db_salt), 0xA0);
  check_true(
      encsqlite_page1_make_logical_plaintext(logical_page, payload) == ENCSQLITE_PAGE_FORMAT_OK,
      "page1 logical plaintext build failed");

  {
    uint8_t root_secret[ENCSQLITE_CODEC_KEY_BYTES];
    fill_sequence(root_secret, sizeof(root_secret), 0x11);
    check_true(
        encsqlite_codec_init(&ctx, root_secret, db_salt, 1U) == ENCSQLITE_CODEC_OK,
        "codec init failed");
  }

  check_true(
      encsqlite_codec_encrypt_page(&ctx, 1U, logical_page, physical_page) == ENCSQLITE_CODEC_OK,
      "page1 encrypt failed");
  check_bytes(physical_page + ENCSQLITE_PAGE1_SALT_OFFSET, db_salt, ENCSQLITE_DB_SALT_BYTES);
  check_true(
      physical_page[ENCSQLITE_PAGE1_EPOCH_OFFSET + 0] == 0x00 &&
          physical_page[ENCSQLITE_PAGE1_EPOCH_OFFSET + 1] == 0x00 &&
          physical_page[ENCSQLITE_PAGE1_EPOCH_OFFSET + 2] == 0x00 &&
          physical_page[ENCSQLITE_PAGE1_EPOCH_OFFSET + 3] == 0x01,
      "page1 epoch mismatch");

  check_true(
      encsqlite_codec_decrypt_page(&ctx, 1U, physical_page, recovered_page) == ENCSQLITE_CODEC_OK,
      "page1 decrypt failed");
  check_bytes(recovered_page, logical_page, sizeof(logical_page));
  check_true(encsqlite_page1_has_sqlite_header(recovered_page) == 1, "page1 header missing");

  encsqlite_codec_clear(&ctx);
}

static void test_page_n_roundtrip(void) {
  encsqlite_codec_context ctx;
  uint8_t logical_page[ENCSQLITE_PAGE_SIZE_BYTES];
  uint8_t physical_page[ENCSQLITE_PAGE_SIZE_BYTES];
  uint8_t recovered_page[ENCSQLITE_PAGE_SIZE_BYTES];

  memset(logical_page, 0, sizeof(logical_page));
  fill_sequence(logical_page, ENCSQLITE_PAGE_N_CIPHERTEXT_BYTES, 0x30);
  make_context(&ctx);

  check_true(
      encsqlite_codec_encrypt_page(&ctx, 5U, logical_page, physical_page) == ENCSQLITE_CODEC_OK,
      "pageN encrypt failed");
  check_true(
      physical_page[ENCSQLITE_PAGEN_EPOCH_OFFSET + 0] == 0x00 &&
          physical_page[ENCSQLITE_PAGEN_EPOCH_OFFSET + 1] == 0x00 &&
          physical_page[ENCSQLITE_PAGEN_EPOCH_OFFSET + 2] == 0x00 &&
          physical_page[ENCSQLITE_PAGEN_EPOCH_OFFSET + 3] == 0x01,
      "pageN epoch mismatch");

  check_true(
      encsqlite_codec_decrypt_page(&ctx, 5U, physical_page, recovered_page) == ENCSQLITE_CODEC_OK,
      "pageN decrypt failed");
  check_bytes(recovered_page, logical_page, sizeof(logical_page));

  encsqlite_codec_clear(&ctx);
}

static void test_page1_bad_header_and_tag_failure(void) {
  encsqlite_codec_context ctx;
  uint8_t logical_page[ENCSQLITE_PAGE_SIZE_BYTES];
  uint8_t physical_page[ENCSQLITE_PAGE_SIZE_BYTES];
  uint8_t payload[ENCSQLITE_PAGE1_CIPHERTEXT_BYTES];
  uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES];

  fill_sequence(payload, sizeof(payload), 0x20);
  fill_sequence(db_salt, sizeof(db_salt), 0xA0);
  check_true(
      encsqlite_page1_make_logical_plaintext(logical_page, payload) == ENCSQLITE_PAGE_FORMAT_OK,
      "page1 logical plaintext build failed");
  logical_page[0] = 'X';

  {
    uint8_t root_secret[ENCSQLITE_CODEC_KEY_BYTES];
    fill_sequence(root_secret, sizeof(root_secret), 0x11);
    check_true(
        encsqlite_codec_init(&ctx, root_secret, db_salt, 1U) == ENCSQLITE_CODEC_OK,
        "codec init failed");
  }

  check_true(
      encsqlite_codec_encrypt_page(&ctx, 1U, logical_page, physical_page) ==
          ENCSQLITE_CODEC_BAD_KEY_OR_FORMAT,
      "page1 header validation should fail");

  check_true(
      encsqlite_page1_make_logical_plaintext(logical_page, payload) == ENCSQLITE_PAGE_FORMAT_OK,
      "page1 logical plaintext rebuild failed");
  check_true(
      encsqlite_codec_encrypt_page(&ctx, 1U, logical_page, physical_page) == ENCSQLITE_CODEC_OK,
      "page1 encrypt failed");
  physical_page[ENCSQLITE_PAGE1_TAG_OFFSET] ^= 0x01U;
  check_true(
      encsqlite_codec_decrypt_page(&ctx, 1U, physical_page, logical_page) ==
          ENCSQLITE_CODEC_BAD_KEY_OR_FORMAT,
      "page1 tag failure should normalize to bad key or format");

  encsqlite_codec_clear(&ctx);
}

static void test_page_swap_and_bitflip_normalization(void) {
  encsqlite_codec_context ctx;
  uint8_t logical_page5[ENCSQLITE_PAGE_SIZE_BYTES];
  uint8_t logical_page6[ENCSQLITE_PAGE_SIZE_BYTES];
  uint8_t physical_page5[ENCSQLITE_PAGE_SIZE_BYTES];
  uint8_t physical_page6[ENCSQLITE_PAGE_SIZE_BYTES];
  uint8_t recovered_page[ENCSQLITE_PAGE_SIZE_BYTES];

  memset(logical_page5, 0, sizeof(logical_page5));
  memset(logical_page6, 0, sizeof(logical_page6));
  fill_sequence(logical_page5, ENCSQLITE_PAGE_N_CIPHERTEXT_BYTES, 0x40);
  fill_sequence(logical_page6, ENCSQLITE_PAGE_N_CIPHERTEXT_BYTES, 0x70);
  make_context(&ctx);

  check_true(
      encsqlite_codec_encrypt_page(&ctx, 5U, logical_page5, physical_page5) == ENCSQLITE_CODEC_OK,
      "page 5 encrypt failed");
  check_true(
      encsqlite_codec_encrypt_page(&ctx, 6U, logical_page6, physical_page6) == ENCSQLITE_CODEC_OK,
      "page 6 encrypt failed");

  physical_page5[ENCSQLITE_PAGEN_CIPHERTEXT_OFFSET + 12] ^= 0x01U;
  check_true(
      encsqlite_codec_decrypt_page(&ctx, 5U, physical_page5, recovered_page) == ENCSQLITE_CODEC_CORRUPT,
      "bit flip should be normalized to corrupt");

  check_true(
      encsqlite_codec_decrypt_page(&ctx, 5U, physical_page6, recovered_page) == ENCSQLITE_CODEC_CORRUPT,
      "page swap should be normalized to corrupt");
  check_true(
      encsqlite_codec_decrypt_page(&ctx, 6U, physical_page5, recovered_page) == ENCSQLITE_CODEC_CORRUPT,
      "reverse page swap should be normalized to corrupt");

  encsqlite_codec_clear(&ctx);
}

int main(void) {
  test_page1_roundtrip();
  test_page_n_roundtrip();
  test_page1_bad_header_and_tag_failure();
  test_page_swap_and_bitflip_normalization();
  return 0;
}
