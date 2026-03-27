#include "encsqlite/codec.h"

#include "encsqlite/crypto.h"

#include <string.h>

static const uint8_t k_master_info[] = "encsqlite/master/v1";
static const uint8_t k_page_info[] = "encsqlite/page/v1";

static int derive_page_key(
    uint8_t page_key[ENCSQLITE_CODEC_KEY_BYTES],
    const uint8_t root_secret[ENCSQLITE_CODEC_KEY_BYTES],
    const uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES]) {
  uint8_t master_key[ENCSQLITE_CODEC_KEY_BYTES];
  int rc;

  rc = encsqlite_hkdf_sha256(
      master_key,
      sizeof(master_key),
      root_secret,
      ENCSQLITE_CODEC_KEY_BYTES,
      db_salt,
      ENCSQLITE_DB_SALT_BYTES,
      k_master_info,
      sizeof(k_master_info) - 1);
  if (rc != ENCSQLITE_CRYPTO_OK) {
    return ENCSQLITE_CODEC_BACKEND_ERROR;
  }

  rc = encsqlite_hkdf_sha256(
      page_key,
      sizeof(master_key),
      master_key,
      sizeof(master_key),
      NULL,
      0,
      k_page_info,
      sizeof(k_page_info) - 1);
  encsqlite_zeroize(master_key, sizeof(master_key));

  return rc == ENCSQLITE_CRYPTO_OK ? ENCSQLITE_CODEC_OK : ENCSQLITE_CODEC_BACKEND_ERROR;
}

static int normalize_auth_failure(uint32_t page_no) {
  return page_no == 1 ? ENCSQLITE_CODEC_BAD_KEY_OR_FORMAT : ENCSQLITE_CODEC_CORRUPT;
}

static int build_aad(
    uint8_t aad[ENCSQLITE_AAD_V1_BYTES],
    const uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES],
    uint32_t page_no,
    uint32_t key_epoch) {
  return encsqlite_page_aad_v1(
             aad,
             ENCSQLITE_AAD_V1_BYTES,
             db_salt,
             page_no,
             ENCSQLITE_PAGE_SIZE_BYTES,
             key_epoch) == ENCSQLITE_PAGE_FORMAT_OK
             ? ENCSQLITE_CODEC_OK
             : ENCSQLITE_CODEC_BACKEND_ERROR;
}

int encsqlite_codec_init(
    encsqlite_codec_context *ctx,
    const uint8_t root_secret[ENCSQLITE_CODEC_KEY_BYTES],
    const uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES],
    uint32_t key_epoch) {
  int rc;

  if (ctx == NULL || root_secret == NULL || db_salt == NULL || key_epoch == 0U) {
    return ENCSQLITE_CODEC_INVALID_ARGUMENT;
  }

  memset(ctx, 0, sizeof(*ctx));
  memcpy(ctx->db_salt, db_salt, ENCSQLITE_DB_SALT_BYTES);
  ctx->key_epoch = key_epoch;

  rc = derive_page_key(ctx->page_key, root_secret, db_salt);
  if (rc != ENCSQLITE_CODEC_OK) {
    encsqlite_codec_clear(ctx);
    return rc;
  }

  return ENCSQLITE_CODEC_OK;
}

void encsqlite_codec_clear(encsqlite_codec_context *ctx) {
  if (ctx == NULL) {
    return;
  }

  encsqlite_zeroize(ctx->db_salt, sizeof(ctx->db_salt));
  encsqlite_zeroize(ctx->page_key, sizeof(ctx->page_key));
  ctx->key_epoch = 0;
}

static int encrypt_page1(
    const encsqlite_codec_context *ctx,
    const uint8_t logical_page[ENCSQLITE_PAGE_SIZE_BYTES],
    uint8_t physical_page[ENCSQLITE_PAGE_SIZE_BYTES]) {
  uint8_t plaintext[ENCSQLITE_PAGE1_CIPHERTEXT_BYTES];
  uint8_t ciphertext[ENCSQLITE_PAGE1_CIPHERTEXT_BYTES];
  uint8_t nonce[ENCSQLITE_GCM_NONCE_BYTES];
  uint8_t tag[ENCSQLITE_GCM_TAG_BYTES];
  uint8_t aad[ENCSQLITE_AAD_V1_BYTES];
  int rc;

  if (!encsqlite_page1_has_sqlite_header(logical_page)) {
    return ENCSQLITE_CODEC_BAD_KEY_OR_FORMAT;
  }

  memcpy(plaintext, logical_page + ENCSQLITE_SQLITE_HEADER_BYTES, sizeof(plaintext));

  rc = encsqlite_random_bytes(nonce, sizeof(nonce));
  if (rc != ENCSQLITE_CRYPTO_OK) {
    encsqlite_zeroize(plaintext, sizeof(plaintext));
    return ENCSQLITE_CODEC_BACKEND_ERROR;
  }

  rc = build_aad(aad, ctx->db_salt, 1, ctx->key_epoch);
  if (rc != ENCSQLITE_CODEC_OK) {
    encsqlite_zeroize(plaintext, sizeof(plaintext));
    encsqlite_zeroize(nonce, sizeof(nonce));
    return rc;
  }

  rc = encsqlite_aes256gcm_encrypt(
      ctx->page_key,
      nonce,
      sizeof(nonce),
      aad,
      sizeof(aad),
      plaintext,
      sizeof(plaintext),
      ciphertext,
      tag);
  if (rc != ENCSQLITE_CRYPTO_OK) {
    encsqlite_zeroize(plaintext, sizeof(plaintext));
    encsqlite_zeroize(ciphertext, sizeof(ciphertext));
    encsqlite_zeroize(nonce, sizeof(nonce));
    encsqlite_zeroize(tag, sizeof(tag));
    encsqlite_zeroize(aad, sizeof(aad));
    return ENCSQLITE_CODEC_BACKEND_ERROR;
  }

  rc = encsqlite_page1_pack(physical_page, ctx->db_salt, ciphertext, nonce, tag, ctx->key_epoch);

  encsqlite_zeroize(plaintext, sizeof(plaintext));
  encsqlite_zeroize(ciphertext, sizeof(ciphertext));
  encsqlite_zeroize(nonce, sizeof(nonce));
  encsqlite_zeroize(tag, sizeof(tag));
  encsqlite_zeroize(aad, sizeof(aad));

  return rc == ENCSQLITE_PAGE_FORMAT_OK ? ENCSQLITE_CODEC_OK : ENCSQLITE_CODEC_BACKEND_ERROR;
}

static int encrypt_page_n(
    const encsqlite_codec_context *ctx,
    uint32_t page_no,
    const uint8_t logical_page[ENCSQLITE_PAGE_SIZE_BYTES],
    uint8_t physical_page[ENCSQLITE_PAGE_SIZE_BYTES]) {
  uint8_t plaintext[ENCSQLITE_PAGE_N_CIPHERTEXT_BYTES];
  uint8_t ciphertext[ENCSQLITE_PAGE_N_CIPHERTEXT_BYTES];
  uint8_t nonce[ENCSQLITE_GCM_NONCE_BYTES];
  uint8_t tag[ENCSQLITE_GCM_TAG_BYTES];
  uint8_t aad[ENCSQLITE_AAD_V1_BYTES];
  int rc;

  memcpy(plaintext, logical_page, sizeof(plaintext));

  rc = encsqlite_random_bytes(nonce, sizeof(nonce));
  if (rc != ENCSQLITE_CRYPTO_OK) {
    encsqlite_zeroize(plaintext, sizeof(plaintext));
    return ENCSQLITE_CODEC_BACKEND_ERROR;
  }

  rc = build_aad(aad, ctx->db_salt, page_no, ctx->key_epoch);
  if (rc != ENCSQLITE_CODEC_OK) {
    encsqlite_zeroize(plaintext, sizeof(plaintext));
    encsqlite_zeroize(nonce, sizeof(nonce));
    return rc;
  }

  rc = encsqlite_aes256gcm_encrypt(
      ctx->page_key,
      nonce,
      sizeof(nonce),
      aad,
      sizeof(aad),
      plaintext,
      sizeof(plaintext),
      ciphertext,
      tag);
  if (rc != ENCSQLITE_CRYPTO_OK) {
    encsqlite_zeroize(plaintext, sizeof(plaintext));
    encsqlite_zeroize(ciphertext, sizeof(ciphertext));
    encsqlite_zeroize(nonce, sizeof(nonce));
    encsqlite_zeroize(tag, sizeof(tag));
    encsqlite_zeroize(aad, sizeof(aad));
    return ENCSQLITE_CODEC_BACKEND_ERROR;
  }

  rc = encsqlite_page_n_pack(physical_page, ciphertext, nonce, tag, ctx->key_epoch);

  encsqlite_zeroize(plaintext, sizeof(plaintext));
  encsqlite_zeroize(ciphertext, sizeof(ciphertext));
  encsqlite_zeroize(nonce, sizeof(nonce));
  encsqlite_zeroize(tag, sizeof(tag));
  encsqlite_zeroize(aad, sizeof(aad));

  return rc == ENCSQLITE_PAGE_FORMAT_OK ? ENCSQLITE_CODEC_OK : ENCSQLITE_CODEC_BACKEND_ERROR;
}

int encsqlite_codec_encrypt_page(
    const encsqlite_codec_context *ctx,
    uint32_t page_no,
    const uint8_t logical_page[ENCSQLITE_PAGE_SIZE_BYTES],
    uint8_t physical_page[ENCSQLITE_PAGE_SIZE_BYTES]) {
  if (ctx == NULL || logical_page == NULL || physical_page == NULL || page_no == 0U || ctx->key_epoch == 0U) {
    return ENCSQLITE_CODEC_INVALID_ARGUMENT;
  }

  if (page_no == 1U) {
    return encrypt_page1(ctx, logical_page, physical_page);
  }
  return encrypt_page_n(ctx, page_no, logical_page, physical_page);
}

static int decrypt_page1(
    const encsqlite_codec_context *ctx,
    const uint8_t physical_page[ENCSQLITE_PAGE_SIZE_BYTES],
    uint8_t logical_page[ENCSQLITE_PAGE_SIZE_BYTES]) {
  uint8_t db_salt[ENCSQLITE_DB_SALT_BYTES];
  uint8_t ciphertext[ENCSQLITE_PAGE1_CIPHERTEXT_BYTES];
  uint8_t nonce[ENCSQLITE_GCM_NONCE_BYTES];
  uint8_t tag[ENCSQLITE_GCM_TAG_BYTES];
  uint8_t plaintext[ENCSQLITE_PAGE1_CIPHERTEXT_BYTES];
  uint8_t aad[ENCSQLITE_AAD_V1_BYTES];
  uint32_t key_epoch = 0;
  int rc;

  rc = encsqlite_page1_unpack(physical_page, db_salt, ciphertext, nonce, tag, &key_epoch);
  if (rc != ENCSQLITE_PAGE_FORMAT_OK) {
    return ENCSQLITE_CODEC_INVALID_ARGUMENT;
  }
  if (memcmp(db_salt, ctx->db_salt, sizeof(db_salt)) != 0) {
    encsqlite_zeroize(db_salt, sizeof(db_salt));
    encsqlite_zeroize(ciphertext, sizeof(ciphertext));
    encsqlite_zeroize(nonce, sizeof(nonce));
    encsqlite_zeroize(tag, sizeof(tag));
    return ENCSQLITE_CODEC_BAD_KEY_OR_FORMAT;
  }

  rc = build_aad(aad, db_salt, 1, key_epoch);
  if (rc != ENCSQLITE_CODEC_OK) {
    encsqlite_zeroize(db_salt, sizeof(db_salt));
    encsqlite_zeroize(ciphertext, sizeof(ciphertext));
    encsqlite_zeroize(nonce, sizeof(nonce));
    encsqlite_zeroize(tag, sizeof(tag));
    return rc;
  }

  rc = encsqlite_aes256gcm_decrypt(
      ctx->page_key,
      nonce,
      sizeof(nonce),
      aad,
      sizeof(aad),
      ciphertext,
      sizeof(ciphertext),
      tag,
      plaintext);
  if (rc == ENCSQLITE_CRYPTO_AUTHENTICATION_FAILED) {
    encsqlite_zeroize(db_salt, sizeof(db_salt));
    encsqlite_zeroize(ciphertext, sizeof(ciphertext));
    encsqlite_zeroize(nonce, sizeof(nonce));
    encsqlite_zeroize(tag, sizeof(tag));
    encsqlite_zeroize(plaintext, sizeof(plaintext));
    encsqlite_zeroize(aad, sizeof(aad));
    return normalize_auth_failure(1);
  }
  if (rc != ENCSQLITE_CRYPTO_OK) {
    encsqlite_zeroize(db_salt, sizeof(db_salt));
    encsqlite_zeroize(ciphertext, sizeof(ciphertext));
    encsqlite_zeroize(nonce, sizeof(nonce));
    encsqlite_zeroize(tag, sizeof(tag));
    encsqlite_zeroize(plaintext, sizeof(plaintext));
    encsqlite_zeroize(aad, sizeof(aad));
    return ENCSQLITE_CODEC_BACKEND_ERROR;
  }

  rc = encsqlite_page1_make_logical_plaintext(logical_page, plaintext);

  encsqlite_zeroize(db_salt, sizeof(db_salt));
  encsqlite_zeroize(ciphertext, sizeof(ciphertext));
  encsqlite_zeroize(nonce, sizeof(nonce));
  encsqlite_zeroize(tag, sizeof(tag));
  encsqlite_zeroize(plaintext, sizeof(plaintext));
  encsqlite_zeroize(aad, sizeof(aad));

  return rc == ENCSQLITE_PAGE_FORMAT_OK ? ENCSQLITE_CODEC_OK : ENCSQLITE_CODEC_BACKEND_ERROR;
}

static int decrypt_page_n(
    const encsqlite_codec_context *ctx,
    uint32_t page_no,
    const uint8_t physical_page[ENCSQLITE_PAGE_SIZE_BYTES],
    uint8_t logical_page[ENCSQLITE_PAGE_SIZE_BYTES]) {
  uint8_t ciphertext[ENCSQLITE_PAGE_N_CIPHERTEXT_BYTES];
  uint8_t nonce[ENCSQLITE_GCM_NONCE_BYTES];
  uint8_t tag[ENCSQLITE_GCM_TAG_BYTES];
  uint8_t plaintext[ENCSQLITE_PAGE_N_CIPHERTEXT_BYTES];
  uint8_t aad[ENCSQLITE_AAD_V1_BYTES];
  uint32_t key_epoch = 0;
  int rc;

  rc = encsqlite_page_n_unpack(physical_page, ciphertext, nonce, tag, &key_epoch);
  if (rc != ENCSQLITE_PAGE_FORMAT_OK) {
    return ENCSQLITE_CODEC_INVALID_ARGUMENT;
  }

  rc = build_aad(aad, ctx->db_salt, page_no, key_epoch);
  if (rc != ENCSQLITE_CODEC_OK) {
    encsqlite_zeroize(ciphertext, sizeof(ciphertext));
    encsqlite_zeroize(nonce, sizeof(nonce));
    encsqlite_zeroize(tag, sizeof(tag));
    return rc;
  }

  rc = encsqlite_aes256gcm_decrypt(
      ctx->page_key,
      nonce,
      sizeof(nonce),
      aad,
      sizeof(aad),
      ciphertext,
      sizeof(ciphertext),
      tag,
      plaintext);
  if (rc == ENCSQLITE_CRYPTO_AUTHENTICATION_FAILED) {
    encsqlite_zeroize(ciphertext, sizeof(ciphertext));
    encsqlite_zeroize(nonce, sizeof(nonce));
    encsqlite_zeroize(tag, sizeof(tag));
    encsqlite_zeroize(plaintext, sizeof(plaintext));
    encsqlite_zeroize(aad, sizeof(aad));
    return normalize_auth_failure(page_no);
  }
  if (rc != ENCSQLITE_CRYPTO_OK) {
    encsqlite_zeroize(ciphertext, sizeof(ciphertext));
    encsqlite_zeroize(nonce, sizeof(nonce));
    encsqlite_zeroize(tag, sizeof(tag));
    encsqlite_zeroize(plaintext, sizeof(plaintext));
    encsqlite_zeroize(aad, sizeof(aad));
    return ENCSQLITE_CODEC_BACKEND_ERROR;
  }

  memset(logical_page, 0, ENCSQLITE_PAGE_SIZE_BYTES);
  memcpy(logical_page, plaintext, sizeof(plaintext));

  encsqlite_zeroize(ciphertext, sizeof(ciphertext));
  encsqlite_zeroize(nonce, sizeof(nonce));
  encsqlite_zeroize(tag, sizeof(tag));
  encsqlite_zeroize(plaintext, sizeof(plaintext));
  encsqlite_zeroize(aad, sizeof(aad));

  return ENCSQLITE_CODEC_OK;
}

int encsqlite_codec_decrypt_page(
    const encsqlite_codec_context *ctx,
    uint32_t page_no,
    const uint8_t physical_page[ENCSQLITE_PAGE_SIZE_BYTES],
    uint8_t logical_page[ENCSQLITE_PAGE_SIZE_BYTES]) {
  if (ctx == NULL || physical_page == NULL || logical_page == NULL || page_no == 0U || ctx->key_epoch == 0U) {
    return ENCSQLITE_CODEC_INVALID_ARGUMENT;
  }

  if (page_no == 1U) {
    return decrypt_page1(ctx, physical_page, logical_page);
  }
  return decrypt_page_n(ctx, page_no, physical_page, logical_page);
}
