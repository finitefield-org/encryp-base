#include "encsqlite/crypto.h"

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <argon2.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <sodium.h>

static int ensure_nonnull_or_empty(const void *ptr, size_t len) {
  return (len == 0 || ptr != NULL) ? ENCSQLITE_CRYPTO_OK : ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
}

static int openssl_process_buffer(
    EVP_CIPHER_CTX *ctx,
    int encrypt,
    const uint8_t *input,
    size_t input_len,
    uint8_t *output) {
  size_t offset = 0;

  while (offset < input_len) {
    size_t remaining = input_len - offset;
    int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
    int produced = 0;
    int rc = encrypt
                 ? EVP_EncryptUpdate(ctx, output, &produced, input, chunk)
                 : EVP_DecryptUpdate(ctx, output, &produced, input, chunk);
    if (rc != 1 || produced != chunk) {
      return ENCSQLITE_CRYPTO_BACKEND_ERROR;
    }
    input += chunk;
    if (output != NULL) {
      output += produced;
    }
    offset += (size_t)chunk;
  }

  return ENCSQLITE_CRYPTO_OK;
}

int encsqlite_crypto_init(void) {
  return sodium_init() >= 0 ? ENCSQLITE_CRYPTO_OK : ENCSQLITE_CRYPTO_NOT_INITIALIZED;
}

void encsqlite_zeroize(void *buffer, size_t length) {
  if (buffer != NULL && length > 0) {
    sodium_memzero(buffer, length);
  }
}

int encsqlite_random_bytes(uint8_t *out, size_t out_len) {
  if (out_len == 0) {
    return ENCSQLITE_CRYPTO_OK;
  }
  if (out == NULL) {
    return ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  }
  if (encsqlite_crypto_init() != ENCSQLITE_CRYPTO_OK) {
    return ENCSQLITE_CRYPTO_NOT_INITIALIZED;
  }

  randombytes_buf(out, out_len);
  return ENCSQLITE_CRYPTO_OK;
}

int encsqlite_aes256gcm_encrypt(
    const uint8_t key[32],
    const uint8_t *nonce,
    size_t nonce_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext,
    uint8_t tag[16]) {
  EVP_CIPHER_CTX *ctx = NULL;
  int rc = ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  int final_len = 0;

  if (key == NULL || nonce == NULL || tag == NULL || ciphertext == NULL) {
    return ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  }
  if (plaintext_len > 0 && plaintext == NULL) {
    return ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  }
  if (ensure_nonnull_or_empty(aad, aad_len) != ENCSQLITE_CRYPTO_OK) {
    return ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  }
  if (nonce_len == 0 || nonce_len > (size_t)INT_MAX) {
    return ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  }

  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    return ENCSQLITE_CRYPTO_BACKEND_ERROR;
  }

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
    rc = ENCSQLITE_CRYPTO_BACKEND_ERROR;
    goto cleanup;
  }
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) != 1) {
    rc = ENCSQLITE_CRYPTO_BACKEND_ERROR;
    goto cleanup;
  }
  if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
    rc = ENCSQLITE_CRYPTO_BACKEND_ERROR;
    goto cleanup;
  }

  if (aad_len > 0) {
    rc = openssl_process_buffer(ctx, 1, aad, aad_len, NULL);
    if (rc != ENCSQLITE_CRYPTO_OK) {
      goto cleanup;
    }
  }

  if (plaintext_len > 0) {
    rc = openssl_process_buffer(ctx, 1, plaintext, plaintext_len, ciphertext);
    if (rc != ENCSQLITE_CRYPTO_OK) {
      goto cleanup;
    }
  }

  if (EVP_EncryptFinal_ex(ctx, NULL, &final_len) != 1 || final_len != 0) {
    rc = ENCSQLITE_CRYPTO_BACKEND_ERROR;
    goto cleanup;
  }
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
    rc = ENCSQLITE_CRYPTO_BACKEND_ERROR;
    goto cleanup;
  }

  rc = ENCSQLITE_CRYPTO_OK;

cleanup:
  EVP_CIPHER_CTX_free(ctx);
  return rc;
}

int encsqlite_aes256gcm_decrypt(
    const uint8_t key[32],
    const uint8_t *nonce,
    size_t nonce_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t tag[16],
    uint8_t *plaintext) {
  EVP_CIPHER_CTX *ctx = NULL;
  int rc = ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  int final_len = 0;

  if (key == NULL || nonce == NULL || tag == NULL || plaintext == NULL) {
    return ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  }
  if (ciphertext_len > 0 && ciphertext == NULL) {
    return ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  }
  if (ensure_nonnull_or_empty(aad, aad_len) != ENCSQLITE_CRYPTO_OK) {
    return ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  }
  if (nonce_len == 0 || nonce_len > (size_t)INT_MAX) {
    return ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  }

  ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    return ENCSQLITE_CRYPTO_BACKEND_ERROR;
  }

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
    rc = ENCSQLITE_CRYPTO_BACKEND_ERROR;
    goto cleanup;
  }
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) != 1) {
    rc = ENCSQLITE_CRYPTO_BACKEND_ERROR;
    goto cleanup;
  }
  if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
    rc = ENCSQLITE_CRYPTO_BACKEND_ERROR;
    goto cleanup;
  }
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) {
    rc = ENCSQLITE_CRYPTO_BACKEND_ERROR;
    goto cleanup;
  }

  if (aad_len > 0) {
    rc = openssl_process_buffer(ctx, 0, aad, aad_len, NULL);
    if (rc != ENCSQLITE_CRYPTO_OK) {
      goto cleanup;
    }
  }

  if (ciphertext_len > 0) {
    rc = openssl_process_buffer(ctx, 0, ciphertext, ciphertext_len, plaintext);
    if (rc != ENCSQLITE_CRYPTO_OK) {
      goto cleanup;
    }
  }

  if (EVP_DecryptFinal_ex(ctx, NULL, &final_len) != 1 || final_len != 0) {
    rc = ENCSQLITE_CRYPTO_AUTHENTICATION_FAILED;
    goto cleanup;
  }

  rc = ENCSQLITE_CRYPTO_OK;

cleanup:
  EVP_CIPHER_CTX_free(ctx);
  return rc;
}

int encsqlite_hkdf_sha256(
    uint8_t *out,
    size_t out_len,
    const uint8_t *ikm,
    size_t ikm_len,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *info,
    size_t info_len) {
  EVP_PKEY_CTX *pctx = NULL;
  size_t derived_len = out_len;
  int rc = ENCSQLITE_CRYPTO_INVALID_ARGUMENT;

  if (out_len == 0) {
    return ENCSQLITE_CRYPTO_OK;
  }
  if (out == NULL || ikm == NULL) {
    return ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  }
  if (ensure_nonnull_or_empty(salt, salt_len) != ENCSQLITE_CRYPTO_OK ||
      ensure_nonnull_or_empty(info, info_len) != ENCSQLITE_CRYPTO_OK) {
    return ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  }
  if (out_len > (size_t)INT_MAX ||
      ikm_len > (size_t)INT_MAX ||
      salt_len > (size_t)INT_MAX ||
      info_len > (size_t)INT_MAX) {
    return ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  }

  pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  if (pctx == NULL) {
    return ENCSQLITE_CRYPTO_BACKEND_ERROR;
  }

  if (EVP_PKEY_derive_init(pctx) <= 0) {
    rc = ENCSQLITE_CRYPTO_BACKEND_ERROR;
    goto cleanup;
  }
  if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
    rc = ENCSQLITE_CRYPTO_BACKEND_ERROR;
    goto cleanup;
  }
  if (salt_len > 0 && EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)salt_len) <= 0) {
    rc = ENCSQLITE_CRYPTO_BACKEND_ERROR;
    goto cleanup;
  }
  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)ikm_len) <= 0) {
    rc = ENCSQLITE_CRYPTO_BACKEND_ERROR;
    goto cleanup;
  }
  if (info_len > 0 && EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)info_len) <= 0) {
    rc = ENCSQLITE_CRYPTO_BACKEND_ERROR;
    goto cleanup;
  }
  if (EVP_PKEY_derive(pctx, out, &derived_len) <= 0 || derived_len != out_len) {
    rc = ENCSQLITE_CRYPTO_BACKEND_ERROR;
    goto cleanup;
  }

  rc = ENCSQLITE_CRYPTO_OK;

cleanup:
  EVP_PKEY_CTX_free(pctx);
  return rc;
}

int encsqlite_argon2id_raw(
    uint8_t *out,
    size_t out_len,
    const encsqlite_argon2id_params *params) {
  argon2_context context;
  uint8_t *password_copy = NULL;
  uint8_t *secret_copy = NULL;
  int rc;

  if (out == NULL || params == NULL || out_len == 0) {
    return ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  }
  if (params->password_len > 0 && params->password == NULL) {
    return ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  }
  if (params->salt_len > 0 && params->salt == NULL) {
    return ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  }
  if (params->secret_len > 0 && params->secret == NULL) {
    return ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  }
  if (params->associated_data_len > 0 && params->associated_data == NULL) {
    return ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  }
  if (params->iterations == 0 || params->memory_kib == 0 || params->lanes == 0) {
    return ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  }
  if (out_len > UINT32_MAX ||
      params->password_len > UINT32_MAX ||
      params->salt_len > UINT32_MAX ||
      params->secret_len > UINT32_MAX ||
      params->associated_data_len > UINT32_MAX) {
    return ENCSQLITE_CRYPTO_INVALID_ARGUMENT;
  }

  password_copy = NULL;
  if (params->password_len > 0) {
    password_copy = (uint8_t *)malloc(params->password_len);
    if (password_copy == NULL) {
      return ENCSQLITE_CRYPTO_BACKEND_ERROR;
    }
    memcpy(password_copy, params->password, params->password_len);
  }

  secret_copy = NULL;
  if (params->secret_len > 0) {
    secret_copy = (uint8_t *)malloc(params->secret_len);
    if (secret_copy == NULL) {
      encsqlite_zeroize(password_copy, params->password_len);
      free(password_copy);
      return ENCSQLITE_CRYPTO_BACKEND_ERROR;
    }
    memcpy(secret_copy, params->secret, params->secret_len);
  }

  memset(&context, 0, sizeof(context));
  context.out = out;
  context.outlen = (uint32_t)out_len;
  context.pwd = password_copy != NULL ? password_copy : (uint8_t *)params->password;
  context.pwdlen = (uint32_t)params->password_len;
  context.salt = (uint8_t *)params->salt;
  context.saltlen = (uint32_t)params->salt_len;
  context.secret = secret_copy != NULL ? secret_copy : (uint8_t *)params->secret;
  context.secretlen = (uint32_t)params->secret_len;
  context.ad = (uint8_t *)params->associated_data;
  context.adlen = (uint32_t)params->associated_data_len;
  context.t_cost = params->iterations;
  context.m_cost = params->memory_kib;
  context.lanes = params->lanes;
  context.threads = params->threads == 0 ? params->lanes : params->threads;
  context.version = ARGON2_VERSION_NUMBER;
  context.allocate_cbk = NULL;
  context.free_cbk = NULL;
  context.flags = ARGON2_DEFAULT_FLAGS;

  rc = argon2id_ctx(&context);
  encsqlite_zeroize(password_copy, params->password_len);
  encsqlite_zeroize(secret_copy, params->secret_len);
  free(password_copy);
  free(secret_copy);

  if (rc != ARGON2_OK) {
    return ENCSQLITE_CRYPTO_BACKEND_ERROR;
  }

  return ENCSQLITE_CRYPTO_OK;
}
