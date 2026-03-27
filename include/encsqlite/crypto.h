#ifndef ENCSQLITE_CRYPTO_H
#define ENCSQLITE_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
  ENCSQLITE_CRYPTO_OK = 0,
  ENCSQLITE_CRYPTO_INVALID_ARGUMENT = -1,
  ENCSQLITE_CRYPTO_BACKEND_ERROR = -2,
  ENCSQLITE_CRYPTO_NOT_INITIALIZED = -3,
  ENCSQLITE_CRYPTO_AUTHENTICATION_FAILED = -4
};

typedef struct {
  const uint8_t *password;
  size_t password_len;
  const uint8_t *salt;
  size_t salt_len;
  const uint8_t *secret;
  size_t secret_len;
  const uint8_t *associated_data;
  size_t associated_data_len;
  uint32_t iterations;
  uint32_t memory_kib;
  uint32_t lanes;
  uint32_t threads;
} encsqlite_argon2id_params;

int encsqlite_crypto_init(void);
void encsqlite_zeroize(void *buffer, size_t length);
int encsqlite_random_bytes(uint8_t *out, size_t out_len);

int encsqlite_aes256gcm_encrypt(
    const uint8_t key[32],
    const uint8_t *nonce,
    size_t nonce_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext,
    uint8_t tag[16]);

int encsqlite_aes256gcm_decrypt(
    const uint8_t key[32],
    const uint8_t *nonce,
    size_t nonce_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t tag[16],
    uint8_t *plaintext);

int encsqlite_hkdf_sha256(
    uint8_t *out,
    size_t out_len,
    const uint8_t *ikm,
    size_t ikm_len,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *info,
    size_t info_len);

int encsqlite_argon2id_raw(
    uint8_t *out,
    size_t out_len,
    const encsqlite_argon2id_params *params);

#ifdef __cplusplus
}
#endif

#endif
