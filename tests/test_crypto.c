#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "encsqlite/crypto.h"

static size_t hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return (size_t)(c - '0');
  }
  if (c >= 'a' && c <= 'f') {
    return (size_t)(c - 'a' + 10);
  }
  if (c >= 'A' && c <= 'F') {
    return (size_t)(c - 'A' + 10);
  }
  fprintf(stderr, "invalid hex digit: %c\n", c);
  abort();
}

static size_t hex_decode(const char *hex, uint8_t *out, size_t out_len) {
  size_t hex_len = strlen(hex);
  size_t i = 0;
  size_t j = 0;

  if ((hex_len % 2) != 0) {
    fprintf(stderr, "odd-length hex input\n");
    abort();
  }
  if (out_len < hex_len / 2) {
    fprintf(stderr, "hex buffer too small\n");
    abort();
  }

  while (i < hex_len) {
    out[j++] = (uint8_t)((hex_value(hex[i]) << 4) | hex_value(hex[i + 1]));
    i += 2;
  }

  return j;
}

static void expect_bytes(const uint8_t *lhs, const uint8_t *rhs, size_t len) {
  if (memcmp(lhs, rhs, len) != 0) {
    fprintf(stderr, "byte comparison failed\n");
    abort();
  }
}

static void expect_true(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "%s\n", message);
    abort();
  }
}

static void test_random_and_zeroize(void) {
  uint8_t random_block[32];
  uint8_t zero_block[32];

  memset(random_block, 0, sizeof(random_block));
  memset(zero_block, 0, sizeof(zero_block));

  expect_true(encsqlite_random_bytes(random_block, sizeof(random_block)) == ENCSQLITE_CRYPTO_OK, "random bytes failed");
  expect_true(memcmp(random_block, zero_block, sizeof(random_block)) != 0, "random bytes unexpectedly all zero");

  encsqlite_zeroize(random_block, sizeof(random_block));
  expect_bytes(random_block, zero_block, sizeof(random_block));
}

static void test_hkdf_rfc5869_case1(void) {
  uint8_t ikm[22];
  uint8_t salt[13];
  uint8_t info[10];
  uint8_t okm[42];
  uint8_t expected[42];

  memset(ikm, 0x0b, sizeof(ikm));
  hex_decode("000102030405060708090a0b0c", salt, sizeof(salt));
  hex_decode("f0f1f2f3f4f5f6f7f8f9", info, sizeof(info));
  hex_decode(
      "3cb25f25faacd57a90434f64d0362f2a"
      "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
      "34007208d5b887185865",
      expected,
      sizeof(expected));

  expect_true(encsqlite_hkdf_sha256(okm, sizeof(okm), ikm, sizeof(ikm), salt, sizeof(salt), info, sizeof(info)) == ENCSQLITE_CRYPTO_OK, "hkdf failed");
  expect_bytes(okm, expected, sizeof(expected));
}

static void test_aes256gcm_nist_vector(void) {
  uint8_t key[32];
  uint8_t nonce[12];
  uint8_t plaintext[16];
  uint8_t expected_ct[16];
  uint8_t expected_tag[16];
  uint8_t ciphertext[16];
  uint8_t tag[16];
  uint8_t decrypted[16];

  hex_decode(
      "31bdadd96698c204aa9ce1448ea94ae1"
      "fb4a9a0b3c9d773b51bb1822666b8f22",
      key,
      sizeof(key));
  hex_decode("0d18e06c7c725ac9e362e1ce", nonce, sizeof(nonce));
  hex_decode("2db5168e932556f8089a0622981d017d", plaintext, sizeof(plaintext));
  hex_decode("fa4362189661d163fcd6a56d8bf0405a", expected_ct, sizeof(expected_ct));
  hex_decode("d636ac1bbedd5cc3ee727dc2ab4a9489", expected_tag, sizeof(expected_tag));

  expect_true(encsqlite_aes256gcm_encrypt(
                  key,
                  nonce,
                  sizeof(nonce),
                  NULL,
                  0,
                  plaintext,
                  sizeof(plaintext),
                  ciphertext,
                  tag) == ENCSQLITE_CRYPTO_OK,
              "aes-gcm encrypt failed");
  expect_bytes(ciphertext, expected_ct, sizeof(expected_ct));
  expect_bytes(tag, expected_tag, sizeof(expected_tag));

  expect_true(encsqlite_aes256gcm_decrypt(
                  key,
                  nonce,
                  sizeof(nonce),
                  NULL,
                  0,
                  ciphertext,
                  sizeof(ciphertext),
                  tag,
                  decrypted) == ENCSQLITE_CRYPTO_OK,
              "aes-gcm decrypt failed");
  expect_bytes(decrypted, plaintext, sizeof(plaintext));

  tag[0] ^= 0x01;
  expect_true(encsqlite_aes256gcm_decrypt(
                  key,
                  nonce,
                  sizeof(nonce),
                  NULL,
                  0,
                  ciphertext,
                  sizeof(ciphertext),
                  tag,
                  decrypted) == ENCSQLITE_CRYPTO_AUTHENTICATION_FAILED,
              "aes-gcm tag corruption was not detected");
}

static void test_aes256gcm_roundtrip_16_byte_nonce(void) {
  uint8_t key[32];
  uint8_t nonce[16];
  uint8_t aad[8];
  uint8_t plaintext[24];
  uint8_t ciphertext[24];
  uint8_t tag[16];
  uint8_t decrypted[24];

  hex_decode(
      "000102030405060708090a0b0c0d0e0f"
      "101112131415161718191a1b1c1d1e1f",
      key,
      sizeof(key));
  hex_decode("000102030405060708090a0b0c0d0e0f", nonce, sizeof(nonce));
  hex_decode("1011121314151617", aad, sizeof(aad));
  hex_decode("202122232425262728292a2b2c2d2e2f3031323334353637", plaintext, sizeof(plaintext));

  expect_true(encsqlite_aes256gcm_encrypt(
                  key,
                  nonce,
                  sizeof(nonce),
                  aad,
                  sizeof(aad),
                  plaintext,
                  sizeof(plaintext),
                  ciphertext,
                  tag) == ENCSQLITE_CRYPTO_OK,
              "aes-gcm roundtrip encrypt failed");
  expect_true(encsqlite_aes256gcm_decrypt(
                  key,
                  nonce,
                  sizeof(nonce),
                  aad,
                  sizeof(aad),
                  ciphertext,
                  sizeof(ciphertext),
                  tag,
                  decrypted) == ENCSQLITE_CRYPTO_OK,
              "aes-gcm roundtrip decrypt failed");
  expect_bytes(decrypted, plaintext, sizeof(plaintext));
}

static void test_argon2id_rfc9106_case(void) {
  uint8_t password[32];
  uint8_t salt[16];
  uint8_t secret[8];
  uint8_t ad[12];
  uint8_t out[32];
  uint8_t expected[32];
  encsqlite_argon2id_params params;

  memset(password, 0x01, sizeof(password));
  memset(salt, 0x02, sizeof(salt));
  memset(secret, 0x03, sizeof(secret));
  memset(ad, 0x04, sizeof(ad));
  hex_decode(
      "0d640df58d78766c08c037a34a8b53c9"
      "d01ef0452d75b65eb52520e96b01e659",
      expected,
      sizeof(expected));

  params.password = password;
  params.password_len = sizeof(password);
  params.salt = salt;
  params.salt_len = sizeof(salt);
  params.secret = secret;
  params.secret_len = sizeof(secret);
  params.associated_data = ad;
  params.associated_data_len = sizeof(ad);
  params.iterations = 3;
  params.memory_kib = 32;
  params.lanes = 4;
  params.threads = 4;

  expect_true(encsqlite_argon2id_raw(out, sizeof(out), &params) == ENCSQLITE_CRYPTO_OK, "argon2id failed");
  expect_bytes(out, expected, sizeof(expected));
}

int main(void) {
  expect_true(encsqlite_crypto_init() == ENCSQLITE_CRYPTO_OK, "crypto init failed");
  test_random_and_zeroize();
  test_hkdf_rfc5869_case1();
  test_aes256gcm_nist_vector();
  test_aes256gcm_roundtrip_16_byte_nonce();
  test_argon2id_rfc9106_case();
  return 0;
}
