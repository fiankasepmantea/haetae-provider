// haetae_ref/include/sign.h
#ifndef SIGN_H
#define SIGN_H

#include <stdint.h>
#include <stddef.h>
#include "params.h"  // Includes CRYPTO_BYTES etc.

// Define constants for OpenSSL integration
#define HAETAE_PRIVKEY_SIZE 64         // Adjust if needed
// #define HAETAE_SIGNATURE_LENGTH CRYPTO_BYTES  // 1474 or 2349 — use your actual value

// This struct is used in haetae_openssl_sign for OpenSSL EVP integration
// typedef struct {
//     uint8_t privkey[HAETAE_PRIVKEY_SIZE];
// } HAETAE_CTX;

// Core HAETAE signature API
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *msg, size_t msglen,
                          const uint8_t *sk);

int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *msg, size_t msglen,
                       const uint8_t *pk);

int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

#endif // SIGN_H
