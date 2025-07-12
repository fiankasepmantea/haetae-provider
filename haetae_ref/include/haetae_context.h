#ifndef HAETAE_CONTEXT_H
#define HAETAE_CONTEXT_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"  // Needed for CRYPTO_BYTES

#define HAETAE_SIGNATURE_LENGTH CRYPTO_BYTES

typedef struct {
    void *provctx;
    uint8_t *privkey;
    size_t privkey_len;
    uint8_t *pubkey;
    size_t pubkey_len;
} HAETAE_CTX;

#endif // HAETAE_CONTEXT_H
