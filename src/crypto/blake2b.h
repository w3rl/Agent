#ifndef AGENT_BLAKE2B_H
#define AGENT_BLAKE2B_H

#include <stddef.h>
#include <stdint.h>
#include "../include/agent.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t hash[8];
    uint64_t input_offset[2];
    uint64_t input[16];
    size_t   input_idx;
    size_t   hash_size;
} crypto_blake2b_ctx;

void crypto_blake2b_init(crypto_blake2b_ctx *ctx, size_t hash_size);
void crypto_blake2b_keyed_init(crypto_blake2b_ctx *ctx, size_t hash_size,
                               const uint8_t *key, size_t key_size);
void crypto_blake2b_update(crypto_blake2b_ctx *ctx,
                           const uint8_t *message, size_t message_size);
void crypto_blake2b_final(crypto_blake2b_ctx *ctx, uint8_t *hash);
void crypto_blake2b(uint8_t *hash, size_t hash_size,
                    const uint8_t *message, size_t message_size);
void crypto_blake2b_keyed(uint8_t *hash, size_t hash_size,
                          const uint8_t *key, size_t key_size,
                          const uint8_t *message, size_t message_size);

#ifdef __cplusplus
}
#endif

#endif // AGENT_BLAKE2B_H
