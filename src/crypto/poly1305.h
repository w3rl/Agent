#ifndef AGENT_POLY1305_H
#define AGENT_POLY1305_H

#include <stddef.h>
#include <stdint.h>
#include "../include/agent.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t  c[16];
    size_t   c_idx;
    uint32_t r[4];
    uint32_t pad[4];
    uint32_t h[5];
} crypto_poly1305_ctx;

void crypto_poly1305_init(crypto_poly1305_ctx *ctx, const uint8_t key[32]);
void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
                            const uint8_t *message, size_t message_size);
void crypto_poly1305_final(crypto_poly1305_ctx *ctx, uint8_t mac[16]);
void crypto_poly1305(uint8_t mac[16], const uint8_t *message, size_t message_size,
                     const uint8_t key[32]);

#ifdef __cplusplus
}
#endif

#endif // AGENT_POLY1305_H
