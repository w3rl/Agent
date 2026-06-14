#ifndef AGENT_AEAD_H
#define AGENT_AEAD_H

#include <stddef.h>
#include <stdint.h>
#include "../include/agent.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t counter;
    uint8_t  key[32];
    uint8_t  nonce[8];
} crypto_aead_ctx;

void crypto_aead_init_x(crypto_aead_ctx *ctx,
                        const uint8_t key[32], const uint8_t nonce[24]);
void crypto_aead_init_djb(crypto_aead_ctx *ctx,
                          const uint8_t key[32], const uint8_t nonce[8]);
void crypto_aead_init_ietf(crypto_aead_ctx *ctx,
                           const uint8_t key[32], const uint8_t nonce[12]);
void crypto_aead_write(crypto_aead_ctx *ctx,
                       uint8_t *cipher_text,
                       uint8_t mac[16],
                       const uint8_t *ad, size_t ad_size,
                       const uint8_t *plain_text, size_t text_size);
int crypto_aead_read(crypto_aead_ctx *ctx,
                     uint8_t *plain_text,
                     const uint8_t mac[16],
                     const uint8_t *ad, size_t ad_size,
                     const uint8_t *cipher_text, size_t text_size);
void crypto_aead_lock(uint8_t *cipher_text, uint8_t mac[16],
                      const uint8_t key[32], const uint8_t nonce[24],
                      const uint8_t *ad, size_t ad_size,
                      const uint8_t *plain_text, size_t text_size);
int crypto_aead_unlock(uint8_t *plain_text, const uint8_t mac[16],
                       const uint8_t key[32], const uint8_t nonce[24],
                       const uint8_t *ad, size_t ad_size,
                       const uint8_t *cipher_text, size_t text_size);

void crypto_aead_lock_ietf(uint8_t *cipher_text, uint8_t mac[16],
                         const uint8_t key[32], const uint8_t nonce[12],
                         const uint8_t *ad, size_t ad_size,
                         const uint8_t *plain_text, size_t text_size);

int crypto_aead_unlock_ietf(uint8_t *plain_text, const uint8_t mac[16],
                          const uint8_t key[32], const uint8_t nonce[12],
                          const uint8_t *ad, size_t ad_size,
                          const uint8_t *cipher_text, size_t text_size);

#ifdef __cplusplus
}
#endif

#endif // AGENT_AEAD_H
