#ifndef AGENT_CHACHA20_H
#define AGENT_CHACHA20_H

#include <stddef.h>
#include <stdint.h>
#include "../include/agent.h"

#ifdef __cplusplus
extern "C" {
#endif

void crypto_chacha20_h(uint8_t out[32], const uint8_t key[32], const uint8_t in[16]);
uint64_t crypto_chacha20_djb(uint8_t *cipher_text, const uint8_t *plain_text,
                             size_t text_size, const uint8_t key[32],
                             const uint8_t nonce[8], uint64_t ctr);
uint32_t crypto_chacha20_ietf(uint8_t *cipher_text, const uint8_t *plain_text,
                              size_t text_size, const uint8_t key[32],
                              const uint8_t nonce[12], uint32_t ctr);
uint64_t crypto_chacha20_x(uint8_t *cipher_text, const uint8_t *plain_text,
                           size_t text_size, const uint8_t key[32],
                           const uint8_t nonce[24], uint64_t ctr);

#ifdef __cplusplus
}
#endif

#endif // AGENT_CHACHA20_H
