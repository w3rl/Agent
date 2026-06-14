#ifndef AGENT_X25519_H
#define AGENT_X25519_H

#include <stddef.h>
#include <stdint.h>
#include "../include/agent.h"

#ifdef __cplusplus
extern "C" {
#endif

void crypto_x25519_public_key(uint8_t public_key[32], const uint8_t secret_key[32]);
void crypto_x25519_keypair(uint8_t public_key[32], uint8_t secret_key[32]);
void crypto_x25519(uint8_t raw_shared_secret[32],
                   const uint8_t your_secret_key[32],
                   const uint8_t their_public_key[32]);
void crypto_x25519_inverse(uint8_t blind_salt[32],
                           const uint8_t private_key[32],
                           const uint8_t curve_point[32]);

#ifdef __cplusplus
}
#endif

#endif // AGENT_X25519_H
