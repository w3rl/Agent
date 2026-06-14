#ifndef AGENT_H
#define AGENT_H

#include <stddef.h>
#include <stdint.h>

// ------------------------------------------------------------
// Common helpers (from Monocypher)
// ------------------------------------------------------------
static inline uint32_t load32_le(const uint8_t s[4]) {
    return (uint32_t)s[0] | ((uint32_t)s[1] << 8) |
           ((uint32_t)s[2] << 16) | ((uint32_t)s[3] << 24);
}
static inline void store32_le(uint8_t out[4], uint32_t in) {
    out[0] = in; out[1] = in >> 8;
    out[2] = in >> 16; out[3] = in >> 24;
}
static inline uint64_t load64_le(const uint8_t s[8]) {
    return (uint64_t)load32_le(s) | ((uint64_t)load32_le(s+4) << 32);
}
static inline void store64_le(uint8_t out[8], uint64_t in) {
    store32_le(out, (uint32_t)in);
    store32_le(out+4, (uint32_t)(in >> 32));
}
static inline uint32_t load24_le(const uint8_t s[3]) {
    return (uint32_t)s[0] | ((uint32_t)s[1] << 8) | ((uint32_t)s[2] << 16);
}
static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}
static inline uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}
#define FOR_T(type, i, start, end) for (type i = (start); i < (end); i++)
#define FOR(i, start, end) FOR_T(size_t, i, start, end)
#define ZERO(buf, size) FOR(_i_, 0, size) (buf)[_i_] = 0

// ------------------------------------------------------------
// Core functions (implemented in include/agent.c)
// ------------------------------------------------------------
void crypto_wipe(void *secret, size_t size);
int  crypto_verify16(const uint8_t a[16], const uint8_t b[16]);
int  crypto_verify32(const uint8_t a[32], const uint8_t b[32]);

// ------------------------------------------------------------
// Include all crypto module headers
// ------------------------------------------------------------
#include "../src/crypto/chacha20.h"
#include "../src/crypto/poly1305.h"
#include "../src/crypto/x25519.h"
#include "../src/crypto/blake2b.h"
#include "../src/crypto/aead.h"

#endif
