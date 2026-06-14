#include "agent.h"

void crypto_wipe(void *secret, size_t size) {
    volatile uint8_t *v_secret = (uint8_t*)secret;
    for (size_t i = 0; i < size; i++) v_secret[i] = 0;
}

static uint64_t x16(const uint8_t a[16], const uint8_t b[16]) {
    return (load64_le(a) ^ load64_le(b)) | (load64_le(a+8) ^ load64_le(b+8));
}
static uint64_t x32(const uint8_t a[32], const uint8_t b[32]) {
    return x16(a, b) | x16(a+16, b+16);
}
static int neq0(uint64_t diff) {
    uint64_t half = (diff >> 32) | ((uint32_t)diff);
    return (int)(1 & ((half - 1) >> 32)) - 1;
}
int crypto_verify16(const uint8_t a[16], const uint8_t b[16]) {
    return neq0(x16(a, b));
}
int crypto_verify32(const uint8_t a[32], const uint8_t b[32]) {
    return neq0(x32(a, b));
}
