#include "chacha20.h"
#include <string.h>

static const uint8_t *chacha20_constant = (const uint8_t*)"expand 32-byte k";

#define QUARTERROUND(a, b, c, d) \
    a += b; d = rotl32(d ^ a, 16); \
    c += d; b = rotl32(b ^ c, 12); \
    a += b; d = rotl32(d ^ a, 8);  \
    c += d; b = rotl32(b ^ c, 7)

static void chacha20_rounds(uint32_t out[16], const uint32_t in[16])
{
    uint32_t t0  = in[ 0];  uint32_t t1  = in[ 1];  uint32_t t2  = in[ 2];  uint32_t t3  = in[ 3];
    uint32_t t4  = in[ 4];  uint32_t t5  = in[ 5];  uint32_t t6  = in[ 6];  uint32_t t7  = in[ 7];
    uint32_t t8  = in[ 8];  uint32_t t9  = in[ 9];  uint32_t t10 = in[10];  uint32_t t11 = in[11];
    uint32_t t12 = in[12];  uint32_t t13 = in[13];  uint32_t t14 = in[14];  uint32_t t15 = in[15];

    for (int i = 0; i < 10; i++) {
        QUARTERROUND(t0, t4, t8 , t12);
        QUARTERROUND(t1, t5, t9 , t13);
        QUARTERROUND(t2, t6, t10, t14);
        QUARTERROUND(t3, t7, t11, t15);
        QUARTERROUND(t0, t5, t10, t15);
        QUARTERROUND(t1, t6, t11, t12);
        QUARTERROUND(t2, t7, t8 , t13);
        QUARTERROUND(t3, t4, t9 , t14);
    }
    out[ 0] = t0;   out[ 1] = t1;   out[ 2] = t2;   out[ 3] = t3;
    out[ 4] = t4;   out[ 5] = t5;   out[ 6] = t6;   out[ 7] = t7;
    out[ 8] = t8;   out[ 9] = t9;   out[10] = t10;  out[11] = t11;
    out[12] = t12;  out[13] = t13;  out[14] = t14;  out[15] = t15;
}

void crypto_chacha20_h(uint8_t out[32], const uint8_t key[32], const uint8_t in[16])
{
    uint32_t block[16];
    block[0] = load32_le(chacha20_constant + 0*4);
    block[1] = load32_le(chacha20_constant + 1*4);
    block[2] = load32_le(chacha20_constant + 2*4);
    block[3] = load32_le(chacha20_constant + 3*4);
    for (int i = 0; i < 8; i++) {
        block[4+i] = load32_le(key + i*4);
    }
    block[12] = load32_le(in + 0*4);
    block[13] = load32_le(in + 1*4);
    block[14] = load32_le(in + 2*4);
    block[15] = load32_le(in + 3*4);

    chacha20_rounds(block, block);
    store32_le(out,     block[0]);
    store32_le(out+4,   block[1]);
    store32_le(out+8,   block[2]);
    store32_le(out+12,  block[3]);
    store32_le(out+16,  block[12]);
    store32_le(out+20,  block[13]);
    store32_le(out+24,  block[14]);
    store32_le(out+28,  block[15]);
}

static const uint8_t zero[128] = {0};

uint64_t crypto_chacha20_djb(uint8_t *cipher_text, const uint8_t *plain_text,
                             size_t text_size, const uint8_t key[32],
                             const uint8_t nonce[8], uint64_t ctr)
{
    uint32_t input[16];
    input[0] = load32_le(chacha20_constant + 0*4);
    input[1] = load32_le(chacha20_constant + 1*4);
    input[2] = load32_le(chacha20_constant + 2*4);
    input[3] = load32_le(chacha20_constant + 3*4);
    for (int i = 0; i < 8; i++) {
        input[4+i] = load32_le(key + i*4);
    }
    input[12] = (uint32_t)ctr;
    input[13] = (uint32_t)(ctr >> 32);
    input[14] = load32_le(nonce);
    input[15] = load32_le(nonce + 4);

    uint32_t pool[16];
    size_t nb_blocks = text_size >> 6;
    for (size_t i = 0; i < nb_blocks; i++) {
        chacha20_rounds(pool, input);
        if (plain_text) {
            for (int j = 0; j < 16; j++) {
                uint32_t p = pool[j] + input[j];
                store32_le(cipher_text, p ^ load32_le(plain_text));
                cipher_text += 4; plain_text += 4;
            }
        } else {
            for (int j = 0; j < 16; j++) {
                uint32_t p = pool[j] + input[j];
                store32_le(cipher_text, p);
                cipher_text += 4;
            }
        }
        input[12]++;
        if (input[12] == 0) input[13]++;
    }
    text_size &= 63;
    if (text_size > 0) {
        if (plain_text == NULL) plain_text = zero;
        chacha20_rounds(pool, input);
        uint8_t tmp[64];
        for (int j = 0; j < 16; j++) {
            store32_le(tmp + j*4, pool[j] + input[j]);
        }
        for (size_t i = 0; i < text_size; i++) {
            cipher_text[i] = tmp[i] ^ plain_text[i];
        }
    }
    return input[12] + ((uint64_t)input[13] << 32) + (text_size > 0);
}

uint32_t crypto_chacha20_ietf(uint8_t *cipher_text, const uint8_t *plain_text,
                              size_t text_size, const uint8_t key[32],
                              const uint8_t nonce[12], uint32_t ctr)
{
    uint64_t big_ctr = ctr + ((uint64_t)load32_le(nonce) << 32);
    return (uint32_t)crypto_chacha20_djb(cipher_text, plain_text, text_size,
                                         key, nonce + 4, big_ctr);
}

uint64_t crypto_chacha20_x(uint8_t *cipher_text, const uint8_t *plain_text,
                           size_t text_size, const uint8_t key[32],
                           const uint8_t nonce[24], uint64_t ctr)
{
    uint8_t sub_key[32];
    crypto_chacha20_h(sub_key, key, nonce);
    ctr = crypto_chacha20_djb(cipher_text, plain_text, text_size,
                              sub_key, nonce + 16, ctr);
    crypto_wipe(sub_key, sizeof(sub_key));
    return ctr;
}
