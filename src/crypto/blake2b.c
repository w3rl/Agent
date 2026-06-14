#include "blake2b.h"
#include <string.h>

static const uint64_t iv[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

static const uint8_t sigma[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
};

#define BLAKE2_G(a, b, c, d, x, y) \
    a += b + x;  d = rotr64(d ^ a, 32); \
    c += d;      b = rotr64(b ^ c, 24); \
    a += b + y;  d = rotr64(d ^ a, 16); \
    c += d;      b = rotr64(b ^ c, 63)

#define BLAKE2_ROUND(i) \
    BLAKE2_G(v0, v4, v8 , v12, input[sigma[i][ 0]], input[sigma[i][ 1]]); \
    BLAKE2_G(v1, v5, v9 , v13, input[sigma[i][ 2]], input[sigma[i][ 3]]); \
    BLAKE2_G(v2, v6, v10, v14, input[sigma[i][ 4]], input[sigma[i][ 5]]); \
    BLAKE2_G(v3, v7, v11, v15, input[sigma[i][ 6]], input[sigma[i][ 7]]); \
    BLAKE2_G(v0, v5, v10, v15, input[sigma[i][ 8]], input[sigma[i][ 9]]); \
    BLAKE2_G(v1, v6, v11, v12, input[sigma[i][10]], input[sigma[i][11]]); \
    BLAKE2_G(v2, v7, v8 , v13, input[sigma[i][12]], input[sigma[i][13]]); \
    BLAKE2_G(v3, v4, v9 , v14, input[sigma[i][14]], input[sigma[i][15]])

static void blake2b_compress(crypto_blake2b_ctx *ctx, int is_last_block)
{
    uint64_t *x = ctx->input_offset;
    size_t y = ctx->input_idx;
    x[0] += y;
    if (x[0] < y) x[1]++;

    uint64_t v0 = ctx->hash[0];  uint64_t v8  = iv[0];
    uint64_t v1 = ctx->hash[1];  uint64_t v9  = iv[1];
    uint64_t v2 = ctx->hash[2];  uint64_t v10 = iv[2];
    uint64_t v3 = ctx->hash[3];  uint64_t v11 = iv[3];
    uint64_t v4 = ctx->hash[4];  uint64_t v12 = iv[4] ^ ctx->input_offset[0];
    uint64_t v5 = ctx->hash[5];  uint64_t v13 = iv[5] ^ ctx->input_offset[1];
    uint64_t v6 = ctx->hash[6];  uint64_t v14 = iv[6] ^ (uint64_t)~(is_last_block - 1);
    uint64_t v7 = ctx->hash[7];  uint64_t v15 = iv[7];

    uint64_t *input = ctx->input;
    BLAKE2_ROUND(0);  BLAKE2_ROUND(1);  BLAKE2_ROUND(2);  BLAKE2_ROUND(3);
    BLAKE2_ROUND(4);  BLAKE2_ROUND(5);  BLAKE2_ROUND(6);  BLAKE2_ROUND(7);
    BLAKE2_ROUND(8);  BLAKE2_ROUND(9);  BLAKE2_ROUND(10); BLAKE2_ROUND(11);

    ctx->hash[0] ^= v0 ^ v8;   ctx->hash[1] ^= v1 ^ v9;
    ctx->hash[2] ^= v2 ^ v10;  ctx->hash[3] ^= v3 ^ v11;
    ctx->hash[4] ^= v4 ^ v12;  ctx->hash[5] ^= v5 ^ v13;
    ctx->hash[6] ^= v6 ^ v14;  ctx->hash[7] ^= v7 ^ v15;
}

void crypto_blake2b_keyed_init(crypto_blake2b_ctx *ctx, size_t hash_size,
                               const uint8_t *key, size_t key_size)
{
    for (int i = 0; i < 8; i++) ctx->hash[i] = iv[i];
    ctx->hash[0] ^= 0x01010000 ^ (key_size << 8) ^ hash_size;
    ctx->input_offset[0] = 0;
    ctx->input_offset[1] = 0;
    ctx->hash_size = hash_size;
    ctx->input_idx = 0;
    ZERO(ctx->input, 16);

    if (key_size > 0) {
        uint8_t key_block[128] = {0};
        memcpy(key_block, key, key_size);
        for (int i = 0; i < 16; i++) {
            ctx->input[i] = load64_le(key_block + i*8);
        }
        ctx->input_idx = 128;
        crypto_wipe(key_block, sizeof(key_block));
    }
}

void crypto_blake2b_init(crypto_blake2b_ctx *ctx, size_t hash_size)
{
    crypto_blake2b_keyed_init(ctx, hash_size, 0, 0);
}

void crypto_blake2b_update(crypto_blake2b_ctx *ctx,
                           const uint8_t *message, size_t message_size)
{
    if (message_size == 0) return;

    if ((ctx->input_idx & 7) != 0) {
        size_t nb_bytes = ((~ctx->input_idx + 1) & 7);
        if (nb_bytes > message_size) nb_bytes = message_size;
        size_t word = ctx->input_idx >> 3;
        size_t byte = ctx->input_idx & 7;
        for (size_t i = 0; i < nb_bytes; i++) {
            ctx->input[word] |= (uint64_t)message[i] << ((byte + i) << 3);
        }
        ctx->input_idx += nb_bytes;
        message += nb_bytes;
        message_size -= nb_bytes;
    }

    if ((ctx->input_idx & 127) != 0) {
        size_t nb_words = ((~ctx->input_idx + 1) & 127) >> 3;
        if (nb_words > (message_size >> 3)) nb_words = message_size >> 3;
        for (size_t i = 0; i < nb_words; i++) {
            ctx->input[(ctx->input_idx >> 3) + i] = load64_le(message + i*8);
        }
        ctx->input_idx += nb_words << 3;
        message += nb_words << 3;
        message_size -= nb_words << 3;
    }

    size_t nb_blocks = message_size >> 7;
    for (size_t i = 0; i < nb_blocks; i++) {
        if (ctx->input_idx == 128) {
            blake2b_compress(ctx, 0);
        }
        for (int j = 0; j < 16; j++) {
            ctx->input[j] = load64_le(message + j*8);
        }
        message += 128;
        ctx->input_idx = 128;
    }
    message_size &= 127;

    if (message_size != 0) {
        if (ctx->input_idx == 128) {
            blake2b_compress(ctx, 0);
            ctx->input_idx = 0;
            ZERO(ctx->input, 16);
        }
        size_t nb_words = message_size >> 3;
        if (nb_words) {
            for (size_t i = 0; i < nb_words; i++) {
                ctx->input[(ctx->input_idx >> 3) + i] = load64_le(message + i*8);
            }
            ctx->input_idx += nb_words << 3;
            message += nb_words << 3;
            message_size -= nb_words << 3;
        }
        for (size_t i = 0; i < message_size; i++) {
            size_t word = ctx->input_idx >> 3;
            size_t byte = ctx->input_idx & 7;
            ctx->input[word] |= (uint64_t)message[i] << (byte << 3);
            ctx->input_idx++;
        }
    }
}

void crypto_blake2b_final(crypto_blake2b_ctx *ctx, uint8_t *hash)
{
    blake2b_compress(ctx, 1);
    size_t hash_size = ctx->hash_size;
    if (hash_size > 64) hash_size = 64;
    size_t nb_words = hash_size >> 3;
    for (size_t i = 0; i < nb_words; i++) {
        store64_le(hash + i*8, ctx->hash[i]);
    }
    for (size_t i = nb_words << 3; i < hash_size; i++) {
        hash[i] = (ctx->hash[i >> 3] >> (8 * (i & 7))) & 0xff;
    }
    crypto_wipe(ctx, sizeof(*ctx));
}

void crypto_blake2b_keyed(uint8_t *hash, size_t hash_size,
                          const uint8_t *key, size_t key_size,
                          const uint8_t *message, size_t message_size)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_keyed_init(&ctx, hash_size, key, key_size);
    crypto_blake2b_update(&ctx, message, message_size);
    crypto_blake2b_final(&ctx, hash);
}

void crypto_blake2b(uint8_t *hash, size_t hash_size,
                    const uint8_t *message, size_t message_size)
{
    crypto_blake2b_keyed(hash, hash_size, 0, 0, message, message_size);
}
