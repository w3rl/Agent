#include "poly1305.h"
#include <string.h>


static void poly1305_blocks(crypto_poly1305_ctx *ctx, const uint8_t *in,
                            size_t nb_blocks, unsigned end) {
    const uint32_t r0 = ctx->r[0];
    const uint32_t r1 = ctx->r[1];
    const uint32_t r2 = ctx->r[2];
    const uint32_t r3 = ctx->r[3];
    const uint32_t rr0 = (r0 >> 2) * 5;
    const uint32_t rr1 = (r1 >> 2) + r1;
    const uint32_t rr2 = (r2 >> 2) + r2;
    const uint32_t rr3 = (r3 >> 2) + r3;
    const uint32_t rr4 = r0 & 3;
    uint32_t h0 = ctx->h[0];
    uint32_t h1 = ctx->h[1];
    uint32_t h2 = ctx->h[2];
    uint32_t h3 = ctx->h[3];
    uint32_t h4 = ctx->h[4];

    while (nb_blocks--) {
        const uint64_t s0 = (uint64_t)h0 + load32_le(in);  in += 4;
        const uint64_t s1 = (uint64_t)h1 + load32_le(in);  in += 4;
        const uint64_t s2 = (uint64_t)h2 + load32_le(in);  in += 4;
        const uint64_t s3 = (uint64_t)h3 + load32_le(in);  in += 4;
        const uint32_t s4 = h4 + end;

        const uint64_t x0 = s0*r0 + s1*rr3 + s2*rr2 + s3*rr1 + s4*rr0;
        const uint64_t x1 = s0*r1 + s1*r0 + s2*rr3 + s3*rr2 + s4*rr1;
        const uint64_t x2 = s0*r2 + s1*r1 + s2*r0 + s3*rr3 + s4*rr2;
        const uint64_t x3 = s0*r3 + s1*r2 + s2*r1 + s3*r0 + s4*rr3;
        const uint32_t x4 = s4 * rr4;

        const uint32_t u5 = (uint32_t)(x3 >> 32) + x4;
        const uint64_t u0 = (uint32_t)(u5 >> 2) * 5 + (x0 & 0xffffffff);
        const uint64_t u1 = (uint32_t)(u0 >> 32) + (x1 & 0xffffffff) + (x0 >> 32);
        const uint64_t u2 = (uint32_t)(u1 >> 32) + (x2 & 0xffffffff) + (x1 >> 32);
        const uint64_t u3 = (uint32_t)(u2 >> 32) + (x3 & 0xffffffff) + (x2 >> 32);
        const uint32_t u4 = (uint32_t)(u3 >> 32) + (u5 & 3);

        h0 = u0 & 0xffffffff;
        h1 = u1 & 0xffffffff;
        h2 = u2 & 0xffffffff;
        h3 = u3 & 0xffffffff;
        h4 = u4;
    }
    ctx->h[0] = h0; ctx->h[1] = h1; ctx->h[2] = h2;
    ctx->h[3] = h3; ctx->h[4] = h4;
}

void crypto_poly1305_init(crypto_poly1305_ctx *ctx, const uint8_t key[32]) {
    ZERO(ctx->h, 5);
    ctx->c_idx = 0;
    for (int i = 0; i < 4; i++) {
        ctx->r[i] = load32_le(key + i*4);
        ctx->pad[i] = load32_le(key + 16 + i*4);
    }
    ctx->r[0] &= 0x0fffffff;
    ctx->r[1] &= 0x0ffffffc;
    ctx->r[2] &= 0x0ffffffc;
    ctx->r[3] &= 0x0ffffffc;
}

void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
                            const uint8_t *message, size_t message_size) {
    if (message_size == 0) return;

    size_t aligned = ( (~ctx->c_idx + 1) & 15 );
    if (aligned > message_size) aligned = message_size;
    for (size_t i = 0; i < aligned; i++) {
        ctx->c[ctx->c_idx++] = *message++;
    }
    message_size -= aligned;
    if (ctx->c_idx == 16) {
        poly1305_blocks(ctx, ctx->c, 1, 1);
        ctx->c_idx = 0;
    }

    size_t nb_blocks = message_size >> 4;
    if (nb_blocks) {
        poly1305_blocks(ctx, message, nb_blocks, 1);
        message += nb_blocks << 4;
        message_size &= 15;
    }

    for (size_t i = 0; i < message_size; i++) {
        ctx->c[ctx->c_idx++] = message[i];
    }
}

void crypto_poly1305_final(crypto_poly1305_ctx *ctx, uint8_t mac[16]) {
    if (ctx->c_idx != 0) {
        ZERO(ctx->c + ctx->c_idx, 16 - ctx->c_idx);
        ctx->c[ctx->c_idx] = 1;
        poly1305_blocks(ctx, ctx->c, 1, 0);
    }

    uint64_t c = 5;
    for (int i = 0; i < 4; i++) {
        c += ctx->h[i];
        c >>= 32;
    }
    c += ctx->h[4];
    c = (c >> 2) * 5;
    for (int i = 0; i < 4; i++) {
        c += (uint64_t)ctx->h[i] + ctx->pad[i];
        store32_le(mac + i*4, (uint32_t)c);
        c >>= 32;
    }
    crypto_wipe(ctx, sizeof(*ctx));
}

void crypto_poly1305(uint8_t mac[16], const uint8_t *message, size_t message_size,
                     const uint8_t key[32]) {
    crypto_poly1305_ctx ctx;
    crypto_poly1305_init(&ctx, key);
    crypto_poly1305_update(&ctx, message, message_size);
    crypto_poly1305_final(&ctx, mac);
}
