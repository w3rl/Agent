#include "aead.h"
#include "chacha20.h"
#include "poly1305.h"
#include <string.h>

static void lock_auth(uint8_t mac[16], const uint8_t auth_key[32],
                      const uint8_t *ad, size_t ad_size,
                      const uint8_t *cipher_text, size_t text_size)
{
    uint8_t sizes[16];
    store64_le(sizes + 0, ad_size);
    store64_le(sizes + 8, text_size);
    crypto_poly1305_ctx poly_ctx;
    crypto_poly1305_init(&poly_ctx, auth_key);
    crypto_poly1305_update(&poly_ctx, ad, ad_size);
    size_t pad1 = (16 - (ad_size % 16)) % 16;
    if (pad1) {
        uint8_t zero[16] = {0};
        crypto_poly1305_update(&poly_ctx, zero, pad1);
    }
    crypto_poly1305_update(&poly_ctx, cipher_text, text_size);
    size_t pad2 = (16 - (text_size % 16)) % 16;
    if (pad2) {
        uint8_t zero[16] = {0};
        crypto_poly1305_update(&poly_ctx, zero, pad2);
    }
    crypto_poly1305_update(&poly_ctx, sizes, 16);
    crypto_poly1305_final(&poly_ctx, mac);
}

void crypto_aead_init_x(crypto_aead_ctx *ctx,
                        const uint8_t key[32], const uint8_t nonce[24])
{
    crypto_chacha20_h(ctx->key, key, nonce);
    for (int i = 0; i < 8; i++) ctx->nonce[i] = nonce[16 + i];
    ctx->counter = 0;
}

void crypto_aead_init_djb(crypto_aead_ctx *ctx,
                          const uint8_t key[32], const uint8_t nonce[8])
{
    for (int i = 0; i < 32; i++) ctx->key[i] = key[i];
    for (int i = 0; i < 8; i++) ctx->nonce[i] = nonce[i];
    ctx->counter = 0;
}

void crypto_aead_init_ietf(crypto_aead_ctx *ctx,
                           const uint8_t key[32], const uint8_t nonce[12])
{
    for (int i = 0; i < 32; i++) ctx->key[i] = key[i];
    for (int i = 0; i < 8; i++) ctx->nonce[i] = nonce[i+4];
    ctx->counter = (uint64_t)load32_le(nonce) << 32;
}

void crypto_aead_write(crypto_aead_ctx *ctx, uint8_t *cipher_text, uint8_t mac[16],
                       const uint8_t *ad, size_t ad_size,
                       const uint8_t *plain_text, size_t text_size)
{
    uint8_t auth_key[64];
    crypto_chacha20_djb(auth_key, 0, 64, ctx->key, ctx->nonce, ctx->counter);
    crypto_chacha20_djb(cipher_text, plain_text, text_size,
                        ctx->key, ctx->nonce, ctx->counter + 1);
    lock_auth(mac, auth_key, ad, ad_size, cipher_text, text_size);
    for (int i = 0; i < 32; i++) ctx->key[i] = auth_key[32 + i];
    crypto_wipe(auth_key, sizeof(auth_key));
}

int crypto_aead_read(crypto_aead_ctx *ctx, uint8_t *plain_text, const uint8_t mac[16],
                     const uint8_t *ad, size_t ad_size,
                     const uint8_t *cipher_text, size_t text_size)
{
    uint8_t auth_key[64];
    uint8_t real_mac[16];
    crypto_chacha20_djb(auth_key, 0, 64, ctx->key, ctx->nonce, ctx->counter);
    lock_auth(real_mac, auth_key, ad, ad_size, cipher_text, text_size);
    int mismatch = crypto_verify16(mac, real_mac);
    if (!mismatch) {
        crypto_chacha20_djb(plain_text, cipher_text, text_size,
                            ctx->key, ctx->nonce, ctx->counter + 1);
        for (int i = 0; i < 32; i++) ctx->key[i] = auth_key[32 + i];
    }
    crypto_wipe(auth_key, sizeof(auth_key));
    crypto_wipe(real_mac, sizeof(real_mac));
    return mismatch;
}

void crypto_aead_lock(uint8_t *cipher_text, uint8_t mac[16],
                      const uint8_t key[32], const uint8_t nonce[24],
                      const uint8_t *ad, size_t ad_size,
                      const uint8_t *plain_text, size_t text_size)
{
    crypto_aead_ctx ctx;
    crypto_aead_init_x(&ctx, key, nonce);
    crypto_aead_write(&ctx, cipher_text, mac, ad, ad_size, plain_text, text_size);
    crypto_wipe(&ctx, sizeof(ctx));
}

int crypto_aead_unlock(uint8_t *plain_text, const uint8_t mac[16],
                       const uint8_t key[32], const uint8_t nonce[24],
                       const uint8_t *ad, size_t ad_size,
                       const uint8_t *cipher_text, size_t text_size)
{
    crypto_aead_ctx ctx;
    crypto_aead_init_x(&ctx, key, nonce);
    int mismatch = crypto_aead_read(&ctx, plain_text, mac, ad, ad_size,
                                    cipher_text, text_size);
    crypto_wipe(&ctx, sizeof(ctx));
    return mismatch;
}

static void crypto_aead_write_ietf(uint8_t *cipher_text, uint8_t mac[16],
                       const uint8_t *ad, size_t ad_size,
                       const uint8_t *plain_text, size_t text_size, const uint8_t key[32], const uint8_t nonce[12])
{
    uint8_t auth_key[32];
    // IETF uses a 32-byte block for poly1305 key, generated from block 0.
    crypto_chacha20_ietf(auth_key, NULL, 32, key, nonce, 0);
    crypto_chacha20_ietf(cipher_text, plain_text, text_size,
                        key, nonce, 1);
    lock_auth(mac, auth_key, ad, ad_size, cipher_text, text_size);
    crypto_wipe(auth_key, sizeof(auth_key));
}

static int crypto_aead_read_ietf(uint8_t *plain_text, const uint8_t mac[16],
                     const uint8_t *ad, size_t ad_size,
                     const uint8_t *cipher_text, size_t text_size, const uint8_t key[32], const uint8_t nonce[12])
{
    uint8_t auth_key[32];
    uint8_t real_mac[16];
    crypto_chacha20_ietf(auth_key, NULL, 32, key, nonce, 0);
    lock_auth(real_mac, auth_key, ad, ad_size, cipher_text, text_size);
    int mismatch = crypto_verify16(mac, real_mac);
    if (!mismatch) {
        crypto_chacha20_ietf(plain_text, cipher_text, text_size,
                            key, nonce, 1);
    }
    crypto_wipe(auth_key, sizeof(auth_key));
    crypto_wipe(real_mac, sizeof(real_mac));
    return mismatch;
}

void crypto_aead_lock_ietf(uint8_t *cipher_text, uint8_t mac[16],
                         const uint8_t key[32], const uint8_t nonce[12],
                         const uint8_t *ad, size_t ad_size,
                         const uint8_t *plain_text, size_t text_size)
{
    crypto_aead_write_ietf(cipher_text, mac, ad, ad_size, plain_text, text_size, key, nonce);
}

int crypto_aead_unlock_ietf(uint8_t *plain_text, const uint8_t mac[16],
                          const uint8_t key[32], const uint8_t nonce[12],
                          const uint8_t *ad, size_t ad_size,
                          const uint8_t *cipher_text, size_t text_size)
{
    return crypto_aead_read_ietf(plain_text, mac, ad, ad_size, cipher_text, text_size, key, nonce);
}
