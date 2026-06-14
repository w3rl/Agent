#include "crypto/noise.h"
#include "crypto/blake2b.h"
#include "crypto/x25519.h"
#include "crypto/aead.h"
#include "include/agent.h"
#include <string.h>
#include <stdio.h>

static const char* PROTOCOL_NAME = "Noise_XX_25519_ChaChaPoly_BLAKE2b";

static void mix_hash(NoiseState* state, const uint8_t* data, size_t data_len) {
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, 32);
    crypto_blake2b_update(&ctx, state->h, 32);
    if (data && data_len > 0) {
        crypto_blake2b_update(&ctx, data, data_len);
    }
    crypto_blake2b_final(&ctx, state->h);
}

// output = (new_ck, k)
static void hkdf(uint8_t* ck, uint8_t* k, const uint8_t* ikm, size_t ikm_len, const uint8_t* salt) {
    uint8_t output[64];
    crypto_blake2b_keyed(output, 64, salt, 32, ikm, ikm_len);
    memcpy(ck, output, 32);
    if (k) {
        memcpy(k, output + 32, 32);
    }
}

static void encrypt_and_hash(NoiseState* state, uint8_t* dst, const uint8_t* src, size_t src_len) {
    uint8_t nonce[12] = {0};
    uint8_t mac[16];
    store64_le(nonce + 4, state->n_tx);
    crypto_aead_lock_ietf(dst, mac, state->k_tx, nonce, state->h, 32, src, src_len);
    memcpy(dst + src_len, mac, 16);
    mix_hash(state, dst, src_len + 16);
    state->n_tx++;
}

static int decrypt_and_hash(NoiseState* state, uint8_t* dst, const uint8_t* src, size_t src_len) {
    uint8_t nonce[12] = {0};
    uint8_t mac[16];
    store64_le(nonce + 4, state->n_rx);
    memcpy(mac, src + src_len - 16, 16);
    if (crypto_aead_unlock_ietf(dst, mac, state->k_rx, nonce, state->h, 32, src, src_len - 16) != 0) {
        return -1;
    }
    mix_hash(state, src, src_len);
    state->n_rx++;
    return 0;
}

void noise_init(NoiseState* state, bool initiator, const uint8_t* static_key) {
    memset(state, 0, sizeof(NoiseState));
    memcpy(state->s, static_key, NOISE_PRIVATE_KEY_SIZE);
    state->initiator = initiator;
    state->handshake_state = 0;

    crypto_blake2b(state->h, 32, (const uint8_t*)PROTOCOL_NAME, strlen(PROTOCOL_NAME));
    memcpy(state->ck, state->h, 32);
    mix_hash(state, NULL, 0); // Prologue is empty
}

int noise_handshake_write(NoiseState* state, uint8_t* buffer, size_t* buffer_len) {
    uint8_t e_pub[NOISE_PUBLIC_KEY_SIZE];
    uint8_t s_pub[NOISE_PUBLIC_KEY_SIZE];
    uint8_t dh[32];

    if (state->initiator) {
        if (state->handshake_state == 0) { // -> e
            crypto_x25519_keypair(e_pub, state->e);
            mix_hash(state, e_pub, NOISE_PUBLIC_KEY_SIZE);
            memcpy(buffer, e_pub, NOISE_PUBLIC_KEY_SIZE);
            *buffer_len = NOISE_PUBLIC_KEY_SIZE;
            state->handshake_state = 1;
            return 0;
        } else if (state->handshake_state == 2) { // -> s, se
            crypto_x25519_public_key(s_pub, state->s);
            encrypt_and_hash(state, buffer, s_pub, NOISE_PUBLIC_KEY_SIZE);
            *buffer_len = NOISE_PUBLIC_KEY_SIZE + 16;

            crypto_x25519(dh, state->s, state->re, 32);
            hkdf(state->ck, state->k_tx, dh, 32, state->ck);

            // Split
            uint8_t temp_k1[32], temp_k2[32];
            hkdf(state->ck, temp_k1, NULL, 0, state->ck);
            hkdf(state->ck, temp_k2, NULL, 0, state->ck);
            memcpy(state->k_tx, temp_k1, 32);
            memcpy(state->k_rx, temp_k2, 32);

            state->handshake_state = 3;
            state->n_tx = 0;
            state->n_rx = 0;
            return 0;
        }
    } else { // Responder
        if (state->handshake_state == 1) { // <- e, ee, s, es
            crypto_x25519_keypair(e_pub, state->e);
            mix_hash(state, e_pub, NOISE_PUBLIC_KEY_SIZE);
            memcpy(buffer, e_pub, NOISE_PUBLIC_KEY_SIZE);

            crypto_x25519(dh, state->e, state->re, 32);
            hkdf(state->ck, state->k_tx, dh, 32, state->ck);
            state->n_tx = 0;

            crypto_x25519_public_key(s_pub, state->s);
            encrypt_and_hash(state, buffer + NOISE_PUBLIC_KEY_SIZE, s_pub, NOISE_PUBLIC_KEY_SIZE);

            crypto_x25519(dh, state->s, state->re, 32);
            hkdf(state->ck, state->k_tx, dh, 32, state->ck);

            *buffer_len = NOISE_PUBLIC_KEY_SIZE + NOISE_PUBLIC_KEY_SIZE + 16;

            // Split
            uint8_t temp_k1[32], temp_k2[32];
            hkdf(state->ck, temp_k1, NULL, 0, state->ck);
            hkdf(state->ck, temp_k2, NULL, 0, state->ck);
            memcpy(state->k_rx, temp_k1, 32);
            memcpy(state->k_tx, temp_k2, 32);
            
            state->handshake_state = 3;
            state->n_tx = 0;
            state->n_rx = 0;
            return 0;
        }
    }
    return -1;
}

int noise_handshake_read(NoiseState* state, const uint8_t* msg, size_t msg_len) {
    uint8_t dh[32];

    if (state->initiator) {
        if (state->handshake_state == 1) { // <- e, ee, s, es
            if (msg_len != NOISE_PUBLIC_KEY_SIZE + NOISE_PUBLIC_KEY_SIZE + 16) return -1;

            memcpy(state->re, msg, NOISE_PUBLIC_KEY_SIZE);
            mix_hash(state, state->re, NOISE_PUBLIC_KEY_SIZE);

            crypto_x25519(dh, state->e, state->re, 32);
            hkdf(state->ck, state->k_rx, dh, 32, state->ck);
            state->n_rx = 0;

            if (decrypt_and_hash(state, state->rs, msg + NOISE_PUBLIC_KEY_SIZE, NOISE_PUBLIC_KEY_SIZE + 16) != 0) return -1;

            crypto_x25519(dh, state->e, state->rs, 32);
            hkdf(state->ck, state->k_rx, dh, 32, state->ck);

            state->handshake_state = 2;
            return 0;
        }
    } else { // Responder
        if (state->handshake_state == 0) { // -> e
            if (msg_len != NOISE_PUBLIC_KEY_SIZE) return -1;
            memcpy(state->re, msg, NOISE_PUBLIC_KEY_SIZE);
            mix_hash(state, state->re, NOISE_PUBLIC_KEY_SIZE);
            state->handshake_state = 1;
            return 0;
        } else if (state->handshake_state == 1) { // <- s, se message from initiator
            if (msg_len != NOISE_PUBLIC_KEY_SIZE + 16) return -1;

            uint8_t temp_s[NOISE_PUBLIC_KEY_SIZE];
            if (decrypt_and_hash(state, temp_s, msg, NOISE_PUBLIC_KEY_SIZE + 16) != 0) return -1;
            memcpy(state->rs, temp_s, NOISE_PUBLIC_KEY_SIZE);

            crypto_x25519(dh, state->e, state->rs, 32);
            hkdf(state->ck, state->k_rx, dh, 32, state->ck);

            // Split
            uint8_t temp_k1[32], temp_k2[32];
            hkdf(state->ck, temp_k1, NULL, 0, state->ck);
            hkdf(state->ck, temp_k2, NULL, 0, state->ck);
            memcpy(state->k_tx, temp_k1, 32);
            memcpy(state->k_rx, temp_k2, 32);

            state->handshake_state = 3;
            state->n_tx = 0;
            state->n_rx = 0;
            return 0;
        }
    }
    return -1;
}

int noise_encrypt(NoiseState* state, const uint8_t* p, size_t p_len, uint8_t* c, size_t* c_len) {
    if (state->handshake_state != 3) return -1;
    uint8_t nonce[12] = {0}; 
    store64_le(nonce + 4, state->n_tx);
    uint8_t mac[16];
    crypto_aead_lock_ietf(c, mac, state->k_tx, nonce, NULL, 0, p, p_len);
    memcpy(c + p_len, mac, 16);
    *c_len = p_len + 16;
    state->n_tx++;
    return 0;
}

int noise_decrypt(NoiseState* state, const uint8_t* c, size_t c_len, uint8_t* p, size_t* p_len) {
    if (state->handshake_state != 3) return -1;
    if (c_len < 16) return -1;
    uint8_t nonce[12] = {0};
    store64_le(nonce + 4, state->n_rx);
    uint8_t mac[16];
    memcpy(mac, c + c_len - 16, 16);
    if (crypto_aead_unlock_ietf(p, mac, state->k_rx, nonce, NULL, 0, c, c_len - 16) != 0) {
        return -1;
    }
    *p_len = c_len - 16;
    state->n_rx++;
    return 0;
}

