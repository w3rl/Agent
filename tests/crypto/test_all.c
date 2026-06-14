#include "../include/agent.h"
#include <stdio.h>
#include <string.h>

static int test_chacha20(void) {
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    const char *plain = "Hello, ChaCha20!";
    uint8_t cipher1[100], cipher2[100], decrypted[100];
    size_t len = strlen(plain);

    // Counter = 0 testi
    crypto_chacha20_ietf(cipher1, (const uint8_t*)plain, len, key, nonce, 0);
    crypto_chacha20_ietf(decrypted, cipher1, len, key, nonce, 0);
    if (memcmp(plain, decrypted, len) != 0) return 1;

    // Counter = 1 testi
    crypto_chacha20_ietf(cipher2, (const uint8_t*)plain, len, key, nonce, 1);
    crypto_chacha20_ietf(decrypted, cipher2, len, key, nonce, 1);
    if (memcmp(plain, decrypted, len) != 0) return 1;

    // Counter değiştiğinde şifreli metnin de değiştiğini doğrula
    if (memcmp(cipher1, cipher2, len) == 0) return 1; 

    return 0;
}

static int test_poly1305(void) {
    const uint8_t key[32] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
        0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
        0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
    };
    const uint8_t msg[] = {
        0x43,0x72,0x79,0x70,0x74,0x6f,0x67,0x72,
        0x61,0x70,0x68,0x69,0x63,0x20,0x46,0x6f,
        0x72,0x75,0x6d,0x20,0x52,0x65,0x73,0x65,
        0x61,0x72,0x63,0x68,0x20,0x47,0x72,0x6f,
        0x75,0x70
    };
    const uint8_t expected[16] = {
        0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,
        0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9
    };
    uint8_t mac[16];
    crypto_poly1305(mac, msg, sizeof(msg), key);
    
    // crypto_verify16 eşleşme durumunda 0 dönmelidir. 
    // Sıfırdan farklıysa hata (1) dönüyoruz.
    return crypto_verify16(mac, expected) == 0 ? 0 : 1;
}

static int test_x25519(void) {
    uint8_t alice_priv[32], bob_priv[32];
    memset(alice_priv, 0x42, 32);
    memset(bob_priv, 0x24, 32);

    uint8_t alice_pub[32], bob_pub[32];
    crypto_x25519_public_key(alice_pub, alice_priv);
    crypto_x25519_public_key(bob_pub, bob_priv);

    uint8_t shared_alice[32], shared_bob[32];
    
    crypto_x25519(shared_alice, alice_priv, bob_pub);
    crypto_x25519(shared_bob,   bob_priv, alice_pub);

    if (memcmp(shared_alice, shared_bob, 32) == 0) {
        return 0; // PASSED
    }
    return 1; // FAILED
}

static int test_blake2b(void) {
    const char *msg = "abc";
    uint8_t hash[64];
    crypto_blake2b(hash, 64, (const uint8_t*)msg, 3);
    const uint8_t expected[64] = {
        0xba,0x80,0xa5,0x3f,0x98,0x1c,0x4d,0x0d,
        0x6a,0x27,0x97,0xb6,0x9f,0x12,0xf6,0xe9,
        0x4c,0x21,0x2f,0x14,0x68,0x5a,0xc4,0xb7,
        0x4b,0x12,0xbb,0x6f,0xdb,0xff,0xa2,0xd1,
        0x7d,0x87,0xc5,0x39,0x2a,0xab,0x79,0x2d,
        0xc2,0x52,0xd5,0xde,0x45,0x33,0xcc,0x95,
        0x18,0xd3,0x8a,0xa8,0xdb,0xf1,0x92,0x5a,
        0xb9,0x23,0x86,0xed,0xd4,0x00,0x99,0x23
    };
    return memcmp(hash, expected, 64) == 0 ? 0 : 1;
}

static int test_aead(void) {
    uint8_t key[32] = {0};
    uint8_t nonce[24] = {0};
    const char *plain = "Hello, AEAD!";
    uint8_t cipher[100], tag[16], decrypted[100];
    size_t len = strlen(plain);

    crypto_aead_lock(cipher, tag, key, nonce, NULL, 0, (const uint8_t*)plain, len);
    int ret = crypto_aead_unlock(decrypted, tag, key, nonce, NULL, 0, cipher, len);
    if (ret != 0 || memcmp(plain, decrypted, len) != 0) return 1;

    // Etiket manipülasyonu (Deşifre etme başarısız olmalı)
    tag[0] ^= 0xff;
    ret = crypto_aead_unlock(decrypted, tag, key, nonce, NULL, 0, cipher, len);
    
    // Eğer ret == 0 ise (yani manipüle edilmiş etikete rağmen başarılı olduysa) hata dön
    if (ret == 0) return 1; 

    return 0;
}

int main(void) {
    int failures = 0;
    printf("Testing ChaCha20... "); fflush(stdout);
    if (test_chacha20()) { printf("FAILED\n"); failures++; } else printf("PASSED\n");
    
    printf("Testing Poly1305... "); fflush(stdout);
    if (test_poly1305()) { printf("FAILED\n"); failures++; } else printf("PASSED\n");
    
    printf("Testing X25519... "); fflush(stdout);
    if (test_x25519()) { printf("FAILED\n"); failures++; } else printf("PASSED\n");
    
    printf("Testing Blake2b... "); fflush(stdout);
    if (test_blake2b()) { printf("FAILED\n"); failures++; } else printf("PASSED\n");
    
    printf("Testing AEAD... "); fflush(stdout);
    if (test_aead()) { printf("FAILED\n"); failures++; } else printf("PASSED\n");
    
    return failures ? 1 : 0;
}
