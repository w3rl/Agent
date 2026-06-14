#include "../core/test.h"
#include "crypto/noise.h"
#include "crypto/x25519.h"
#include <string.h>
#include <stdio.h>

void test_noise_handshake() {
    printf("Testing Noise XX handshake...
");

    uint8_t initiator_s[NOISE_PRIVATE_KEY_SIZE];
    uint8_t initiator_s_pub[NOISE_PUBLIC_KEY_SIZE];
    uint8_t responder_s[NOISE_PRIVATE_KEY_SIZE];
    uint8_t responder_s_pub[NOISE_PUBLIC_KEY_SIZE];

    // Generate static key pairs
    crypto_x25519_keypair(initiator_s_pub, initiator_s);
    crypto_x25519_keypair(responder_s_pub, responder_s);

    NoiseState initiator, responder;
    noise_init(&initiator, true, initiator_s);
    noise_init(&responder, false, responder_s);

    uint8_t msg1[1024], msg2[1024], msg3[1024];
    size_t msg1_len, msg2_len, msg3_len;

    // -> e
    ASSERT(noise_handshake_write(&initiator, msg1, &msg1_len) == 0);

    // e ->
    ASSERT(noise_handshake_read(&responder, msg1, msg1_len) == 0);

    // <- e, ee, s, es
    ASSERT(noise_handshake_write(&responder, msg2, &msg2_len) == 0);

    // <- e, ee, s, es
    ASSERT(noise_handshake_read(&initiator, msg2, msg2_len) == 0);

    // -> s, se
    ASSERT(noise_handshake_write(&initiator, msg3, &msg3_len) == 0);

    // -> s, se
    ASSERT(noise_handshake_read(&responder, msg3, msg3_len) == 0);

    ASSERT(initiator.handshake_state == 3);
    ASSERT(responder.handshake_state == 3);

    // Test encryption
    uint8_t p1[] = "hello world";
    uint8_t c1[100];
    size_t c1_len;
    ASSERT(noise_encrypt(&initiator, p1, sizeof(p1), c1, &c1_len) == 0);

    uint8_t p2[100];
    size_t p2_len;
    ASSERT(noise_decrypt(&responder, c1, c1_len, p2, &p2_len) == 0);
    ASSERT(p2_len == sizeof(p1));
    ASSERT(memcmp(p1, p2, sizeof(p1)) == 0);

    uint8_t p3[] = "hello again";
    uint8_t c2[100];
    size_t c2_len;
    ASSERT(noise_encrypt(&responder, p3, sizeof(p3), c2, &c2_len) == 0);

    uint8_t p4[100];
    size_t p4_len;
    ASSERT(noise_decrypt(&initiator, c2, c2_len, p4, &p4_len) == 0);
    ASSERT(p4_len == sizeof(p3));
    ASSERT(memcmp(p3, p4, sizeof(p3)) == 0);

    printf("OK
");
}

int main() {
    test_noise_handshake();
    return 0;
}
