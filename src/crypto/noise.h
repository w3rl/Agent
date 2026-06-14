#ifndef AGENT_NOISE_H
#define AGENT_NOISE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define NOISE_PUBLIC_KEY_SIZE 32
#define NOISE_PRIVATE_KEY_SIZE 32
#define NOISE_SYMMETRIC_KEY_SIZE 32
#define NOISE_TIMESTAMP_SIZE 12
#define NOISE_MAC_SIZE 16
#define NOISE_HANDSHAKE_SIZE 48

// Noise handshake state
typedef struct {
    uint8_t s[NOISE_PRIVATE_KEY_SIZE];  // static private key
    uint8_t e[NOISE_PRIVATE_KEY_SIZE];  // ephemeral private key
    uint8_t rs[NOISE_PUBLIC_KEY_SIZE]; // remote static public key
    uint8_t re[NOISE_PUBLIC_KEY_SIZE]; // remote ephemeral public key
    uint8_t h[32];                     // handshake hash
    uint8_t ck[32];                    // chaining key
    uint8_t k_tx[NOISE_SYMMETRIC_KEY_SIZE]; // symmetric key for sending
    uint8_t k_rx[NOISE_SYMMETRIC_KEY_SIZE]; // symmetric key for receiving
    uint64_t n_tx;                      // nonce for sending
    uint64_t n_rx;                      // nonce for receiving
    bool initiator;
    int handshake_state; // 0: pre-handshake, 1: first message sent, 2: second message sent, 3: handshake complete
} NoiseState;

// Functions for Noise handshake
void noise_init(NoiseState* state, bool initiator, const uint8_t* static_key);
int noise_handshake_write(NoiseState* state, uint8_t* buffer, size_t* buffer_len);
int noise_handshake_read(NoiseState* state, const uint8_t* message, size_t message_len);
int noise_encrypt(NoiseState* state, const uint8_t* plaintext, size_t plaintext_len, uint8_t* ciphertext, size_t* ciphertext_len);
int noise_decrypt(NoiseState* state, const uint8_t* ciphertext, size_t ciphertext_len, uint8_t* plaintext, size_t* plaintext_len);

#endif // AGENT_NOISE_H
