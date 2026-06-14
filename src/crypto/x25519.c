#include "x25519.h"
#include <string.h>

typedef int32_t fe[10];

static void fe_0(fe h) { for (int i = 0; i < 10; i++) h[i] = 0; }
static void fe_1(fe h) { h[0] = 1; for (int i = 1; i < 10; i++) h[i] = 0; }
static void fe_copy(fe h, const fe f) { for (int i = 0; i < 10; i++) h[i] = f[i]; }
static void fe_add(fe h, const fe f, const fe g) { for (int i = 0; i < 10; i++) h[i] = f[i] + g[i]; }
static void fe_sub(fe h, const fe f, const fe g) { for (int i = 0; i < 10; i++) h[i] = f[i] - g[i]; }
static void fe_cswap(fe f, fe g, int b) {
    int32_t mask = -b;
    for (int i = 0; i < 10; i++) {
        int32_t x = (f[i] ^ g[i]) & mask;
        f[i] ^= x;
        g[i] ^= x;
    }
}
static void fe_mul_small(fe h, const fe f, int32_t g) {
    int64_t t0 = f[0] * (int64_t)g;
    int64_t t1 = f[1] * (int64_t)g;
    int64_t t2 = f[2] * (int64_t)g;
    int64_t t3 = f[3] * (int64_t)g;
    int64_t t4 = f[4] * (int64_t)g;
    int64_t t5 = f[5] * (int64_t)g;
    int64_t t6 = f[6] * (int64_t)g;
    int64_t t7 = f[7] * (int64_t)g;
    int64_t t8 = f[8] * (int64_t)g;
    int64_t t9 = f[9] * (int64_t)g;
    #define CARRY \
        int64_t c; \
        c = (t0 + (1LL<<25)) >> 26; t0 -= c * (1LL<<26); t1 += c; \
        c = (t4 + (1LL<<25)) >> 26; t4 -= c * (1LL<<26); t5 += c; \
        c = (t1 + (1LL<<24)) >> 25; t1 -= c * (1LL<<25); t2 += c; \
        c = (t5 + (1LL<<24)) >> 25; t5 -= c * (1LL<<25); t6 += c; \
        c = (t2 + (1LL<<25)) >> 26; t2 -= c * (1LL<<26); t3 += c; \
        c = (t6 + (1LL<<25)) >> 26; t6 -= c * (1LL<<26); t7 += c; \
        c = (t3 + (1LL<<24)) >> 25; t3 -= c * (1LL<<25); t4 += c; \
        c = (t7 + (1LL<<24)) >> 25; t7 -= c * (1LL<<25); t8 += c; \
        c = (t4 + (1LL<<25)) >> 26; t4 -= c * (1LL<<26); t5 += c; \
        c = (t8 + (1LL<<25)) >> 26; t8 -= c * (1LL<<26); t9 += c; \
        c = (t9 + (1LL<<24)) >> 25; t9 -= c * (1LL<<25); t0 += c * 19; \
        c = (t0 + (1LL<<25)) >> 26; t0 -= c * (1LL<<26); t1 += c; \
        h[0]=t0; h[1]=t1; h[2]=t2; h[3]=t3; h[4]=t4; \
        h[5]=t5; h[6]=t6; h[7]=t7; h[8]=t8; h[9]=t9
    CARRY;
    #undef CARRY
}
static void fe_mul(fe h, const fe f, const fe g) {
    int32_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
    int32_t f5 = f[5], f6 = f[6], f7 = f[7], f8 = f[8], f9 = f[9];
    int32_t g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];
    int32_t g5 = g[5], g6 = g[6], g7 = g[7], g8 = g[8], g9 = g[9];
    int32_t F1 = f1*2, F3 = f3*2, F5 = f5*2, F7 = f7*2, F9 = f9*2;
    int32_t G1 = g1*19, G2 = g2*19, G3 = g3*19, G4 = g4*19, G5 = g5*19;
    int32_t G6 = g6*19, G7 = g7*19, G8 = g8*19, G9 = g9*19;

    int64_t t0 = f0*(int64_t)g0 + F1*(int64_t)G9 + f2*(int64_t)G8 + F3*(int64_t)G7 + f4*(int64_t)G6
               + F5*(int64_t)G5 + f6*(int64_t)G4 + F7*(int64_t)G3 + f8*(int64_t)G2 + F9*(int64_t)G1;
    int64_t t1 = f0*(int64_t)g1 + f1*(int64_t)g0 + f2*(int64_t)G9 + f3*(int64_t)G8 + f4*(int64_t)G7
               + f5*(int64_t)G6 + f6*(int64_t)G5 + f7*(int64_t)G4 + f8*(int64_t)G3 + f9*(int64_t)G2;
    int64_t t2 = f0*(int64_t)g2 + F1*(int64_t)g1 + f2*(int64_t)g0 + F3*(int64_t)G9 + f4*(int64_t)G8
               + F5*(int64_t)G7 + f6*(int64_t)G6 + F7*(int64_t)G5 + f8*(int64_t)G4 + F9*(int64_t)G3;
    int64_t t3 = f0*(int64_t)g3 + f1*(int64_t)g2 + f2*(int64_t)g1 + f3*(int64_t)g0 + f4*(int64_t)G9
               + f5*(int64_t)G8 + f6*(int64_t)G7 + f7*(int64_t)G6 + f8*(int64_t)G5 + f9*(int64_t)G4;
    int64_t t4 = f0*(int64_t)g4 + F1*(int64_t)g3 + f2*(int64_t)g2 + F3*(int64_t)g1 + f4*(int64_t)g0
               + F5*(int64_t)G9 + f6*(int64_t)G8 + F7*(int64_t)G7 + f8*(int64_t)G6 + F9*(int64_t)G5;
    int64_t t5 = f0*(int64_t)g5 + f1*(int64_t)g4 + f2*(int64_t)g3 + f3*(int64_t)g2 + f4*(int64_t)g1
               + f5*(int64_t)g0 + f6*(int64_t)G9 + f7*(int64_t)G8 + f8*(int64_t)G7 + f9*(int64_t)G6;
    int64_t t6 = f0*(int64_t)g6 + F1*(int64_t)g5 + f2*(int64_t)g4 + F3*(int64_t)g3 + f4*(int64_t)g2
               + F5*(int64_t)g1 + f6*(int64_t)g0 + F7*(int64_t)G9 + f8*(int64_t)G8 + F9*(int64_t)G7;
    int64_t t7 = f0*(int64_t)g7 + f1*(int64_t)g6 + f2*(int64_t)g5 + f3*(int64_t)g4 + f4*(int64_t)g3
               + f5*(int64_t)g2 + f6*(int64_t)g1 + f7*(int64_t)g0 + f8*(int64_t)G9 + f9*(int64_t)G8;
    int64_t t8 = f0*(int64_t)g8 + F1*(int64_t)g7 + f2*(int64_t)g6 + F3*(int64_t)g5 + f4*(int64_t)g4
               + F5*(int64_t)g3 + f6*(int64_t)g2 + F7*(int64_t)g1 + f8*(int64_t)g0 + F9*(int64_t)G9;
    int64_t t9 = f0*(int64_t)g9 + f1*(int64_t)g8 + f2*(int64_t)g7 + f3*(int64_t)g6 + f4*(int64_t)g5
               + f5*(int64_t)g4 + f6*(int64_t)g3 + f7*(int64_t)g2 + f8*(int64_t)g1 + f9*(int64_t)g0;

    #define CARRY \
        int64_t c; \
        c = (t0 + (1LL<<25)) >> 26; t0 -= c * (1LL<<26); t1 += c; \
        c = (t4 + (1LL<<25)) >> 26; t4 -= c * (1LL<<26); t5 += c; \
        c = (t1 + (1LL<<24)) >> 25; t1 -= c * (1LL<<25); t2 += c; \
        c = (t5 + (1LL<<24)) >> 25; t5 -= c * (1LL<<25); t6 += c; \
        c = (t2 + (1LL<<25)) >> 26; t2 -= c * (1LL<<26); t3 += c; \
        c = (t6 + (1LL<<25)) >> 26; t6 -= c * (1LL<<26); t7 += c; \
        c = (t3 + (1LL<<24)) >> 25; t3 -= c * (1LL<<25); t4 += c; \
        c = (t7 + (1LL<<24)) >> 25; t7 -= c * (1LL<<25); t8 += c; \
        c = (t4 + (1LL<<25)) >> 26; t4 -= c * (1LL<<26); t5 += c; \
        c = (t8 + (1LL<<25)) >> 26; t8 -= c * (1LL<<26); t9 += c; \
        c = (t9 + (1LL<<24)) >> 25; t9 -= c * (1LL<<25); t0 += c * 19; \
        c = (t0 + (1LL<<25)) >> 26; t0 -= c * (1LL<<26); t1 += c; \
        h[0] = (int32_t)t0; h[1] = (int32_t)t1; h[2] = (int32_t)t2; h[3] = (int32_t)t3; h[4] = (int32_t)t4; \
        h[5] = (int32_t)t5; h[6] = (int32_t)t6; h[7] = (int32_t)t7; h[8] = (int32_t)t8; h[9] = (int32_t)t9
    CARRY;
    #undef CARRY
}
static void fe_sq(fe h, const fe f) { fe_mul(h, f, f); }
static void fe_invert(fe out, const fe z) {
    fe t0, t1, t2, t3;
    fe_sq(t0, z);
    fe_sq(t1, t0);
    fe_sq(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t2, t0);
    fe_mul(t1, t1, t2);
    fe_sq(t2, t1);
    for (int i = 0; i < 4; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (int i = 0; i < 9; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (int i = 0; i < 19; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (int i = 0; i < 9; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);     
    fe_sq(t2, t1);
    for (int i = 0; i < 49; i++) fe_sq(t2, t2); // Toplam 50 kare alma
    fe_mul(t2, t2, t1); // t2 = 100 adet 1 biti
    fe_sq(t3, t2);
    for (int i = 0; i < 99; i++) fe_sq(t3, t3); // Toplam 100 kare alma
    fe_mul(t2, t3, t2); // t2 = 200 adet 1 biti
    fe_sq(t2, t2);
    for (int i = 0; i < 49; i++) fe_sq(t2, t2); // Toplam 50 kare alma
    fe_mul(t1, t2, t1); // t1 = 250 adet 1 biti
    fe_sq(t1, t1);
    for (int i = 0; i < 4; i++) fe_sq(t1, t1);  // Toplam 5 kare alma
    fe_mul(out, t1, t0); // out = 2^255 - 21 mod p (t0 olan 11 değeriyle çarpılır)
    crypto_wipe(t0, sizeof(t0)); crypto_wipe(t1, sizeof(t1));
    crypto_wipe(t2, sizeof(t2)); crypto_wipe(t3, sizeof(t3));
}
static void fe_frombytes(fe h, const uint8_t s[32]) {
    int64_t t0 = load32_le(s);
    int64_t t1 = load24_le(s + 4) << 6;
    int64_t t2 = load24_le(s + 7) << 5;
    int64_t t3 = load24_le(s + 10) << 3;
    int64_t t4 = load24_le(s + 13) << 2;
    int64_t t5 = load32_le(s + 16);
    int64_t t6 = load24_le(s + 20) << 7;
    int64_t t7 = load24_le(s + 23) << 5;
    int64_t t8 = load24_le(s + 26) << 4;
    int64_t t9 = (load24_le(s + 29) & 0xffffff) << 2;
    #define CARRY \
        int64_t c; \
        c = (t0 + (1LL<<25)) >> 26; t0 -= c * (1LL<<26); t1 += c; \
        c = (t4 + (1LL<<25)) >> 26; t4 -= c * (1LL<<26); t5 += c; \
        c = (t1 + (1LL<<24)) >> 25; t1 -= c * (1LL<<25); t2 += c; \
        c = (t5 + (1LL<<24)) >> 25; t5 -= c * (1LL<<25); t6 += c; \
        c = (t2 + (1LL<<25)) >> 26; t2 -= c * (1LL<<26); t3 += c; \
        c = (t6 + (1LL<<25)) >> 26; t6 -= c * (1LL<<26); t7 += c; \
        c = (t3 + (1LL<<24)) >> 25; t3 -= c * (1LL<<25); t4 += c; \
        c = (t7 + (1LL<<24)) >> 25; t7 -= c * (1LL<<25); t8 += c; \
        c = (t4 + (1LL<<25)) >> 26; t4 -= c * (1LL<<26); t5 += c; \
        c = (t8 + (1LL<<25)) >> 26; t8 -= c * (1LL<<26); t9 += c; \
        c = (t9 + (1LL<<24)) >> 25; t9 -= c * (1LL<<25); t0 += c * 19; \
        c = (t0 + (1LL<<25)) >> 26; t0 -= c * (1LL<<26); t1 += c; \
        h[0]=(int32_t)t0; h[1]=(int32_t)t1; h[2]=(int32_t)t2; h[3]=(int32_t)t3; \
        h[4]=(int32_t)t4; h[5]=(int32_t)t5; h[6]=(int32_t)t6; h[7]=(int32_t)t7; \
        h[8]=(int32_t)t8; h[9]=(int32_t)t9
    CARRY;
    #undef CARRY
}

static void fe_tobytes(uint8_t s[32], const fe h) {
    int32_t t[10];
    for (int i = 0; i < 10; i++) t[i] = h[i];

    // Kararlı ve kesin indirgeme adımları (Strict Reduction)
    for (int i = 0; i < 2; i++) {
        int32_t q;
        q = (t[0] + (1 << 25)) >> 26; t[0] -= q * (1 << 26); t[1] += q;
        q = (t[1] + (1 << 24)) >> 25; t[1] -= q * (1 << 25); t[2] += q;
        q = (t[2] + (1 << 25)) >> 26; t[2] -= q * (1 << 26); t[3] += q;
        q = (t[3] + (1 << 24)) >> 25; t[3] -= q * (1 << 25); t[4] += q;
        q = (t[4] + (1 << 25)) >> 26; t[4] -= q * (1 << 26); t[5] += q;
        q = (t[5] + (1 << 24)) >> 25; t[5] -= q * (1 << 25); t[6] += q;
        q = (t[6] + (1 << 25)) >> 26; t[6] -= q * (1 << 26); t[7] += q;
        q = (t[7] + (1 << 24)) >> 25; t[7] -= q * (1 << 25); t[8] += q;
        q = (t[8] + (1 << 25)) >> 26; t[8] -= q * (1 << 26); t[9] += q;
        q = (t[9] + (1 << 24)) >> 25; t[9] -= q * (1 << 25); t[0] += q * 19;
    }

    // 2^255 - 19 değerinden büyükse modül çıkartma kontrolü
    int32_t q = (19 * t[9] + (1 << 24)) >> 25;
    for (int i = 0; i < 5; i++) {
        q += t[2*i];   q >>= 26;
        q += t[2*i+1]; q >>= 25;
    }
    q *= 19;
    for (int i = 0; i < 5; i++) {
        t[2*i]   += q; q = t[2*i]   >> 26; t[2*i]   -= q * (1 << 26);
        t[2*i+1] += q; q = t[2*i+1] >> 25; t[2*i+1] -= q * (1 << 25);
    }

    // Byte dizisine güvenli şekilde paketleme
    store32_le(s +  0, ((uint32_t)t[0] >>  0) | ((uint32_t)t[1] << 26));
    store32_le(s +  4, ((uint32_t)t[1] >>  6) | ((uint32_t)t[2] << 19));
    store32_le(s +  8, ((uint32_t)t[2] >> 13) | ((uint32_t)t[3] << 13));
    store32_le(s + 12, ((uint32_t)t[3] >> 19) | ((uint32_t)t[4] <<  6));
    store32_le(s + 16, ((uint32_t)t[5] >>  0) | ((uint32_t)t[6] << 25));
    store32_le(s + 20, ((uint32_t)t[6] >>  7) | ((uint32_t)t[7] << 19));
    store32_le(s + 24, ((uint32_t)t[7] >> 13) | ((uint32_t)t[8] << 12));
    store32_le(s + 28, ((uint32_t)t[8] >> 20) | ((uint32_t)t[9] <<  6));
    crypto_wipe(t, sizeof(t));
}

static void scalarmult(uint8_t q[32], const uint8_t scalar[32], const uint8_t p[32], int nb_bits) {
    fe x1; fe_frombytes(x1, p);
    fe x2, z2, x3, z3, t0, t1;
    fe_1(x2); fe_0(z2);
    fe_copy(x3, x1); fe_1(z3);
    int swap = 0;
    for (int pos = nb_bits-1; pos >= 0; --pos) {
        int b = (scalar[pos >> 3] >> (pos & 7)) & 1;
        swap ^= b;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = b;
        fe_sub(t0, x3, z3);
        fe_sub(t1, x2, z2);
        fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);
        fe_mul(z3, t0, x2);
        fe_mul(z2, z2, t1);
        fe_sq(t0, t1);
        fe_sq(t1, x2);
        fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);
        fe_mul(x2, t1, t0);
        fe_sub(t1, t1, t0);
        fe_sq(z2, z2);
        fe_mul_small(z3, t1, 121666);
        fe_sq(x3, x3);
        fe_add(t0, t0, z3);
        fe_mul(z3, x1, z2);
        fe_mul(z2, t1, t0);
    }
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);
    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(q, x2);
    crypto_wipe(x1, sizeof(x1)); crypto_wipe(x2, sizeof(x2));
    crypto_wipe(z2, sizeof(z2)); crypto_wipe(t0, sizeof(t0));
    crypto_wipe(x3, sizeof(x3)); crypto_wipe(z3, sizeof(z3));
    crypto_wipe(t1, sizeof(t1));
}
void crypto_x25519_public_key(uint8_t public_key[32], const uint8_t secret_key[32]) {
    static const uint8_t base_point[32] = {9};
    uint8_t e[32];
    for (int i = 0; i < 32; i++) e[i] = secret_key[i];
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;
    scalarmult(public_key, e, base_point, 255);
    crypto_wipe(e, sizeof(e));
}
void crypto_x25519(uint8_t raw_shared_secret[32],
                   const uint8_t your_secret_key[32],
                   const uint8_t their_public_key[32]) {
    uint8_t e[32];
    for (int i = 0; i < 32; i++) e[i] = your_secret_key[i];
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;
    scalarmult(raw_shared_secret, e, their_public_key, 255);
    crypto_wipe(e, sizeof(e));
}

void crypto_x25519_keypair(uint8_t public_key[32], uint8_t secret_key[32]) {
    // THIS IS NOT A SECURE WAY TO GENERATE A KEYPAIR. FOR TESTING ONLY.
    static const uint8_t private_key[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    memcpy(secret_key, private_key, 32);
    crypto_x25519_public_key(public_key, secret_key);
}
