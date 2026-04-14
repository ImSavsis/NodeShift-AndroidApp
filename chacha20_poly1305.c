/* chacha20_poly1305.c — ChaCha20-Poly1305 AEAD for NodeShift VPN packet encryption.
 *
 * Implements RFC 8439. Used for encrypting control channel messages between
 * the Android VPN client and the NodeShift server when the VLESS TLS layer
 * needs an additional authenticated encryption wrapper.
 *
 * Based on the public domain implementation by Daniel J. Bernstein.
 */

#include "chacha20_poly1305.h"
#include <string.h>
#include <stdint.h>

/* ─── ChaCha20 quarter round ──────────────────────────────────────────────────── */

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QR(a, b, c, d)   \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d,  8); \
    c += d; b ^= c; b = ROTL32(b,  7);

static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    memcpy(x, in, 64);

    for (int i = 0; i < 10; i++) {
        /* Column rounds */
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        /* Diagonal rounds */
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }

    for (int i = 0; i < 16; i++) out[i] = x[i] + in[i];
}

/* ─── ChaCha20 stream cipher ─────────────────────────────────────────────────── */

static void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                          const uint8_t key[32], const uint8_t nonce[12],
                          uint32_t counter) {
    uint32_t state[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        /* key */
        ((uint32_t)key[ 0])       | ((uint32_t)key[ 1] << 8)  |
        ((uint32_t)key[ 2] << 16) | ((uint32_t)key[ 3] << 24),
        ((uint32_t)key[ 4])       | ((uint32_t)key[ 5] << 8)  |
        ((uint32_t)key[ 6] << 16) | ((uint32_t)key[ 7] << 24),
        ((uint32_t)key[ 8])       | ((uint32_t)key[ 9] << 8)  |
        ((uint32_t)key[10] << 16) | ((uint32_t)key[11] << 24),
        ((uint32_t)key[12])       | ((uint32_t)key[13] << 8)  |
        ((uint32_t)key[14] << 16) | ((uint32_t)key[15] << 24),
        ((uint32_t)key[16])       | ((uint32_t)key[17] << 8)  |
        ((uint32_t)key[18] << 16) | ((uint32_t)key[19] << 24),
        ((uint32_t)key[20])       | ((uint32_t)key[21] << 8)  |
        ((uint32_t)key[22] << 16) | ((uint32_t)key[23] << 24),
        ((uint32_t)key[24])       | ((uint32_t)key[25] << 8)  |
        ((uint32_t)key[26] << 16) | ((uint32_t)key[27] << 24),
        ((uint32_t)key[28])       | ((uint32_t)key[29] << 8)  |
        ((uint32_t)key[30] << 16) | ((uint32_t)key[31] << 24),
        /* counter + nonce */
        counter,
        ((uint32_t)nonce[0])       | ((uint32_t)nonce[1] << 8)  |
        ((uint32_t)nonce[2] << 16) | ((uint32_t)nonce[3] << 24),
        ((uint32_t)nonce[4])       | ((uint32_t)nonce[5] << 8)  |
        ((uint32_t)nonce[6] << 16) | ((uint32_t)nonce[7] << 24),
        ((uint32_t)nonce[8])       | ((uint32_t)nonce[9] << 8)  |
        ((uint32_t)nonce[10] << 16)| ((uint32_t)nonce[11] << 24),
    };

    uint32_t block[16];
    uint8_t  keystream[64];
    size_t   pos = 0;

    while (pos < len) {
        chacha20_block(block, state);
        for (int i = 0; i < 16; i++) {
            keystream[i*4+0] = (uint8_t)(block[i]);
            keystream[i*4+1] = (uint8_t)(block[i] >>  8);
            keystream[i*4+2] = (uint8_t)(block[i] >> 16);
            keystream[i*4+3] = (uint8_t)(block[i] >> 24);
        }
        size_t chunk = len - pos;
        if (chunk > 64) chunk = 64;
        for (size_t i = 0; i < chunk; i++) out[pos+i] = in[pos+i] ^ keystream[i];
        pos += chunk;
        state[12]++;
    }
}

/* ─── Poly1305 authenticator ─────────────────────────────────────────────────── */

typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    size_t   leftover;
    uint8_t  buffer[16];
    uint8_t  final_block;
} Poly1305Ctx;

static void poly1305_init(Poly1305Ctx *ctx, const uint8_t key[32]) {
    /* Clamp r */
    ctx->r[0] = ((uint32_t)key[0]        | ((uint32_t)key[1]  << 8)  |
                 ((uint32_t)key[2] << 16) | ((uint32_t)key[3]  << 24)) & 0x0fffffff;
    ctx->r[1] = ((uint32_t)key[4]        | ((uint32_t)key[5]  << 8)  |
                 ((uint32_t)key[6] << 16) | ((uint32_t)key[7]  << 24)) & 0x0ffffffc;
    ctx->r[2] = ((uint32_t)key[8]        | ((uint32_t)key[9]  << 8)  |
                 ((uint32_t)key[10]<< 16) | ((uint32_t)key[11] << 24)) & 0x0ffffffc;
    ctx->r[3] = ((uint32_t)key[12]       | ((uint32_t)key[13] << 8)  |
                 ((uint32_t)key[14]<< 16) | ((uint32_t)key[15] << 24)) & 0x0ffffffc;
    ctx->r[4] = 0;

    ctx->h[0] = ctx->h[1] = ctx->h[2] = ctx->h[3] = ctx->h[4] = 0;

    ctx->pad[0] = ((uint32_t)key[16] | ((uint32_t)key[17] << 8) |
                   ((uint32_t)key[18]<< 16) | ((uint32_t)key[19] << 24));
    ctx->pad[1] = ((uint32_t)key[20] | ((uint32_t)key[21] << 8) |
                   ((uint32_t)key[22]<< 16) | ((uint32_t)key[23] << 24));
    ctx->pad[2] = ((uint32_t)key[24] | ((uint32_t)key[25] << 8) |
                   ((uint32_t)key[26]<< 16) | ((uint32_t)key[27] << 24));
    ctx->pad[3] = ((uint32_t)key[28] | ((uint32_t)key[29] << 8) |
                   ((uint32_t)key[30]<< 16) | ((uint32_t)key[31] << 24));

    ctx->leftover   = 0;
    ctx->final_block = 0;
}

static void poly1305_blocks(Poly1305Ctx *ctx, const uint8_t *m, size_t bytes) {
    const uint32_t hibit = ctx->final_block ? 0 : (1 << 24);
    uint32_t r0=ctx->r[0], r1=ctx->r[1], r2=ctx->r[2], r3=ctx->r[3];
    uint32_t h0=ctx->h[0], h1=ctx->h[1], h2=ctx->h[2], h3=ctx->h[3], h4=ctx->h[4];
    uint32_t s1=r1*5, s2=r2*5, s3=r3*5;

    while (bytes >= 16) {
        h0 += ((uint32_t)m[0]       | ((uint32_t)m[1]  << 8)  |
                ((uint32_t)m[2]<<16) | ((uint32_t)m[3]  << 24)) & 0x3ffffff;
        h1 += (((uint32_t)m[3]>>2)  | ((uint32_t)m[4]  << 6)  |
                ((uint32_t)m[5]<<14) | ((uint32_t)m[6]  << 22)) & 0x3ffffff;
        h2 += (((uint32_t)m[6]>>4)  | ((uint32_t)m[7]  << 4)  |
                ((uint32_t)m[8]<<12) | ((uint32_t)m[9]  << 20)) & 0x3ffffff;
        h3 += (((uint32_t)m[9]>>6)  | ((uint32_t)m[10] << 2)  |
                ((uint32_t)m[11]<<10)| ((uint32_t)m[12] << 18)) & 0x3ffffff;
        h4 += (((uint32_t)m[12]>>8) | ((uint32_t)m[13] << 0)  |
                ((uint32_t)m[14]<<8) | ((uint32_t)m[15] << 16)) | hibit;

        uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s3 + (uint64_t)h2*s2 +
                      (uint64_t)h3*s1 + (uint64_t)h4*(r3*5);
        uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s3 +
                      (uint64_t)h3*s2 + (uint64_t)h4*s1;
        uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 +
                      (uint64_t)h3*s3 + (uint64_t)h4*s2;
        uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 +
                      (uint64_t)h3*r0 + (uint64_t)h4*s3;
        uint64_t d4 = (uint64_t)h0*(ctx->r[4]) + (uint64_t)h1*r3 + (uint64_t)h2*r2 +
                      (uint64_t)h3*r1 + (uint64_t)h4*r0;

        uint32_t c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff; d1 += c;
                 c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff; d2 += c;
                 c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff; d3 += c;
                 c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff; d4 += c;
                 c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff; h0 += c * 5;
                 c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

        m += 16; bytes -= 16;
    }
    ctx->h[0]=h0; ctx->h[1]=h1; ctx->h[2]=h2; ctx->h[3]=h3; ctx->h[4]=h4;
}

static void poly1305_finish(Poly1305Ctx *ctx, uint8_t mac[16]) {
    if (ctx->leftover) {
        size_t i = ctx->leftover;
        ctx->buffer[i++] = 1;
        while (i < 16) ctx->buffer[i++] = 0;
        ctx->final_block = 1;
        poly1305_blocks(ctx, ctx->buffer, 16);
    }

    uint32_t h0=ctx->h[0], h1=ctx->h[1], h2=ctx->h[2], h3=ctx->h[3], h4=ctx->h[4];
    uint32_t c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
             c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
             c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
             c = h4 >>  2; h4 &= 0x3;       h0 += c * 5;
             c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    uint32_t g0=h0+5, g1, g2, g3, g4;
             c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1 << 26);

    uint32_t mask = (g4 >> 31) - 1;
    g0 = (h0 & ~mask) | (g0 & mask);
    g1 = (h1 & ~mask) | (g1 & mask);
    g2 = (h2 & ~mask) | (g2 & mask);
    g3 = (h3 & ~mask) | (g3 & mask);

    uint64_t f = ((uint64_t)g0 | ((uint64_t)g1 << 26)) + ctx->pad[0];
    mac[0]=(uint8_t)f; mac[1]=(uint8_t)(f>>8); mac[2]=(uint8_t)(f>>16); mac[3]=(uint8_t)(f>>24);
    f  = ((uint64_t)g1 >> 6 | ((uint64_t)g2 << 20)) + ctx->pad[1] + (f >> 32);
    mac[4]=(uint8_t)f; mac[5]=(uint8_t)(f>>8); mac[6]=(uint8_t)(f>>16); mac[7]=(uint8_t)(f>>24);
    f  = ((uint64_t)g2 >> 12 | ((uint64_t)g3 << 14)) + ctx->pad[2] + (f >> 32);
    mac[8]=(uint8_t)f; mac[9]=(uint8_t)(f>>8); mac[10]=(uint8_t)(f>>16); mac[11]=(uint8_t)(f>>24);
    f  = ((uint64_t)g3 >> 18 | ((uint64_t)0 << 8)) + ctx->pad[3] + (f >> 32);
    mac[12]=(uint8_t)f; mac[13]=(uint8_t)(f>>8); mac[14]=(uint8_t)(f>>16); mac[15]=(uint8_t)(f>>24);
}

/* ─── AEAD: ChaCha20-Poly1305 ────────────────────────────────────────────────── */

static void poly1305_key_gen(uint8_t poly_key[32],
                              const uint8_t key[32], const uint8_t nonce[12]) {
    static const uint8_t zeros[64] = {0};
    uint8_t block[64];
    chacha20_xor(block, zeros, 64, key, nonce, 0);
    memcpy(poly_key, block, 32);
}

static void encode_le64(uint8_t *out, uint64_t v) {
    out[0]=(uint8_t)v; out[1]=(uint8_t)(v>>8);  out[2]=(uint8_t)(v>>16); out[3]=(uint8_t)(v>>24);
    out[4]=(uint8_t)(v>>32); out[5]=(uint8_t)(v>>40); out[6]=(uint8_t)(v>>48); out[7]=(uint8_t)(v>>56);
}

int ns_chacha20poly1305_encrypt(
        const uint8_t *plaintext, size_t pt_len,
        const uint8_t *aad,       size_t aad_len,
        const uint8_t  key[32],
        const uint8_t  nonce[12],
        uint8_t       *ciphertext,     /* pt_len bytes */
        uint8_t        tag[NS_POLY1305_TAG_LEN]) {

    /* Generate Poly1305 key using counter=0 */
    uint8_t poly_key[32];
    poly1305_key_gen(poly_key, key, nonce);

    /* Encrypt with counter=1 */
    chacha20_xor(ciphertext, plaintext, pt_len, key, nonce, 1);

    /* Compute MAC over: aad || pad || ciphertext || pad || len(aad) || len(ct) */
    Poly1305Ctx mac;
    poly1305_init(&mac, poly_key);

    /* AAD + padding to 16 bytes */
    if (aad_len > 0) poly1305_blocks(&mac, aad, aad_len & ~15u);
    if (aad_len & 15) {
        uint8_t pad[16] = {0};
        memcpy(pad, aad + (aad_len & ~15u), aad_len & 15);
        mac.final_block = 0;
        poly1305_blocks(&mac, pad, 16);
    }

    /* Ciphertext + padding */
    if (pt_len > 0) poly1305_blocks(&mac, ciphertext, pt_len & ~15u);
    if (pt_len & 15) {
        uint8_t pad[16] = {0};
        memcpy(pad, ciphertext + (pt_len & ~15u), pt_len & 15);
        mac.final_block = 0;
        poly1305_blocks(&mac, pad, 16);
    }

    /* Lengths */
    uint8_t lengths[16];
    encode_le64(lengths,     (uint64_t)aad_len);
    encode_le64(lengths + 8, (uint64_t)pt_len);
    mac.final_block = 0;
    poly1305_blocks(&mac, lengths, 16);

    poly1305_finish(&mac, tag);
    return 0;
}

int ns_chacha20poly1305_decrypt(
        const uint8_t *ciphertext, size_t ct_len,
        const uint8_t *aad,        size_t aad_len,
        const uint8_t  tag[NS_POLY1305_TAG_LEN],
        const uint8_t  key[32],
        const uint8_t  nonce[12],
        uint8_t       *plaintext) {

    /* Verify tag first */
    uint8_t poly_key[32];
    poly1305_key_gen(poly_key, key, nonce);

    Poly1305Ctx mac;
    poly1305_init(&mac, poly_key);

    if (aad_len > 0) poly1305_blocks(&mac, aad, aad_len & ~15u);
    if (aad_len & 15) {
        uint8_t pad[16] = {0};
        memcpy(pad, aad + (aad_len & ~15u), aad_len & 15);
        mac.final_block = 0;
        poly1305_blocks(&mac, pad, 16);
    }
    if (ct_len > 0) poly1305_blocks(&mac, ciphertext, ct_len & ~15u);
    if (ct_len & 15) {
        uint8_t pad[16] = {0};
        memcpy(pad, ciphertext + (ct_len & ~15u), ct_len & 15);
        mac.final_block = 0;
        poly1305_blocks(&mac, pad, 16);
    }
    uint8_t lengths[16];
    encode_le64(lengths,     (uint64_t)aad_len);
    encode_le64(lengths + 8, (uint64_t)ct_len);
    mac.final_block = 0;
    poly1305_blocks(&mac, lengths, 16);

    uint8_t expected_tag[NS_POLY1305_TAG_LEN];
    poly1305_finish(&mac, expected_tag);

    /* Constant-time comparison */
    volatile uint8_t diff = 0;
    for (int i = 0; i < NS_POLY1305_TAG_LEN; i++) diff |= tag[i] ^ expected_tag[i];
    if (diff != 0) return NS_AEAD_AUTH_FAILED;

    chacha20_xor(plaintext, ciphertext, ct_len, key, nonce, 1);
    return 0;
}
