/*
 * sha256.c - Minimal SHA-256 (FIPS 180-4). Public-domain style reference
 * implementation, self-contained (no OpenSSL dependency).
 */
#include "sha256.h"

#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define BSIG1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SSIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SSIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static void sha256_compress(uint32_t state[8], const uint8_t block[64])
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++)
        w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + BSIG1(e) + CH(e, f, g) + K[i] + w[i];
        uint32_t t2 = BSIG0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void wb_sha256_init(wb_sha256_ctx *c)
{
    c->state[0] = 0x6a09e667; c->state[1] = 0xbb67ae85;
    c->state[2] = 0x3c6ef372; c->state[3] = 0xa54ff53a;
    c->state[4] = 0x510e527f; c->state[5] = 0x9b05688c;
    c->state[6] = 0x1f83d9ab; c->state[7] = 0x5be0cd19;
    c->bitlen = 0;
    c->buflen = 0;
}

void wb_sha256_update(wb_sha256_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    while (len > 0) {
        size_t take = 64 - c->buflen;
        if (take > len)
            take = len;
        memcpy(c->buffer + c->buflen, p, take);
        c->buflen += take;
        p += take;
        len -= take;
        if (c->buflen == 64) {
            sha256_compress(c->state, c->buffer);
            c->bitlen += 512;
            c->buflen = 0;
        }
    }
}

void wb_sha256_final(wb_sha256_ctx *c, uint8_t out[WB_SHA256_DIGEST_LEN])
{
    uint64_t total_bits = c->bitlen + (uint64_t)c->buflen * 8;

    /* Append 0x80 then pad with zeros, leaving 8 bytes for the length. */
    uint8_t pad = 0x80;
    wb_sha256_update(c, &pad, 1);
    uint8_t zero = 0x00;
    while (c->buflen != 56)
        wb_sha256_update(c, &zero, 1);

    uint8_t lenbuf[8];
    for (int i = 0; i < 8; i++)
        lenbuf[i] = (uint8_t)(total_bits >> (56 - i * 8));
    wb_sha256_update(c, lenbuf, 8);  /* triggers the final compression */

    for (int i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(c->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->state[i]);
    }
}

static void to_hex(const uint8_t *d, size_t n, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2]     = hex[(d[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex[d[i] & 0xf];
    }
    out[n * 2] = '\0';
}

void wb_sha256_final_hex(wb_sha256_ctx *c, char out[WB_SHA256_HEX_LEN])
{
    uint8_t digest[WB_SHA256_DIGEST_LEN];
    wb_sha256_final(c, digest);
    to_hex(digest, WB_SHA256_DIGEST_LEN, out);
}

void wb_sha256_hex(const void *data, size_t len, char out[WB_SHA256_HEX_LEN])
{
    wb_sha256_ctx c;
    wb_sha256_init(&c);
    wb_sha256_update(&c, data, len);
    wb_sha256_final_hex(&c, out);
}
