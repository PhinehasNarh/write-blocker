/*
 * sha256.h - Minimal, dependency-free SHA-256 (FIPS 180-4).
 *
 * Streaming use:
 *   wb_sha256_ctx c; wb_sha256_init(&c);
 *   wb_sha256_update(&c, buf, len);   // call repeatedly
 *   char hex[WB_SHA256_HEX_LEN];
 *   wb_sha256_final_hex(&c, hex);     // NUL-terminated lowercase hex
 */
#ifndef WB_SHA256_H
#define WB_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define WB_SHA256_DIGEST_LEN 32          /* raw bytes */
#define WB_SHA256_HEX_LEN    (64 + 1)    /* hex string + NUL */

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buffer[64];
    size_t   buflen;
} wb_sha256_ctx;

void wb_sha256_init(wb_sha256_ctx *c);
void wb_sha256_update(wb_sha256_ctx *c, const void *data, size_t len);
void wb_sha256_final(wb_sha256_ctx *c, uint8_t out[WB_SHA256_DIGEST_LEN]);

/* Convenience: finalize directly into a lowercase hex string. */
void wb_sha256_final_hex(wb_sha256_ctx *c, char out[WB_SHA256_HEX_LEN]);

/* One-shot hashing of a buffer into hex. */
void wb_sha256_hex(const void *data, size_t len, char out[WB_SHA256_HEX_LEN]);

#endif /* WB_SHA256_H */
