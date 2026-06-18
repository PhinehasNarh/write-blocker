/*
 * hash.h - Whole-device SHA-256 hashing built on the backend reader.
 */
#ifndef WB_HASH_H
#define WB_HASH_H

#include "sha256.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Hash an entire device into a lowercase hex SHA-256 string. Reads the device
 * read-only through the backend reader. When quiet is 0, a percentage progress
 * line is written to stderr. Returns WB_OK or a wb_status_code on error.
 */
int wb_hash_device(const char *id, char hex_out[WB_SHA256_HEX_LEN], int quiet);

#ifdef __cplusplus
}
#endif

#endif /* WB_HASH_H */
