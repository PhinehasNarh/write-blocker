/*
 * hash.c - Whole-device SHA-256 using the backend's sequential reader.
 */
#include "hash.h"
#include "writeblock.h"

#include <stdio.h>
#include <stdlib.h>

/* 1 MiB read buffer: a multiple of both 512 and 4096, so device reads on
 * platforms that require sector alignment (Windows, macOS raw) stay aligned. */
#define WB_HASH_BUF (1024u * 1024u)

int wb_hash_device(const char *id, char hex_out[WB_SHA256_HEX_LEN], int quiet)
{
    wb_reader *r = NULL;
    uint64_t size = 0;
    int rc = wb_reader_open(id, &r, &size);
    if (rc != WB_OK)
        return rc;

    unsigned char *buf = (unsigned char *)malloc(WB_HASH_BUF);
    if (!buf) {
        wb_reader_close(r);
        return WB_ERR_NOMEM;
    }

    wb_sha256_ctx c;
    wb_sha256_init(&c);

    uint64_t done = 0;
    int last_pct = -1;
    for (;;) {
        size_t got = 0;
        rc = wb_reader_read(r, buf, WB_HASH_BUF, &got);
        if (rc != WB_OK)
            break;
        if (got == 0)
            break;  /* end of device */
        wb_sha256_update(&c, buf, got);
        done += got;

        if (!quiet && size > 0) {
            int pct = (int)((done * 100) / size);
            if (pct != last_pct) {
                fprintf(stderr, "\rhashing %s: %d%%", id, pct);
                fflush(stderr);
                last_pct = pct;
            }
        }
    }
    if (!quiet && last_pct >= 0)
        fprintf(stderr, "\n");

    free(buf);
    wb_reader_close(r);
    if (rc != WB_OK)
        return rc;

    wb_sha256_final_hex(&c, hex_out);
    return WB_OK;
}
