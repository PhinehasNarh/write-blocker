/*
 * audit.c - Append-only, hash-chained audit log.
 *
 * Each line is a JSON object. The canonical "pre-image" of a record is the
 * object containing every field including "prev" but excluding "rec":
 *
 *   {"ts":...,"action":...,...,"hash":...,"prev":"<prev rec>"}
 *
 * and rec = SHA256(pre-image). Because "prev" holds the previous record's rec,
 * the records form a tamper-evident chain. Verification recomputes each rec
 * from the stored line and checks that every "prev" matches the prior "rec".
 */
#define _POSIX_C_SOURCE 200809L  /* expose strtok_r on glibc under -std=c11 */
#include "audit.h"
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Portable re-entrant strtok: strtok_s on Windows, strtok_r elsewhere. */
#ifdef _WIN32
#define wb_strtok(s, d, ctx) strtok_s((s), (d), (ctx))
#else
#define wb_strtok(s, d, ctx) strtok_r((s), (d), (ctx))
#endif

#define ZERO_HASH "0000000000000000000000000000000000000000000000000000000000000000"
#define REC_MARKER ",\"rec\":\""
#define PREV_MARKER "\"prev\":\""

/* JSON-escape src into dst (NUL-terminated, truncated to fit dstlen). */
static void json_escape(const char *src, char *dst, size_t dstlen)
{
    size_t o = 0;
    if (dstlen == 0)
        return;
    if (src == NULL)
        src = "";
    for (const char *p = src; *p && o + 7 < dstlen; p++) {
        unsigned char ch = (unsigned char)*p;
        if (ch == '"' || ch == '\\') {
            dst[o++] = '\\';
            dst[o++] = (char)ch;
        } else if (ch < 0x20) {
            o += (size_t)snprintf(dst + o, dstlen - o, "\\u%04x", ch);
        } else {
            dst[o++] = (char)ch;
        }
    }
    dst[o] = '\0';
}

/* True if s points to 64 lowercase/uppercase hex characters. */
static int is_hex64(const char *s)
{
    for (int i = 0; i < 64; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return 0;
    }
    return 1;
}

/* Read the whole file into a malloc'd, NUL-terminated buffer. NULL if absent. */
static char *read_file(const char *path, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return NULL;
    }
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[got] = '\0';
    if (len_out)
        *len_out = got;
    return buf;
}

/* Copy the rec hash of the last record in buf into out[65]; ZERO_HASH if none. */
static void last_rec(const char *buf, char out[WB_SHA256_HEX_LEN])
{
    memcpy(out, ZERO_HASH, WB_SHA256_HEX_LEN);
    if (!buf)
        return;
    const char *p = buf, *found = NULL;
    while ((p = strstr(p, REC_MARKER)) != NULL) {
        found = p + strlen(REC_MARKER);
        p = found;
    }
    if (found && is_hex64(found)) {
        memcpy(out, found, 64);
        out[64] = '\0';
    }
}

static void iso8601_utc(char *buf, size_t len)
{
    time_t t = time(NULL);
    struct tm *g = gmtime(&t);
    if (g)
        strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", g);
    else
        snprintf(buf, len, "1970-01-01T00:00:00Z");
}

int wb_audit_append(const char *path, const char *action, const wb_device_t *dev,
                    const char *case_id, const char *examiner, const char *hash)
{
    if (!path || !*path || !action || !dev)
        return WB_ERR_INVAL;

    char prev[WB_SHA256_HEX_LEN];
    size_t flen = 0;
    char *existing = read_file(path, &flen);
    last_rec(existing, prev);
    free(existing);

    char ts[32];
    iso8601_utc(ts, sizeof(ts));

    char e_action[64], e_dev[2 * WB_ID_MAX], e_serial[2 * WB_SERIAL_MAX];
    char e_model[2 * WB_MODEL_MAX], e_case[256], e_exam[256], e_hash[160];
    json_escape(action, e_action, sizeof(e_action));
    json_escape(dev->id, e_dev, sizeof(e_dev));
    json_escape(dev->serial, e_serial, sizeof(e_serial));
    json_escape(dev->model, e_model, sizeof(e_model));
    json_escape(case_id, e_case, sizeof(e_case));
    json_escape(examiner, e_exam, sizeof(e_exam));
    json_escape(hash ? hash : "", e_hash, sizeof(e_hash));

    /* Canonical pre-image: every field plus "prev", but not "rec". */
    char preimage[4096];
    snprintf(preimage, sizeof(preimage),
        "{\"ts\":\"%s\",\"action\":\"%s\",\"device\":\"%s\",\"serial\":\"%s\","
        "\"model\":\"%s\",\"size_bytes\":%llu,\"case\":\"%s\",\"examiner\":\"%s\","
        "\"hash\":\"%s\",\"prev\":\"%s\"}",
        ts, e_action, e_dev, e_serial, e_model,
        (unsigned long long)dev->size_bytes, e_case, e_exam, e_hash, prev);

    char rec[WB_SHA256_HEX_LEN];
    wb_sha256_hex(preimage, strlen(preimage), rec);

    FILE *f = fopen(path, "ab");
    if (!f)
        return WB_ERR_IO;
    /* Write the pre-image with the closing brace replaced by the rec field. */
    size_t plen = strlen(preimage);
    int ok = 1;
    if (fwrite(preimage, 1, plen - 1, f) != plen - 1) ok = 0;  /* drop trailing '}' */
    if (fprintf(f, ",\"rec\":\"%s\"}\n", rec) < 0) ok = 0;
    if (fclose(f) != 0) ok = 0;
    return ok ? WB_OK : WB_ERR_IO;
}

int wb_audit_verify(const char *path, size_t *records_out)
{
    size_t flen = 0;
    char *buf = read_file(path, &flen);
    if (!buf)
        return WB_ERR_NOT_FOUND;

    char expected_prev[WB_SHA256_HEX_LEN];
    memcpy(expected_prev, ZERO_HASH, WB_SHA256_HEX_LEN);

    size_t count = 0;
    int rc = WB_OK;
    char *save = NULL;
    for (char *line = wb_strtok(buf, "\n", &save);
         line != NULL;
         line = wb_strtok(NULL, "\n", &save)) {
        if (*line == '\0' || *line == '\r')
            continue;

        char *marker = strstr(line, REC_MARKER);
        if (!marker || !is_hex64(marker + strlen(REC_MARKER))) {
            rc = WB_ERR_GENERIC;
            break;
        }
        const char *stored_rec = marker + strlen(REC_MARKER);

        /* Pre-image is the line up to the rec field, with a closing brace. */
        size_t pre_len = (size_t)(marker - line);
        char preimage[4096];
        if (pre_len + 2 > sizeof(preimage)) {
            rc = WB_ERR_GENERIC;
            break;
        }
        memcpy(preimage, line, pre_len);
        preimage[pre_len] = '}';
        preimage[pre_len + 1] = '\0';

        char computed[WB_SHA256_HEX_LEN];
        wb_sha256_hex(preimage, strlen(preimage), computed);
        if (strncmp(computed, stored_rec, 64) != 0) {
            rc = WB_ERR_GENERIC;  /* record content was altered */
            break;
        }

        char *pm = strstr(line, PREV_MARKER);
        if (!pm || !is_hex64(pm + strlen(PREV_MARKER))) {
            rc = WB_ERR_GENERIC;
            break;
        }
        if (strncmp(pm + strlen(PREV_MARKER), expected_prev, 64) != 0) {
            rc = WB_ERR_GENERIC;  /* chain link broken (insert/delete/reorder) */
            break;
        }

        memcpy(expected_prev, computed, 64);
        expected_prev[64] = '\0';
        count++;
    }

    free(buf);
    if (rc == WB_OK && records_out)
        *records_out = count;
    return rc;
}
