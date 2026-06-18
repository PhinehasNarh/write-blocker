/*
 * audit.h - Tamper-evident, append-only audit log for protect/unprotect and
 * hashing actions. Each record is a JSON object on its own line and carries a
 * SHA-256 chain: rec = SHA256(prev_rec || fields), so altering or removing any
 * past entry breaks the chain and is detectable with `verify`.
 */
#ifndef WB_AUDIT_H
#define WB_AUDIT_H

#include "writeblock.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Append one record to the log at path (created if absent). action is e.g.
 * "protect"/"unprotect"/"hash". case_id, examiner, and hash may be NULL or "".
 * Returns WB_OK or a wb_status_code.
 */
int wb_audit_append(const char *path, const char *action, const wb_device_t *dev,
                    const char *case_id, const char *examiner, const char *hash);

/*
 * Verify the hash chain of the log at path. On success *records_out (if
 * non-NULL) holds the number of records checked. Returns WB_OK if intact,
 * WB_ERR_GENERIC if the chain is broken, or another wb_status_code.
 */
int wb_audit_verify(const char *path, size_t *records_out);

#ifdef __cplusplus
}
#endif

#endif /* WB_AUDIT_H */
