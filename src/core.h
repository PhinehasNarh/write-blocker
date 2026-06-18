/*
 * core.h - Platform-neutral helpers used by the CLI. The heavy lifting
 * (enumeration, protect/unprotect) lives in the backends; these are shared
 * formatting and lookup utilities.
 */
#ifndef WB_CORE_H
#define WB_CORE_H

#include "writeblock.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Format a byte count into a short human string ("14.9 GB") in buf. */
void wb_format_size(uint64_t bytes, char *buf, size_t buflen);

/*
 * Enumerate devices and copy the one whose id matches into *out.
 * Returns WB_OK on match, WB_ERR_NOT_FOUND if no device has that id, or the
 * enumeration error code. Matching is exact on the id field.
 */
int wb_find_device(const char *id, wb_device_t *out);

/* Render read_only state (1/0/-1) as "protected"/"writable"/"unknown". */
const char *wb_state_str(int read_only);

#ifdef __cplusplus
}
#endif

#endif /* WB_CORE_H */
