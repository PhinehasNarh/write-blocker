/*
 * platform.h - Internal helpers shared between the platform-neutral core and
 * the per-OS backends. The public backend contract lives in writeblock.h;
 * this header adds small utilities the backends and core agree on.
 */
#ifndef WB_PLATFORM_H
#define WB_PLATFORM_H

#include "writeblock.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Returns 1 if the current process holds the privilege required to change
 * device write protection (Administrator on Windows, root elsewhere),
 * otherwise 0. Implemented per backend.
 */
int wb_have_privilege(void);

/* Name of the privilege required, e.g. "Administrator" or "root". */
const char *wb_privilege_name(void);

#ifdef __cplusplus
}
#endif

#endif /* WB_PLATFORM_H */
