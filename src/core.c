/*
 * core.c - Platform-neutral helpers: error strings, size formatting, and a
 * device lookup built on top of the backend's wb_enumerate().
 */
#include "core.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

const char *wb_strerror(int rc)
{
    switch (rc) {
    case WB_OK:              return "success";
    case WB_ERR_GENERIC:     return "operation failed";
    case WB_ERR_NOT_FOUND:   return "device not found";
    case WB_ERR_PERM:        return "permission denied (administrator/root required)";
    case WB_ERR_UNSUPPORTED: return "operation not supported on this device or platform";
    case WB_ERR_IO:          return "I/O or system call error";
    case WB_ERR_INVAL:       return "invalid argument";
    case WB_ERR_NOMEM:       return "out of memory";
    default:                 return "unknown error";
    }
}

const char *wb_state_str(int read_only)
{
    switch (read_only) {
    case 1:  return "protected";
    case 0:  return "writable";
    default: return "unknown";
    }
}

void wb_format_size(uint64_t bytes, char *buf, size_t buflen)
{
    if (buf == NULL || buflen == 0)
        return;
    if (bytes == 0) {
        snprintf(buf, buflen, "unknown");
        return;
    }

    static const char *units[] = { "B", "KB", "MB", "GB", "TB", "PB" };
    double value = (double)bytes;
    size_t unit = 0;
    while (value >= 1024.0 && unit < (sizeof(units) / sizeof(units[0])) - 1) {
        value /= 1024.0;
        unit++;
    }
    if (unit == 0)
        snprintf(buf, buflen, "%llu %s", (unsigned long long)bytes, units[unit]);
    else
        snprintf(buf, buflen, "%.1f %s", value, units[unit]);
}

int wb_find_device(const char *id, wb_device_t *out)
{
    if (id == NULL || out == NULL)
        return WB_ERR_INVAL;

    wb_device_t *list = NULL;
    size_t count = 0;
    int rc = wb_enumerate(&list, &count);
    if (rc != WB_OK)
        return rc;

    int result = WB_ERR_NOT_FOUND;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(list[i].id, id) == 0) {
            *out = list[i];
            result = WB_OK;
            break;
        }
    }

    free(list);
    return result;
}
