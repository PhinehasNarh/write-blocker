/*
 * win.c - Windows backend. Enumerates physical drives and toggles the
 * per-disk read-only attribute via IOCTL_DISK_SET_DISK_ATTRIBUTES (the same
 * mechanism as `diskpart` -> attributes disk set readonly). No reboot needed.
 *
 * Requires Administrator.
 */
#include "writeblock.h"
#include "platform.h"

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef DISK_ATTRIBUTE_READ_ONLY
#define DISK_ATTRIBUTE_READ_ONLY 0x0000000000000002ULL
#endif

#define MAX_PHYSICAL_DRIVES 64

int wb_have_privilege(void)
{
    BOOL is_admin = FALSE;
    PSID admin_sid = NULL;
    SID_IDENTIFIER_AUTHORITY nt_auth = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&nt_auth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &admin_sid)) {
        if (!CheckTokenMembership(NULL, admin_sid, &is_admin))
            is_admin = FALSE;
        FreeSid(admin_sid);
    }
    return is_admin ? 1 : 0;
}

const char *wb_privilege_name(void)
{
    return "Administrator";
}

/* Open \\.\PhysicalDrive<n> with the given access; INVALID_HANDLE_VALUE on failure. */
static HANDLE open_drive(int n, DWORD access)
{
    char path[64];
    snprintf(path, sizeof(path), "\\\\.\\PhysicalDrive%d", n);
    return CreateFileA(path, access,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       OPEN_EXISTING, 0, NULL);
}

/* Physical drive number that holds the Windows directory, or -1 if unknown. */
static int system_disk_number(void)
{
    char windir[MAX_PATH];
    if (GetWindowsDirectoryA(windir, sizeof(windir)) == 0 || windir[1] != ':')
        return -1;

    char volpath[16];
    snprintf(volpath, sizeof(volpath), "\\\\.\\%c:", windir[0]);
    HANDLE h = CreateFileA(volpath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return -1;

    VOLUME_DISK_EXTENTS ext;
    DWORD ret = 0;
    int disk = -1;
    if (DeviceIoControl(h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0,
                        &ext, sizeof(ext), &ret, NULL) &&
        ext.NumberOfDiskExtents > 0) {
        disk = (int)ext.Extents[0].DiskNumber;
    }
    CloseHandle(h);
    return disk;
}

/* Copy a trimmed ASCII field from the descriptor buffer at offset into dst. */
static void append_field(char *dst, size_t dstlen, const BYTE *buf, DWORD offset)
{
    if (offset == 0)
        return;
    const char *s = (const char *)(buf + offset);
    /* skip leading spaces */
    while (*s == ' ')
        s++;
    size_t cur = strlen(dst);
    if (cur && cur < dstlen - 1)
        dst[cur++] = ' ';
    while (*s && cur < dstlen - 1)
        dst[cur++] = *s++;
    dst[cur] = '\0';
    /* trim trailing spaces */
    while (cur > 0 && dst[cur - 1] == ' ')
        dst[--cur] = '\0';
}

/* Fill model + removable from STORAGE_DEVICE_DESCRIPTOR. Returns 0 on success. */
static int query_descriptor(HANDLE h, wb_device_t *dev)
{
    STORAGE_PROPERTY_QUERY q;
    memset(&q, 0, sizeof(q));
    q.PropertyId = StorageDeviceProperty;
    q.QueryType = PropertyStandardQuery;

    BYTE buf[1024];
    DWORD ret = 0;
    if (!DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof(q),
                         buf, sizeof(buf), &ret, NULL))
        return -1;

    STORAGE_DEVICE_DESCRIPTOR *d = (STORAGE_DEVICE_DESCRIPTOR *)buf;
    dev->model[0] = '\0';
    append_field(dev->model, sizeof(dev->model), buf, d->VendorIdOffset);
    append_field(dev->model, sizeof(dev->model), buf, d->ProductIdOffset);

    dev->removable = (d->BusType == BusTypeUsb || d->RemovableMedia) ? 1 : 0;
    return 0;
}

/* Read current read-only attribute: 1, 0, or -1 if unavailable. */
static int query_readonly_handle(HANDLE h)
{
    GET_DISK_ATTRIBUTES attrs;
    memset(&attrs, 0, sizeof(attrs));
    DWORD ret = 0;
    if (!DeviceIoControl(h, IOCTL_DISK_GET_DISK_ATTRIBUTES, NULL, 0,
                         &attrs, sizeof(attrs), &ret, NULL))
        return -1;
    return (attrs.Attributes & DISK_ATTRIBUTE_READ_ONLY) ? 1 : 0;
}

int wb_enumerate(wb_device_t **out, size_t *count)
{
    *out = NULL;
    *count = 0;

    int sysdisk = system_disk_number();

    size_t cap = 8, n = 0;
    wb_device_t *arr = calloc(cap, sizeof(*arr));
    if (!arr)
        return WB_ERR_NOMEM;

    for (int i = 0; i < MAX_PHYSICAL_DRIVES; i++) {
        /*
         * Prefer GENERIC_READ so the FILE_READ_ACCESS ioctls (notably
         * IOCTL_DISK_GET_LENGTH_INFO) succeed. That open needs Administrator;
         * if it is denied, fall back to a zero-access query handle, which
         * still answers the FILE_ANY_ACCESS queries (property + attributes).
         */
        HANDLE h = open_drive(i, GENERIC_READ);
        if (h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED)
            h = open_drive(i, 0);
        if (h == INVALID_HANDLE_VALUE)
            continue;  /* gap in numbering, or device busy; keep scanning */

        if (n == cap) {
            cap *= 2;
            wb_device_t *tmp = realloc(arr, cap * sizeof(*arr));
            if (!tmp) {
                free(arr);
                CloseHandle(h);
                return WB_ERR_NOMEM;
            }
            arr = tmp;
        }

        wb_device_t *dev = &arr[n];
        memset(dev, 0, sizeof(*dev));
        snprintf(dev->id, sizeof(dev->id), "\\\\.\\PhysicalDrive%d", i);

        query_descriptor(h, dev);

        GET_LENGTH_INFORMATION len;
        DWORD ret = 0;
        if (DeviceIoControl(h, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0,
                            &len, sizeof(len), &ret, NULL))
            dev->size_bytes = (uint64_t)len.Length.QuadPart;

        dev->read_only = query_readonly_handle(h);
        dev->is_system = (sysdisk == i) ? 1 : 0;

        n++;
        CloseHandle(h);
    }

    *out = arr;
    *count = n;
    return WB_OK;
}

/* Extract the drive number from "\\.\PhysicalDriveN"; -1 if not that form. */
static int drive_number_from_id(const char *id)
{
    const char *prefix = "\\\\.\\PhysicalDrive";
    size_t plen = strlen(prefix);
    if (strncmp(id, prefix, plen) != 0)
        return -1;
    const char *num = id + plen;
    if (*num < '0' || *num > '9')
        return -1;
    return atoi(num);
}

static int set_readonly(const char *id, int readonly)
{
    int n = drive_number_from_id(id);
    if (n < 0)
        return WB_ERR_INVAL;

    HANDLE h = open_drive(n, GENERIC_READ | GENERIC_WRITE);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED)
            return WB_ERR_PERM;
        if (err == ERROR_FILE_NOT_FOUND)
            return WB_ERR_NOT_FOUND;
        return WB_ERR_IO;
    }

    SET_DISK_ATTRIBUTES set;
    memset(&set, 0, sizeof(set));
    set.Version = sizeof(set);
    set.Persist = FALSE;  /* applies for this session, cleared on reboot/replug */
    set.AttributesMask = DISK_ATTRIBUTE_READ_ONLY;
    set.Attributes = readonly ? DISK_ATTRIBUTE_READ_ONLY : 0;

    DWORD ret = 0;
    int rc = WB_OK;
    if (!DeviceIoControl(h, IOCTL_DISK_SET_DISK_ATTRIBUTES, &set, sizeof(set),
                         NULL, 0, &ret, NULL)) {
        rc = (GetLastError() == ERROR_ACCESS_DENIED) ? WB_ERR_PERM : WB_ERR_IO;
    }
    CloseHandle(h);
    return rc;
}

int wb_protect(const char *id)
{
    if (!id || !*id)
        return WB_ERR_INVAL;
    return set_readonly(id, 1);
}

int wb_unprotect(const char *id)
{
    if (!id || !*id)
        return WB_ERR_INVAL;
    return set_readonly(id, 0);
}

int wb_status(const char *id, int *read_only_out)
{
    if (!id || !*id || !read_only_out)
        return WB_ERR_INVAL;
    int n = drive_number_from_id(id);
    if (n < 0)
        return WB_ERR_INVAL;

    HANDLE h = open_drive(n, 0);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND)
            return WB_ERR_NOT_FOUND;
        if (err == ERROR_ACCESS_DENIED)
            return WB_ERR_PERM;
        return WB_ERR_IO;
    }
    int ro = query_readonly_handle(h);
    CloseHandle(h);
    if (ro < 0)
        return WB_ERR_IO;
    *read_only_out = ro;
    return WB_OK;
}
