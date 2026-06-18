/*
 * macos.c - macOS backend.
 *
 * Enumeration uses IOKit (IOMedia whole disks). Write protection is the
 * weakest of the four platforms at OS level: macOS has no per-block read-only
 * ioctl like Linux. We therefore remount the disk's mounted volumes read-only
 * via DiskArbitration (unmount, then mount with the "rdonly" argument), and
 * the reverse to unprotect. This blocks writes through the filesystem but is
 * not a tamper-proof block of raw device writes. A future phase adds a
 * DriverKit/kext storage filter for forensic-grade blocking.
 *
 * Requires root.
 */
#include "writeblock.h"
#include "platform.h"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/storage/IOMedia.h>
#include <IOKit/storage/IOStorageDeviceCharacteristics.h>
#include <DiskArbitration/DiskArbitration.h>

#include <sys/mount.h>
#include <sys/param.h>
#include <sys/disk.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef kIOMainPortDefault
#define kIOMainPortDefault kIOMasterPortDefault
#endif

int wb_have_privilege(void)
{
    return geteuid() == 0;
}

const char *wb_privilege_name(void)
{
    return "root";
}

/* Read a CFString IOKit property into buf. Returns 0 on success. */
static int cfstr_prop_to_buf(CFTypeRef ref, char *buf, size_t len)
{
    if (!ref || CFGetTypeID(ref) != CFStringGetTypeID())
        return -1;
    return CFStringGetCString((CFStringRef)ref, buf, (CFIndex)len,
                              kCFStringEncodingUTF8) ? 0 : -1;
}

/*
 * Best-effort string from the IOKit Device Characteristics dict found by
 * searching the parent chain (e.g. Product Name, Product Serial Number).
 */
static void fill_characteristic(io_object_t media, CFStringRef value_key,
                                char *buf, size_t len)
{
    buf[0] = '\0';
    CFTypeRef dict = IORegistryEntrySearchCFProperty(
        media, kIOServicePlane, CFSTR(kIOPropertyDeviceCharacteristicsKey),
        kCFAllocatorDefault, kIORegistryIterateRecursively | kIORegistryIterateParents);
    if (dict && CFGetTypeID(dict) == CFDictionaryGetTypeID()) {
        CFTypeRef v = CFDictionaryGetValue((CFDictionaryRef)dict, value_key);
        cfstr_prop_to_buf(v, buf, len);
    }
    if (dict)
        CFRelease(dict);
}

/* Read a CFBoolean property from the IOMedia object (default 0). */
static int bool_prop(io_object_t media, CFStringRef key)
{
    int result = 0;
    CFTypeRef v = IORegistryEntryCreateCFProperty(media, key, kCFAllocatorDefault, 0);
    if (v && CFGetTypeID(v) == CFBooleanGetTypeID())
        result = CFBooleanGetValue((CFBooleanRef)v) ? 1 : 0;
    if (v)
        CFRelease(v);
    return result;
}

/* Does a mount's "from" name (e.g. /dev/disk2s1) belong to whole disk id? */
static int mount_belongs_to(const char *from, const char *disk_id)
{
    size_t dlen = strlen(disk_id);
    if (strncmp(from, disk_id, dlen) != 0)
        return 0;
    char next = from[dlen];
    return (next == '\0' || next == 's');  /* exact disk or a sliceN */
}

/*
 * Read-only state for a whole disk based on its mounted volumes:
 *   1  = all mounted volumes are read-only
 *   0  = at least one mounted volume is writable
 *  -1  = no mounted volumes (cannot tell)
 */
static int disk_readonly_state(const char *disk_id)
{
    struct statfs *mnt = NULL;
    int n = getmntinfo(&mnt, MNT_NOWAIT);
    int mounted = 0, writable = 0;
    for (int i = 0; i < n; i++) {
        if (!mount_belongs_to(mnt[i].f_mntfromname, disk_id))
            continue;
        mounted++;
        if (!(mnt[i].f_flags & MNT_RDONLY))
            writable = 1;
    }
    if (!mounted)
        return -1;
    return writable ? 0 : 1;
}

int wb_enumerate(wb_device_t **out, size_t *count)
{
    *out = NULL;
    *count = 0;

    CFMutableDictionaryRef match = IOServiceMatching(kIOMediaClass);
    if (!match)
        return WB_ERR_GENERIC;
    /* Whole disks only (skip partitions). */
    CFDictionarySetValue(match, CFSTR(kIOMediaWholeKey), kCFBooleanTrue);

    io_iterator_t iter = 0;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, match, &iter) != KERN_SUCCESS)
        return WB_ERR_IO;

    size_t cap = 8, cnt = 0;
    wb_device_t *arr = calloc(cap, sizeof(*arr));
    if (!arr) {
        IOObjectRelease(iter);
        return WB_ERR_NOMEM;
    }

    io_object_t media;
    while ((media = IOIteratorNext(iter)) != 0) {
        CFTypeRef bsd = IORegistryEntryCreateCFProperty(
            media, CFSTR(kIOBSDNameKey), kCFAllocatorDefault, 0);
        char bsdname[64] = {0};
        if (cfstr_prop_to_buf(bsd, bsdname, sizeof(bsdname)) != 0) {
            if (bsd) CFRelease(bsd);
            IOObjectRelease(media);
            continue;
        }
        if (bsd) CFRelease(bsd);

        if (cnt == cap) {
            cap *= 2;
            wb_device_t *tmp = realloc(arr, cap * sizeof(*arr));
            if (!tmp) {
                free(arr);
                IOObjectRelease(media);
                IOObjectRelease(iter);
                return WB_ERR_NOMEM;
            }
            arr = tmp;
        }

        wb_device_t *dev = &arr[cnt];
        memset(dev, 0, sizeof(*dev));
        snprintf(dev->id, sizeof(dev->id), "/dev/%s", bsdname);

        CFTypeRef sz = IORegistryEntryCreateCFProperty(
            media, CFSTR(kIOMediaSizeKey), kCFAllocatorDefault, 0);
        if (sz && CFGetTypeID(sz) == CFNumberGetTypeID()) {
            long long bytes = 0;
            CFNumberGetValue((CFNumberRef)sz, kCFNumberLongLongType, &bytes);
            dev->size_bytes = (uint64_t)bytes;
        }
        if (sz) CFRelease(sz);

        dev->removable = (bool_prop(media, CFSTR(kIOMediaRemovableKey)) ||
                          bool_prop(media, CFSTR(kIOMediaEjectableKey))) ? 1 : 0;
        fill_characteristic(media, CFSTR(kIOPropertyProductNameKey),
                            dev->model, sizeof(dev->model));
        fill_characteristic(media, CFSTR(kIOPropertyProductSerialNumberKey),
                            dev->serial, sizeof(dev->serial));
        dev->read_only = disk_readonly_state(dev->id);
        /* The system disk is the one whose volume is mounted at "/". */
        {
            struct statfs root;
            if (statfs("/", &root) == 0 &&
                mount_belongs_to(root.f_mntfromname, dev->id))
                dev->is_system = 1;
        }

        cnt++;
        IOObjectRelease(media);
    }
    IOObjectRelease(iter);

    *out = arr;
    *count = cnt;
    return WB_OK;
}

/* DiskArbitration callback context. */
typedef struct { int rc; } da_result;

static void da_callback(DADiskRef disk, DADissenterRef dissenter, void *ctx)
{
    (void)disk;
    da_result *r = (da_result *)ctx;
    r->rc = dissenter ? WB_ERR_IO : WB_OK;
    CFRunLoopStop(CFRunLoopGetCurrent());
}

/* Unmount one volume (by BSD slice name) and remount; readonly chooses mode. */
static int remount_volume(DASessionRef session, const char *bsd_slice, int readonly)
{
    DADiskRef vol = DADiskCreateFromBSDName(kCFAllocatorDefault, session, bsd_slice);
    if (!vol)
        return WB_ERR_IO;

    da_result res = { WB_ERR_IO };

    DADiskUnmount(vol, kDADiskUnmountOptionDefault, da_callback, &res);
    CFRunLoopRun();
    if (res.rc != WB_OK) {
        CFRelease(vol);
        return res.rc;
    }

    CFStringRef args[2] = { NULL, NULL };
    if (readonly)
        args[0] = CFSTR("rdonly");

    res.rc = WB_ERR_IO;
    DADiskMountWithArguments(vol, NULL, kDADiskMountOptionDefault,
                             da_callback, &res, readonly ? args : NULL);
    CFRunLoopRun();

    CFRelease(vol);
    return res.rc;
}

/* Apply readonly/read-write to every mounted volume of the whole disk. */
static int set_readonly(const char *id, int readonly)
{
    DASessionRef session = DASessionCreate(kCFAllocatorDefault);
    if (!session)
        return WB_ERR_IO;
    DASessionScheduleWithRunLoop(session, CFRunLoopGetCurrent(),
                                 kCFRunLoopDefaultMode);

    /* Snapshot the volumes belonging to this disk before unmounting. */
    char slices[32][64];
    int nslices = 0;
    struct statfs *mnt = NULL;
    int n = getmntinfo(&mnt, MNT_NOWAIT);
    for (int i = 0; i < n && nslices < 32; i++) {
        if (mount_belongs_to(mnt[i].f_mntfromname, id)) {
            const char *base = strrchr(mnt[i].f_mntfromname, '/');
            base = base ? base + 1 : mnt[i].f_mntfromname;
            snprintf(slices[nslices], sizeof(slices[nslices]), "%s", base);
            nslices++;
        }
    }

    int rc = WB_OK;
    if (nslices == 0) {
        /* Nothing mounted: no filesystem path to writes to block at OS level. */
        rc = WB_ERR_UNSUPPORTED;
    } else {
        for (int i = 0; i < nslices; i++) {
            int r = remount_volume(session, slices[i], readonly);
            if (r != WB_OK)
                rc = r;  /* report the last error, keep trying the rest */
        }
    }

    DASessionUnscheduleFromRunLoop(session, CFRunLoopGetCurrent(),
                                   kCFRunLoopDefaultMode);
    CFRelease(session);
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
    *read_only_out = disk_readonly_state(id);
    return WB_OK;
}

/* ---- Sequential reader (read-only) ---- */

struct wb_reader {
    int      fd;
    uint64_t size;
    uint64_t pos;
    uint32_t block;
};

/* Map "/dev/diskN" to the raw "/dev/rdiskN" node for faster unbuffered reads. */
static void raw_path(const char *id, char *out, size_t len)
{
    const char *base = strrchr(id, '/');
    base = base ? base + 1 : id;          /* "diskN" */
    snprintf(out, len, "/dev/r%s", base); /* "/dev/rdiskN" */
}

int wb_reader_open(const char *id, wb_reader **out, uint64_t *size_out)
{
    if (!id || !*id || !out)
        return WB_ERR_INVAL;

    char rpath[80];
    raw_path(id, rpath, sizeof(rpath));
    int fd = open(rpath, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        fd = open(id, O_RDONLY | O_CLOEXEC);  /* fall back to the block node */
    if (fd < 0)
        return (errno == EACCES || errno == EPERM) ? WB_ERR_PERM
             : (errno == ENOENT) ? WB_ERR_NOT_FOUND : WB_ERR_IO;

    uint32_t blocksize = 512;
    uint64_t blockcount = 0;
    ioctl(fd, DKIOCGETBLOCKSIZE, &blocksize);
    ioctl(fd, DKIOCGETBLOCKCOUNT, &blockcount);
    if (blocksize == 0)
        blocksize = 512;

    wb_reader *r = malloc(sizeof(*r));
    if (!r) {
        close(fd);
        return WB_ERR_NOMEM;
    }
    r->fd = fd;
    r->size = blockcount * (uint64_t)blocksize;
    r->pos = 0;
    r->block = blocksize;

    if (size_out)
        *size_out = r->size;
    *out = r;
    return WB_OK;
}

int wb_reader_read(wb_reader *r, void *buf, size_t want, size_t *got)
{
    if (!r || !buf || !got)
        return WB_ERR_INVAL;
    *got = 0;
    if (r->size && r->pos >= r->size)
        return WB_OK;  /* end of device */

    /* The raw device requires block-aligned read lengths (except the tail). */
    uint64_t remaining = r->size ? (r->size - r->pos) : want;
    uint64_t toread = want;
    if (toread > remaining)
        toread = remaining;
    if (toread != remaining && (toread % r->block) != 0)
        toread -= (toread % r->block);
    if (toread == 0)
        return WB_ERR_IO;

    ssize_t n = read(r->fd, buf, (size_t)toread);
    if (n < 0)
        return WB_ERR_IO;
    r->pos += (uint64_t)n;
    *got = (size_t)n;
    return WB_OK;
}

void wb_reader_close(wb_reader *r)
{
    if (r) {
        close(r->fd);
        free(r);
    }
}
