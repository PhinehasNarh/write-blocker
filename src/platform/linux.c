/*
 * linux.c - Linux backend. Uses the block layer's read-only flag (BLKROSET /
 * BLKROGET, the same mechanism as `blockdev --setro`) and /sys/block for
 * enumeration. Android shares this implementation (see android.c).
 *
 * Requires root (CAP_SYS_ADMIN) to change the flag.
 */
#define _GNU_SOURCE
#include "writeblock.h"
#include "platform.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <linux/fs.h>   /* BLKROSET, BLKROGET, BLKGETSIZE64 */

#define SYS_BLOCK "/sys/block"

int wb_have_privilege(void)
{
    return geteuid() == 0;
}

const char *wb_privilege_name(void)
{
    return "root";
}

/* Pointer to the basename component of a device id ("/dev/sdb" -> "sdb"). */
static const char *dev_basename(const char *id)
{
    const char *slash = strrchr(id, '/');
    return slash ? slash + 1 : id;
}

/* Read a single-line sysfs attribute into buf, trimming trailing whitespace. */
static int read_sysfs_str(const char *name, const char *attr, char *buf, size_t len)
{
    char path[512];
    snprintf(path, sizeof(path), SYS_BLOCK "/%s/%s", name, attr);
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    if (!fgets(buf, (int)len, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    size_t n = strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
                     buf[n - 1] == ' ' || buf[n - 1] == '\t'))
        buf[--n] = '\0';
    return 0;
}

/* Should this /sys/block entry be reported as a real storage device? */
static int is_reportable(const char *name)
{
    if (strncmp(name, "ram", 3) == 0)  return 0;
    if (strncmp(name, "zram", 4) == 0) return 0;
    if (strncmp(name, "dm-", 3) == 0)  return 0;
    if (strncmp(name, "md", 2) == 0)   return 0;
    return 1;  /* sd*, nvme*, mmcblk*, vd*, hd*, loop* */
}

/*
 * Determine the whole-disk kernel name backing the root filesystem, e.g.
 * "sda" or "nvme0n1". Best effort: empty string if it cannot be resolved.
 */
static void root_disk(char *out, size_t len)
{
    out[0] = '\0';

    FILE *f = fopen("/proc/mounts", "r");
    if (!f)
        return;

    char src[256], mnt[256];
    char rootsrc[256] = {0};
    while (fscanf(f, "%255s %255s %*s %*s %*d %*d", src, mnt) == 2) {
        if (strcmp(mnt, "/") == 0) {
            strncpy(rootsrc, src, sizeof(rootsrc) - 1);
            break;
        }
    }
    fclose(f);
    if (rootsrc[0] == '\0')
        return;

    /* Resolve symlinks (e.g. /dev/root, /dev/disk/by-uuid/...). */
    char resolved[PATH_MAX];
    const char *part = rootsrc;
    if (realpath(rootsrc, resolved))
        part = resolved;
    const char *pbase = dev_basename(part);

    /* Find the /sys/block disk that owns this partition (or is it). */
    DIR *d = opendir(SYS_BLOCK);
    if (!d)
        return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.')
            continue;
        if (strcmp(e->d_name, pbase) == 0) {        /* whole disk mounted */
            strncpy(out, e->d_name, len - 1);
            out[len - 1] = '\0';
            break;
        }
        char ppath[768];
        snprintf(ppath, sizeof(ppath), SYS_BLOCK "/%s/%s", e->d_name, pbase);
        if (access(ppath, F_OK) == 0) {             /* partition of this disk */
            strncpy(out, e->d_name, len - 1);
            out[len - 1] = '\0';
            break;
        }
    }
    closedir(d);
}

/* Query the live read-only flag via ioctl. Returns 1/0, or -1 on failure. */
static int query_readonly(const char *id)
{
    int fd = open(id, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int ro = -1;
    if (ioctl(fd, BLKROGET, &ro) != 0)
        ro = -1;
    close(fd);
    return ro;
}

int wb_enumerate(wb_device_t **out, size_t *count)
{
    *out = NULL;
    *count = 0;

    DIR *d = opendir(SYS_BLOCK);
    if (!d)
        return WB_ERR_IO;

    char sysroot[64];
    root_disk(sysroot, sizeof(sysroot));

    size_t cap = 8, n = 0;
    wb_device_t *arr = calloc(cap, sizeof(*arr));
    if (!arr) {
        closedir(d);
        return WB_ERR_NOMEM;
    }

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.' || !is_reportable(e->d_name))
            continue;

        if (n == cap) {
            cap *= 2;
            wb_device_t *tmp = realloc(arr, cap * sizeof(*arr));
            if (!tmp) {
                free(arr);
                closedir(d);
                return WB_ERR_NOMEM;
            }
            arr = tmp;
        }

        wb_device_t *dev = &arr[n];
        memset(dev, 0, sizeof(*dev));
        snprintf(dev->id, sizeof(dev->id), "/dev/%s", e->d_name);

        char tmp[128];
        if (read_sysfs_str(e->d_name, "size", tmp, sizeof(tmp)) == 0)
            dev->size_bytes = strtoull(tmp, NULL, 10) * 512ULL;

        if (read_sysfs_str(e->d_name, "removable", tmp, sizeof(tmp)) == 0)
            dev->removable = (tmp[0] == '1');

        if (read_sysfs_str(e->d_name, "device/model", dev->model,
                           sizeof(dev->model)) != 0)
            dev->model[0] = '\0';

        if (read_sysfs_str(e->d_name, "device/serial", dev->serial,
                           sizeof(dev->serial)) != 0)
            dev->serial[0] = '\0';

        /* Prefer the live ioctl value; fall back to sysfs "ro". */
        int ro = query_readonly(dev->id);
        if (ro < 0 && read_sysfs_str(e->d_name, "ro", tmp, sizeof(tmp)) == 0)
            ro = (tmp[0] == '1') ? 1 : 0;
        dev->read_only = ro;

        dev->is_system = (sysroot[0] && strcmp(sysroot, e->d_name) == 0) ? 1 : 0;

        n++;
    }
    closedir(d);

    *out = arr;
    *count = n;
    return WB_OK;
}

/* Set the block read-only flag. val=1 protects, val=0 unprotects. */
static int set_readonly(const char *id, int val)
{
    int fd = open(id, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        return (errno == EACCES || errno == EPERM) ? WB_ERR_PERM
             : (errno == ENOENT) ? WB_ERR_NOT_FOUND : WB_ERR_IO;

    int rc = WB_OK;
    if (ioctl(fd, BLKROSET, &val) != 0)
        rc = (errno == EACCES || errno == EPERM) ? WB_ERR_PERM : WB_ERR_IO;
    close(fd);
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
    int ro = query_readonly(id);
    if (ro < 0) {
        /* Distinguish "missing" from "no permission" for a clearer message. */
        if (access(id, F_OK) != 0)
            return WB_ERR_NOT_FOUND;
        return WB_ERR_IO;
    }
    *read_only_out = ro;
    return WB_OK;
}

/* ---- Sequential reader (read-only) ---- */

struct wb_reader {
    int fd;
};

int wb_reader_open(const char *id, wb_reader **out, uint64_t *size_out)
{
    if (!id || !*id || !out)
        return WB_ERR_INVAL;
    int fd = open(id, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return (errno == EACCES || errno == EPERM) ? WB_ERR_PERM
             : (errno == ENOENT) ? WB_ERR_NOT_FOUND : WB_ERR_IO;

    wb_reader *r = malloc(sizeof(*r));
    if (!r) {
        close(fd);
        return WB_ERR_NOMEM;
    }
    r->fd = fd;

    if (size_out) {
        uint64_t sz = 0;
        if (ioctl(fd, BLKGETSIZE64, &sz) != 0)
            sz = 0;
        *size_out = sz;
    }
    *out = r;
    return WB_OK;
}

int wb_reader_read(wb_reader *r, void *buf, size_t want, size_t *got)
{
    if (!r || !buf || !got)
        return WB_ERR_INVAL;
    ssize_t n = read(r->fd, buf, want);
    if (n < 0) {
        *got = 0;
        return WB_ERR_IO;
    }
    *got = (size_t)n;  /* 0 means end of device */
    return WB_OK;
}

void wb_reader_close(wb_reader *r)
{
    if (r) {
        close(r->fd);
        free(r);
    }
}

/* ---- Active block self-test (non-destructive write-back) ---- */

int wb_selftest(const char *id, int *blocked_out)
{
    if (!id || !*id || !blocked_out)
        return WB_ERR_INVAL;

    int fd = open(id, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        /* A read-only block device can refuse an O_RDWR open: confirm the
         * device is otherwise readable, then report it as blocked. */
        if (errno == EROFS || errno == EACCES || errno == EPERM) {
            int r = open(id, O_RDONLY | O_CLOEXEC);
            if (r >= 0) {
                close(r);
                *blocked_out = 1;
                return WB_OK;
            }
            return WB_ERR_PERM;
        }
        return (errno == ENOENT) ? WB_ERR_NOT_FOUND : WB_ERR_IO;
    }

    /* Read the first sector, then write the identical bytes back. */
    unsigned char buf[4096];
    ssize_t n = pread(fd, buf, sizeof(buf), 0);
    if (n <= 0) {
        close(fd);
        return WB_ERR_IO;
    }
    ssize_t w = pwrite(fd, buf, (size_t)n, 0);
    if (w < 0) {
        int blocked = (errno == EROFS || errno == EACCES || errno == EPERM);
        close(fd);
        if (!blocked)
            return WB_ERR_IO;  /* inconclusive: a real I/O error, not a block */
        *blocked_out = 1;
        return WB_OK;
    }

    /* The identical-bytes write succeeded: the device is NOT blocked. */
    fsync(fd);
    close(fd);
    *blocked_out = 0;
    return WB_OK;
}
