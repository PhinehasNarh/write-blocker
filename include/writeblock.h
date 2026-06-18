/*
 * writeblock.h - Public types and backend interface for the cross-platform
 * write blocker.
 *
 * A write blocker enables/disables write protection on a storage device using
 * OS-level facilities so the device cannot be modified during forensic
 * acquisition. Each platform implements the wb_* backend functions declared
 * here; the CLI and core logic stay platform-neutral.
 */
#ifndef WRITEBLOCK_H
#define WRITEBLOCK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum lengths for the fixed-size fields in wb_device_t. */
#define WB_ID_MAX     256
#define WB_MODEL_MAX  128
#define WB_SERIAL_MAX 64

/* Return codes shared by every backend. wb_strerror() maps these to text. */
typedef enum {
    WB_OK = 0,             /* success */
    WB_ERR_GENERIC = 1,    /* unspecified failure */
    WB_ERR_NOT_FOUND = 2,  /* device id did not match any device */
    WB_ERR_PERM = 3,       /* needs admin/root, or access denied */
    WB_ERR_UNSUPPORTED = 4,/* operation not supported on this platform/device */
    WB_ERR_IO = 5,         /* ioctl/syscall/registry failure */
    WB_ERR_INVAL = 6,      /* invalid argument */
    WB_ERR_NOMEM = 7       /* allocation failure */
} wb_status_code;

/* A single storage device as seen by a backend. */
typedef struct {
    char     id[WB_ID_MAX];         /* platform path/id: \\.\PhysicalDrive1, /dev/sdb */
    char     model[WB_MODEL_MAX];   /* friendly model/name, may be empty */
    char     serial[WB_SERIAL_MAX]; /* serial number, may be empty */
    uint64_t size_bytes;            /* total size, 0 if unknown */
    int      removable;             /* 1 if USB/removable, else 0 */
    int      read_only;             /* 1 protected, 0 writable, -1 unknown */
    int      is_system;             /* 1 if this looks like the OS/boot disk */
} wb_device_t;

/*
 * Enumerate storage devices. On success returns WB_OK, sets *out to a
 * malloc'd array of *count elements. Caller must free(*out). On failure
 * *out is NULL and *count is 0.
 */
int wb_enumerate(wb_device_t **out, size_t *count);

/* Enable write protection on the device identified by id. */
int wb_protect(const char *id);

/* Disable write protection on the device identified by id. */
int wb_unprotect(const char *id);

/*
 * Report current write-protect state. On success *read_only_out is set to
 * 1 (protected), 0 (writable), or -1 (unknown).
 */
int wb_status(const char *id, int *read_only_out);

/* Human-readable message for a wb_status_code. Never returns NULL. */
const char *wb_strerror(int rc);

/*
 * Sequential read-only access to a whole device, used for hashing and
 * imaging. The reader is opaque and defined by each backend.
 *
 * wb_reader_open:  on success returns WB_OK, sets *out and, if size_out is
 *                  non-NULL, the device size in bytes.
 * wb_reader_read:  reads up to want bytes into buf; sets *got to the number
 *                  read (0 means end of device). Returns WB_OK or an error.
 * wb_reader_close: releases the reader (NULL is ignored).
 */
typedef struct wb_reader wb_reader;
int  wb_reader_open(const char *id, wb_reader **out, uint64_t *size_out);
int  wb_reader_read(wb_reader *r, void *buf, size_t want, size_t *got);
void wb_reader_close(wb_reader *r);

/*
 * Active proof of the write block. Reads the first sector and writes the
 * identical bytes back, so the test never changes device contents: a blocked
 * device rejects the write and a writable device receives byte-identical data.
 * On success sets *blocked_out to 1 (write rejected) or 0 (write succeeded).
 * Returns WB_OK if the test ran, or a wb_status_code on error.
 */
int wb_selftest(const char *id, int *blocked_out);

#ifdef __cplusplus
}
#endif

#endif /* WRITEBLOCK_H */
