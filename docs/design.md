# Design: writeblock

## Goal

Prevent any modification to a target storage device using OS-level facilities,
behind one common C interface, on Windows, Linux, macOS, and Android, with
first-class handling of removable/USB media.

## Architecture

A platform-neutral core (`core.c`, `cli.c`, `main.c`) calls a backend that
implements the contract in `include/writeblock.h`:

```c
int wb_enumerate(wb_device_t **out, size_t *count);
int wb_protect(const char *id);
int wb_unprotect(const char *id);
int wb_status(const char *id, int *read_only_out);
const char *wb_strerror(int rc);          /* in core.c */
int wb_have_privilege(void);              /* per backend */
const char *wb_privilege_name(void);      /* per backend */

/* Sequential read-only access for hashing/imaging (per backend). */
int  wb_reader_open(const char *id, wb_reader **out, uint64_t *size_out);
int  wb_reader_read(wb_reader *r, void *buf, size_t want, size_t *got);
void wb_reader_close(wb_reader *r);
```

### Forensic features (v0.2.0)
- **Hashing** (`src/hash.c`) streams the device through `wb_reader_*` into the
  self-contained SHA-256 (`src/sha256.c`); a 1 MiB buffer keeps reads
  sector-aligned for the Windows and macOS raw readers.
- **Audit log** (`src/audit.c`) appends one JSON object per action. The hashed
  pre-image of a record includes a `prev` field equal to the previous record's
  `rec`, so the records form a SHA-256 chain; `audit-verify` recomputes every
  `rec` and checks each `prev` link, detecting edits, deletions, or reordering.

CMake selects exactly one backend file by `CMAKE_SYSTEM_NAME` (Android first,
then Windows/Linux/Darwin). The core never touches OS-specific APIs.

`wb_device_t` carries: `id`, `model`, `size_bytes`, `removable`, `read_only`
(1/0/-1), and `is_system` (boot/OS disk, used to refuse accidental changes).

## Per-platform mechanism

### Windows (`src/platform/win.c`)
- Enumerate `\\.\PhysicalDrive0..63`; gaps are skipped.
- Model + bus type: `IOCTL_STORAGE_QUERY_PROPERTY` (StorageDeviceProperty).
  `removable` is set for `BusTypeUsb` or `RemovableMedia`.
- Size: `IOCTL_DISK_GET_LENGTH_INFO`.
- State: `IOCTL_DISK_GET_DISK_ATTRIBUTES` -> `DISK_ATTRIBUTE_READ_ONLY`.
- Protect/unprotect: `IOCTL_DISK_SET_DISK_ATTRIBUTES` with the read-only bit and
  mask. `Persist = FALSE`, so it applies for the session and clears on
  reboot/replug. Same mechanism as `diskpart`'s `attributes disk set readonly`.
- System disk: resolved via `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` on the
  Windows-directory volume.
- Privilege: `CheckTokenMembership` against the Administrators SID.

### Linux (`src/platform/linux.c`)
- Enumerate `/sys/block/*` (skips `ram*`, `zram*`, `dm-*`, `md*`; keeps `sd*`,
  `nvme*`, `mmcblk*`, `vd*`, `hd*`, `loop*`).
- Size from `size` (512-byte sectors), `removable`, `device/model` from sysfs.
- State: `ioctl(BLKROGET)`, falling back to `/sys/block/<dev>/ro`.
- Protect/unprotect: `ioctl(BLKROSET, &val)` (same flag as `blockdev --setro`).
- System disk: parse `/proc/mounts` for `/`, resolve the source, and match the
  owning whole disk via `/sys/block`.
- Privilege: `geteuid() == 0`.

### Android (`src/platform/android.c`)
- Android is Linux; this file `#include`s `linux.c` so the block-layer logic is
  shared verbatim. Built with the NDK toolchain. Run as root over `adb`.
- Devices of interest: `mmcblk*` (eMMC/SD) and `sd*` (USB-OTG), already listed by
  the Linux enumeration.

### macOS (`src/platform/macos.c`) - weakest at OS level
- Enumerate whole disks via IOKit (`IOMedia` with `Whole == true`): BSD name,
  size, removable/ejectable, product name.
- macOS has no per-block read-only ioctl. Protect therefore unmounts each
  mounted volume of the disk and remounts it read-only via DiskArbitration
  (`DADiskUnmount` then `DADiskMountWithArguments` with `rdonly`). Unprotect
  reverses it. This blocks filesystem writes but not raw device writes, and if
  no volume is mounted there is nothing to remount (`WB_ERR_UNSUPPORTED`).
- State: derived from `getmntinfo` `MNT_RDONLY` flags on the disk's volumes.
- Flagged for a DriverKit/kext storage filter in a later phase.

## Limitations

- OS-level flags are reversible by any privileged user; not tamper-proof.
- macOS only covers mounted filesystems, not raw writes.
- Windows non-persistent attribute clears on reboot/replug (by design here).
- Hardware write blockers remain the standard for court-defensible imaging.

## Verification

Build first:

```sh
cmake -S . -B build && cmake --build build
```

### Linux (primary end-to-end test, uses a throwaway loop device)

```sh
# Create a 64 MB backing file and attach it as a loop block device
dd if=/dev/zero of=/tmp/wb.img bs=1M count=64
LOOP=$(sudo losetup -f --show /tmp/wb.img)   # e.g. /dev/loop0

sudo ./build/writeblock protect "$LOOP" --yes
./build/writeblock status "$LOOP"            # -> protected

# A write must now fail with EROFS
sudo dd if=/dev/zero of="$LOOP" bs=1M count=1   # expected: "Operation not permitted"/EROFS

sudo ./build/writeblock unprotect "$LOOP" --yes
sudo dd if=/dev/zero of="$LOOP" bs=1M count=1   # now succeeds

sudo losetup -d "$LOOP"; rm -f /tmp/wb.img
```

### Windows (spare USB stick, Administrator shell)

```
writeblock list --removable-only
writeblock protect \\.\PhysicalDrive2 --yes
writeblock status \\.\PhysicalDrive2          :: -> protected
:: Try to format/write the volume -> blocked (media is write-protected)
:: Cross-check: diskpart -> select disk 2 -> attributes disk   (Read-only: Yes)
writeblock unprotect \\.\PhysicalDrive2 --yes
```

### macOS (external/USB volume, root)

```sh
sudo ./build/writeblock list --removable-only
sudo ./build/writeblock protect /dev/disk2 --yes
sudo ./build/writeblock status /dev/disk2     # -> protected
# Attempt to write a file to the mounted volume -> read-only filesystem
sudo ./build/writeblock unprotect /dev/disk2 --yes
```

### Android (NDK build pushed to device, root)

```sh
adb push build-android/writeblock /data/local/tmp/
adb shell su -c '/data/local/tmp/writeblock list'
adb shell su -c '/data/local/tmp/writeblock protect /dev/block/sda --yes'
# Attempt a write to the block device -> fails
adb shell su -c '/data/local/tmp/writeblock unprotect /dev/block/sda --yes'
```

### Safety checks (any platform)
- Running `protect`/`unprotect` without admin/root prints a clear privilege error.
- Targeting the system disk without `--yes` is refused.

## Out of scope (future phases)
- Kernel filter drivers for tamper-resistant blocking (Windows storage filter,
  Linux device-mapper/module, macOS DriverKit).
- GUI, integrated hashing/imaging, and an audit log of protect/unprotect actions.
