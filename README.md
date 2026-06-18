# writeblock

A cross-platform, OS-level **software write blocker** for digital forensics.
It enables or disables write protection on a storage device using built-in
operating-system facilities, so the device cannot be modified during evidence
acquisition and its hash stays valid.

Supported targets from a single C codebase:

| Platform | Mechanism | Privilege |
|----------|-----------|-----------|
| Windows  | Per-disk read-only attribute (`IOCTL_DISK_SET_DISK_ATTRIBUTES`, same as `diskpart attributes disk set readonly`) | Administrator |
| Linux    | Block read-only flag (`BLKROSET`/`BLKROGET`, same as `blockdev --setro`) | root |
| Android  | Same as Linux (shares the implementation), via the NDK | root |
| macOS    | Remount mounted volumes read-only via DiskArbitration | root |

## Important: what this is and is not

This is **OS-level** write blocking. It is fast, needs no signed kernel drivers,
and is effective against normal write paths. It is **not tamper-proof**: a user
with administrator/root rights can clear the same flag this tool sets. For
forensic-grade, tamper-resistant blocking you need a kernel filter driver, which
is planned for a later phase (see [docs/design.md](docs/design.md)).

For court-defensible acquisitions, a hardware write blocker remains the gold
standard. Use this tool when hardware is unavailable or for triage, and always
verify with before/after hashing.

## Build

Requires CMake 3.15+ and a C11 compiler.

```sh
cmake -S . -B build
cmake --build build
```

The binary is `build/writeblock` (`writeblock.exe` on Windows).

### Android (NDK)

```sh
cmake -S . -B build-android \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26
cmake --build build-android
```

Then `adb push build-android/writeblock /data/local/tmp/` and run via
`adb shell su -c /data/local/tmp/writeblock ...`.

## Usage

```
writeblock list [--removable-only] [--json]
writeblock status <device-id> [--json]
writeblock protect <device-id> [--yes] [--hash] [--case ID] [--examiner NAME] [--log PATH]
writeblock unprotect <device-id> [--yes] [--hash] [--case ID] [--examiner NAME] [--log PATH]
writeblock hash <device-id> [--quiet] [--json]
writeblock verify <device-id> <sha256> [--quiet]
writeblock selftest <device-id> [--yes]
writeblock audit-verify [--log PATH]
writeblock version
```

### Proving the block (self-test)

`selftest` (and `protect --selftest`) actively confirms the block: it reads the
first sector and writes the identical bytes back, so it never changes device
contents. A blocked device rejects the write (reported BLOCKED, exit 0); a
writable device receives byte-identical data (reported NOT BLOCKED, exit 6).
This turns "a flag was set" into positive proof that writes are refused.

### Integrity and audit

- `hash` computes a whole-device SHA-256; `verify` compares a device against a
  known digest. Use these before and after acquisition to prove the media did
  not change.
- `protect`/`unprotect` append a record to a tamper-evident, hash-chained audit
  log (`writeblock-audit.jsonl` by default, or `--log PATH`). `--hash` records
  the device SHA-256 with the action, and `--case`/`--examiner` add case
  metadata. `audit-verify` confirms the chain has not been altered.

Device ids come from `list`:

- Windows: `\\.\PhysicalDrive1`
- Linux/Android: `/dev/sdb`, `/dev/mmcblk0`
- macOS: `/dev/disk2`

### Examples

```sh
# See what is attached and its current state (run elevated for full detail)
writeblock list --removable-only

# Block writes to a USB disk before imaging
sudo writeblock protect /dev/sdb        # Linux
writeblock protect \\.\PhysicalDrive2   # Windows (Administrator shell)

# Confirm it is protected
writeblock status /dev/sdb

# Re-enable writes when done
sudo writeblock unprotect /dev/sdb
```

## Safety behavior

- `protect`/`unprotect` require an explicit device id; the tool never acts on
  "all devices".
- Non-system devices prompt for `[y/N]` confirmation unless `--yes` is given.
- The system/boot disk requires typing its exact device id to proceed; there is
  deliberately no `--yes` bypass for it.
- The required privilege (Administrator/root) is checked up front with a clear
  error.
- Exit codes are stable for scripting: `0` ok, `2` usage, `3` permission,
  `4` not found, `5` unsupported, `6` verify/chain mismatch.

## Layout

```
include/writeblock.h     Public types + backend contract (incl. reader API)
src/main.c               Entry point
src/cli.c                Arg parsing, dispatch, prompts, output
src/core.c               Error strings, size formatting, device lookup
src/sha256.c             Self-contained SHA-256
src/hash.c               Whole-device hashing via the backend reader
src/audit.c              Tamper-evident hash-chained audit log
src/platform/win.c       Windows backend
src/platform/linux.c     Linux backend
src/platform/android.c   Android backend (compiles linux.c)
src/platform/macos.c     macOS backend
docs/design.md           Mechanism details + per-platform test procedure
```

See [docs/design.md](docs/design.md) for mechanism internals, limitations, and
the end-to-end test procedure for each platform.
