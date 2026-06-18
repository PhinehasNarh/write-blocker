# Ideas and Roadmap

Recommended features and improvements for `writeblock`, grouped by theme and
roughly ordered by value. The current tool is a v1 that does OS-level write
protection (`list`/`status`/`protect`/`unprotect`) on Windows, Linux, Android,
and macOS. Items marked **(planned)** were already named as out-of-scope in
[docs/design.md](docs/design.md); the rest are new.

## Legend
- Impact: how much it improves forensic value or usability (high/med/low)
- Effort: rough build cost (S/M/L)

---

## 1. Forensic-grade robustness (true blocking)

The single biggest limitation today is that OS-level flags are reversible by a
privileged user and macOS only covers mounted filesystems. Closing this gap is
the highest-value direction.

- **Windows storage filter driver** (planned) - a KMDF upper-filter on the disk
  stack that fails `IRP_MJ_WRITE` for flagged devices. Tamper-resistant, but
  needs driver signing (EV cert / attestation signing). Impact: high, Effort: L.
- **Linux device-mapper read-only target / kernel module** (planned) - expose
  the target through a `dm-linear` read-only mapping, or a small module that
  rejects writes at the bio layer. More robust than `BLKROSET`. Impact: high, Effort: M-L.
- **macOS DriverKit/kext storage filter** (planned) - replace the remount hack
  with a real block-level filter. Notarization required. Impact: high, Effort: L.
- **Raw-write blocking on macOS** - even before a kext, block `/dev/rdiskN`
  access by holding an exclusive open or using DiskArbitration to deny mounts
  for the session. Impact: med, Effort: M.

## 2. Integrity and verification

A write blocker is only trustworthy if you can prove the media did not change.

- **Before/after hashing** (planned) - compute SHA-256 (and optionally MD5 for
  legacy case files) of the whole device on `protect`, and re-verify on
  `unprotect`, reporting a match/mismatch. Impact: high, Effort: M.
- **Streaming hash + progress** - hash large disks with a progress bar and
  cancel support; use a buffered reader (e.g. 4-8 MB blocks). Impact: med, Effort: M.
- **Self-test of the block** - after `protect`, attempt a tiny test write and
  confirm it is rejected, so the user gets positive proof the block is active
  rather than trusting the flag. Impact: high, Effort: S.
- **Sector-count / capacity record** - capture device size, serial, and bus
  type at protect time and warn if they change. Impact: med, Effort: S.

## 3. Audit and chain of custody

- **Tamper-evident audit log** (planned) - append-only JSON-lines log of every
  protect/unprotect with timestamp, device id, serial, user, result, and the
  hashes. Optionally hash-chain each entry (each record includes the previous
  record's hash). Impact: high, Effort: M.
- **Case metadata** - optional `--case <id>` / `--examiner <name>` flags written
  into the log for evidence tracking. Impact: med, Effort: S.
- **Exportable report** - generate a Markdown/PDF acquisition report from the
  log (device, hashes, timeline). Impact: med, Effort: M.

## 4. Usability and interface

- **Daemon / watch mode** - a long-running mode that auto-protects any newly
  attached removable device on connect (the macOS mount-approval block also
  needs a resident process to be effective). Impact: high, Effort: M.
- **GUI** (planned) - a small cross-platform front end (e.g. a status tray plus
  a device list with protect toggles). Impact: med, Effort: L.
- **`status --all` / richer `list`** - show serial number, partition table type,
  filesystem labels, and mount points. Impact: med, Effort: S-M.
- **Device matching by serial/label**, not just kernel path, so a stick gets the
  same identity across replugs. Impact: med, Effort: M.
- **`--quiet` / exit-code contract** - documented, stable exit codes for
  scripting (0 ok, distinct codes per error class). Impact: med, Effort: S.
- **Color and table polish** for `list`; respect `NO_COLOR`. Impact: low, Effort: S.

## 5. Safety hardening

- **Mounted-volume warning** - before protecting a disk with mounted, writable
  filesystems, warn that in-flight writes may error; offer to dismount first.
  Impact: med, Effort: S.
- **Windows: dismount/lock volumes** before setting the read-only attribute so
  the block takes effect on already-mounted volumes (today it mainly affects new
  mounts). Impact: high, Effort: M.
- **Confirmation token for system disk** - require typing the device id (not just
  `--yes`) to modify the system/boot disk. Impact: med, Effort: S.
- **Refuse on active OS pagefile/swap device.** Impact: med, Effort: S.

## 6. Platform coverage and depth

- **Android: enumerate `/dev/block/` and partition-level targets**, handle
  `force_ro` for eMMC boot partitions, and document Magisk/rooted constraints.
  Impact: med, Effort: M.
- **Linux: NVMe/SCSI serials** via sysfs (`device/wwid`, `device/serial`) and
  by-id paths in `list`. Impact: med, Effort: S.
- **BSD support** (FreeBSD/macOS share heritage) via GEOM read-only. Impact: low, Effort: M.
- **Network/loop/zram filtering flags** - a `--all` switch to include the
  pseudo-devices currently hidden. Impact: low, Effort: S.

## 7. Quality, testing, and distribution

- **CI build matrix** - GitHub Actions building on Windows, Linux, and macOS on
  every push (the project cannot be compiled in the current dev environment, so
  CI is the real compile gate). Impact: high, Effort: S.
- **Automated Linux integration test** - the loop-device scenario from
  docs/design.md run in CI as a self-check. Impact: high, Effort: S.
- **Static analysis** - `clang-tidy`, `cppcheck`, and MSVC `/analyze` in CI;
  build with `-Werror`/`-fsanitize=address,undefined` for tests. Impact: med, Effort: S.
- **Unit tests for core helpers** - `wb_format_size`, id parsing, JSON escaping.
  Impact: med, Effort: S.
- **Signed release binaries** per platform (and the eventual signed drivers).
  Impact: med, Effort: M.
- **Man page / `--version`** and a `CHANGELOG.md`. Impact: low, Effort: S.

## 8. Stretch / research

- **Write-blocked imaging in one step** - integrate protect + hash + image
  (raw/E01) so a single command produces a verified forensic image. Impact: high, Effort: L.
- **Hardware write-blocker detection** - recognize when a known hardware blocker
  is in line and report it instead of applying software blocking. Impact: low, Effort: M.
- **Remote/agent mode** - protect devices on a remote host over an authenticated
  channel for lab workflows. Impact: low, Effort: L.

---

## Suggested next three

1. **CI build matrix + loop-device integration test** (section 7) - gives a real
   compile/run gate the local environment cannot provide.
2. **Self-test of the block + before/after SHA-256** (sections 2) - turns the
   tool from "set a flag" into "prove the media is blocked and unchanged."
3. **Windows volume dismount/lock before setting read-only** (section 5) - closes
   the most likely real-world correctness gap on the primary desktop platform.
