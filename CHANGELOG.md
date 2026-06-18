# Changelog

All notable changes to `writeblock` are documented here. Versions use semantic
versioning once a 1.0 is cut; pre-1.0 minors may change behavior.

## [0.2.0] - Forensic features

### Added
- `hash <device-id>`: whole-device SHA-256 (streaming, progress to stderr),
  with `--json` output.
- `verify <device-id> <sha256>`: hash a device and compare to an expected
  digest; non-zero exit on mismatch.
- Tamper-evident, append-only audit log (JSON-lines) with a SHA-256 hash chain.
  `protect`/`unprotect` now record an entry; `audit-verify` checks the chain.
- `--hash` records the device SHA-256 alongside a protect/unprotect action.
- `--case <id>` and `--examiner <name>` metadata written to the audit log.
- `--log <path>` to choose the audit log (default `writeblock-audit.jsonl`).
- `--quiet` to suppress hashing progress.
- `version` command and `--version`.
- Device serial number in `list`/`status` output and JSON (`serial` field).
- Sequential read-only device reader in every backend (Linux/Windows/macOS/
  Android), used by hashing.
- Stable, documented process exit codes (0 ok, 2 usage, 3 perm, 4 not found,
  5 unsupported, 6 verify mismatch).
- Self-contained SHA-256 implementation (no OpenSSL dependency).

### Changed
- System/boot disk now requires typing the exact device id to proceed (no
  `--yes` bypass), replacing the previous `--yes`-only guard.
- Windows enumeration opens `GENERIC_READ` (with a zero-access fallback) so the
  device size is reported for administrators.

## [0.1.0] - Initial release

### Added
- Cross-platform OS-level write blocker in C: `list`, `status`, `protect`,
  `unprotect` with `--removable-only`, `--json`, `--yes`.
- Backends: Windows (disk read-only attribute), Linux (`BLKROSET`), Android
  (shares Linux), macOS (DiskArbitration read-only remount).
- CMake build, README, and docs/design.md with per-platform test procedures.
