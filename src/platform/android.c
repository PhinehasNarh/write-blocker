/*
 * android.c - Android backend.
 *
 * Android runs the Linux kernel, so block-device write protection works
 * through the exact same BLKROSET/BLKROGET ioctls and /sys/block enumeration
 * as desktop Linux. Rather than duplicate that logic, this translation unit
 * compiles the Linux backend directly. CMake selects android.c (not linux.c)
 * for Android targets, so linux.c is only compiled once here.
 *
 * Practical notes for Android:
 *   - Run as root (adb shell su -c writeblock ...). Without root the BLKROSET
 *     ioctl fails with WB_ERR_PERM.
 *   - Targets of interest: mmcblk* (internal eMMC/SD) and sd* (USB-OTG mass
 *     storage). These already appear in /sys/block, so no extra discovery is
 *     needed here.
 *   - Build with the NDK toolchain (see docs/design.md).
 */
#include "linux.c"
