/*
 * cli.c - Argument parsing, command dispatch, safety prompts, output, and the
 * forensic extras (device hashing, tamper-evident audit log). All storage
 * access goes through the backend and the core/hash/audit helpers.
 */
#include "cli.h"
#include "core.h"
#include "platform.h"
#include "hash.h"
#include "audit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <strings.h>   /* strcasecmp */
#endif

#define WB_PROG    "writeblock"
#define WB_VERSION "0.2.0"
#define DEFAULT_LOG "writeblock-audit.jsonl"

/* Stable, documented exit codes for scripting. */
enum {
    EX_OK          = 0,
    EX_FAIL        = 1,  /* generic runtime failure */
    EX_USAGE       = 2,  /* bad arguments */
    EX_PERM        = 3,  /* needs administrator/root */
    EX_NOTFOUND    = 4,  /* device not found */
    EX_UNSUPPORTED = 5,  /* not supported on this device/platform */
    EX_MISMATCH    = 6   /* verify: hash/chain mismatch */
};

/* Map a wb_status_code to a process exit code. */
static int exit_for(int rc)
{
    switch (rc) {
    case WB_OK:              return EX_OK;
    case WB_ERR_PERM:        return EX_PERM;
    case WB_ERR_NOT_FOUND:   return EX_NOTFOUND;
    case WB_ERR_UNSUPPORTED: return EX_UNSUPPORTED;
    case WB_ERR_INVAL:       return EX_USAGE;
    default:                 return EX_FAIL;
    }
}

static void usage(FILE *f)
{
    fprintf(f,
        "%s %s - cross-platform OS-level write blocker\n"
        "\n"
        "Usage:\n"
        "  %s list [--removable-only] [--json]\n"
        "  %s status <device-id> [--json]\n"
        "  %s protect <device-id> [--yes] [--hash] [options]\n"
        "  %s unprotect <device-id> [--yes] [--hash] [options]\n"
        "  %s hash <device-id> [--quiet] [--json]\n"
        "  %s verify <device-id> <sha256> [--quiet]\n"
        "  %s audit-verify [--log <path>]\n"
        "  %s version\n"
        "\n"
        "Options:\n"
        "  --removable-only  Only show removable/USB devices (list).\n"
        "  --json            Machine-readable JSON (list, status, hash).\n"
        "  --yes             Skip the [y/N] prompt (non-system devices).\n"
        "  --hash            Compute and record the device SHA-256 with the action.\n"
        "  --case <id>       Case identifier recorded in the audit log.\n"
        "  --examiner <name> Examiner recorded in the audit log.\n"
        "  --log <path>      Audit log file (default: %s).\n"
        "  --quiet           Suppress hashing progress.\n"
        "\n"
        "Device ids come from 'list' (e.g. \\\\.\\PhysicalDrive1, /dev/sdb,\n"
        "/dev/disk2). protect/unprotect/hash require %s.\n"
        "\n"
        "Note: OS-level write protection is not tamper-proof against a privileged\n"
        "user. See the README for details.\n",
        WB_PROG, WB_VERSION, WB_PROG, WB_PROG, WB_PROG, WB_PROG, WB_PROG,
        WB_PROG, WB_PROG, WB_PROG, DEFAULT_LOG, wb_privilege_name());
}

/* ---- argument helpers ---- */

static int has_flag(int argc, char **argv, const char *name)
{
    for (int i = 0; i < argc; i++)
        if (strcmp(argv[i], name) == 0)
            return 1;
    return 0;
}

/* Value of "--name value" or "--name=value"; NULL if absent. */
static const char *flag_value(int argc, char **argv, const char *name)
{
    size_t nlen = strlen(name);
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], name) == 0)
            return (i + 1 < argc) ? argv[i + 1] : NULL;
        if (strncmp(argv[i], name, nlen) == 0 && argv[i][nlen] == '=')
            return argv[i] + nlen + 1;
    }
    return NULL;
}

/* First argument not starting with "--" and not consumed as a flag value. */
static const char *positional(int argc, char **argv, int index)
{
    int seen = 0;
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "--", 2) == 0)
            continue;
        /* Skip a token that is the value of a preceding space-separated flag. */
        if (i > 0 && strncmp(argv[i - 1], "--", 2) == 0 &&
            strchr(argv[i - 1], '=') == NULL &&
            strcmp(argv[i - 1], "--removable-only") != 0 &&
            strcmp(argv[i - 1], "--json") != 0 &&
            strcmp(argv[i - 1], "--yes") != 0 &&
            strcmp(argv[i - 1], "--hash") != 0 &&
            strcmp(argv[i - 1], "--quiet") != 0)
            continue;
        if (seen == index)
            return argv[i];
        seen++;
    }
    return NULL;
}

/* ---- output ---- */

static void print_device_row(const wb_device_t *d)
{
    char size[32];
    wb_format_size(d->size_bytes, size, sizeof(size));
    printf("%-24s %-9s %-10s %-11s %-20.20s %s%s\n",
           d->id,
           d->removable ? "removable" : "fixed",
           wb_state_str(d->read_only),
           size,
           d->model[0] ? d->model : "-",
           d->serial[0] ? d->serial : "-",
           d->is_system ? "  [SYSTEM]" : "");
}

static void print_json_string(const char *s)
{
    putchar('"');
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\')
            printf("\\%c", c);
        else if (c < 0x20)
            printf("\\u%04x", c);
        else
            putchar(c);
    }
    putchar('"');
}

static void print_device_json(const wb_device_t *d)
{
    printf("{\"id\":");
    print_json_string(d->id);
    printf(",\"model\":");
    print_json_string(d->model);
    printf(",\"serial\":");
    print_json_string(d->serial);
    printf(",\"size_bytes\":%llu,\"removable\":%s,\"read_only\":%d,\"is_system\":%s}",
           (unsigned long long)d->size_bytes,
           d->removable ? "true" : "false",
           d->read_only,
           d->is_system ? "true" : "false");
}

/* ---- commands ---- */

static int cmd_list(int removable_only, int json)
{
    wb_device_t *list = NULL;
    size_t count = 0;
    int rc = wb_enumerate(&list, &count);
    if (rc != WB_OK) {
        fprintf(stderr, "%s: list failed: %s\n", WB_PROG, wb_strerror(rc));
        return exit_for(rc);
    }

    if (json) {
        printf("[");
        int first = 1;
        for (size_t i = 0; i < count; i++) {
            if (removable_only && !list[i].removable)
                continue;
            if (!first) printf(",");
            print_device_json(&list[i]);
            first = 0;
        }
        printf("]\n");
    } else {
        printf("%-24s %-9s %-10s %-11s %-20s %s\n",
               "DEVICE", "TYPE", "STATE", "SIZE", "MODEL", "SERIAL");
        size_t shown = 0;
        for (size_t i = 0; i < count; i++) {
            if (removable_only && !list[i].removable)
                continue;
            print_device_row(&list[i]);
            shown++;
        }
        if (shown == 0)
            printf("(no matching devices)\n");
    }
    free(list);
    return EX_OK;
}

static int cmd_status(const char *id, int json)
{
    wb_device_t dev;
    int rc = wb_find_device(id, &dev);
    if (rc != WB_OK) {
        fprintf(stderr, "%s: status failed: %s\n", WB_PROG, wb_strerror(rc));
        return exit_for(rc);
    }
    int ro = dev.read_only;
    if (wb_status(id, &ro) == WB_OK)
        dev.read_only = ro;

    if (json) {
        print_device_json(&dev);
        printf("\n");
    } else {
        char size[32];
        wb_format_size(dev.size_bytes, size, sizeof(size));
        printf("Device: %s\n", dev.id);
        printf("Model:  %s\n", dev.model[0] ? dev.model : "(unknown)");
        printf("Serial: %s\n", dev.serial[0] ? dev.serial : "(unknown)");
        printf("Size:   %s\n", size);
        printf("Type:   %s\n", dev.removable ? "removable" : "fixed");
        printf("State:  %s%s\n", wb_state_str(dev.read_only),
               dev.is_system ? "  [SYSTEM DISK]" : "");
    }
    return EX_OK;
}

static int cmd_hash(const char *id, int quiet, int json)
{
    if (!wb_have_privilege()) {
        fprintf(stderr, "%s: %s privilege required to read the raw device.\n",
                WB_PROG, wb_privilege_name());
        return EX_PERM;
    }
    char hex[WB_SHA256_HEX_LEN];
    int rc = wb_hash_device(id, hex, quiet);
    if (rc != WB_OK) {
        fprintf(stderr, "%s: hash failed: %s\n", WB_PROG, wb_strerror(rc));
        return exit_for(rc);
    }
    if (json)
        printf("{\"device\":\"%s\",\"sha256\":\"%s\"}\n", id, hex);
    else
        printf("%s  %s\n", hex, id);
    return EX_OK;
}

static int cmd_verify(const char *id, const char *expected, int quiet)
{
    if (!wb_have_privilege()) {
        fprintf(stderr, "%s: %s privilege required to read the raw device.\n",
                WB_PROG, wb_privilege_name());
        return EX_PERM;
    }
    char hex[WB_SHA256_HEX_LEN];
    int rc = wb_hash_device(id, hex, quiet);
    if (rc != WB_OK) {
        fprintf(stderr, "%s: verify failed: %s\n", WB_PROG, wb_strerror(rc));
        return exit_for(rc);
    }
#ifdef _WIN32
    int match = (_stricmp(hex, expected) == 0);
#else
    int match = (strcasecmp(hex, expected) == 0);
#endif
    if (match) {
        printf("OK: %s matches %s\n", id, hex);
        return EX_OK;
    }
    fprintf(stderr, "MISMATCH: %s is %s, expected %s\n", id, hex, expected);
    return EX_MISMATCH;
}

static int cmd_audit_verify(const char *logpath)
{
    size_t records = 0;
    int rc = wb_audit_verify(logpath, &records);
    if (rc == WB_OK) {
        printf("audit log OK: %zu record(s), chain intact (%s)\n",
               records, logpath);
        return EX_OK;
    }
    if (rc == WB_ERR_NOT_FOUND) {
        fprintf(stderr, "%s: audit log not found: %s\n", WB_PROG, logpath);
        return EX_NOTFOUND;
    }
    fprintf(stderr, "%s: audit log chain BROKEN: %s\n", WB_PROG, logpath);
    return EX_MISMATCH;
}

/* ---- confirmation ---- */

static int confirm_yn(const char *action, const wb_device_t *d, int assume_yes)
{
    if (assume_yes)
        return 1;
    char size[32];
    wb_format_size(d->size_bytes, size, sizeof(size));
    printf("About to %s:\n  %s  %s  %s  (%s)\n", action, d->id,
           d->model[0] ? d->model : "(unknown)", size,
           d->removable ? "removable" : "fixed");
    printf("Continue? [y/N] ");
    fflush(stdout);
    char line[16];
    if (!fgets(line, sizeof(line), stdin))
        return 0;
    return (line[0] == 'y' || line[0] == 'Y');
}

/* System/boot disk: require typing the exact id, with no --yes bypass. */
static int confirm_type_id(const wb_device_t *d)
{
    printf("WARNING: %s is the SYSTEM/BOOT disk.\n", d->id);
    printf("To proceed, type the device id exactly: ");
    fflush(stdout);
    char line[WB_ID_MAX + 2];
    if (!fgets(line, sizeof(line), stdin))
        return 0;
    line[strcspn(line, "\r\n")] = '\0';
    return strcmp(line, d->id) == 0;
}

/* Shared body for protect/unprotect. */
static int do_change(const char *id, int protect, int assume_yes, int want_hash,
                     const char *case_id, const char *examiner, const char *logpath,
                     int quiet)
{
    if (!wb_have_privilege()) {
        fprintf(stderr, "%s: %s privilege required to change write protection.\n",
                WB_PROG, wb_privilege_name());
        return EX_PERM;
    }

    wb_device_t dev;
    int rc = wb_find_device(id, &dev);
    if (rc != WB_OK) {
        fprintf(stderr, "%s: %s\n", WB_PROG, wb_strerror(rc));
        return exit_for(rc);
    }

    const char *action = protect ? "write-protect (block writes to)"
                                  : "unprotect (allow writes to)";
    int ok = dev.is_system ? confirm_type_id(&dev)
                           : confirm_yn(action, &dev, assume_yes);
    if (!ok) {
        fprintf(stderr, "%s: aborted.\n", WB_PROG);
        return EX_FAIL;
    }

    char hex[WB_SHA256_HEX_LEN];
    int have_hash = 0;

    /* For unprotect, hash while still protected so the proof precedes the change. */
    if (want_hash && !protect) {
        if (wb_hash_device(id, hex, quiet) == WB_OK)
            have_hash = 1;
    }

    rc = protect ? wb_protect(id) : wb_unprotect(id);
    if (rc != WB_OK) {
        fprintf(stderr, "%s: failed to %s %s: %s\n", WB_PROG,
                protect ? "protect" : "unprotect", id, wb_strerror(rc));
        return exit_for(rc);
    }

    /* For protect, hash after blocking so the device is read-only while read. */
    if (want_hash && protect) {
        if (wb_hash_device(id, hex, quiet) == WB_OK)
            have_hash = 1;
    }

    printf("%s is now %s.\n", id, protect ? "write-protected" : "writable");
    if (have_hash)
        printf("SHA-256: %s\n", hex);

    int arc = wb_audit_append(logpath, protect ? "protect" : "unprotect",
                              &dev, case_id, examiner, have_hash ? hex : NULL);
    if (arc == WB_OK)
        printf("audit: recorded in %s\n", logpath);
    else
        fprintf(stderr, "%s: warning: could not write audit log %s: %s\n",
                WB_PROG, logpath, wb_strerror(arc));
    return EX_OK;
}

int wb_cli_main(int argc, char **argv)
{
    if (argc < 2) {
        usage(stderr);
        return EX_USAGE;
    }

    const char *cmd = argv[1];
    int n = argc - 2;
    char **a = argv + 2;

    if (!strcmp(cmd, "-h") || !strcmp(cmd, "--help") || !strcmp(cmd, "help")) {
        usage(stdout);
        return EX_OK;
    }
    if (!strcmp(cmd, "version") || !strcmp(cmd, "--version")) {
        printf("%s %s\n", WB_PROG, WB_VERSION);
        return EX_OK;
    }

    if (!strcmp(cmd, "list"))
        return cmd_list(has_flag(n, a, "--removable-only"), has_flag(n, a, "--json"));

    if (!strcmp(cmd, "status")) {
        const char *id = positional(n, a, 0);
        if (!id) { fprintf(stderr, "%s: status requires a device id\n", WB_PROG); return EX_USAGE; }
        return cmd_status(id, has_flag(n, a, "--json"));
    }

    if (!strcmp(cmd, "hash")) {
        const char *id = positional(n, a, 0);
        if (!id) { fprintf(stderr, "%s: hash requires a device id\n", WB_PROG); return EX_USAGE; }
        return cmd_hash(id, has_flag(n, a, "--quiet"), has_flag(n, a, "--json"));
    }

    if (!strcmp(cmd, "verify")) {
        const char *id = positional(n, a, 0);
        const char *expected = positional(n, a, 1);
        if (!id || !expected) {
            fprintf(stderr, "%s: verify requires <device-id> <sha256>\n", WB_PROG);
            return EX_USAGE;
        }
        return cmd_verify(id, expected, has_flag(n, a, "--quiet"));
    }

    if (!strcmp(cmd, "audit-verify")) {
        const char *log = flag_value(n, a, "--log");
        return cmd_audit_verify(log ? log : DEFAULT_LOG);
    }

    if (!strcmp(cmd, "protect") || !strcmp(cmd, "unprotect")) {
        const char *id = positional(n, a, 0);
        if (!id) { fprintf(stderr, "%s: %s requires a device id\n", WB_PROG, cmd); return EX_USAGE; }
        const char *log = flag_value(n, a, "--log");
        return do_change(id, !strcmp(cmd, "protect"),
                         has_flag(n, a, "--yes"), has_flag(n, a, "--hash"),
                         flag_value(n, a, "--case"), flag_value(n, a, "--examiner"),
                         log ? log : DEFAULT_LOG, has_flag(n, a, "--quiet"));
    }

    fprintf(stderr, "%s: unknown command '%s'\n", WB_PROG, cmd);
    usage(stderr);
    return EX_USAGE;
}
