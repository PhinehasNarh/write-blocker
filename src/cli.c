/*
 * cli.c - Argument parsing, command dispatch, safety prompts, and output
 * formatting (plain and JSON). All storage access goes through the backend
 * (wb_enumerate/wb_protect/wb_unprotect/wb_status) and the core helpers.
 */
#include "cli.h"
#include "core.h"
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WB_PROG "writeblock"

static void usage(FILE *f)
{
    fprintf(f,
        "%s - cross-platform OS-level write blocker\n"
        "\n"
        "Usage:\n"
        "  %s list [--removable-only] [--json]\n"
        "  %s status <device-id> [--json]\n"
        "  %s protect <device-id> [--yes]\n"
        "  %s unprotect <device-id> [--yes]\n"
        "\n"
        "Commands:\n"
        "  list        Enumerate storage devices and show write-protect state.\n"
        "  status      Show the write-protect state of one device.\n"
        "  protect     Enable write blocking on a device.\n"
        "  unprotect   Disable write blocking on a device.\n"
        "\n"
        "Options:\n"
        "  --removable-only  Only show removable/USB devices (list).\n"
        "  --json            Emit machine-readable JSON (list, status).\n"
        "  --yes             Skip the interactive confirmation prompt.\n"
        "\n"
        "Device ids come from 'list' (e.g. \\\\.\\PhysicalDrive1 on Windows,\n"
        "/dev/sdb on Linux/Android, /dev/disk2 on macOS).\n"
        "\n"
        "Note: this tool uses OS-level write protection. It requires %s and is\n"
        "not tamper-proof against a privileged user. See the README for details.\n",
        WB_PROG, WB_PROG, WB_PROG, WB_PROG, WB_PROG, wb_privilege_name());
}

/* Print one device as a plain-text table row. */
static void print_device_row(const wb_device_t *d)
{
    char size[32];
    wb_format_size(d->size_bytes, size, sizeof(size));
    printf("%-24s %-10s %-10s %-12s %.*s%s\n",
           d->id,
           d->removable ? "removable" : "fixed",
           wb_state_str(d->read_only),
           size,
           WB_MODEL_MAX, d->model,
           d->is_system ? "  [SYSTEM]" : "");
}

/* Print a JSON-escaped string (only the characters we expect in ids/models). */
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
    printf(",\"size_bytes\":%llu,\"removable\":%s,\"read_only\":%d,\"is_system\":%s}",
           (unsigned long long)d->size_bytes,
           d->removable ? "true" : "false",
           d->read_only,
           d->is_system ? "true" : "false");
}

static int cmd_list(int removable_only, int json)
{
    wb_device_t *list = NULL;
    size_t count = 0;
    int rc = wb_enumerate(&list, &count);
    if (rc != WB_OK) {
        fprintf(stderr, "%s: list failed: %s\n", WB_PROG, wb_strerror(rc));
        return 1;
    }

    if (json) {
        printf("[");
        int first = 1;
        for (size_t i = 0; i < count; i++) {
            if (removable_only && !list[i].removable)
                continue;
            if (!first)
                printf(",");
            print_device_json(&list[i]);
            first = 0;
        }
        printf("]\n");
    } else {
        printf("%-24s %-10s %-10s %-12s %s\n",
               "DEVICE", "TYPE", "STATE", "SIZE", "MODEL");
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
    return 0;
}

static int cmd_status(const char *id, int json)
{
    wb_device_t dev;
    int rc = wb_find_device(id, &dev);
    if (rc != WB_OK) {
        fprintf(stderr, "%s: status failed: %s\n", WB_PROG, wb_strerror(rc));
        return 1;
    }

    /* Prefer a live query; fall back to the enumerated value. */
    int ro = dev.read_only;
    int qrc = wb_status(id, &ro);
    if (qrc == WB_OK)
        dev.read_only = ro;

    if (json) {
        print_device_json(&dev);
        printf("\n");
    } else {
        char size[32];
        wb_format_size(dev.size_bytes, size, sizeof(size));
        printf("Device: %s\n", dev.id);
        printf("Model:  %s\n", dev.model[0] ? dev.model : "(unknown)");
        printf("Size:   %s\n", size);
        printf("Type:   %s\n", dev.removable ? "removable" : "fixed");
        printf("State:  %s%s\n", wb_state_str(dev.read_only),
               dev.is_system ? "  [SYSTEM DISK]" : "");
    }
    return 0;
}

/* Returns 1 if the user confirms (or assume_yes), 0 to abort. */
static int confirm(const char *action, const wb_device_t *d, int assume_yes)
{
    if (assume_yes)
        return 1;

    char size[32];
    wb_format_size(d->size_bytes, size, sizeof(size));
    printf("About to %s:\n", action);
    printf("  %s  %s  %s  (%s)\n",
           d->id, d->model[0] ? d->model : "(unknown)", size,
           d->removable ? "removable" : "fixed");
    if (d->is_system)
        printf("  WARNING: this looks like the SYSTEM/BOOT disk.\n");
    printf("Continue? [y/N] ");
    fflush(stdout);

    char line[16];
    if (fgets(line, sizeof(line), stdin) == NULL)
        return 0;
    return (line[0] == 'y' || line[0] == 'Y');
}

/* Shared body for protect/unprotect. protect=1 enables, 0 disables. */
static int do_change(const char *id, int protect, int assume_yes)
{
    if (!wb_have_privilege()) {
        fprintf(stderr, "%s: %s privilege required to change write protection.\n",
                WB_PROG, wb_privilege_name());
        return 1;
    }

    wb_device_t dev;
    int rc = wb_find_device(id, &dev);
    if (rc != WB_OK) {
        fprintf(stderr, "%s: %s\n", WB_PROG, wb_strerror(rc));
        return 1;
    }

    /* The system disk is refused unless the user explicitly passes --yes. */
    if (dev.is_system && !assume_yes) {
        fprintf(stderr,
                "%s: refusing to modify the system/boot disk (%s) without --yes.\n",
                WB_PROG, dev.id);
        return 1;
    }

    const char *action = protect ? "write-protect (block writes to)"
                                  : "unprotect (allow writes to)";
    if (!confirm(action, &dev, assume_yes)) {
        fprintf(stderr, "%s: aborted.\n", WB_PROG);
        return 1;
    }

    rc = protect ? wb_protect(id) : wb_unprotect(id);
    if (rc != WB_OK) {
        fprintf(stderr, "%s: failed to %s %s: %s\n", WB_PROG,
                protect ? "protect" : "unprotect", id, wb_strerror(rc));
        return 1;
    }

    printf("%s is now %s.\n", id, protect ? "write-protected" : "writable");
    return 0;
}

/* Returns 1 and strips the flag if argv[i] equals name; helper for parsing. */
static int has_flag(int argc, char **argv, const char *name)
{
    for (int i = 0; i < argc; i++)
        if (strcmp(argv[i], name) == 0)
            return 1;
    return 0;
}

/* Find the first non-flag argument (not starting with "--") after the command. */
static const char *first_positional(int argc, char **argv)
{
    for (int i = 0; i < argc; i++)
        if (strncmp(argv[i], "--", 2) != 0)
            return argv[i];
    return NULL;
}

int wb_cli_main(int argc, char **argv)
{
    if (argc < 2) {
        usage(stderr);
        return 2;
    }

    const char *cmd = argv[1];
    int rest_argc = argc - 2;
    char **rest = argv + 2;

    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0 ||
        strcmp(cmd, "help") == 0) {
        usage(stdout);
        return 0;
    }

    if (strcmp(cmd, "list") == 0) {
        int removable_only = has_flag(rest_argc, rest, "--removable-only");
        int json = has_flag(rest_argc, rest, "--json");
        return cmd_list(removable_only, json);
    }

    if (strcmp(cmd, "status") == 0) {
        const char *id = first_positional(rest_argc, rest);
        if (id == NULL) {
            fprintf(stderr, "%s: status requires a device id\n", WB_PROG);
            return 2;
        }
        return cmd_status(id, has_flag(rest_argc, rest, "--json"));
    }

    if (strcmp(cmd, "protect") == 0 || strcmp(cmd, "unprotect") == 0) {
        const char *id = first_positional(rest_argc, rest);
        if (id == NULL) {
            fprintf(stderr, "%s: %s requires a device id\n", WB_PROG, cmd);
            return 2;
        }
        int assume_yes = has_flag(rest_argc, rest, "--yes");
        return do_change(id, strcmp(cmd, "protect") == 0, assume_yes);
    }

    fprintf(stderr, "%s: unknown command '%s'\n", WB_PROG, cmd);
    usage(stderr);
    return 2;
}
