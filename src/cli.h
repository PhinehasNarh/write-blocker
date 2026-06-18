/*
 * cli.h - Entry point for command-line parsing and dispatch.
 */
#ifndef WB_CLI_H
#define WB_CLI_H

#ifdef __cplusplus
extern "C" {
#endif

/* Parse argv and run the requested command. Returns a process exit code. */
int wb_cli_main(int argc, char **argv);

#ifdef __cplusplus
}
#endif

#endif /* WB_CLI_H */
