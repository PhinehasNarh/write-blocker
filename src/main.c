/*
 * main.c - Thin entry point. All logic lives in cli.c and the backends.
 */
#include "cli.h"

int main(int argc, char **argv)
{
    return wb_cli_main(argc, argv);
}
