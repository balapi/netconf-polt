/*
<:copyright-BRCM:2016-2020:Apache:standard

 Copyright (c) 2016-2020 Broadcom. All Rights Reserved

 The term “Broadcom” refers to Broadcom Inc. and/or its subsidiaries

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

:>
 */
#include <bcmolt_daemon.h>

static FILE *daemon_in_fifo;
static FILE *daemon_out_fifo;
static bcmos_bool terminated;

static int _fifo_read_handler(long arg)
{
    bcmolt_daemon_parms *parms = (bcmolt_daemon_parms *)arg;
    int c;
    char str[256];

    bcmolt_daemon_file_name(parms, DAEMON_CLI_OUTPUT_FILE_SUFFIX, str, sizeof(str));
    daemon_out_fifo = fopen(str, "r");
    if (daemon_out_fifo == NULL)
    {
        printf("daemon_attach: couldn't open CLI FIFO %s. Error %s\n", str, strerror(errno));
        terminated = BCMOS_TRUE;
        return 0;
    }
    while ((c = fgetc(daemon_out_fifo)) >= 0)
    {
        putchar(c);
        fflush(stdout);
    }
    printf("daemon_attach: Error or EOF when reading from CLI FIFO (%s). Terminated\n", strerror(errno));
    terminated = BCMOS_TRUE;
    fclose(daemon_out_fifo);

    return 0;
}

static int print_help(char *cmd)
{
    fprintf(stderr, "Usage:\n"
        "%s [-global] [-path path] name\n", cmd);
    fprintf(stderr, "\t-global\t\tOnly one daemon instance per host. The default is instance per user\n");
    fprintf(stderr, "\t-path path\t\tDaemon control files location. The default is /tmp\n");
    return -1;
}

int main(int argc, char *argv[])
{
    bcmolt_daemon_parms daemon_parms = {};
    bcmos_task_parm rd_task_parms =
    {
        .name = "fifo_read",
        .priority = TASK_PRIORITY_CLI,
        .handler = _fifo_read_handler,
        .data = (long)&daemon_parms
    };
    bcmos_task fifo_rd_task;
    int i;
    int c;
    char str[256];
    bcmos_errno rc;

    /* Process command line parameters */
    for (i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "-global"))
        {
            daemon_parms.is_global = BCMOS_TRUE;
        }
        else if (!strcmp(argv[i], "-path"))
        {
            ++i;
            if (i >= argc)
                return print_help(argv[0]);
            daemon_parms.path = argv[i];
        }
        else
        {
            if (daemon_parms.name)
                return print_help(argv[0]);
            daemon_parms.name = argv[i];
        }
    }
    if (!daemon_parms.name)
        return print_help(argv[0]);

    /* Open FIFOs */
    bcmolt_daemon_file_name(&daemon_parms, DAEMON_CLI_INPUT_FILE_SUFFIX, str, sizeof(str));
    daemon_in_fifo = fopen(str, "w");
    if (daemon_in_fifo == NULL)
    {
        printf("daemon_attach: couldn't open CLI FIFO %s. Error %s\n", str, strerror(errno));
        return BCM_ERR_IO;
    }

    /* Create task that will read from the FIFO and print to stdout */
    rc = bcmos_task_create(&fifo_rd_task, &rd_task_parms);
    BUG_ON(rc != BCM_ERR_OK);

    bcmos_printf("Attached to %s Daemon. Enter CLI command\n", daemon_parms.name);

    /* Read from stdin and write to the FIFO */
    while (!terminated && (c = getchar()) >= 0)
    {
        if (fputc(c, daemon_in_fifo) < 0)
        {
            printf("daemon_attach: Failed to write to CLI FIFO (%s). Terminated\n", strerror(errno));
            break;
        }
        fflush(daemon_in_fifo);
    }

    fclose(daemon_in_fifo);
    bcmos_task_destroy(&fifo_rd_task);

    return 0;
}
