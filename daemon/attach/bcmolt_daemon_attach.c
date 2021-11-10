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
#if defined(CONFIG_LINENOISE) && !defined(LINENOISE_DISABLE_TERMIOS)
#include <linenoise.h>
#include <termios.h>
static struct termios termios_org;
#endif

static FILE *daemon_in_fifo;
static FILE *daemon_out_fifo;
static bcmos_bool terminated;
static bcmos_bool no_lineedit;

#if defined(CONFIG_LINENOISE)
static bcmos_bool raw_mode;
#endif

static void raw_terminal_mode_disable(void)
{
    /* Don't even check the return value as it's too late. */
#if defined(CONFIG_LINENOISE) && !defined(LINENOISE_DISABLE_TERMIOS)
    if (raw_mode)
    {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &termios_org);
        raw_mode = BCMOS_FALSE;
    }
#endif
}

#if defined(CONFIG_LINENOISE)
/* Raw mode */
static bcmos_bool raw_terminal_mode_enable(void)
{
#if !defined(LINENOISE_DISABLE_TERMIOS)
    int rc = -1;
    struct termios raw;

    if (raw_mode)
        return BCMOS_TRUE;

    if (tcgetattr(STDIN_FILENO, &termios_org) == -1)
    {
        return BCMOS_FALSE;
    }
    raw = termios_org;  /* modify the original mode */
    /* input modes: no break, no CR to NL, no parity check, no strip char,
     * no start/stop output control. */
    raw.c_iflag &= ~(BRKINT | IGNBRK | ICRNL | INPCK | ISTRIP | IXON | IXOFF);

    /* output modes - disable post processing */
    /* raw.c_oflag &= ~(OPOST); */

    /* control modes - set 8 bit chars */
    raw.c_cflag |= (CS8 /* | ISIG */);

    /* local modes - echoing off, canonical off, no extended functions,
     * no signal chars (^Z,^C) */
    raw.c_lflag &= ~(ECHO | ICANON | IEXTEN);
    /* control chars - set return condition: min number of bytes and timer.
     * We want read to return every single byte, without timeout. */
    raw.c_cc[VMIN] = 1; raw.c_cc[VTIME] = 0; /* 1 byte, no timer */

    /* put terminal in raw mode after flushing */
    rc = tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);

    raw_mode = (rc != -1) ? BCMOS_TRUE : BCMOS_FALSE;
#endif
    return raw_mode;
}
#endif

/* Check termios support */
static bcmos_bool raw_terminal_mode_check(void)
{
    int rc = -1;
#if defined(CONFIG_LINENOISE) && !defined(LINENOISE_DISABLE_TERMIOS)
    struct termios raw;
    rc = tcgetattr(STDIN_FILENO, &raw);
#endif
    return (rc != -1);
}

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
    /* coverity[tainted_data] - we want to mirror the input directly, even if it's "tainted" */
    while ((c = fgetc(daemon_out_fifo)) >= 0)
    {
        /* Special handling of EnableRaw / DisableRaw special characters */
#if defined(CONFIG_LINENOISE)
        if (c == REMOTE_SET_RAW_ON_CHAR)
        {
            raw_terminal_mode_enable();
        }
        else if (c == REMOTE_SET_RAW_OFF_CHAR)
        {
            raw_terminal_mode_disable();
        }
        else
#endif
        {
            putchar(c);
            fflush(stdout);
        }
    }
    printf("daemon_attach: Error or EOF when reading from CLI FIFO (%s). Terminated\n", strerror(errno));
    terminated = BCMOS_TRUE;
    if (!no_lineedit)
        raw_terminal_mode_disable();
    fclose(daemon_out_fifo);

    return 0;
}

static int print_help(char *cmd)
{
    fprintf(stderr, "Usage:\n"
        "%s [-global] [-no-lineedit] [-path path] name\n", cmd);
    fprintf(stderr, "\t-global\t\tOnly one daemon instance per host. The default is instance per user\n");
    fprintf(stderr, "\t-no-lineedit\t\tDisable enhanced line editing\n");
    fprintf(stderr, "\t-path path\t\tDaemon control files location. The default is /tmp\n");
    return -1;
}

static void daemon_attach_signal_handler(int signal_number)
{
    switch (signal_number)
    {
    case SIGINT:
    case SIGTERM:
    case SIGKILL:
        printf("daemon_attach: Caught SIGINT/SIGTERM/SIGKILL signal. Terminating..\n");
        if (!no_lineedit)
            raw_terminal_mode_disable();
        terminated = BCMOS_TRUE;
        close(STDIN_FILENO);
        break;

    default:
        printf("daemon_attach: Caught unexpected signal %d. Signal ignored\n", signal_number);
        break;
    }
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
    struct sigaction act;
    bcmos_errno rc;

    /* Process command line parameters */
    for (i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "-global"))
        {
            daemon_parms.is_global = BCMOS_TRUE;
        }
        else if (!strcmp(argv[i], "-no-lineedit"))
        {
            no_lineedit = BCMOS_TRUE;
        }
        else if (!strcmp(argv[i], "-path"))
        {
            ++i;
            if (i >= argc)
                return print_help(argv[0]);
            daemon_parms.path = argv[i];
        }
        else if (argv[i][0] == '-')
        {
            return print_help(argv[0]);
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

    memset (&act, 0, sizeof (act));
    act.sa_handler = (__sighandler_t)daemon_attach_signal_handler;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);

    bcmos_printf("Attached to %s Daemon. Enter CLI command\n", daemon_parms.name);
    /* Try to switch the terminal into the raw mode and force linenoise to accept
       the terminal as "smart" if successful. Otherwise, linenoise will refuse to do
       line editing on a pipe file
    */
    if (!no_lineedit && raw_terminal_mode_check())
    {
        bcmos_printf("Enhanced line editing is enabled\n");
        fputs("/~ enable=yes multiline=yes force=yes\n", daemon_in_fifo);
        fflush(daemon_in_fifo);
    }

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
    if (!no_lineedit)
        raw_terminal_mode_disable();

    return 0;
}
