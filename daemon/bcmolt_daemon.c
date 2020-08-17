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
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <bcmolt_daemon.h>

#define DAEMON_FILE_NAME_LENGTH 64

static bcmolt_daemon_parms daemon_parms;
static int daemon_pid_file = -1;

/* Get PID file name */
static char *daemon_pid_file_name(const bcmolt_daemon_parms *parms)
{
    static char pid_file_name[DAEMON_FILE_NAME_LENGTH];
    return bcmolt_daemon_file_name(parms, DAEMON_PID_FILE_SUFFIX, pid_file_name, sizeof(pid_file_name));
}

static bcmos_bool daemon_check_running(const bcmolt_daemon_parms *parms, int *p_pid_file)
{
    char str[16];
    int pid_file;
    const char *pid_file_name = daemon_pid_file_name(parms);

    pid_file = open(pid_file_name, O_RDWR | O_CREAT, 0640);
    if (pid_file < 0)
    {
        printf("%s daemon: can't open PID file %s for writing\n", parms->name, pid_file_name);
        return BCMOS_TRUE;
    }
    if (flock(pid_file, LOCK_EX | LOCK_NB))
    {
        /* Can't lock file */
        printf("%s daemon: already running\n", parms->name);
        close(pid_file);
        return BCMOS_TRUE;
    }

    if (p_pid_file != NULL)
        *p_pid_file = pid_file;

    /* Get current PID */
    sprintf(str, "%d\n", getpid());

    /* Write PID to lockfile */
    if (write(pid_file, str, strlen(str)) < 0)
    {
        printf("%s daemon: write into pidfile %s failed. '%s'\n",
            parms->name, pid_file_name, strerror(errno));
    }

    if (daemon_parms.name == NULL)
    {
        daemon_parms = *parms;
    }

    /* pid_file is intentionally left opened. It serves as a lock file
       that prevents another application instance from starting
    */

    return BCMOS_FALSE;
}

static void _bcmolt_daemon_init_started(void)
{
    char done_file_name[DAEMON_FILE_NAME_LENGTH];
    bcmolt_daemon_file_name(&daemon_parms, DAEMON_INIT_DONE_FILE_SUFFIX, done_file_name,
        sizeof(done_file_name));
    unlink(done_file_name);
}

/* Delete all temporary daemon artifacts */
void bcmolt_daemon_terminate(int exit_code)
{
    _bcmolt_daemon_init_started();
    if (daemon_pid_file >= 0)
        close(daemon_pid_file);
    unlink(daemon_pid_file_name(&daemon_parms));
    if (daemon_parms.is_cli_support)
    {
        char in_file_name[DAEMON_FILE_NAME_LENGTH];
        char out_file_name[DAEMON_FILE_NAME_LENGTH];
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        bcmolt_daemon_file_name(&daemon_parms, DAEMON_CLI_INPUT_FILE_SUFFIX, in_file_name, sizeof(in_file_name));
        bcmolt_daemon_file_name(&daemon_parms, DAEMON_CLI_OUTPUT_FILE_SUFFIX, out_file_name, sizeof(out_file_name));
        unlink(in_file_name);
        unlink(out_file_name);
    }
    exit(exit_code);
}

/* Signal handler */
static void daemon_signal_handler(int signal_number)
{
    switch (signal_number)
    {
    case SIGINT:
    case SIGTERM:
    case SIGKILL:
        printf("%s daemon: Caught SIGINT/SIGTERM/SIGKILL signal. Terminating..\n", daemon_parms.name);
        if (daemon_parms.terminate_cb)
            daemon_parms.terminate_cb();
        bcmolt_daemon_terminate(0);
        break;

    case SIGHUP:
        if (daemon_parms.restart_cb)
        {
            printf("%s daemon: Caught SIGHUP signal. Restarting..\n", daemon_parms.name);
            daemon_parms.restart_cb();
            break;
        }
#if __GNUC__ > 6
        __attribute__((fallthrough));
#endif

    default:
        printf("%s daemon: Caught unexpected signal %d. Signal ignored\n", daemon_parms.name, signal_number);
        break;
    }
}

/* output handler: in addition to printing it flushes stdout */
static int daemon_print_redirect_cb(void *data, const char *format, va_list ap)
{
    int n = vprintf(format, ap);
    fflush(stdout);
    return n;
}

/* daemonize caller */
bcmos_errno bcmolt_daemon_start(const bcmolt_daemon_parms *parms)
{
    struct sigaction act;
    pid_t pid = 0;
    int fd;
    int flags;
    int pid_file;
    char in_file_name[DAEMON_FILE_NAME_LENGTH];
    char out_file_name[DAEMON_FILE_NAME_LENGTH];

    if (parms == NULL || parms->name == NULL)
        return BCM_ERR_PARM;

    /* Check if not running already */
    if (daemon_check_running(parms, &pid_file))
    {
        exit(EXIT_FAILURE);
    }

    printf("Starting %s daemon in the background\n", parms->descr ? parms->descr : parms->name);

    _bcmolt_daemon_init_started();

    /* Fork off the parent process */
    pid = fork();

    /* An error occurred */
    if (pid < 0)
    {
        exit(EXIT_FAILURE);
    }

    /* Success: Let the parent terminate */
    if (pid > 0)
    {
        exit(EXIT_SUCCESS);
    }

    /* On success: The child process becomes session leader */
    if (setsid() < 0)
    {
        exit(EXIT_FAILURE);
    }
    /* Ignore signal sent from child to parent process */
    signal(SIGCHLD, SIG_IGN);

    /* Set up a HUP signal handler*/
    memset (&act, 0, sizeof (act));
    act.sa_handler = (__sighandler_t)daemon_signal_handler;
    if ((parms->restart_cb != NULL && sigaction(SIGHUP, &act, NULL) < 0) ||
        (parms->terminate_cb != NULL &&
            (sigaction(SIGINT, &act, NULL) < 0 || sigaction(SIGTERM, &act, NULL) < 0)))
    {
        perror("sigaction");
        close(pid_file);
        unlink(daemon_pid_file_name(parms));
        return BCM_ERR_INTERNAL;
    }

    umask(0);

    /* Create CLI FIFO files if CLI support is enabled */
    if (parms->is_cli_support)
    {
        bcmolt_daemon_file_name(parms, DAEMON_CLI_INPUT_FILE_SUFFIX, in_file_name, sizeof(in_file_name));
        bcmolt_daemon_file_name(parms, DAEMON_CLI_OUTPUT_FILE_SUFFIX, out_file_name, sizeof(out_file_name));

        /* Create an input FIFO for CLI */
        unlink(in_file_name);
        unlink(out_file_name);
        if (((mkfifo(in_file_name, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) < 0) &&
             (errno != EEXIST)) ||
            ((mkfifo(out_file_name, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH) < 0) &&
             (errno != EEXIST)))
        {
            close(pid_file);
            unlink(daemon_pid_file_name(parms));
            printf("%s: couldn't create CLI FIFO. Error %s\n", parms->name, strerror(errno));
            return BCM_ERR_IO;
        }
    }

    /* Close all open file descriptors */
    for (fd = sysconf(_SC_OPEN_MAX); fd >= 0; fd--)
    {
        if ((fd != pid_file) && (parms->is_cli_support || fd != STDOUT_FILENO))
            close(fd);
    }

    if (parms->is_cli_support)
    {
        /* Associate stdin, stdout, stderr with a pipe */
        /* stdin */
        fd = open(in_file_name, O_RDONLY | O_NONBLOCK);
        if (fd != STDIN_FILENO)
        {
            dup2(fd, STDIN_FILENO);
            close(fd);
        }
        /* stdout. must be open as RDWR, because non-blocking open as WRONLY will fail (see fifo(7)) */
        fd = open(out_file_name, O_RDWR | O_NONBLOCK);
        if (fd != STDOUT_FILENO)
        {
            dup2(fd, STDOUT_FILENO);
            close(fd);
        }
        /* stderr */
        dup2(STDOUT_FILENO, STDERR_FILENO);

        /* Make STDIN blocking */
        flags = fcntl(STDIN_FILENO, F_GETFL, 0);
        fcntl(STDIN_FILENO, F_SETFL, flags & ~O_NONBLOCK);

        /* Force STDOUT flush following output to CLI FIFO */
        bcmos_print_redirect(BCMOS_PRINT_REDIRECT_MODE_REDIRECT, daemon_print_redirect_cb, NULL);
    }
    daemon_pid_file = pid_file;

    return BCM_ERR_OK;
}

/* Indicate that application init is completed */
bcmos_errno bcmolt_daemon_init_completed(void)
{
    char done_file_name[DAEMON_FILE_NAME_LENGTH];
    int done_file;

    bcmolt_daemon_file_name(&daemon_parms, DAEMON_INIT_DONE_FILE_SUFFIX, done_file_name,
        sizeof(done_file_name));
    done_file = open(done_file_name, O_RDWR|O_CREAT, 0640);
    if (done_file < 0)
    {
        printf("dev_mgmt_daemon: can't open DONE file %s for writing\n", done_file_name);
        return BCM_ERR_IO;
    }
    close(done_file);

    return BCM_ERR_OK;
}

/* Check if application is already running */
bcmos_bool bcmolt_daemon_check_lock(const bcmolt_daemon_parms *parms)
{
    return daemon_check_running(parms, NULL);
}
