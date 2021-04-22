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
#include <bcm_tr451_polt.h>

#include <bcmcli.h>
#include <bcmolt_daemon.h>
#ifndef BCM_OPEN_SOURCE_SIM
#include <bcmolt_host_api.h>
#include <bcmtr_interface.h>
#endif
#ifndef BCM_OPEN_SOURCE
#include <bcmolt_olt_selector.h>
#include <bcmtr_transport_cli.h>
#include <bcmtr_debug_cli.h>
#include <bcmos_cli.h>
#endif
#ifdef ENABLE_LOG
#include <bcm_dev_log_cli.h>
#endif

#define BCM_POLT_LOG_SIZE               (10*1000*1000)

static bcmcli_session *current_session;
static bcmos_bool do_not_daemonize;

static int polt_argc;
static char **polt_argv;
static void polt_restart(void);

static int print_help(char *cmd)
{
    fprintf(stderr, "Usage:\n"
        "%s"
#ifndef BCM_OPEN_SOURCE_SIM
        " -device_address IP:port"
#endif
#if defined(DEV_LOG_SYSLOG)
        " -syslog"
#endif
        " -d"
        " -log info|debug"
        " -f init_script"
        "\n", cmd);
#ifndef BCM_OPEN_SOURCE_SIM
    fprintf(stderr, "\t-device_address IP:port\tOLT Device address (for UDP communication)\n");
#endif
#if defined(DEV_LOG_SYSLOG)
    fprintf(stderr, "\t-syslog\t\t\tLog to syslog. This is the default if -d is not specified\n");
#endif
    fprintf(stderr, "\t-d\t\t\tStay in foreground (debug mode)\n");
    fprintf(stderr, "\t-log\t\t\tSet log level. Default is 'info'\n");
    fprintf(stderr, "\t-f\t\t\trun CLI script\n");
    return -1;
}

#ifndef BCM_OPEN_SOURCE_SIM
/* parse ip:port */
static bcmos_errno _parse_ip_port(const char *s, uint32_t *ip, uint16_t *port)
{
    int n;
    uint32_t ip1, ip2, ip3, ip4, pp;

    n = sscanf(s, "%u.%u.%u.%u:%u", &ip1, &ip2, &ip3, &ip4, &pp);
    if (n != 5 || ip1 > 0xff || ip2 > 0xff || ip3 > 0xff || ip4 > 0xff || pp > 0xffff)
    {
        fprintf(stderr, "Can't parse %s. Must be ip_address:port\n", s);
        return BCM_ERR_PARM;
    }
    *ip = (ip1 << 24) | (ip2 << 16) | (ip3 << 8) | ip4;
    *port = pp;
    return BCM_ERR_OK;
}
#endif

/* Shut down dolt server */
static void bcm_polt_shutdown(void)
{
#ifndef BCM_OPEN_SOURCE_SIM
    bcmtr_exit();
#endif
    bcmcli_session_close(current_session);
    bcmcli_token_destroy(NULL);
}

/* quit command handler */
static int _cmd_quit(bcmcli_session *sess, const bcmcli_cmd_parm parm[], uint16_t nParms)
{
#define POLT_TERMINATED_MSG         "pOLT terminated by 'Quit' command\n"
    bcmcli_stop(sess);
    BCM_LOG(INFO, def_log_id, POLT_TERMINATED_MSG);
    bcmos_usleep(100000);
    return 0;
}

/* Run CLI script */
static bcmos_errno _run_cli_script(bcmcli_session *session, const char *fname, bcmos_bool stop_on_error)
{
    bcmos_file *script_file;
    char line_buf[4096];
    int line = 0;
    bcmos_errno err = BCM_ERR_OK;

    script_file = bcmos_file_open(fname, BCMOS_FILE_FLAG_READ);
    if (script_file == NULL)
    {
        bcmcli_print(session, "Can't open file %s for reading\n", fname);
        return BCM_ERR_NOENT;
    }

    while (bcmos_file_gets(script_file, line_buf, sizeof(line_buf)) != NULL)
    {
        ++line;

        /* Echo */
        bcmcli_print(session, "%d: %s\n", line, line_buf);
        if (line_buf[0] == '#')
            continue;

        /* Execute */
        err = bcmcli_parse(session, line_buf);
        if (err != BCM_ERR_OK && stop_on_error)
            break;
    }

    bcmos_file_close(script_file);

    return err;
}

/* Run script command handler
    BCMCLI_MAKE_PARM("name", "Script file name", BCMCLI_PARM_STRING, 0),
    BCMCLI_MAKE_PARM_ENUM_DEFVAL("stop_on_error", "Stop on error", bcmcli_enum_bool_table, 0, "no"));
*/
static int _cmd_run_script(bcmcli_session *sess, const bcmcli_cmd_parm parm[], uint16_t nParms)
{
    const char *filename = (const char *)parm[0].value.string;
    bcmos_bool stop_on_error = (bcmos_bool)parm[1].value.number;
    return _run_cli_script(sess, filename, stop_on_error);
}

static int bcm_polt_start(void)
{
#ifndef BCM_OPEN_SOURCE_SIM
    bcmolt_host_init_parms init_parms = {
        .transport.type = BCM_HOST_API_CONN_LOCAL
    };
    dev_log_init_parms *p_log_parms = &init_parms.log;
#else
    dev_log_init_parms log_parms = {};
    dev_log_init_parms *p_log_parms = &log_parms;
#endif
    bcmos_bool log_syslog = BCMOS_FALSE;
    tr451_polt_init_parms polt_init_parms = {
        .log_level = DEV_LOG_LEVEL_INFO
    };
    bcmolt_daemon_parms daemon_parms = {
        .name = "tr451_polt"
    };
    const char *init_script_name = NULL;
    bcmos_errno rc;
    int i;

    for (i = 1; i < polt_argc; i++)
    {
        if (!strcmp(polt_argv[i], "-d"))
        {
            do_not_daemonize = BCMOS_TRUE;
        }
#ifndef BCM_OPEN_SOURCE_SIM
        else if (!strcmp(polt_argv[i], "-device_address"))
        {
            uint32_t remote_ip = 0;
            uint16_t remote_port = 0;
            ++i;
            if (_parse_ip_port(polt_argv[i], &remote_ip, &remote_port) != BCM_ERR_OK)
                return -1;
            init_parms.transport.type = BCM_HOST_API_CONN_REMOTE;
            init_parms.transport.addr.ip.u32 = remote_ip;
            init_parms.transport.addr.port = remote_port;
        }
#endif
#ifdef DEV_LOG_SYSLOG
        else if (!strcmp(polt_argv[i], "-syslog"))
        {
            log_syslog = BCMOS_TRUE;
        }
#endif
        else if (!strcmp(polt_argv[i], "-log"))
        {
            ++i;
            if (i >= polt_argc)
                return print_help(polt_argv[0]);
            if (!strcmp(polt_argv[i], "debug"))
                polt_init_parms.log_level = DEV_LOG_LEVEL_DEBUG;
            else if (strcmp(polt_argv[i], "info"))
                return print_help(polt_argv[0]);
        }
        else if (!strcmp(polt_argv[i], "-f"))
        {
            ++i;
            if (i >= polt_argc)
                return print_help(polt_argv[0]);
            init_script_name = polt_argv[i];
        }
        else
        {
            return print_help(polt_argv[0]);
        }
    }

    /* Daemonize if necessary */
    if (!do_not_daemonize)
    {
        daemon_parms.is_cli_support = BCMOS_TRUE;
        daemon_parms.terminate_cb = bcm_polt_shutdown;
        daemon_parms.restart_cb = polt_restart;
        rc = bcmolt_daemon_start(&daemon_parms);
        BUG_ON(rc);
        log_syslog = BCMOS_TRUE;
    }


    if (!log_syslog)
    {
        p_log_parms->type = BCM_DEV_LOG_FILE_MEMORY;
        p_log_parms->mem_size = BCM_POLT_LOG_SIZE;
    }
    else
    {
        p_log_parms->type = BCM_DEV_LOG_FILE_SYSLOG;
    }

#ifndef BCM_OPEN_SOURCE_SIM
    /* Initialize host application */
    rc = bcmolt_host_init(&init_parms);
    BUG_ON(rc != BCM_ERR_OK);

#else

    bcmos_trace_level_set(BCMOS_TRACE_LEVEL_INFO);

#ifdef ENABLE_LOG
    /* Initialize logger */
    rc = bcm_log_init(p_log_parms);
    BCMOS_TRACE_CHECK_RETURN(rc, rc, "bcmolt_log_init()\n");
#endif

#endif /* #ifndef BCM_OPEN_SOURCE_SIM */

    /* Initialize CLI */
    bcmcli_session_parm mon_session_parm = {};
    /* Create CLI session */
    memset(&mon_session_parm, 0, sizeof(mon_session_parm));
    mon_session_parm.access_right = BCMCLI_ACCESS_ADMIN;

    rc = bcmcli_session_open(&mon_session_parm, &current_session);
    BUG_ON(rc != BCM_ERR_OK);

#ifndef BCM_OPEN_SOURCE
    /* OLT selector */
    bcmolt_olt_sel_init(NULL);

    /* Transport CLI */
    bcmtr_cli_init();

    /* CLD directory */
    bcmtr_cld_cli_init();

    /* os CLI directory */
    bcmos_cli_init(NULL);
#endif

#ifdef ENABLE_LOG
    /* logger CLI directory */
    bcm_dev_log_cli_init(NULL);
#endif

    /* Add Execute Script command */
    BCMCLI_MAKE_CMD(NULL, "run", "Run CLI script", _cmd_run_script,
        BCMCLI_MAKE_PARM("name", "Script file name", BCMCLI_PARM_STRING, 0),
        BCMCLI_MAKE_PARM_ENUM_DEFVAL("stop_on_error", "Stop on error", bcmcli_enum_bool_table, 0, "no"));

    /* Add quit command */
    BCMCLI_MAKE_CMD_NOPARM(NULL, "quit", "Quit", _cmd_quit);

    if (!do_not_daemonize)
        bcmolt_daemon_init_completed();

    /* Init tr451 polt library */
    rc = bcm_tr451_polt_init(&polt_init_parms);
    BUG_ON(rc != BCM_ERR_OK);

    /* Run init script if any */
    if (init_script_name)
    {
        rc = _run_cli_script(current_session, init_script_name, BCMOS_FALSE);
        if (rc != BCM_ERR_OK)
            return rc;
    }

    /* CLI loop. In case of daemonized management daemon it is expected that stdin, stdout are redirected */
    while (!bcmcli_is_stopped(current_session))
    {
        /* Process user input until EOF or quit command */
        bcmcli_driver(current_session);
        if (feof(stdin) && !do_not_daemonize)
        {
            bcmos_usleep(100000);
            clearerr(stdin);
        }
    }

    bcm_polt_shutdown();

    if (!do_not_daemonize)
        bcmolt_daemon_terminate(0);

    return 0;
}

static void polt_restart(void)
{
    bcm_polt_shutdown();
    bcm_polt_start();
}

int main(int argc, char *argv[])
{
    polt_argc = argc;
    polt_argv = argv;
    return bcm_polt_start();
}
