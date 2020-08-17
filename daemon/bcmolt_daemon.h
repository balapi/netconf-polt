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
#ifndef _BCMOLT_DAEMON_H_
#define _BCMOLT_DAEMON_H_

/**
 * @file bcmolt_daemon.h
 * @brief Service that enables running application in daemon mode
 */
#include <bcmos_system.h>
#include <pwd.h>

#define DAEMON_PID_FILE_SUFFIX            "pid"
#define DAEMON_INIT_DONE_FILE_SUFFIX      "init_done"
#define DAEMON_CLI_INPUT_FILE_SUFFIX      "cli.input"
#define DAEMON_CLI_OUTPUT_FILE_SUFFIX     "cli.output"

/** Daemon parameters */
typedef struct bcmolt_daemon_parms
{
    const char *name;            /**< Daemon name */
    const char *descr;           /**< Optional daemon descriptive string */
    void (*terminate_cb)(void);  /**< Optional terminate callback. Called as part of SIGINT, SIGTERM handling */
    void (*restart_cb)(void);    /**< Optional restart callback. Called as part of SIGHUP handling */
    const char *path;            /**< Optional path for daemon files. If NULL, /tmp is used by default */
    bcmos_bool is_cli_support;   /**< TRUE=create pipes for CLI support */
    bcmos_bool is_global;        /**< TRUE=only 1 instance is allowed per host. FALSE=allow 1 instance per user */
} bcmolt_daemon_parms;

/**
 * @brief  Daemonize application
 * @param  *parms:          daemon parameters
 * @return error status
 */
bcmos_errno bcmolt_daemon_start(const bcmolt_daemon_parms *parms);

/**
 * @brief  Indicate that application init is completed
 * @return error status
 */
bcmos_errno bcmolt_daemon_init_completed(void);

/**
 * @brief  Terminate daemon
 */
void bcmolt_daemon_terminate(int exit_code);

/**
 * @brief Check if application is already running. If application is NOT running,
 * a special lock file is created that prevents another application instance from starting.
 * @param  *parms:          daemon parameters
 * @return BCMOS_TRUE if running
 */
bcmos_bool bcmolt_daemon_check_lock(const bcmolt_daemon_parms *parms);

/**
 * @brief  Get special file name
 * @param[IN]  *parms:
 * @param[IN]  *suffix:
 * @param[OUT] *file_name:
 * @param[IN]  name_size:
 * @retval file_name
 */
static inline char *bcmolt_daemon_file_name(const bcmolt_daemon_parms *parms, const char *suffix,
    char *file_name, uint32_t name_size)
{
    const char *path = parms->path ? parms->path : "/tmp";
    if (parms->is_global)
        snprintf(file_name, name_size, "%s/%s_%s", path, parms->name, suffix);
    else
    {
        struct passwd *pw = getpwuid(geteuid());
        snprintf(file_name, name_size, "%s/%s_%s_%s", path, pw ? pw->pw_name : "default", parms->name, suffix);
    }
    return file_name;
}

#endif
