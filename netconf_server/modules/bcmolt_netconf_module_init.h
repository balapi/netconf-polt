/*
 *  <:copyright-BRCM:2016-2020:Apache:standard
 *
 *   Copyright (c) 2016-2020 Broadcom. All Rights Reserved
 *
 *   The term “Broadcom” refers to Broadcom Inc. and/or its subsidiaries
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 *  :>
 *
 *****************************************************************************/

/*
 * netconf_modules_init.h
 *
 *  Created on: 17 Jun 2016
 *      Author: igort
 */

#ifndef NETCONF_MODULES_INIT_H_
#define NETCONF_MODULES_INIT_H_

#include <bcmos_system.h>
#include <libyang/libyang.h>
#include <sysrepo.h>

// !!! temporary
#define SR_DATA_SEARCH_DIR      "sysrepo/data"
#define SR_MODELS_SEARCH_DIR    "sysrepo/yang"

/** Startup uptions */
typedef struct nc_startup_options
{
    uint8_t olt;
    bcmos_bool restore_running;         /**< Restore last "running" configuration on startup */
    bcmos_bool reset_cfg;               /**< Reset configuration on startup */
    bcmos_bool tr451_onu_management;    /**< Use TR-451 ONU management */
    bcmos_bool dummy_tr385_management;  /**< Enable dummy TR-385 management */
    bcmos_bool per_flow_mode;
} nc_startup_options;

bcmos_errno bcm_netconf_modules_init(sr_session_ctx_t *srs, struct ly_ctx *ly_ctx, const nc_startup_options *startup_options);
void bcm_netconf_modules_exit(sr_session_ctx_t *srs, struct ly_ctx *ly_ctx);
sr_session_ctx_t *bcm_netconf_session_get(void);

/** Get startup options list
 * \returns startup options
 */
const nc_startup_options *netconf_agent_startup_options_get(void);

uint8_t netconf_agent_olt_id(void);

/* TR-451 support */
bcmos_bool bcm_tr451_onu_management_is_enabled(void);

extern bcmos_bool bcmolt_per_flow_mode;

/** Get per-flow mode status */
static inline bcmos_bool bcmolt_is_per_flow_mode(void)
{
    return bcmolt_per_flow_mode;
}

/* Set per-flow mode. This function is called by bbf-xpon
 * if it discovers bcm6862x device for which per-flow mode is
 * not supported. */
static inline void bcmolt_per_flow_mode_disable(void)
{
    bcmolt_per_flow_mode = BCMOS_FALSE;
}

#endif /* NETCONF_MODULES_INIT_H_ */
