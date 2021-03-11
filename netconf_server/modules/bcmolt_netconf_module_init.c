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
 * Init all module libraries
 */
#include <bcmolt_netconf_module_init.h>
#include <bcmolt_netconf_module_utils.h>

#ifdef NETCONF_MODULE_BBF_XPON
#include <bbf-xpon.h>
#endif
#ifdef NETCONF_MODULE_BBF_POLT_VOMCI
#include <bbf-vomci.h>
#endif
#ifdef MFC_RELAY
#include <bbf-mfc.h>
#endif

static nc_startup_options startup_options;
static sr_session_ctx_t *netconf_session;

bcmos_errno bcm_netconf_modules_init(sr_session_ctx_t *srs, struct ly_ctx *ly_ctx, const nc_startup_options *startup_opts)
{
    bcmos_errno err = BCM_ERR_OK;

    startup_options = *startup_opts;
    netconf_session = srs;

    /*
     * Initialize modules
     */

#ifdef NETCONF_MODULE_BBF_XPON
#ifdef DUMMY_BBF_XPON
    if (startup_options.dummy_tr385_management)
#endif
    err = err ? err : bbf_xpon_module_init(srs, ly_ctx);
#endif
#ifdef NETCONF_MODULE_BBF_POLT_VOMCI
    if (bcm_tr451_onu_management_is_enabled())
        err = err ? err : bbf_polt_vomci_module_init(srs, ly_ctx);
#endif
#ifdef MFC_RELAY 
    err = err ? err : bbf_polt_mfc_module_init(srs, ly_ctx);
#endif

    /*
     * Start modules
     */
#ifdef NETCONF_MODULE_BBF_XPON
#ifdef DUMMY_BBF_XPON
    if (startup_options.dummy_tr385_management)
#endif
    err = err ? err : bbf_xpon_module_start(srs, ly_ctx);
#endif
#ifdef NETCONF_MODULE_BBF_POLT_VOMCI
    if (bcm_tr451_onu_management_is_enabled())
        err = err ? err : bbf_polt_vomci_module_start(srs, ly_ctx);
#endif
#ifdef MFC_RELAY 
    err = err ? err : bbf_polt_mfc_module_start(srs, ly_ctx);
#endif

    return err;
}

void bcm_netconf_modules_exit(sr_session_ctx_t *srs, struct ly_ctx *ly_ctx)
{
#ifdef NETCONF_MODULE_BBF_XPON
#ifdef DUMMY_BBF_XPON
    if (startup_options.dummy_tr385_management)
#endif
    bbf_xpon_module_exit(srs, ly_ctx);
#endif
#ifdef NETCONF_MODULE_BBF_POLT_VOMCI
    if (bcm_tr451_onu_management_is_enabled())
        bbf_polt_vomci_module_exit(srs, ly_ctx);
#endif
#ifdef MFC_RELAY 
    bbf_polt_mfc_module_exit(srs, ly_ctx);
#endif

}

const nc_startup_options *netconf_agent_startup_options_get(void)
{
    return &startup_options;
}

uint8_t netconf_agent_olt_id(void)
{
    return startup_options.olt;
}

/* TR-451 support */
bcmos_bool bcm_tr451_onu_management_is_enabled(void)
{
#ifdef NETCONF_MODULE_BBF_POLT_VOMCI
    return startup_options.tr451_onu_management;
#else
    return BCMOS_FALSE;
#endif
}

sr_session_ctx_t *bcm_netconf_session_get(void)
{
    return netconf_session;
}
