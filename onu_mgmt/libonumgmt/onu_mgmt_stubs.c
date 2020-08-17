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

#include <bcmolt_api.h>
#include <onu_mgmt_model_types.h>
#include "onu_mgmt.h"

bcmos_errno bcmonu_mgmt_cfg_set(bcmonu_mgmt_cfg *cfg)
{
    return BCM_ERR_OK;
}

bcmos_errno bcmonu_mgmt_cfg_get(bcmonu_mgmt_cfg *cfg)
{
    return BCM_ERR_OK;
}

bcmos_errno bcmonu_mgmt_cfg_clear(bcmonu_mgmt_cfg *cfg)
{
    return BCM_ERR_OK;
}

bcmos_errno bcmonu_mgmt_init(bcmos_module_id module_id)
{
    return BCM_ERR_OK;
}

bcmos_errno bcmonu_mgmt_deinit(bcmos_module_id module_id)
{
    return BCM_ERR_OK;
}

bcmos_errno bcmonu_mgmt_olt_init(bcmolt_oltid olt_id)
{
    return BCM_ERR_OK;
}

bcmos_bool bcmonu_mgmt_is_loopback(void)
{
    return BCMOS_TRUE;
}

void bcmonu_mgmt_set_loopback(bcmos_bool is_loopback)
{
}

bcm_onu_mgmt_svc bcmonu_mgmt_svc_get(void)
{
    return BCM_ONU_MGMT_SVC__COUNT;
}

bcmos_errno bcmonu_mgmt_onu_notify_register(onu_mgmt_notify_cb cb)
{
    return BCM_ERR_OK;
}

void bcmonu_mgmt_onu_notify_unregister(onu_mgmt_notify_cb cb)
{
}

bcmos_errno bcmonu_mgmt_flow_notify_register(onu_mgmt_notify_cb cb)
{
    return BCM_ERR_OK;
}

void bcmonu_mgmt_flow_notify_unregister(onu_mgmt_notify_cb cb)
{
}
