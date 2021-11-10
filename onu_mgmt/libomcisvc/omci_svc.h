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

#ifndef _OMCI_SVC_H_
#define _OMCI_SVC_H_

/**
 * @file omci_svc.h
 * @brief Function declarations and all inclusions required for the OMCI Service Layer
 *
 * @defgroup api OMCI Service Layer
 */

#include <bcmolt_api.h>
#include <onu_mgmt_model_types.h>
#include <omci_svc_adapt_old_code.h>

/** @{ */

typedef void (*omci_svc_notify_cb)(bcmonu_mgmt_cfg *cfg);

bcmos_errno bcmomci_svc_cfg_set(bcmonu_mgmt_cfg *cfg);
bcmos_errno bcmomci_svc_cfg_get(bcmonu_mgmt_cfg *cfg);
bcmos_errno bcmomci_svc_cfg_clear(bcmonu_mgmt_cfg *cfg);

bcmos_errno omci_svc_init(onu_state_changed_cb onu_cb, int is_issu);
bcmos_errno omci_svc_deinit(void);
bcmos_errno omci_svc_olt_init(bcmolt_oltid olt_id);

bcmos_errno omci_svc_subscribe_omci_proxy_ind(bcmolt_oltid olt_id);
bcmos_errno omci_svc_unsubscribe_omci_proxy_ind(bcmolt_oltid olt_id);
void omci_svc_omci_data_ind_itu_pon(
        bcmolt_oltid olt_id,
        bcmolt_interface pon_ni, 
        bcmolt_onu_id onu_id, 
        uint32_t packet_size, 
        bcmolt_bin_str buffer);



/** @} */

#endif

