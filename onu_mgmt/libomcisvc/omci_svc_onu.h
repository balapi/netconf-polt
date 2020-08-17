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

#ifndef _OMCI_SVC_onu_H_
#define _OMCI_SVC_onu_H_

#include <bcmos_system.h>
#include <onu_mgmt_model_types.h>

/** \ingroup api
 @{
*/

extern onu_state_changed_cb omci_onu_state_changed;
extern omci_svc_onu_cfg_db_t omci_svc_onu_cfg_db;

bcmos_errno omci_svc_onu_set(bcmonu_mgmt_onu_cfg *onu, bcmonu_mgmt_complete_cb cb, void *context);
bcmos_errno omci_svc_onu_get(bcmonu_mgmt_onu_cfg *onu);
bcmos_errno omci_svc_onu_clear(bcmonu_mgmt_onu_cfg *onu, bcmonu_mgmt_complete_cb cb, void *context);

void omci_svc_mib_upload_add_uni(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, uint16_t entity_id, bcmonu_mgmt_uni_type type);
void omci_svc_mib_upload_add_tcont(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, uint16_t entity_id);
void omci_svc_mib_upload_add_priority_queue(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, uint16_t entity_id, uint16_t port);

/** @} */

#endif

