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

#ifndef _OMCI_SVC_FLOW_H_
#define _OMCI_SVC_FLOW_H_

#include <bcmos_system.h>
#include <onu_mgmt_model_types.h>
#include "omci_svc_common.h"

/** \ingroup api
 @{
*/
extern omci_svc_flow_cfg_db_t omci_svc_flow_cfg_db;

bcmos_errno omci_svc_flow_set(bcmonu_mgmt_flow_cfg *flow, bcmonu_mgmt_complete_cb cb, void *context, bcmos_bool is_clear);
bcmos_errno omci_svc_flow_get(bcmonu_mgmt_flow_cfg *flow);
bcmos_errno omci_svc_flow_clear(bcmonu_mgmt_flow_cfg *flow, bcmonu_mgmt_complete_cb cb, void *context);

typedef uint32_t omci_svc_ext_vlan_tag_oper_cfg_data_filter;
BCMOLT_TYPE2STR(omci_svc_ext_vlan_tag_oper_cfg_data_filter, extern);

/** @brief omci svc layer structure used by adapter layers */
typedef bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table omci_svc_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table;

omci_svc_uni *omci_svc_uni_get(omci_svc_onu *onu_context, bcmonu_mgmt_flow_cfg *flow);
bcmos_bool omci_svc_is_flow_double_tagged(bcmonu_mgmt_flow_cfg *flow);
unsigned long omci_svc_filter_mask_get(bcmonu_mgmt_flow_cfg *flow);

void omci_svc_ext_vlan_tag_oper_cfg_data_entry_filter_set_double_tag(bcmonu_mgmt_onu_key *onu_key,
    omci_svc_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table *entry,
    bcmonu_mgmt_flow_cfg *flow,
    unsigned long filter_mask);

void omci_svc_ext_vlan_tag_oper_cfg_data_entry_filter_set_single_tag(bcmonu_mgmt_onu_key *onu_key,
    omci_svc_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table *entry,
    bcmonu_mgmt_flow_cfg *flow,
    unsigned long filter_mask);

void omci_svc_ext_vlan_tag_oper_cfg_data_entry_treatment_set_double_tag(bcmonu_mgmt_onu_key *onu_key,
    bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table *entry,
    bcmonu_mgmt_flow_cfg *flow,
    bcmos_bool is_add_entry);

void omci_svc_ext_vlan_tag_oper_cfg_data_entry_treatment_set_single_tag(bcmonu_mgmt_onu_key *onu_key,
    bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table *entry,
    bcmonu_mgmt_flow_cfg *flow,
    bcmos_bool is_add_entry);

void omci_svc_mcast_operations_profile_dynamic_acl_set(bcmonu_mgmt_onu_key *onu_key,
    bcm_omci_mcast_operations_profile_dynamic_access_control_list_table *entry,
    bcmonu_mgmt_flow_cfg *flow,
    bcmonu_mgmt_svc_port_id gem_port_id,
    bcmos_bool is_add_entry);

/** @} */

#endif

