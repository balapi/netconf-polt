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

/**
 * @file omci_svc_adapter_common.h
 * @brief This file has all the definitions and function prototypes to be used for the OCS,  BCM or ideally any other stack
 */

#ifndef _OMCI_SVC_ADAPTER_COMMON_H_
#define _OMCI_SVC_ADAPTER_COMMON_H_

#include <bcmos_system.h>
/** @note the bcmolt API hdr files are included for api functions for omci Oper and Indication calls */
#include <bcmolt_api.h>
#include "bcmolt_api_model_supporting_structs.h"

#include <onu_mgmt_model_types.h>
#include <onu_mgmt_model_api_structs.h>


#ifdef USE_OCS_OMCI_STACK
#include "omci_svc_adapter_ocs_omci.h"
#else
#include "omci_svc_adapter_bcm_omci.h"
#endif
#include "omci_svc_adapt_old_code.h"

#include <omci_stack_api.h>


typedef uint16_t  omci_svc_omci_attr_id;

/**
 *  @brief attrid List structure to be reported by Stack to service layer for Responses etc.
 */
typedef struct
{
    uint8_t count;
    omci_svc_omci_attr_id attrId[OMCI_SVC_OMCI_MAX_ATTR_COUNT_IN_ME];
} omci_svc_omci_attrid_list;

/**********************************************************
 * Common extern functions used for all adapters
 **********************************************************/

/* forward declaration */
struct omci_svc_onu;

/** Stack specific functions */
bcmos_bool omci_svc_omci_if_support_activate(void);
bcmos_bool omci_svc_omci_if_support_deactivate(void);
bcmos_bool omci_svc_omci_if_support_link_up(void);

/** Stack Init */
bcmos_errno omci_svc_omci_init(void);
bcmos_errno omci_svc_omci_deinit(void);
bcmos_errno omci_svc_omci_init_for_olt(bcmolt_oltid olt_id);

/* Stack requests for OMCI */
bcmos_errno omci_svc_omci_activate_req(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id);
bcmos_errno omci_svc_omci_deactivate_req(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id);

bcmos_errno omci_svc_omci_mib_reset_req(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id);
bcmos_errno omci_svc_omci_mib_upload_req(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id);
void omci_svc_omci_mib_upload_analyze(bcmonu_mgmt_onu_key *key, struct omci_svc_onu *onu_context, void *context);

bcmos_errno omci_svc_omci_mcast_gem_iw_tp_me_add_entry_ipv4_addr_table(bcmolt_oltid olt_id, bcmonu_mgmt_onu_key *onu_key,  bcmonu_mgmt_flow_cfg *flow, bcmonu_mgmt_svc_port_id gem_port_id);
bcmos_errno omci_svc_omci_mcast_gem_iw_tp_me_remove_entry_ipv4_addr_table(bcmolt_oltid olt_id, bcmonu_mgmt_onu_key *onu_key,  bcmonu_mgmt_flow_cfg *flow, bcmonu_mgmt_svc_port_id gem_port_id);

bcmos_errno omci_svc_omci_vlan_tag_filter_data_me_create(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... );
bcmos_errno omci_svc_omci_vlan_tag_filter_data_me_delete(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id);

bcmos_errno omci_svc_omci_mcast_operations_profile_me_add_entry_dynamic_acl(bcmonu_mgmt_onu_key *onu_key, struct omci_svc_onu *onu_context, bcmonu_mgmt_flow_cfg *flow, bcmonu_mgmt_svc_port_id gem_port_id);
bcmos_errno omci_svc_omci_mcast_operations_profile_me_remove_entry_dynamic_acl(bcmonu_mgmt_onu_key *onu_key, struct omci_svc_onu *onu_context, bcmonu_mgmt_flow_cfg *flow);

bcmos_errno omci_svc_omci_ext_vlan_tag_oper_config_data_me_add_entry(bcmonu_mgmt_onu_key *onu_key, struct omci_svc_onu *onu_context, bcmonu_mgmt_flow_cfg *flow, unsigned long filter_mask);
bcmos_errno omci_svc_omci_ext_vlan_tag_oper_config_data_me_remove_entry(bcmonu_mgmt_onu_key *onu_key, struct omci_svc_onu *onu_context, bcmonu_mgmt_flow_cfg *flow, unsigned long filter_mask);

bcmos_errno omci_svc_omci_mac_bridge_port_config_data_me_delete(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id);

bcmos_errno omci_svc_omci_gem_iw_tp_me_delete(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id);


bcmos_errno omci_svc_omci_mcast_gem_iw_tp_me_delete(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id);


bcmos_errno omci_svc_omci_ieee_8021_p_mapper_svc_prof_me_delete(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id);

bcmos_errno omci_svc_omci_gem_port_net_ctp_me_delete(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id);



/** Stack Responses for OMCI */
void omci_svc_omci_create_cnf(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id,
    uint16_t me_class_id, uint16_t entity_id, omci_svc_omci_result result,
    omci_svc_omci_attrid_list *unsupp_attr_id_list, omci_svc_omci_attrid_list *failed_attr_id_list);
void omci_svc_omci_set_cnf(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id,
    uint16_t me_class_id, uint16_t entity_id, omci_svc_omci_result result,
    omci_svc_omci_attrid_list *attr_id_list, omci_svc_omci_attrid_list *unsupp_attr_id_list, omci_svc_omci_attrid_list *failed_attr_id_list);
void omci_svc_omci_delete_cnf(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id,
    uint16_t me_class_id, uint16_t entity_id, omci_svc_omci_result result);
void omci_svc_omci_add_entry_cnf(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id,
    uint16_t me_class_id, uint16_t entity_id, omci_svc_omci_attr_id attr_id, omci_svc_omci_result result);
void omci_svc_omci_remove_entry_cnf(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id,
    uint16_t me_class_id, uint16_t entity_id, omci_svc_omci_attr_id attr_id, omci_svc_omci_result result);


void omci_svc_omci_activate_cnf(bcmolt_oltid olt_id, uint32_t pon_id, uint16_t onu_id, bcmos_errno result);
void omci_svc_omci_deactivate_cnf(bcmolt_oltid olt_id, uint32_t pon_id, uint16_t onu_id, bcmos_errno result);
void omci_svc_omci_link_state_ind(uint32_t pon_id, uint16_t onu_id, int state);
void omci_svc_omci_mib_reset_cnf(bcmolt_oltid olt_id, uint32_t pon_id, uint16_t onu_id, omci_svc_omci_result result);
void omci_svc_omci_mib_upload_cnf(bcmolt_oltid olt_id, uint32_t pon_id, uint16_t onu_id, omci_svc_omci_result result, uint32_t me_count);
void omci_svc_omci_mib_upload_next_ind(bcmolt_oltid olt_id, uint32_t pon_id, uint16_t onu_id, omci_svc_omci_result result, void *me, omci_svc_omci_attrid_list *attrid_list);

/** @todo aspen OCS stack is not migrated for now */
/** cli & logging functions for OCS stack only */
//void omci_svc_omci_cli_init(bcmcli_entry *cli_dir, bcmcli_entry *omci_dir);
//void omci_svc_omci_logging_init(void);

/** wrapper functions for sending & receiving data to/from Maple */
bcmos_errno omci_svc_omci_data_req(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint8_t msg_count, void *msg_buf[], uint16_t msg_len[]);
bcmos_bool omci_svc_omci_is_olt_calc_crc(bcmolt_u8_list_u32_max_2048 *buf);
void omci_svc_omci_update_xgpon_omci_buf_len(bcmolt_u8_list_u32_max_2048 *buf);


/** @brief called by adapter to extract omci packet parameters. It is dependent on the omci proxy mode being used. */
bcmos_errno omci_svc_adapter_data_ind_extract_params(bcmolt_devid olt, onu_mgmt_proxy_rx_pkt_type proxy_type, void *omci_packet_arg, uint32_t *logical_pon_arg, bcmolt_pon_onu_id *onu_id, void **buf, uint16_t *packet_size);


#endif //_OMCI_SVC_ADAPTER_COMMON_H_
