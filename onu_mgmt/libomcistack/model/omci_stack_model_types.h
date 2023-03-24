/*
*  <:copyright-BRCM:2018-2020:Apache:standard
*  
*   Copyright (c) 2018-2020 Broadcom. All Rights Reserved
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
*/

#ifndef _OMCI_STACK_MODEL_TYPES_H_
#define _OMCI_STACK_MODEL_TYPES_H_

#include <bcmos_system.h>
#include "omci_stack_model_ids.h"
#include "omci_stack_me_hdr.h"


/** GAL Ethernet Profile ME cfg data */
#define BCM_OMCI_CFG_DATA_MAX_GEM_PAYLOAD_SIZE_LEN 2

typedef struct
{
    uint16_t max_gem_payload_size;
} bcm_omci_gal_eth_prof_cfg_data;

/** GAL Ethernet Profile ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_gal_eth_prof_cfg_data data;
} bcm_omci_gal_eth_prof_cfg;

bcmos_bool bcm_omci_gal_eth_prof_cfg_data_bounds_check(const bcm_omci_gal_eth_prof_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_gal_eth_prof_cfg_id *failed_prop);
void bcm_omci_gal_eth_prof_cfg_data_set_default(bcm_omci_gal_eth_prof_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_gal_eth_prof_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_GEM_IW_TP_IW_OPT_CIRCUIT_EMULATED_TDM = 0,
    BCM_OMCI_GEM_IW_TP_IW_OPT_MAC_BRIDGED_LAN = 1,
    BCM_OMCI_GEM_IW_TP_IW_OPT_RESERVED_2 = 2,
    BCM_OMCI_GEM_IW_TP_IW_OPT_RESERVED_3 = 3,
    BCM_OMCI_GEM_IW_TP_IW_OPT_VIDEO_RETURN_PATH = 4,
    BCM_OMCI_GEM_IW_TP_IW_OPT_IEEE_8021_P_MAPPER = 5,
    BCM_OMCI_GEM_IW_TP_IW_OPT_DS_BROADCAST = 6,
    BCM_OMCI_GEM_IW_TP_IW_OPT_MPLS_TW_TDM_SVC = 7,
    BCM_OMCI_GEM_IW_TP_IW_OPT__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_gem_iw_tp_iw_opt;

typedef enum
{
    BCM_OMCI_GEM_IW_TP_OPER_STATE_ENABLED = 0,
    BCM_OMCI_GEM_IW_TP_OPER_STATE_DISABLED = 1,
    BCM_OMCI_GEM_IW_TP_OPER_STATE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_gem_iw_tp_oper_state;

typedef enum
{
    BCM_OMCI_GEM_IW_TP_GAL_LPBK_CONFIG_NO_LOOPBACK = 0,
    BCM_OMCI_GEM_IW_TP_GAL_LPBK_CONFIG_LOOPBACK_DS = 1,
    BCM_OMCI_GEM_IW_TP_GAL_LPBK_CONFIG__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_gem_iw_tp_gal_lpbk_config;


/** GEM Interworking Termination Point ME cfg data */
#define BCM_OMCI_CFG_DATA_GEM_PORT_NET_CTP_CONN_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_IW_OPT_LEN 1
#define BCM_OMCI_CFG_DATA_SVC_PROF_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_IW_TP_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_PPTP_COUNT_LEN 1
#define BCM_OMCI_CFG_DATA_OPER_STATE_LEN 1
#define BCM_OMCI_CFG_DATA_GAL_PROF_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_GAL_LPBK_CONFIG_LEN 1

typedef struct
{
    uint16_t gem_port_net_ctp_conn_ptr;
    bcm_omci_gem_iw_tp_iw_opt iw_opt;
    uint16_t svc_prof_ptr;
    uint16_t iw_tp_ptr;
    uint8_t pptp_count;
    bcm_omci_gem_iw_tp_oper_state oper_state;
    uint16_t gal_prof_ptr;
    bcm_omci_gem_iw_tp_gal_lpbk_config gal_lpbk_config;
} bcm_omci_gem_iw_tp_cfg_data;

/** GEM Interworking Termination Point ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_gem_iw_tp_cfg_data data;
} bcm_omci_gem_iw_tp_cfg;

bcmos_bool bcm_omci_gem_iw_tp_cfg_data_bounds_check(const bcm_omci_gem_iw_tp_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_gem_iw_tp_cfg_id *failed_prop);
void bcm_omci_gem_iw_tp_cfg_data_set_default(bcm_omci_gem_iw_tp_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_gem_iw_tp_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_GEM_PORT_NET_CTP_DIRECTION_UNI_TO_ANI = 1,
    BCM_OMCI_GEM_PORT_NET_CTP_DIRECTION_ANI_TO_UNI = 2,
    BCM_OMCI_GEM_PORT_NET_CTP_DIRECTION_BIDIRECTIONAL = 3,
    BCM_OMCI_GEM_PORT_NET_CTP_DIRECTION__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_gem_port_net_ctp_direction;

typedef enum
{
    BCM_OMCI_GEM_PORT_NET_CTP_ENCRYPTION_KEY_RING_NO_ENCRYPTION = 0,
    BCM_OMCI_GEM_PORT_NET_CTP_ENCRYPTION_KEY_RING_UNICAST_ENCRYPTION_BOTH_DIR = 1,
    BCM_OMCI_GEM_PORT_NET_CTP_ENCRYPTION_KEY_RING_BROADCAST_ENCRYPTION = 2,
    BCM_OMCI_GEM_PORT_NET_CTP_ENCRYPTION_KEY_RING_UNICAST_ENCRYPTION_DS = 3,
    BCM_OMCI_GEM_PORT_NET_CTP_ENCRYPTION_KEY_RING__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_gem_port_net_ctp_encryption_key_ring;


/** GEM Port Network CTP ME cfg data */
#define BCM_OMCI_CFG_DATA_PORT_ID_LEN 2
#define BCM_OMCI_CFG_DATA_TCONT_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_DIRECTION_LEN 1
#define BCM_OMCI_CFG_DATA_TRAFFIC_MGMT_PTR_US_LEN 2
#define BCM_OMCI_CFG_DATA_TRAFFIC_DESC_PROF_PTR_US_LEN 2
#define BCM_OMCI_CFG_DATA_UNI_COUNT_LEN 1
#define BCM_OMCI_CFG_DATA_PRI_QUEUE_PTR_DS_LEN 2
#define BCM_OMCI_CFG_DATA_ENCRYPTION_STATE_LEN 1
#define BCM_OMCI_CFG_DATA_TRAFFIC_DESC_PROF_PTR_DS_LEN 2
#define BCM_OMCI_CFG_DATA_ENCRYPTION_KEY_RING_LEN 1

typedef struct
{
    uint16_t port_id;
    uint16_t tcont_ptr;
    bcm_omci_gem_port_net_ctp_direction direction;
    uint16_t traffic_mgmt_ptr_us;
    uint16_t traffic_desc_prof_ptr_us;
    uint8_t uni_count;
    uint16_t pri_queue_ptr_ds;
    uint8_t encryption_state;
    uint16_t traffic_desc_prof_ptr_ds;
    bcm_omci_gem_port_net_ctp_encryption_key_ring encryption_key_ring;
} bcm_omci_gem_port_net_ctp_cfg_data;

/** GEM Port Network CTP ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_gem_port_net_ctp_cfg_data data;
} bcm_omci_gem_port_net_ctp_cfg;

bcmos_bool bcm_omci_gem_port_net_ctp_cfg_data_bounds_check(const bcm_omci_gem_port_net_ctp_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_gem_port_net_ctp_cfg_id *failed_prop);
void bcm_omci_gem_port_net_ctp_cfg_data_set_default(bcm_omci_gem_port_net_ctp_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_gem_port_net_ctp_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_UNMARKED_FRAME_OPT_DERIVE_IMPLIED_PCP = 0,
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_UNMARKED_FRAME_OPT_SET_IMPLIED_PCP = 1,
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_UNMARKED_FRAME_OPT__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_ieee_8021_p_mapper_svc_prof_unmarked_frame_opt;

typedef enum
{
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_MAPPER_TP_TYPE_BRIDGING_MAPPING = 0,
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_MAPPER_TP_TYPE_PPTP_ETH_UNI = 1,
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_MAPPER_TP_TYPE_IP_HOST_CONFIG_DATA = 2,
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_MAPPER_TP_TYPE_ETH_FLOW_TP = 3,
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_MAPPER_TP_TYPE_PPTP_XDSL_UNI = 4,
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_MAPPER_TP_TYPE_RESERVED = 5,
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_MAPPER_TP_TYPE_PPTP_MOCA_UNI = 6,
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_MAPPER_TP_TYPE_VIRTUAL_ETH_INTERFACE_POINT = 7,
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_MAPPER_TP_TYPE_INTERWORKING_VCC_TP = 8,
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_MAPPER_TP_TYPE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_ieee_8021_p_mapper_svc_prof_mapper_tp_type;


/** IEEE 802.1p mapper service profile ME cfg data */
#define BCM_OMCI_CFG_DATA_TP_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_INTERWORK_TP_PTR_PRI_0_LEN 2
#define BCM_OMCI_CFG_DATA_INTERWORK_TP_PTR_PRI_1_LEN 2
#define BCM_OMCI_CFG_DATA_INTERWORK_TP_PTR_PRI_2_LEN 2
#define BCM_OMCI_CFG_DATA_INTERWORK_TP_PTR_PRI_3_LEN 2
#define BCM_OMCI_CFG_DATA_INTERWORK_TP_PTR_PRI_4_LEN 2
#define BCM_OMCI_CFG_DATA_INTERWORK_TP_PTR_PRI_5_LEN 2
#define BCM_OMCI_CFG_DATA_INTERWORK_TP_PTR_PRI_6_LEN 2
#define BCM_OMCI_CFG_DATA_INTERWORK_TP_PTR_PRI_7_LEN 2
#define BCM_OMCI_CFG_DATA_UNMARKED_FRAME_OPT_LEN 1
#define BCM_OMCI_CFG_DATA_DSCP_TO_PBIT_MAPPING_LEN 24
#define BCM_OMCI_CFG_DATA_DEFAULT_PBIT_ASSUMPTION_LEN 1
#define BCM_OMCI_CFG_DATA_MAPPER_TP_TYPE_LEN 1

typedef struct
{
    uint16_t tp_ptr;
    uint16_t interwork_tp_ptr_pri_0;
    uint16_t interwork_tp_ptr_pri_1;
    uint16_t interwork_tp_ptr_pri_2;
    uint16_t interwork_tp_ptr_pri_3;
    uint16_t interwork_tp_ptr_pri_4;
    uint16_t interwork_tp_ptr_pri_5;
    uint16_t interwork_tp_ptr_pri_6;
    uint16_t interwork_tp_ptr_pri_7;
    bcm_omci_ieee_8021_p_mapper_svc_prof_unmarked_frame_opt unmarked_frame_opt;
    uint8_t dscp_to_pbit_mapping[24];
    uint8_t default_pbit_assumption;
    bcm_omci_ieee_8021_p_mapper_svc_prof_mapper_tp_type mapper_tp_type;
} bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_data;

/** IEEE 802.1p mapper service profile ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_data data;
} bcm_omci_ieee_8021_p_mapper_svc_prof_cfg;

bcmos_bool bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_data_bounds_check(const bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_id *failed_prop);
void bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_data_set_default(bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_ieee_8021_p_mapper_svc_prof_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_TP_TYPE_PHY_PATH_TP_ETH_UNI = 1,
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_TP_TYPE_INTERWORKING_VCC_TP = 2,
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_TP_TYPE_IEEE_8021_P_MAPPER_SVC_PROF = 3,
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_TP_TYPE_IP_HOST_CONFIG_DATA = 4,
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_TP_TYPE_GEM_INTERWORKING_TP = 5,
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_TP_TYPE_MULTICAST_GEM_INTERWORKING_TP = 6,
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_TP_TYPE_PHY_PATH_TP_XDSL_UNI_PART_1 = 7,
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_TP_TYPE_PHY_PATH_TP_VDSL_UNI = 8,
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_TP_TYPE_ETH_FLOW_TP = 9,
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_TP_TYPE_RESERVED_TP = 10,
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_TP_TYPE_VIRTUAL_ETH_INTERFACE_POINT = 11,
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_TP_TYPE_PHY_PATH_TO_MOCA_UNI = 12,
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_TP_TYPE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_mac_bridge_port_config_data_tp_type;


/** MAC Bridge Port Configuration Data ME cfg data */
#define BCM_OMCI_CFG_DATA_BRIDGE_ID_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_PORT_NUM_LEN 1
#define BCM_OMCI_CFG_DATA_TP_TYPE_LEN 1
#define BCM_OMCI_CFG_DATA_TP_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_PORT_PRI_LEN 2
#define BCM_OMCI_CFG_DATA_PORT_PATH_COST_LEN 2
#define BCM_OMCI_CFG_DATA_PORT_SPANNING_TREE_IND_LEN 1
#define BCM_OMCI_CFG_DATA_DEPRECATED_1_LEN 1
#define BCM_OMCI_CFG_DATA_DEPRECATED_2_LEN 1
#define BCM_OMCI_CFG_DATA_PORT_MAC_ADDR_LEN 6
#define BCM_OMCI_CFG_DATA_OUTBOUND_TD_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_INBOUND_TD_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_MAC_LEARNING_DEPTH_LEN 1

typedef struct
{
    uint16_t bridge_id_ptr;
    uint8_t port_num;
    bcm_omci_mac_bridge_port_config_data_tp_type tp_type;
    uint16_t tp_ptr;
    uint16_t port_pri;
    uint16_t port_path_cost;
    uint8_t port_spanning_tree_ind;
    uint8_t deprecated_1;
    uint8_t deprecated_2;
    uint8_t port_mac_addr[6];
    uint16_t outbound_td_ptr;
    uint16_t inbound_td_ptr;
    uint8_t mac_learning_depth;
} bcm_omci_mac_bridge_port_config_data_cfg_data;

/** MAC Bridge Port Configuration Data ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_mac_bridge_port_config_data_cfg_data data;
} bcm_omci_mac_bridge_port_config_data_cfg;

bcmos_bool bcm_omci_mac_bridge_port_config_data_cfg_data_bounds_check(const bcm_omci_mac_bridge_port_config_data_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_mac_bridge_port_config_data_cfg_id *failed_prop);
void bcm_omci_mac_bridge_port_config_data_cfg_data_set_default(bcm_omci_mac_bridge_port_config_data_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_mac_bridge_port_config_data_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);


/** MAC Bridge Service Profile ME cfg data */
#define BCM_OMCI_CFG_DATA_SPANNING_TREE_IND_LEN 1
#define BCM_OMCI_CFG_DATA_LEARNING_IND_LEN 1
#define BCM_OMCI_CFG_DATA_PORT_BRIDGING_IND_LEN 1
#define BCM_OMCI_CFG_DATA_PRI_LEN 2
#define BCM_OMCI_CFG_DATA_MAX_AGE_LEN 2
#define BCM_OMCI_CFG_DATA_HELLO_TIME_LEN 2
#define BCM_OMCI_CFG_DATA_FORWARD_DELAY_LEN 2
#define BCM_OMCI_CFG_DATA_UNKNOWN_MAC_ADDR_DISCARD_LEN 1
#define BCM_OMCI_CFG_DATA_MAC_LEARNING_DEPTH_LEN 1
#define BCM_OMCI_CFG_DATA_DYNAMIC_FILTERING_AGEING_TIME_LEN 4

typedef struct
{
    uint8_t spanning_tree_ind;
    uint8_t learning_ind;
    uint8_t port_bridging_ind;
    uint16_t pri;
    uint16_t max_age;
    uint16_t hello_time;
    uint16_t forward_delay;
    uint8_t unknown_mac_addr_discard;
    uint8_t mac_learning_depth;
    uint32_t dynamic_filtering_ageing_time;
} bcm_omci_mac_bridge_svc_prof_cfg_data;

/** MAC Bridge Service Profile ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_mac_bridge_svc_prof_cfg_data data;
} bcm_omci_mac_bridge_svc_prof_cfg;

bcmos_bool bcm_omci_mac_bridge_svc_prof_cfg_data_bounds_check(const bcm_omci_mac_bridge_svc_prof_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_mac_bridge_svc_prof_cfg_id *failed_prop);
void bcm_omci_mac_bridge_svc_prof_cfg_data_set_default(bcm_omci_mac_bridge_svc_prof_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_mac_bridge_svc_prof_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_BRIDGING_A_NO_INVESTIGATION_UNTAGGED_BRIDGING_A = 0,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_DISCARDING_C_UNTAGGED_BRIDGING_A = 1,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_BRIDGING_A_NO_INVESTIGATION_UNTAGGED_DISCARDING_C = 2,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_H_VID_INVESTIGATION_UNTAGGED_BRIDGING_A = 3,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_H_VID_INVESTIGATION_UNTAGGED_DISCARDING_C = 4,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_G_VID_INVESTIGATION_UNTAGGED_BRIDGING_A = 5,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_G_VID_INVESTIGATION_UNTAGGED_DISCARDING_C = 6,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_H_PRI_INVESTIGATION_UNTAGGED_BRIDGING_A = 7,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_H_PRI_INVESTIGATION_UNTAGGED_DISCARDING_C = 8,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_G_PRI_INVESTIGATION_UNTAGGED_BRIDGING_A = 9,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_G_PRI_INVESTIGATION_UNTAGGED_DISCARDING_C = 10,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_H_TCI_INVESTIGATION_UNTAGGED_BRIDGING_A = 11,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_H_TCI_INVESTIGATION_UNTAGGED_DISCARDING_C = 12,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_G_TCI_INVESTIGATION_UNTAGGED_BRIDGING_A = 13,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_G_TCI_INVESTIGATION_UNTAGGED_DISCARDING_C = 14,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_H_VID_INVESTIGATION_UNTAGGED_BRIDGING_A_DUP = 15,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_H_VID_INVESTIGATION_UNTAGGED_DISCARDING_C_DUP = 16,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_H_PRI_INVESTIGATION_UNTAGGED_BRIDGING_A_DUP = 17,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_H_PRI_INVESTIGATION_UNTAGGED_DISCARDING_C_DUP = 18,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_H_TCI_INVESTIGATION_UNTAGGED_BRIDGING_A_DUP = 19,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_H_TCI_INVESTIGATION_UNTAGGED_DISCARDING_C_DUP = 20,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_BRIDGING_A_NO_INVESTIGATION_UNTAGGED_DISCARDING_C_DUP = 21,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_J_VID_INVESTIGATION_UNTAGGED_BRIDGING_A = 22,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_J_VID_INVESTIGATION_UNTAGGED_DISCARDING_C = 23,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_J_PRI_INVESTIGATION_UNTAGGED_BRIDGING_A = 24,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_J_PRI_INVESTIGATION_UNTAGGED_DISCARDING_C = 25,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_J_TCI_INVESTIGATION_UNTAGGED_BRIDGING_A = 26,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_J_TCI_INVESTIGATION_UNTAGGED_DISCARDING_C = 27,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_VID_INVESTIGATION_H_UNTAGGED_BRIDGING_A = 28,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_VID_INVESTIGATION_H_UNTAGGED_DISCARDING_C = 29,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_PRI_INVESTIGATION_H_UNTAGGED_BRIDGING_A = 30,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_PRI_INVESTIGATION_H_UNTAGGED_DISCARDING_C = 31,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_TCI_INVESTIGATION_H_UNTAGGED_BRIDGING_A = 32,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_TCI_INVESTIGATION_H_UNTAGGED_DISCARDING_C = 33,
    BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_vlan_tag_filter_data_forward_oper;


/** VLAN Tagging Filter Data ME cfg data */
#define BCM_OMCI_CFG_DATA_VLAN_FILTER_LIST_LEN 24
#define BCM_OMCI_CFG_DATA_FORWARD_OPER_LEN 1
#define BCM_OMCI_CFG_DATA_NUM_OF_ENTRIES_LEN 1

typedef struct
{
    uint8_t vlan_filter_list[24];
    bcm_omci_vlan_tag_filter_data_forward_oper forward_oper;
    uint8_t num_of_entries;
} bcm_omci_vlan_tag_filter_data_cfg_data;

/** VLAN Tagging Filter Data ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_vlan_tag_filter_data_cfg_data data;
} bcm_omci_vlan_tag_filter_data_cfg;

bcmos_bool bcm_omci_vlan_tag_filter_data_cfg_data_bounds_check(const bcm_omci_vlan_tag_filter_data_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_vlan_tag_filter_data_cfg_id *failed_prop);
void bcm_omci_vlan_tag_filter_data_cfg_data_set_default(bcm_omci_vlan_tag_filter_data_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_vlan_tag_filter_data_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_TCONT_POLICY_NULL = 0, /* Null */
    BCM_OMCI_TCONT_POLICY_STRICT_PRIORITY = 1, /* Strict priority */
    BCM_OMCI_TCONT_POLICY_WRR = 2, /* WRR */
    BCM_OMCI_TCONT_POLICY__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_tcont_policy;


/** T-CONT ME cfg data */
#define BCM_OMCI_CFG_DATA_ALLOC_ID_LEN 2
#define BCM_OMCI_CFG_DATA_DEPRECATED_LEN 1
#define BCM_OMCI_CFG_DATA_POLICY_LEN 1

typedef struct
{
    uint16_t alloc_id;
    uint8_t deprecated;
    bcm_omci_tcont_policy policy;
} bcm_omci_tcont_cfg_data;

/** T-CONT ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_tcont_cfg_data data;
} bcm_omci_tcont_cfg;

bcmos_bool bcm_omci_tcont_cfg_data_bounds_check(const bcm_omci_tcont_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_tcont_cfg_id *failed_prop);
void bcm_omci_tcont_cfg_data_set_default(bcm_omci_tcont_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_tcont_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_ASSOC_TYPE_MAC_BRIDGE_PORT_CFG_DATA = 0, /* MAC Bridge Port Configuration Data */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_ASSOC_TYPE_IEEE_8021P_MAPPER_SERVICE_PROFILE = 1, /* IEEE 802.1p Mapper Service Profile */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_ASSOC_TYPE_PPTP_ETH_UNI = 2, /* Physical Path Termination Point Ethernet UNI */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_ASSOC_TYPE_IP_HOST_CFG_DATA = 3, /* IP Host Config Data or IPv6 Host Config Data */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_ASSOC_TYPE_PPTP_XDSL_UNI = 4, /* Physical Path Termination Point xDSL UNI */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_ASSOC_TYPE_GEM_IWTP = 5, /* GEM Interworking Termination Point */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_ASSOC_TYPE_MCAST_GEM_IWTP = 6, /* Multicast GEM Interworking Termination Point */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_ASSOC_TYPE_PPTP_MOCA_UNI = 7, /* Physical Path Termination Point MoCA UNI */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_ASSOC_TYPE_RESERVED = 8, /* Reserved */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_ASSOC_TYPE_ETH_FLOW_TP = 9, /* Ethernet Flow Termination Point */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_ASSOC_TYPE_VEIP = 10, /* Virtual Ethernet Interface Point */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_ASSOC_TYPE_MPLS_PSEUDOWIRE_TP = 11, /* MPLS Pseudowire Termination Point */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_ASSOC_TYPE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_ext_vlan_tag_oper_config_data_assoc_type;

typedef enum
{
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_DS_MODE_US_INVERSE = 0, /* The operation performed in the downstream direction is the inverse of that performed in the upstream direction */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_DS_MODE_FORWARD_UNMODIFIED = 1, /* Regardless of the filter rules no operation is performed in the downstream direction. All downstream frames are forwarded unmodified */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_DS_MODE_MATCH_INVERSE_ON_VID_PBIT_DEFAULT_FORWARD = 2, /* Filter on VID and p-bit value. On a match perform the inverse operation on both the VID and p-bit value. If no match is found forward the frame unmodified */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_DS_MODE_MATCH_INVERSE_ON_VID_DEFAULT_FORWARD = 3, /* Filter on VID only. On a match perform the inverse VID operation only; pass the p bits through. If no match is found forward the frame unmodified */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_DS_MODE_MATCH_INVERSE_ON_PBIT_DEFAULT_FORWARD = 4, /* Filter on p-bit only. On a match perform the inverse p-bit operation only; pass the VID through. If no match is found forward the frame unmodified */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_DS_MODE_MATCH_INVERSE_ON_VID_PBIT_DEFAULT_DISCARD = 5, /* Filter on VID and p-bit value. On a match perform the inverse operation on both the VID and p-bit value. If no match is found discard the frame */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_DS_MODE_MATCH_INVERSE_ON_VID_DEFAULT_DISCARD = 6, /* Filter on VID. On a match perform the inverse operation on the VID only; pass the p bits through. If no match is found discard the frame */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_DS_MODE_MATCH_INVERSE_ON_PBIT_DEFAULT_DISCARD = 7, /* Filter on p-bit only. On a match perform the inverse p-bit operation only; pass the VID through. If no match is found discard the frame */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_DS_MODE_DISCARD_ALL = 8, /* Regardless of the filter rules discard all downstream traffic */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_DS_MODE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_ext_vlan_tag_oper_config_data_ds_mode;


/** Extended VLAN Tagging Operation Configuration Data ME cfg data */
#define BCM_OMCI_CFG_DATA_ASSOC_TYPE_LEN 1
#define BCM_OMCI_CFG_DATA_RX_FRAME_VLAN_TAG_OPER_TABLE_MAX_SIZE_LEN 2
#define BCM_OMCI_CFG_DATA_INPUT_TPID_LEN 2
#define BCM_OMCI_CFG_DATA_OUTPUT_TPID_LEN 2
#define BCM_OMCI_CFG_DATA_DS_MODE_LEN 1
#define BCM_OMCI_CFG_DATA_RX_FRAME_VLAN_TAG_OPER_TABLE_LEN 16
#define BCM_OMCI_CFG_DATA_ASSOC_ME_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_DSCP_TO_PBIT_MAPPING_LEN 24
#if (BCM_CPU_ENDIAN == BCMOS_ENDIAN_BIG)
typedef struct
{
    uint32_t filter_outer_priority:4; /* Filter outer priority */
    uint32_t filter_outer_vid:13; /* Filter outer VID */
    uint32_t filter_outer_tpid:3; /* Filter outer TPID/DEI */
    uint32_t pad:12; /* Padding */
} bcm_omci_ext_vlan_tag_oper_config_data_outer_filter_word;
#else
typedef struct
{
    uint32_t pad:12; /* Padding */
    uint32_t filter_outer_tpid:3; /* Filter outer TPID/DEI */
    uint32_t filter_outer_vid:13; /* Filter outer VID */
    uint32_t filter_outer_priority:4; /* Filter outer priority */
} bcm_omci_ext_vlan_tag_oper_config_data_outer_filter_word;
#endif
#if (BCM_CPU_ENDIAN == BCMOS_ENDIAN_BIG)
typedef struct
{
    uint32_t filter_inner_priority:4; /* Filter inner priority */
    uint32_t filter_inner_vid:13; /* Filter inner VID */
    uint32_t filter_inner_tpid:3; /* Filter inner TPID/DEI */
    uint32_t pad:8; /* Padding */
    uint32_t filter_ether_type:4; /* Filter Ethertype */
} bcm_omci_ext_vlan_tag_oper_config_data_inner_filter_word;
#else
typedef struct
{
    uint32_t filter_ether_type:4; /* Filter Ethertype */
    uint32_t pad:8; /* Padding */
    uint32_t filter_inner_tpid:3; /* Filter inner TPID/DEI */
    uint32_t filter_inner_vid:13; /* Filter inner VID */
    uint32_t filter_inner_priority:4; /* Filter inner priority */
} bcm_omci_ext_vlan_tag_oper_config_data_inner_filter_word;
#endif
#if (BCM_CPU_ENDIAN == BCMOS_ENDIAN_BIG)
typedef struct
{
    uint32_t treatment:2; /* Treatment */
    uint32_t pad:10; /* Padding */
    uint32_t treatment_outer_priority:4; /* Treatment outer priority */
    uint32_t treatment_outer_vid:13; /* Treatment outer VID */
    uint32_t treatment_outer_tpid:3; /* Treatment outer TPID/DEI */
} bcm_omci_ext_vlan_tag_oper_config_data_outer_treatment_word;
#else
typedef struct
{
    uint32_t treatment_outer_tpid:3; /* Treatment outer TPID/DEI */
    uint32_t treatment_outer_vid:13; /* Treatment outer VID */
    uint32_t treatment_outer_priority:4; /* Treatment outer priority */
    uint32_t pad:10; /* Padding */
    uint32_t treatment:2; /* Treatment */
} bcm_omci_ext_vlan_tag_oper_config_data_outer_treatment_word;
#endif
#if (BCM_CPU_ENDIAN == BCMOS_ENDIAN_BIG)
typedef struct
{
    uint32_t pad:12; /* Padding */
    uint32_t treatment_inner_priority:4; /* Treatment inner priority */
    uint32_t treatment_inner_vid:13; /* Treatment inner VID */
    uint32_t treatment_inner_tpid:3; /* Treatment inner TPID/DEI */
} bcm_omci_ext_vlan_tag_oper_config_data_inner_treatment_word;
#else
typedef struct
{
    uint32_t treatment_inner_tpid:3; /* Treatment inner TPID/DEI */
    uint32_t treatment_inner_vid:13; /* Treatment inner VID */
    uint32_t treatment_inner_priority:4; /* Treatment inner priority */
    uint32_t pad:12; /* Padding */
} bcm_omci_ext_vlan_tag_oper_config_data_inner_treatment_word;
#endif

typedef struct
{
    bcm_omci_ext_vlan_tag_oper_config_data_outer_filter_word outer_filter_word; /* Outer filter word */
    bcm_omci_ext_vlan_tag_oper_config_data_inner_filter_word inner_filter_word; /* Inner filter word */
    bcm_omci_ext_vlan_tag_oper_config_data_outer_treatment_word outer_treatment_word; /* Outer treatment word */
    bcm_omci_ext_vlan_tag_oper_config_data_inner_treatment_word inner_treatment_word; /* Inner treatment word */
} bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table;


typedef struct
{
    bcm_omci_ext_vlan_tag_oper_config_data_assoc_type assoc_type;
    uint16_t rx_frame_vlan_tag_oper_table_max_size;
    uint16_t input_tpid;
    uint16_t output_tpid;
    bcm_omci_ext_vlan_tag_oper_config_data_ds_mode ds_mode;
    bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table rx_frame_vlan_tag_oper_table;
    uint16_t assoc_me_ptr;
    uint8_t dscp_to_pbit_mapping[24];
} bcm_omci_ext_vlan_tag_oper_config_data_cfg_data;

/** Extended VLAN Tagging Operation Configuration Data ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_ext_vlan_tag_oper_config_data_cfg_data data;
} bcm_omci_ext_vlan_tag_oper_config_data_cfg;

bcmos_bool bcm_omci_ext_vlan_tag_oper_config_data_cfg_data_bounds_check(const bcm_omci_ext_vlan_tag_oper_config_data_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_ext_vlan_tag_oper_config_data_cfg_id *failed_prop);
void bcm_omci_ext_vlan_tag_oper_config_data_cfg_data_set_default(bcm_omci_ext_vlan_tag_oper_config_data_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_ext_vlan_tag_oper_config_data_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_PRIORITY_QUEUE_G_DROP_PRECEDENCE_COLOUR_MARKING_NO_MARKING = 0,
    BCM_OMCI_PRIORITY_QUEUE_G_DROP_PRECEDENCE_COLOUR_MARKING_INTERNAL_MARKING = 1,
    BCM_OMCI_PRIORITY_QUEUE_G_DROP_PRECEDENCE_COLOUR_MARKING_DEI = 2,
    BCM_OMCI_PRIORITY_QUEUE_G_DROP_PRECEDENCE_COLOUR_MARKING_PCP_8_P_0_D = 3,
    BCM_OMCI_PRIORITY_QUEUE_G_DROP_PRECEDENCE_COLOUR_MARKING_PCP_7_P_1_D = 4,
    BCM_OMCI_PRIORITY_QUEUE_G_DROP_PRECEDENCE_COLOUR_MARKING_PCP_6_P_2_D = 5,
    BCM_OMCI_PRIORITY_QUEUE_G_DROP_PRECEDENCE_COLOUR_MARKING_PCP_5_P_3_D = 6,
    BCM_OMCI_PRIORITY_QUEUE_G_DROP_PRECEDENCE_COLOUR_MARKING_DSCP_AF_CLASS = 7,
    BCM_OMCI_PRIORITY_QUEUE_G_DROP_PRECEDENCE_COLOUR_MARKING__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_priority_queue_g_drop_precedence_colour_marking;


/** priority queue-G ME cfg data */
#define BCM_OMCI_CFG_DATA_QUEUE_CONFIG_OPT_LEN 1
#define BCM_OMCI_CFG_DATA_MAX_QUEUE_SIZE_LEN 2
#define BCM_OMCI_CFG_DATA_ALLOCATED_QUEUE_SIZE_LEN 2
#define BCM_OMCI_CFG_DATA_DISCARD_COUNTER_RESET_INTERVAL_LEN 2
#define BCM_OMCI_CFG_DATA_DISCARD_THRESHOLD_LEN 2
#define BCM_OMCI_CFG_DATA_RELATED_PORT_LEN 4
#define BCM_OMCI_CFG_DATA_TRAFFIC_SCHEDULER_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_WEIGHT_LEN 1
#define BCM_OMCI_CFG_DATA_BACK_PRESSURE_OPER_LEN 2
#define BCM_OMCI_CFG_DATA_BACK_PRESSURE_TIME_LEN 4
#define BCM_OMCI_CFG_DATA_BACK_PRESSURE_OCCUR_QUEUE_THR_LEN 2
#define BCM_OMCI_CFG_DATA_BACK_PRESSURE_CLEAR_QUEUE_THR_LEN 2
#define BCM_OMCI_CFG_DATA_PACKET_DROP_QUEUE_THR_LEN 8
#define BCM_OMCI_CFG_DATA_PACKET_DROP_MAX_P_LEN 2
#define BCM_OMCI_CFG_DATA_QUEUE_DROP_W_Q_LEN 1
#define BCM_OMCI_CFG_DATA_DROP_PRECEDENCE_COLOUR_MARKING_LEN 1

typedef struct
{
    uint8_t queue_config_opt;
    uint16_t max_queue_size;
    uint16_t allocated_queue_size;
    uint16_t discard_counter_reset_interval;
    uint16_t discard_threshold;
    uint8_t related_port[4];
    uint16_t traffic_scheduler_ptr;
    uint8_t weight;
    uint16_t back_pressure_oper;
    uint32_t back_pressure_time;
    uint16_t back_pressure_occur_queue_thr;
    uint16_t back_pressure_clear_queue_thr;
    uint8_t packet_drop_queue_thr[8];
    uint16_t packet_drop_max_p;
    uint8_t queue_drop_w_q;
    bcm_omci_priority_queue_g_drop_precedence_colour_marking drop_precedence_colour_marking;
} bcm_omci_priority_queue_g_cfg_data;

/** priority queue-G ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_priority_queue_g_cfg_data data;
} bcm_omci_priority_queue_g_cfg;

bcmos_bool bcm_omci_priority_queue_g_cfg_data_bounds_check(const bcm_omci_priority_queue_g_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_priority_queue_g_cfg_id *failed_prop);
void bcm_omci_priority_queue_g_cfg_data_set_default(bcm_omci_priority_queue_g_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_priority_queue_g_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_MCAST_GEM_IW_TP_IW_OPT_NO_OP = 0,
    BCM_OMCI_MCAST_GEM_IW_TP_IW_OPT_MAC_BRIDGED_LAN = 1,
    BCM_OMCI_MCAST_GEM_IW_TP_IW_OPT_RESERVED = 3,
    BCM_OMCI_MCAST_GEM_IW_TP_IW_OPT_IEEE_8021_P_MAPPER = 5,
    BCM_OMCI_MCAST_GEM_IW_TP_IW_OPT__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_mcast_gem_iw_tp_iw_opt;

typedef enum
{
    BCM_OMCI_MCAST_GEM_IW_TP_OPER_STATE_ENABLED = 0,
    BCM_OMCI_MCAST_GEM_IW_TP_OPER_STATE_DISABLED = 1,
    BCM_OMCI_MCAST_GEM_IW_TP_OPER_STATE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_mcast_gem_iw_tp_oper_state;


/** Multicast GEM interworking termination point ME cfg data */
#define BCM_OMCI_CFG_DATA_GEM_PORT_NET_CTP_CONN_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_IW_OPT_LEN 1
#define BCM_OMCI_CFG_DATA_SVC_PROF_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_NOT_USED_1_LEN 2
#define BCM_OMCI_CFG_DATA_PPTP_COUNTER_LEN 1
#define BCM_OMCI_CFG_DATA_OPER_STATE_LEN 1
#define BCM_OMCI_CFG_DATA_GAL_PROF_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_NOT_USED_2_LEN 1
#define BCM_OMCI_CFG_DATA_IPV_4_MCAST_ADDR_TABLE_LEN 12
#define BCM_OMCI_CFG_DATA_IPV_6_MCAST_ADDR_TABLE_LEN 24

typedef struct
{
    uint16_t gem_port_id;
    uint16_t secondary_key;
    uint32_t mcast_addr_range_start;
    uint32_t mcast_addr_range_stop;
} bcm_omci_mcast_gem_iw_tp_ipv_4_mcast_addr_table;


typedef struct
{
    uint16_t gem_port_id;
    uint16_t secondary_key;
    uint32_t mcast_addr_range_start_lsb;
    uint32_t mcast_addr_range_stop_lsb;
    uint8_t mcast_addr_range_msb[12];
} bcm_omci_mcast_gem_iw_tp_ipv_6_mcast_addr_table;


typedef struct
{
    uint16_t gem_port_net_ctp_conn_ptr;
    bcm_omci_mcast_gem_iw_tp_iw_opt iw_opt;
    uint16_t svc_prof_ptr;
    uint16_t not_used_1;
    uint8_t pptp_counter;
    bcm_omci_mcast_gem_iw_tp_oper_state oper_state;
    uint16_t gal_prof_ptr;
    uint8_t not_used_2;
    bcm_omci_mcast_gem_iw_tp_ipv_4_mcast_addr_table ipv_4_mcast_addr_table;
    bcm_omci_mcast_gem_iw_tp_ipv_6_mcast_addr_table ipv_6_mcast_addr_table;
} bcm_omci_mcast_gem_iw_tp_cfg_data;

/** Multicast GEM interworking termination point ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_mcast_gem_iw_tp_cfg_data data;
} bcm_omci_mcast_gem_iw_tp_cfg;

bcmos_bool bcm_omci_mcast_gem_iw_tp_cfg_data_bounds_check(const bcm_omci_mcast_gem_iw_tp_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_mcast_gem_iw_tp_cfg_id *failed_prop);
void bcm_omci_mcast_gem_iw_tp_cfg_data_set_default(bcm_omci_mcast_gem_iw_tp_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_mcast_gem_iw_tp_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_IGMP_VERSION_DEPRECATED = 1,
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_IGMP_VERSION_IGMP_VERSION_2 = 2,
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_IGMP_VERSION_IGMP_VERSION_3 = 3,
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_IGMP_VERSION_MLD_VERSION_1 = 16,
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_IGMP_VERSION_MLD_VERSION_2 = 17,
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_IGMP_VERSION__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_mcast_operations_profile_igmp_version;

typedef enum
{
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_IGMP_FUNCTION_TRANSPARENT_IGMP_SNOOPING = 0,
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_IGMP_FUNCTION_SPR = 1,
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_IGMP_FUNCTION_IGMP_PROXY = 2,
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_IGMP_FUNCTION__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_mcast_operations_profile_igmp_function;

typedef enum
{
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_UPSTREAM_IGMP_TAG_CONTROL_PASS_IGMP_MLD_TRANSPARENT = 0,
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_UPSTREAM_IGMP_TAG_CONTROL_ADD_VLAN_TAG = 1,
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_UPSTREAM_IGMP_TAG_CONTROL_REPLACE_VLAN_TAG = 2,
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_UPSTREAM_IGMP_TAG_CONTROL_REPLACE_VLAN_ID = 3,
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_UPSTREAM_IGMP_TAG_CONTROL__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_mcast_operations_profile_upstream_igmp_tag_control;

typedef enum
{
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_DS_IGMP_AND_MULTICAST_TCI_CONTROL_TYPE_TRANSPARENT = 0, /* Pass downstream IGMP/MLD and multicast traffic transparently; neither stripping nor modifying tags that may be present */
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_DS_IGMP_AND_MULTICAST_TCI_CONTROL_TYPE_STRIP_OUTER_TAG = 1, /* Strip the outer VLAN tag (including P bits) from downstream IGMP/MLD and multicast traffic */
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_DS_IGMP_AND_MULTICAST_TCI_CONTROL_TYPE_ADD_OUTER_TAG = 2,
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_DS_IGMP_AND_MULTICAST_TCI_CONTROL_TYPE_REPLACE_OUTER_TCI = 3,
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_DS_IGMP_AND_MULTICAST_TCI_CONTROL_TYPE_REPLACE_OUTER_VID = 4,
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_DS_IGMP_AND_MULTICAST_TCI_CONTROL_TYPE_ADD_OUTER_TAG_BY_SUBSCRIBER_CONFIG_INFO = 5,
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_DS_IGMP_AND_MULTICAST_TCI_CONTROL_TYPE_REPLACE_OUTER_TCI_BY_SUBSCRIBER_CONFIG_INFO = 6,
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_DS_IGMP_AND_MULTICAST_TCI_CONTROL_TYPE_REPLACE_OUTER_VID_BY_SUBSCRIBER_CONFIG_INFO = 7,
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_DS_IGMP_AND_MULTICAST_TCI_CONTROL_TYPE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_mcast_operations_profile_ds_igmp_and_multicast_tci_control_type;

/** Multicast Operations Profile ME cfg data */
#define BCM_OMCI_CFG_DATA_IGMP_VERSION_LEN 1
#define BCM_OMCI_CFG_DATA_IGMP_FUNCTION_LEN 1
#define BCM_OMCI_CFG_DATA_IMMEDIATE_LEAVE_LEN 1
#define BCM_OMCI_CFG_DATA_UPSTREAM_IGMP_TCI_LEN 2
#define BCM_OMCI_CFG_DATA_UPSTREAM_IGMP_TAG_CONTROL_LEN 1
#define BCM_OMCI_CFG_DATA_UPSTREAM_IGMP_RATE_LEN 4
#define BCM_OMCI_CFG_DATA_DYNAMIC_ACCESS_CONTROL_LIST_TABLE_LEN 24
#define BCM_OMCI_CFG_DATA_STATIC_ACCESS_CONTROL_LIST_TABLE_LEN 24
#define BCM_OMCI_CFG_DATA_LOST_GROUPS_LIST_TABLE_LEN 10
#define BCM_OMCI_CFG_DATA_ROBUSTNESS_LEN 1
#define BCM_OMCI_CFG_DATA_QUERIER_IP_ADDRESS_LEN 4
#define BCM_OMCI_CFG_DATA_QUERY_INTERVAL_LEN 4
#define BCM_OMCI_CFG_DATA_QUERY_MAX_RESPONSE_TIME_LEN 4
#define BCM_OMCI_CFG_DATA_LAST_MEMBER_QUERY_INTERVAL_LEN 1
#define BCM_OMCI_CFG_DATA_UNAUTH_JOIN_REQUEST_BEHAVIOUR_LEN 1
#define BCM_OMCI_CFG_DATA_DS_IGMP_AND_MULTICAST_TCI_LEN 3

typedef struct
{
    uint16_t table_control;
    uint16_t gem_port_id;
    uint16_t vlan_id;
    uint32_t src_ip;
    uint32_t ip_mcast_addr_start;
    uint32_t ip_mcast_addr_end;
    uint32_t imputed_grp_bw;
    uint16_t reserved;
} bcm_omci_mcast_operations_profile_dynamic_access_control_list_table;


typedef struct
{
    uint16_t table_control;
    uint16_t gem_port_id;
    uint16_t vlan_id;
    uint32_t src_ip;
    uint32_t ip_mcast_addr_start;
    uint32_t ip_mcast_addr_end;
    uint32_t imputed_grp_bw;
    uint16_t reserved;
} bcm_omci_mcast_operations_profile_static_access_control_list_table;


typedef struct
{
    bcm_omci_mcast_operations_profile_ds_igmp_and_multicast_tci_control_type control_type;
    uint16_t tci;
} bcm_omci_mcast_operations_profile_ds_igmp_and_multicast_tci;


typedef struct
{
    bcm_omci_mcast_operations_profile_igmp_version igmp_version;
    bcm_omci_mcast_operations_profile_igmp_function igmp_function;
    uint8_t immediate_leave;
    uint16_t upstream_igmp_tci;
    bcm_omci_mcast_operations_profile_upstream_igmp_tag_control upstream_igmp_tag_control;
    uint32_t upstream_igmp_rate;
    bcm_omci_mcast_operations_profile_dynamic_access_control_list_table dynamic_access_control_list_table;
    bcm_omci_mcast_operations_profile_static_access_control_list_table static_access_control_list_table;
    uint8_t lost_groups_list_table[10];
    uint8_t robustness;
    uint32_t querier_ip_address;
    uint32_t query_interval;
    uint32_t query_max_response_time;
    uint8_t last_member_query_interval;
    uint8_t unauth_join_request_behaviour;
    bcm_omci_mcast_operations_profile_ds_igmp_and_multicast_tci ds_igmp_and_multicast_tci;
} bcm_omci_mcast_operations_profile_cfg_data;

/** Multicast Operations Profile ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_mcast_operations_profile_cfg_data data;
} bcm_omci_mcast_operations_profile_cfg;

bcmos_bool bcm_omci_mcast_operations_profile_cfg_data_bounds_check(const bcm_omci_mcast_operations_profile_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_mcast_operations_profile_cfg_id *failed_prop);
void bcm_omci_mcast_operations_profile_cfg_data_set_default(bcm_omci_mcast_operations_profile_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_mcast_operations_profile_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_ME_TYPE_MAC_BRIDGE_PORT_CONFIG_DATA = 0,
    BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_ME_TYPE_IEEE_8021P_MAPPER_SERVICE_PROFILE = 1,
    BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_ME_TYPE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_mcast_subscriber_config_info_me_type;


/** Multicast subscriber config info ME cfg data */
#define BCM_OMCI_CFG_DATA_ME_TYPE_LEN 1
#define BCM_OMCI_CFG_DATA_MCAST_OPERATIONS_PROF_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_MAX_SIMULTANEOUS_GROUPS_LEN 2
#define BCM_OMCI_CFG_DATA_MAX_MULTICAST_BW_LEN 4
#define BCM_OMCI_CFG_DATA_BW_ENFORCEMENT_LEN 1
#define BCM_OMCI_CFG_DATA_MCAST_SVC_PKG_TABLE_LEN 20
#define BCM_OMCI_CFG_DATA_ALLOWED_PREVIEW_GROUPS_TABLE_LEN 24

typedef struct
{
    bcm_omci_mcast_subscriber_config_info_me_type me_type;
    uint16_t mcast_operations_prof_ptr;
    uint16_t max_simultaneous_groups;
    uint32_t max_multicast_bw;
    uint8_t bw_enforcement;
    uint8_t mcast_svc_pkg_table[20];
    uint8_t allowed_preview_groups_table[24];
} bcm_omci_mcast_subscriber_config_info_cfg_data;

/** Multicast subscriber config info ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_mcast_subscriber_config_info_cfg_data data;
} bcm_omci_mcast_subscriber_config_info_cfg;

bcmos_bool bcm_omci_mcast_subscriber_config_info_cfg_data_bounds_check(const bcm_omci_mcast_subscriber_config_info_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_mcast_subscriber_config_info_cfg_id *failed_prop);
void bcm_omci_mcast_subscriber_config_info_cfg_data_set_default(bcm_omci_mcast_subscriber_config_info_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_mcast_subscriber_config_info_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_PPTP_ETH_UNI_AUTO_DETECTION_CONFIG_AUTO_DETECT_CONFIG_AUTO_RATE_AUTO_MODE = 0,
    BCM_OMCI_PPTP_ETH_UNI_AUTO_DETECTION_CONFIG_AUTO_DETECT_CONFIG_10_MEG_FULL_DUPLEX = 1,
    BCM_OMCI_PPTP_ETH_UNI_AUTO_DETECTION_CONFIG_AUTO_DETECT_CONFIG_100_MEG_FULL_DUPLEX = 2,
    BCM_OMCI_PPTP_ETH_UNI_AUTO_DETECTION_CONFIG_AUTO_DETECT_CONFIG_1000_MEG_FULL_DUPLEX = 3,
    BCM_OMCI_PPTP_ETH_UNI_AUTO_DETECTION_CONFIG_AUTO_DETECT_CONFIG_AUTO_RATE_FULL_DUPLEX = 4,
    BCM_OMCI_PPTP_ETH_UNI_AUTO_DETECTION_CONFIG_AUTO_DETECT_CONFIG_10_GIG_FULL_DUPLEX = 5,
    BCM_OMCI_PPTP_ETH_UNI_AUTO_DETECTION_CONFIG_AUTO_DETECT_CONFIG_10_MEG_AUTO_MODE = 16,
    BCM_OMCI_PPTP_ETH_UNI_AUTO_DETECTION_CONFIG_AUTO_DETECT_CONFIG_10_MEG_HALF_DUPLEX = 17,
    BCM_OMCI_PPTP_ETH_UNI_AUTO_DETECTION_CONFIG_AUTO_DETECT_CONFIG_100_MEG_HALF_DUPLEX = 18,
    BCM_OMCI_PPTP_ETH_UNI_AUTO_DETECTION_CONFIG_AUTO_DETECT_CONFIG_1000_MEG_HALF_DUPLEX = 19,
    BCM_OMCI_PPTP_ETH_UNI_AUTO_DETECTION_CONFIG_AUTO_DETECT_CONFIG_AUTO_RATE_HALF_DUPLEX = 20,
    BCM_OMCI_PPTP_ETH_UNI_AUTO_DETECTION_CONFIG_AUTO_DETECT_CONFIG_1000_MEG_AUTO_MODE = 32,
    BCM_OMCI_PPTP_ETH_UNI_AUTO_DETECTION_CONFIG_AUTO_DETECT_CONFIG_100_MEG_AUTO_MODE = 48,
    BCM_OMCI_PPTP_ETH_UNI_AUTO_DETECTION_CONFIG__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_pptp_eth_uni_auto_detection_config;

typedef enum
{
    BCM_OMCI_PPTP_ETH_UNI_ETHERNET_LOOPBACK_CONFIG_NO_LOOPBACK = 0,
    BCM_OMCI_PPTP_ETH_UNI_ETHERNET_LOOPBACK_CONFIG_LOOP_3 = 3,
    BCM_OMCI_PPTP_ETH_UNI_ETHERNET_LOOPBACK_CONFIG__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_pptp_eth_uni_ethernet_loopback_config;

typedef enum
{
    BCM_OMCI_PPTP_ETH_UNI_ADMIN_STATE_UNLOCK = 0,
    BCM_OMCI_PPTP_ETH_UNI_ADMIN_STATE_LOCK = 1,
    BCM_OMCI_PPTP_ETH_UNI_ADMIN_STATE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_pptp_eth_uni_admin_state;

typedef enum
{
    BCM_OMCI_PPTP_ETH_UNI_OPER_STATE_ENABLED = 0,
    BCM_OMCI_PPTP_ETH_UNI_OPER_STATE_DISABLED = 1,
    BCM_OMCI_PPTP_ETH_UNI_OPER_STATE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_pptp_eth_uni_oper_state;

typedef enum
{
    BCM_OMCI_PPTP_ETH_UNI_CONFIG_IND_CONFIG_UNKNOWN = 0,
    BCM_OMCI_PPTP_ETH_UNI_CONFIG_IND_CONFIG_10_BASE_T_FULL_DUPLEX = 1,
    BCM_OMCI_PPTP_ETH_UNI_CONFIG_IND_CONFIG_100_BASE_T_FULL_DUPLEX = 2,
    BCM_OMCI_PPTP_ETH_UNI_CONFIG_IND_CONFIG_GIG_ETHERNET_FULL_DUPLEX = 3,
    BCM_OMCI_PPTP_ETH_UNI_CONFIG_IND_CONFIG_10_GIG_ETHERNET_FULL_DUPLEX = 4,
    BCM_OMCI_PPTP_ETH_UNI_CONFIG_IND_CONFIG_10_BASE_T_HALF_DUPLEX = 17,
    BCM_OMCI_PPTP_ETH_UNI_CONFIG_IND_CONFIG_100_BASE_T_HALF_DUPLEX = 18,
    BCM_OMCI_PPTP_ETH_UNI_CONFIG_IND_CONFIG_GIG_ETHERNET_HALF_DUPLEX = 19,
    BCM_OMCI_PPTP_ETH_UNI_CONFIG_IND__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_pptp_eth_uni_config_ind;

typedef enum
{
    BCM_OMCI_PPTP_ETH_UNI_DTE_OR_DCE_IND_DCE_OR_MDI_X = 0, /* Default */
    BCM_OMCI_PPTP_ETH_UNI_DTE_OR_DCE_IND_DTE_OR_MDI = 1,
    BCM_OMCI_PPTP_ETH_UNI_DTE_OR_DCE_IND_AUTO_SELECTION = 2,
    BCM_OMCI_PPTP_ETH_UNI_DTE_OR_DCE_IND__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_pptp_eth_uni_dte_or_dce_ind;

typedef enum
{
    BCM_OMCI_PPTP_ETH_UNI_BRIDGED_OR_IP_IND_BRIDGED = 0,
    BCM_OMCI_PPTP_ETH_UNI_BRIDGED_OR_IP_IND_IP_ROUTER = 1,
    BCM_OMCI_PPTP_ETH_UNI_BRIDGED_OR_IP_IND_DEPENDENCY_ON_PARENT_CKT_PACK = 2,
    BCM_OMCI_PPTP_ETH_UNI_BRIDGED_OR_IP_IND__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_pptp_eth_uni_bridged_or_ip_ind;


/** PPTP Ethernet UNI ME cfg data */
#define BCM_OMCI_CFG_DATA_EXPECTED_TYPE_LEN 1
#define BCM_OMCI_CFG_DATA_SENSED_TYPE_LEN 1
#define BCM_OMCI_CFG_DATA_AUTO_DETECTION_CONFIG_LEN 1
#define BCM_OMCI_CFG_DATA_ETHERNET_LOOPBACK_CONFIG_LEN 1
#define BCM_OMCI_CFG_DATA_ADMIN_STATE_LEN 1
#define BCM_OMCI_CFG_DATA_OPER_STATE_LEN 1
#define BCM_OMCI_CFG_DATA_CONFIG_IND_LEN 1
#define BCM_OMCI_CFG_DATA_MAX_FRAME_SIZE_LEN 2
#define BCM_OMCI_CFG_DATA_DTE_OR_DCE_IND_LEN 1
#define BCM_OMCI_CFG_DATA_PAUSE_TIME_LEN 2
#define BCM_OMCI_CFG_DATA_BRIDGED_OR_IP_IND_LEN 1
#define BCM_OMCI_CFG_DATA_ARC_LEN 1
#define BCM_OMCI_CFG_DATA_ARC_INTERVAL_LEN 1
#define BCM_OMCI_CFG_DATA_PPPOE_FILTER_LEN 1
#define BCM_OMCI_CFG_DATA_POWER_CONTROL_LEN 1

typedef struct
{
    uint8_t expected_type;
    uint8_t sensed_type;
    bcm_omci_pptp_eth_uni_auto_detection_config auto_detection_config;
    bcm_omci_pptp_eth_uni_ethernet_loopback_config ethernet_loopback_config;
    bcm_omci_pptp_eth_uni_admin_state admin_state;
    bcm_omci_pptp_eth_uni_oper_state oper_state;
    bcm_omci_pptp_eth_uni_config_ind config_ind;
    uint16_t max_frame_size;
    bcm_omci_pptp_eth_uni_dte_or_dce_ind dte_or_dce_ind;
    uint16_t pause_time;
    bcm_omci_pptp_eth_uni_bridged_or_ip_ind bridged_or_ip_ind;
    uint8_t arc;
    uint8_t arc_interval;
    uint8_t pppoe_filter;
    uint8_t power_control;
} bcm_omci_pptp_eth_uni_cfg_data;

/** PPTP Ethernet UNI ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_pptp_eth_uni_cfg_data data;
} bcm_omci_pptp_eth_uni_cfg;

bcmos_bool bcm_omci_pptp_eth_uni_cfg_data_bounds_check(const bcm_omci_pptp_eth_uni_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_pptp_eth_uni_cfg_id *failed_prop);
void bcm_omci_pptp_eth_uni_cfg_data_set_default(bcm_omci_pptp_eth_uni_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_pptp_eth_uni_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_VIRTUAL_ETH_INTF_POINT_ADMIN_STATE_UNLOCK = 0,
    BCM_OMCI_VIRTUAL_ETH_INTF_POINT_ADMIN_STATE_LOCK = 1,
    BCM_OMCI_VIRTUAL_ETH_INTF_POINT_ADMIN_STATE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_virtual_eth_intf_point_admin_state;

typedef enum
{
    BCM_OMCI_VIRTUAL_ETH_INTF_POINT_OPER_STATE_ENABLED = 0,
    BCM_OMCI_VIRTUAL_ETH_INTF_POINT_OPER_STATE_DISABLED = 1,
    BCM_OMCI_VIRTUAL_ETH_INTF_POINT_OPER_STATE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_virtual_eth_intf_point_oper_state;


/** Virtual Ethernet Interface Point ME cfg data */
#define BCM_OMCI_CFG_DATA_ADMIN_STATE_LEN 1
#define BCM_OMCI_CFG_DATA_OPER_STATE_LEN 1
#define BCM_OMCI_CFG_DATA_INTERDOMAIN_NAME_LEN 25
#define BCM_OMCI_CFG_DATA_TCP_UDP_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_IANA_ASSIGNED_PORT_LEN 2

typedef struct
{
    bcm_omci_virtual_eth_intf_point_admin_state admin_state;
    bcm_omci_virtual_eth_intf_point_oper_state oper_state;
    uint8_t interdomain_name[25];
    uint16_t tcp_udp_ptr;
    uint16_t iana_assigned_port;
} bcm_omci_virtual_eth_intf_point_cfg_data;

/** Virtual Ethernet Interface Point ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_virtual_eth_intf_point_cfg_data data;
} bcm_omci_virtual_eth_intf_point_cfg;

bcmos_bool bcm_omci_virtual_eth_intf_point_cfg_data_bounds_check(const bcm_omci_virtual_eth_intf_point_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_virtual_eth_intf_point_cfg_id *failed_prop);
void bcm_omci_virtual_eth_intf_point_cfg_data_set_default(bcm_omci_virtual_eth_intf_point_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_virtual_eth_intf_point_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);


/** ONU data ME cfg data */
#define BCM_OMCI_CFG_DATA_MIB_DATA_SYNC_LEN 1

typedef struct
{
    uint8_t mib_data_sync;
} bcm_omci_onu_data_cfg_data;

/** ONU data ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_onu_data_cfg_data data;
} bcm_omci_onu_data_cfg;

bcmos_bool bcm_omci_onu_data_cfg_data_bounds_check(const bcm_omci_onu_data_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_onu_data_cfg_id *failed_prop);
void bcm_omci_onu_data_cfg_data_set_default(bcm_omci_onu_data_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_onu_data_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_ONU_G_TRAFFIC_MANAGEMENT_PRIORITY = 0,
    BCM_OMCI_ONU_G_TRAFFIC_MANAGEMENT_RATE = 1,
    BCM_OMCI_ONU_G_TRAFFIC_MANAGEMENT_PRIORITY_AND_RATE = 2,
    BCM_OMCI_ONU_G_TRAFFIC_MANAGEMENT__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_onu_g_traffic_management;

typedef enum
{
    BCM_OMCI_ONU_G_ADMIN_STATE_UNLOCK = 0,
    BCM_OMCI_ONU_G_ADMIN_STATE_LOCK = 1,
    BCM_OMCI_ONU_G_ADMIN_STATE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_onu_g_admin_state;

typedef enum
{
    BCM_OMCI_ONU_G_OPER_STATE_ENABLED = 0,
    BCM_OMCI_ONU_G_OPER_STATE_DISABLED = 1,
    BCM_OMCI_ONU_G_OPER_STATE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_onu_g_oper_state;

typedef enum
{
    BCM_OMCI_ONU_G_CREDENTIALS_STATUS_INITIAL_STATE = 0,
    BCM_OMCI_ONU_G_CREDENTIALS_STATUS_SUCCESSFUL_AUTHENTICATION = 1,
    BCM_OMCI_ONU_G_CREDENTIALS_STATUS_LOID_ERROR = 2,
    BCM_OMCI_ONU_G_CREDENTIALS_STATUS_PASSWORD_ERROR = 3,
    BCM_OMCI_ONU_G_CREDENTIALS_STATUS_DUPLICATE_LOID = 4,
    BCM_OMCI_ONU_G_CREDENTIALS_STATUS__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_onu_g_credentials_status;


/** ONU-G (9.1.1) ME cfg data */
#define BCM_OMCI_CFG_DATA_VENDOR_ID_LEN 4
#define BCM_OMCI_CFG_DATA_VERSION_LEN 14
#define BCM_OMCI_CFG_DATA_SERIAL_NUMBER_LEN 8
#define BCM_OMCI_CFG_DATA_TRAFFIC_MANAGEMENT_LEN 1
#define BCM_OMCI_CFG_DATA_DEPRECATED0_LEN 1
#define BCM_OMCI_CFG_DATA_BATTERY_BACKUP_LEN 1
#define BCM_OMCI_CFG_DATA_ADMIN_STATE_LEN 1
#define BCM_OMCI_CFG_DATA_OPER_STATE_LEN 1
#define BCM_OMCI_CFG_DATA_SURVIVAL_TIME_LEN 1
#define BCM_OMCI_CFG_DATA_LOGICAL_ONU_ID_LEN 24
#define BCM_OMCI_CFG_DATA_LOGICAL_PASSWORD_LEN 12
#define BCM_OMCI_CFG_DATA_CREDENTIALS_STATUS_LEN 1
#define BCM_OMCI_CFG_DATA_EXTENDED_TC_OPTIONS_LEN 2

typedef struct
{
    uint32_t vendor_id;
    uint8_t version[14];
    uint8_t serial_number[8];
    bcm_omci_onu_g_traffic_management traffic_management;
    uint8_t deprecated0;
    uint8_t battery_backup;
    bcm_omci_onu_g_admin_state admin_state;
    bcm_omci_onu_g_oper_state oper_state;
    uint8_t survival_time;
    uint8_t logical_onu_id[24];
    uint8_t logical_password[12];
    bcm_omci_onu_g_credentials_status credentials_status;
    uint16_t extended_tc_options;
} bcm_omci_onu_g_cfg_data;

/** ONU-G (9.1.1) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_onu_g_cfg_data data;
} bcm_omci_onu_g_cfg;

bcmos_bool bcm_omci_onu_g_cfg_data_bounds_check(const bcm_omci_onu_g_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_onu_g_cfg_id *failed_prop);
void bcm_omci_onu_g_cfg_data_set_default(bcm_omci_onu_g_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_onu_g_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_ONU2_G_OMCC_VERSION_BASELINE_2004 = 128,
    BCM_OMCI_ONU2_G_OMCC_VERSION_BASELINE_2004_AMD1 = 129,
    BCM_OMCI_ONU2_G_OMCC_VERSION_BASELINE_2004_AMD2 = 130,
    BCM_OMCI_ONU2_G_OMCC_VERSION_BASELINE_2004_AMD3 = 131,
    BCM_OMCI_ONU2_G_OMCC_VERSION_BASELINE_2008 = 132,
    BCM_OMCI_ONU2_G_OMCC_VERSION_BASELINE_2008_AMD1 = 133,
    BCM_OMCI_ONU2_G_OMCC_VERSION_BASELINE_2008_AMD2 = 134,
    BCM_OMCI_ONU2_G_OMCC_VERSION_BASELINE_AND_EXTENDED_2008_AMD2 = 150,
    BCM_OMCI_ONU2_G_OMCC_VERSION_BASELINE_2010 = 160,
    BCM_OMCI_ONU2_G_OMCC_VERSION_BASELINE_AMD1 = 161,
    BCM_OMCI_ONU2_G_OMCC_VERSION_BASELINE_AMD2 = 162,
    BCM_OMCI_ONU2_G_OMCC_VERSION_BASELINE_2012 = 163,
    BCM_OMCI_ONU2_G_OMCC_VERSION_BASELINE_AND_EXTENDED_2010 = 176,
    BCM_OMCI_ONU2_G_OMCC_VERSION_BASELINE_AND_EXTENDED_AMD1 = 177,
    BCM_OMCI_ONU2_G_OMCC_VERSION_BASELINE_AND_EXTENDED_AMD2 = 178,
    BCM_OMCI_ONU2_G_OMCC_VERSION_BASELINE_AND_EXTENDED_2012 = 179,
    BCM_OMCI_ONU2_G_OMCC_VERSION_BASELINE_AND_EXTENDED_2014 = 180,
    BCM_OMCI_ONU2_G_OMCC_VERSION__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_onu2_g_omcc_version;

typedef enum
{
    BCM_OMCI_ONU2_G_SECURITY_CAPABILITY_AES_128 = 1,
    BCM_OMCI_ONU2_G_SECURITY_CAPABILITY__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_onu2_g_security_capability;

typedef enum
{
    BCM_OMCI_ONU2_G_SECURITY_MODE_AES_128 = 1,
    BCM_OMCI_ONU2_G_SECURITY_MODE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_onu2_g_security_mode;

typedef enum
{
    BCM_OMCI_ONU2_G_CONNECTIVITY_MODE_NO_SELECTION = 0,
    BCM_OMCI_ONU2_G_CONNECTIVITY_MODE_N_1_BRIDGING = 1,
    BCM_OMCI_ONU2_G_CONNECTIVITY_MODE_1_M_MAPPING = 2,
    BCM_OMCI_ONU2_G_CONNECTIVITY_MODE_1_P_FILTERING = 3,
    BCM_OMCI_ONU2_G_CONNECTIVITY_MODE_N_M_BRIDGE_MAPPING = 4,
    BCM_OMCI_ONU2_G_CONNECTIVITY_MODE_1_MP_MAP_FILERING = 5,
    BCM_OMCI_ONU2_G_CONNECTIVITY_MODE_N_P_BRIDGE_FILTERING = 6,
    BCM_OMCI_ONU2_G_CONNECTIVITY_MODE_N_P_BRIDGE_MAP_FILTERING = 7,
    BCM_OMCI_ONU2_G_CONNECTIVITY_MODE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_onu2_g_connectivity_mode;


/** ONU2-G (9.1.2) ME cfg data */
#define BCM_OMCI_CFG_DATA_EQUIPMENT_ID_LEN 20
#define BCM_OMCI_CFG_DATA_OMCC_VERSION_LEN 1
#define BCM_OMCI_CFG_DATA_VENDOR_PRODUCT_CODE_LEN 2
#define BCM_OMCI_CFG_DATA_SECURITY_CAPABILITY_LEN 1
#define BCM_OMCI_CFG_DATA_SECURITY_MODE_LEN 1
#define BCM_OMCI_CFG_DATA_TOTAL_PRIORITY_QUEUE_NUMBER_LEN 2
#define BCM_OMCI_CFG_DATA_TOTAL_TRAF_SCHED_NUMBER_LEN 1
#define BCM_OMCI_CFG_DATA_DEPRECATED0_LEN 1
#define BCM_OMCI_CFG_DATA_TOTAL_GEM_PORT_NUMBER_LEN 2
#define BCM_OMCI_CFG_DATA_SYS_UP_TIME_LEN 4
#define BCM_OMCI_CFG_DATA_CONNECTIVITY_CAPABILITY_LEN 2
#define BCM_OMCI_CFG_DATA_CONNECTIVITY_MODE_LEN 1
#define BCM_OMCI_CFG_DATA_QOS_CONFIG_FLEXIBILITY_LEN 2
#define BCM_OMCI_CFG_DATA_PRIORITY_QUEUE_SCALE_FACTOR_LEN 2

typedef struct
{
    uint8_t equipment_id[20];
    bcm_omci_onu2_g_omcc_version omcc_version;
    uint16_t vendor_product_code;
    bcm_omci_onu2_g_security_capability security_capability;
    bcm_omci_onu2_g_security_mode security_mode;
    uint16_t total_priority_queue_number;
    uint8_t total_traf_sched_number;
    uint8_t deprecated0;
    uint16_t total_gem_port_number;
    uint32_t sys_up_time;
    uint16_t connectivity_capability;
    bcm_omci_onu2_g_connectivity_mode connectivity_mode;
    uint16_t qos_config_flexibility;
    uint16_t priority_queue_scale_factor;
} bcm_omci_onu2_g_cfg_data;

/** ONU2-G (9.1.2) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_onu2_g_cfg_data data;
} bcm_omci_onu2_g_cfg;

bcmos_bool bcm_omci_onu2_g_cfg_data_bounds_check(const bcm_omci_onu2_g_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_onu2_g_cfg_id *failed_prop);
void bcm_omci_onu2_g_cfg_data_set_default(bcm_omci_onu2_g_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_onu2_g_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_SW_IMAGE_IS_COMMITTED_UNCOMMITTED = 0,
    BCM_OMCI_SW_IMAGE_IS_COMMITTED_COMMITTED = 1,
    BCM_OMCI_SW_IMAGE_IS_COMMITTED__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_sw_image_is_committed;

typedef enum
{
    BCM_OMCI_SW_IMAGE_IS_ACTIVE_INACTIVE = 0,
    BCM_OMCI_SW_IMAGE_IS_ACTIVE_ACTIVE = 1,
    BCM_OMCI_SW_IMAGE_IS_ACTIVE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_sw_image_is_active;

typedef enum
{
    BCM_OMCI_SW_IMAGE_IS_VALID_INVALID = 0,
    BCM_OMCI_SW_IMAGE_IS_VALID_VALID = 1,
    BCM_OMCI_SW_IMAGE_IS_VALID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_sw_image_is_valid;


/** Software image (9.1.4) ME cfg data */
#define BCM_OMCI_CFG_DATA_VERSION_LEN 14
#define BCM_OMCI_CFG_DATA_IS_COMMITTED_LEN 1
#define BCM_OMCI_CFG_DATA_IS_ACTIVE_LEN 1
#define BCM_OMCI_CFG_DATA_IS_VALID_LEN 1
#define BCM_OMCI_CFG_DATA_PRODUCT_CODE_LEN 25
#define BCM_OMCI_CFG_DATA_IMAGE_HASH_LEN 16

typedef struct
{
    uint8_t version[14];
    bcm_omci_sw_image_is_committed is_committed;
    bcm_omci_sw_image_is_active is_active;
    bcm_omci_sw_image_is_valid is_valid;
    uint8_t product_code[25];
    uint8_t image_hash[16];
} bcm_omci_sw_image_cfg_data;

/** Software image (9.1.4) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_sw_image_cfg_data data;
} bcm_omci_sw_image_cfg;

bcmos_bool bcm_omci_sw_image_cfg_data_bounds_check(const bcm_omci_sw_image_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_sw_image_cfg_id *failed_prop);
void bcm_omci_sw_image_cfg_data_set_default(bcm_omci_sw_image_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_sw_image_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);


/** ANI-G (9.2.1) ME cfg data */
#define BCM_OMCI_CFG_DATA_SR_INDICATION_LEN 1
#define BCM_OMCI_CFG_DATA_TOTAL_TCONT_NUMBER_LEN 2
#define BCM_OMCI_CFG_DATA_GEM_BLOCK_LENGTH_LEN 2
#define BCM_OMCI_CFG_DATA_PIGGY_BACK_DBA_REPORTING_LEN 1
#define BCM_OMCI_CFG_DATA_DEPRECATED_LEN 1
#define BCM_OMCI_CFG_DATA_SF_THRESHOLD_LEN 1
#define BCM_OMCI_CFG_DATA_SD_THRESHOLD_LEN 1
#define BCM_OMCI_CFG_DATA_ARC_LEN 1
#define BCM_OMCI_CFG_DATA_ARC_INTERVAL_LEN 1
#define BCM_OMCI_CFG_DATA_OPTICAL_SIGNAL_LEVEL_LEN 2
#define BCM_OMCI_CFG_DATA_LOWER_OPTICAL_THRESHOLD_LEN 1
#define BCM_OMCI_CFG_DATA_UPPER_OPTICAL_THRESHOLD_LEN 1
#define BCM_OMCI_CFG_DATA_ONU_RESPONSE_TIME_LEN 2
#define BCM_OMCI_CFG_DATA_TRANSMIT_OPTICAL_LEVEL_LEN 2
#define BCM_OMCI_CFG_DATA_LOWER_TRANSMIT_POWER_THRESHOLD_LEN 1
#define BCM_OMCI_CFG_DATA_UPPER_TRANSMIT_POWER_THRESHOLD_LEN 1

typedef struct
{
    uint8_t sr_indication;
    uint16_t total_tcont_number;
    uint16_t gem_block_length;
    uint8_t piggy_back_dba_reporting;
    uint8_t deprecated;
    uint8_t sf_threshold;
    uint8_t sd_threshold;
    uint8_t arc;
    uint8_t arc_interval;
    uint16_t optical_signal_level;
    uint8_t lower_optical_threshold;
    uint8_t upper_optical_threshold;
    uint16_t onu_response_time;
    uint16_t transmit_optical_level;
    uint8_t lower_transmit_power_threshold;
    uint8_t upper_transmit_power_threshold;
} bcm_omci_ani_g_cfg_data;

/** ANI-G (9.2.1) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_ani_g_cfg_data data;
} bcm_omci_ani_g_cfg;

bcmos_bool bcm_omci_ani_g_cfg_data_bounds_check(const bcm_omci_ani_g_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_ani_g_cfg_id *failed_prop);
void bcm_omci_ani_g_cfg_data_set_default(bcm_omci_ani_g_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_ani_g_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);


/** GEM Port Network CTP PM(9.2.13) ME cfg data */
#define BCM_OMCI_CFG_DATA_INTERVAL_END_TIME_LEN 1
#define BCM_OMCI_CFG_DATA_THRESHOLD_DATA_LEN 2
#define BCM_OMCI_CFG_DATA_TX_GEM_FRAMES_LEN 4
#define BCM_OMCI_CFG_DATA_RX_GEM_FRAMES_LEN 4
#define BCM_OMCI_CFG_DATA_RX_PAYLOAD_BYTES_LEN 8
#define BCM_OMCI_CFG_DATA_TX_PAYLOAD_BYTES_LEN 8
#define BCM_OMCI_CFG_DATA_ENCRY_KEY_ERRORS_LEN 4

typedef struct
{
    uint8_t interval_end_time;
    uint16_t threshold_data;
    uint32_t tx_gem_frames;
    uint32_t rx_gem_frames;
    uint8_t rx_payload_bytes[8];
    uint8_t tx_payload_bytes[8];
    uint32_t encry_key_errors;
} bcm_omci_gem_port_net_ctp_pm_cfg_data;

/** GEM Port Network CTP PM(9.2.13) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_gem_port_net_ctp_pm_cfg_data data;
} bcm_omci_gem_port_net_ctp_pm_cfg;

bcmos_bool bcm_omci_gem_port_net_ctp_pm_cfg_data_bounds_check(const bcm_omci_gem_port_net_ctp_pm_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_gem_port_net_ctp_pm_cfg_id *failed_prop);
void bcm_omci_gem_port_net_ctp_pm_cfg_data_set_default(bcm_omci_gem_port_net_ctp_pm_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_gem_port_net_ctp_pm_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);


/** ETH FRAME UPSTREAM PM(9.3.30) ME cfg data */
#define BCM_OMCI_CFG_DATA_INTERVAL_END_TIME_LEN 1
#define BCM_OMCI_CFG_DATA_THRESHOLD_DATA_LEN 2
#define BCM_OMCI_CFG_DATA_UP_DROP_EVENTS_LEN 4
#define BCM_OMCI_CFG_DATA_UP_OCTETS_LEN 4
#define BCM_OMCI_CFG_DATA_UP_PACKETS_LEN 4
#define BCM_OMCI_CFG_DATA_UP_BROADCAST_PACKETS_LEN 4
#define BCM_OMCI_CFG_DATA_UP_MULTICAST_PACKETS_LEN 4
#define BCM_OMCI_CFG_DATA_UP_CRC_ERRORED_PACKETS_LEN 4
#define BCM_OMCI_CFG_DATA_UP_UNDERSIZE_PACKETS_LEN 4
#define BCM_OMCI_CFG_DATA_UP_OVERSIZE_PACKETS_LEN 4
#define BCM_OMCI_CFG_DATA_UP_PACKETS_64_OCTETS_LEN 4
#define BCM_OMCI_CFG_DATA_UP_PACKETS_65_127_OCTETS_LEN 4
#define BCM_OMCI_CFG_DATA_UP_PACKETS_128_255_OCTETS_LEN 4
#define BCM_OMCI_CFG_DATA_UP_PACKETS_256_511_OCTETS_LEN 4
#define BCM_OMCI_CFG_DATA_UP_PACKETS_512_1023_OCTETS_LEN 4
#define BCM_OMCI_CFG_DATA_UP_PACKETS_1024_1518_OCTETS_LEN 4

typedef struct
{
    uint8_t interval_end_time;
    uint16_t threshold_data;
    uint32_t up_drop_events;
    uint32_t up_octets;
    uint32_t up_packets;
    uint32_t up_broadcast_packets;
    uint32_t up_multicast_packets;
    uint32_t up_crc_errored_packets;
    uint32_t up_undersize_packets;
    uint32_t up_oversize_packets;
    uint32_t up_packets_64_octets;
    uint32_t up_packets_65_127_octets;
    uint32_t up_packets_128_255_octets;
    uint32_t up_packets_256_511_octets;
    uint32_t up_packets_512_1023_octets;
    uint32_t up_packets_1024_1518_octets;
} bcm_omci_eth_frame_upstream_pm_cfg_data;

/** ETH FRAME UPSTREAM PM(9.3.30) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_eth_frame_upstream_pm_cfg_data data;
} bcm_omci_eth_frame_upstream_pm_cfg;

bcmos_bool bcm_omci_eth_frame_upstream_pm_cfg_data_bounds_check(const bcm_omci_eth_frame_upstream_pm_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_eth_frame_upstream_pm_cfg_id *failed_prop);
void bcm_omci_eth_frame_upstream_pm_cfg_data_set_default(bcm_omci_eth_frame_upstream_pm_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_eth_frame_upstream_pm_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);


/** ETH FRAME DOWNSTREAM PM(9.3.31) ME cfg data */
#define BCM_OMCI_CFG_DATA_INTERVAL_END_TIME_LEN 1
#define BCM_OMCI_CFG_DATA_THRESHOLD_DATA_LEN 2
#define BCM_OMCI_CFG_DATA_DN_DROP_EVENTS_LEN 4
#define BCM_OMCI_CFG_DATA_DN_OCTETS_LEN 4
#define BCM_OMCI_CFG_DATA_DN_PACKETS_LEN 4
#define BCM_OMCI_CFG_DATA_DN_BROADCAST_PACKETS_LEN 4
#define BCM_OMCI_CFG_DATA_DN_MULTICAST_PACKETS_LEN 4
#define BCM_OMCI_CFG_DATA_DN_CRC_ERRORED_PACKETS_LEN 4
#define BCM_OMCI_CFG_DATA_DN_UNDERSIZE_PACKETS_LEN 4
#define BCM_OMCI_CFG_DATA_DN_OVERSIZE_PACKETS_LEN 4
#define BCM_OMCI_CFG_DATA_DN_PACKETS_64_OCTETS_LEN 4
#define BCM_OMCI_CFG_DATA_DN_PACKETS_65_127_OCTETS_LEN 4
#define BCM_OMCI_CFG_DATA_DN_PACKETS_128_255_OCTETS_LEN 4
#define BCM_OMCI_CFG_DATA_DN_PACKETS_256_511_OCTETS_LEN 4
#define BCM_OMCI_CFG_DATA_DN_PACKETS_512_1023_OCTETS_LEN 4
#define BCM_OMCI_CFG_DATA_DN_PACKETS_1024_1518_OCTETS_LEN 4

typedef struct
{
    uint8_t interval_end_time;
    uint16_t threshold_data;
    uint32_t dn_drop_events;
    uint32_t dn_octets;
    uint32_t dn_packets;
    uint32_t dn_broadcast_packets;
    uint32_t dn_multicast_packets;
    uint32_t dn_crc_errored_packets;
    uint32_t dn_undersize_packets;
    uint32_t dn_oversize_packets;
    uint32_t dn_packets_64_octets;
    uint32_t dn_packets_65_127_octets;
    uint32_t dn_packets_128_255_octets;
    uint32_t dn_packets_256_511_octets;
    uint32_t dn_packets_512_1023_octets;
    uint32_t dn_packets_1024_1518_octets;
} bcm_omci_eth_frame_downstream_pm_cfg_data;

/** ETH FRAME DOWNSTREAM PM(9.3.31) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_eth_frame_downstream_pm_cfg_data data;
} bcm_omci_eth_frame_downstream_pm_cfg;

bcmos_bool bcm_omci_eth_frame_downstream_pm_cfg_data_bounds_check(const bcm_omci_eth_frame_downstream_pm_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_eth_frame_downstream_pm_cfg_id *failed_prop);
void bcm_omci_eth_frame_downstream_pm_cfg_data_set_default(bcm_omci_eth_frame_downstream_pm_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_eth_frame_downstream_pm_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);


/** FEC PERFORMANCE PM DATA(9.2.9) ME cfg data */
#define BCM_OMCI_CFG_DATA_INTERVAL_END_TIME_LEN 1
#define BCM_OMCI_CFG_DATA_THRESHOLD_DATA_LEN 2
#define BCM_OMCI_CFG_DATA_CORRECTED_BYTES_LEN 4
#define BCM_OMCI_CFG_DATA_CORRECTED_CODE_WORDS_LEN 4
#define BCM_OMCI_CFG_DATA_UNCORRECTABLE_CODE_WORDS_LEN 4
#define BCM_OMCI_CFG_DATA_TOTAL_CODE_WORDS_LEN 4
#define BCM_OMCI_CFG_DATA_FEC_SECONDS_LEN 2

typedef struct
{
    uint8_t interval_end_time;
    uint16_t threshold_data;
    uint32_t corrected_bytes;
    uint32_t corrected_code_words;
    uint32_t uncorrectable_code_words;
    uint32_t total_code_words;
    uint16_t fec_seconds;
} bcm_omci_fec_pm_cfg_data;

/** FEC PERFORMANCE PM DATA(9.2.9) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_fec_pm_cfg_data data;
} bcm_omci_fec_pm_cfg;

bcmos_bool bcm_omci_fec_pm_cfg_data_bounds_check(const bcm_omci_fec_pm_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_fec_pm_cfg_id *failed_prop);
void bcm_omci_fec_pm_cfg_data_set_default(bcm_omci_fec_pm_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_fec_pm_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);


/** XG-PON TC PERFORMANCE PM DATA(9.2.15) ME cfg data */
#define BCM_OMCI_CFG_DATA_INTERVAL_END_TIME_LEN 1
#define BCM_OMCI_CFG_DATA_THRESHOLD_DATA_LEN 2
#define BCM_OMCI_CFG_DATA_PSBD_HEC_ERROR_COUNT_LEN 4
#define BCM_OMCI_CFG_DATA_XGTC_HEC_ERROR_COUNT_LEN 4
#define BCM_OMCI_CFG_DATA_UNKNOWN_PROFILE_COUNT_LEN 4
#define BCM_OMCI_CFG_DATA_TRANSMITTED_XGEM_FRAMES_LEN 4
#define BCM_OMCI_CFG_DATA_FRAGMENT_XGEM_FRAMES_LEN 4
#define BCM_OMCI_CFG_DATA_XGEM_HEC_LOST_WORDS_COUNT_LEN 4
#define BCM_OMCI_CFG_DATA_XGEM_KEY_ERRORS_LEN 4
#define BCM_OMCI_CFG_DATA_XGEM_HEC_ERROR_COUNT_LEN 4
#define BCM_OMCI_CFG_DATA_TX_BYTES_IN_NON_IDLE_XGEM_FRAMES_LEN 8
#define BCM_OMCI_CFG_DATA_RX_BYTES_IN_NON_IDLE_XGEM_FRAMES_LEN 8
#define BCM_OMCI_CFG_DATA_LODS_EVENT_COUNT_LEN 4
#define BCM_OMCI_CFG_DATA_LODS_EVENT_RESTORED_COUNT_LEN 4
#define BCM_OMCI_CFG_DATA_ONU_REACTIVATION_BY_LODS_EVENTS_LEN 4

typedef struct
{
    uint8_t interval_end_time;
    uint16_t threshold_data;
    uint32_t psbd_hec_error_count;
    uint32_t xgtc_hec_error_count;
    uint32_t unknown_profile_count;
    uint32_t transmitted_xgem_frames;
    uint32_t fragment_xgem_frames;
    uint32_t xgem_hec_lost_words_count;
    uint32_t xgem_key_errors;
    uint32_t xgem_hec_error_count;
    uint8_t tx_bytes_in_non_idle_xgem_frames[8];
    uint8_t rx_bytes_in_non_idle_xgem_frames[8];
    uint32_t lods_event_count;
    uint32_t lods_event_restored_count;
    uint32_t onu_reactivation_by_lods_events;
} bcm_omci_xgpon_tc_pm_cfg_data;

/** XG-PON TC PERFORMANCE PM DATA(9.2.15) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_xgpon_tc_pm_cfg_data data;
} bcm_omci_xgpon_tc_pm_cfg;

bcmos_bool bcm_omci_xgpon_tc_pm_cfg_data_bounds_check(const bcm_omci_xgpon_tc_pm_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_xgpon_tc_pm_cfg_id *failed_prop);
void bcm_omci_xgpon_tc_pm_cfg_data_set_default(bcm_omci_xgpon_tc_pm_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_xgpon_tc_pm_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);


/** IP Host Config Data (9.4.1) ME cfg data */
#define BCM_OMCI_CFG_DATA_IP_OPTIONS_LEN 1
#define BCM_OMCI_CFG_DATA_MAC_ADDR_LEN 6
#define BCM_OMCI_CFG_DATA_ONU_ID_LEN 25
#define BCM_OMCI_CFG_DATA_IP_ADDRESS_LEN 4
#define BCM_OMCI_CFG_DATA_MASK_LEN 4
#define BCM_OMCI_CFG_DATA_GATEWAY_LEN 4
#define BCM_OMCI_CFG_DATA_PRIMARY_DNS_LEN 4
#define BCM_OMCI_CFG_DATA_SECONDARY_DNS_LEN 4
#define BCM_OMCI_CFG_DATA_CURRENT_ADDRESS_LEN 4
#define BCM_OMCI_CFG_DATA_CURRENT_MASK_LEN 4
#define BCM_OMCI_CFG_DATA_CURRENT_GATEWAY_LEN 4
#define BCM_OMCI_CFG_DATA_CURRENT_PRIMARY_DNS_LEN 4
#define BCM_OMCI_CFG_DATA_CURRENT_SECONDARY_DNS_LEN 4
#define BCM_OMCI_CFG_DATA_DOMAIN_NAME_LEN 25
#define BCM_OMCI_CFG_DATA_HOST_NAME_LEN 25
#define BCM_OMCI_CFG_DATA_RELAY_AGENT_OPTIONS_LEN 2

typedef struct
{
    uint8_t ip_options;
    uint8_t mac_addr[6];
    uint8_t onu_id[25];
    uint32_t ip_address;
    uint32_t mask;
    uint32_t gateway;
    uint32_t primary_dns;
    uint32_t secondary_dns;
    uint32_t current_address;
    uint32_t current_mask;
    uint32_t current_gateway;
    uint32_t current_primary_dns;
    uint32_t current_secondary_dns;
    uint8_t domain_name[25];
    uint8_t host_name[25];
    uint8_t relay_agent_options[2];
} bcm_omci_ip_host_config_data_cfg_data;

/** IP Host Config Data (9.4.1) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_ip_host_config_data_cfg_data data;
} bcm_omci_ip_host_config_data_cfg;

bcmos_bool bcm_omci_ip_host_config_data_cfg_data_bounds_check(const bcm_omci_ip_host_config_data_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_ip_host_config_data_cfg_id *failed_prop);
void bcm_omci_ip_host_config_data_cfg_data_set_default(bcm_omci_ip_host_config_data_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_ip_host_config_data_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_VOIP_LINE_STATUS_CODEC_PCMU = 0,
    BCM_OMCI_VOIP_LINE_STATUS_CODEC_GSM = 3,
    BCM_OMCI_VOIP_LINE_STATUS_CODEC_G723 = 4,
    BCM_OMCI_VOIP_LINE_STATUS_CODEC_DVI4_8KHZ = 5,
    BCM_OMCI_VOIP_LINE_STATUS_CODEC_DVI4_16KHZ = 6,
    BCM_OMCI_VOIP_LINE_STATUS_CODEC_LPC = 7,
    BCM_OMCI_VOIP_LINE_STATUS_CODEC_PCMA = 8,
    BCM_OMCI_VOIP_LINE_STATUS_CODEC_G722 = 9,
    BCM_OMCI_VOIP_LINE_STATUS_CODEC_L16_2CH = 10,
    BCM_OMCI_VOIP_LINE_STATUS_CODEC_L16_1CH = 11,
    BCM_OMCI_VOIP_LINE_STATUS_CODEC_QCELP = 12,
    BCM_OMCI_VOIP_LINE_STATUS_CODEC_CN = 13,
    BCM_OMCI_VOIP_LINE_STATUS_CODEC_MPA = 14,
    BCM_OMCI_VOIP_LINE_STATUS_CODEC_G728 = 15,
    BCM_OMCI_VOIP_LINE_STATUS_CODEC_DVI4_11KHZ = 16,
    BCM_OMCI_VOIP_LINE_STATUS_CODEC_DVI4_22KHZ = 17,
    BCM_OMCI_VOIP_LINE_STATUS_CODEC_G729 = 18,
    BCM_OMCI_VOIP_LINE_STATUS_CODEC__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_voip_line_status_codec;

typedef enum
{
    BCM_OMCI_VOIP_LINE_STATUS_VOICE_SERVER_STATUS_NONE = 0,
    BCM_OMCI_VOIP_LINE_STATUS_VOICE_SERVER_STATUS_REGISTERED = 1,
    BCM_OMCI_VOIP_LINE_STATUS_VOICE_SERVER_STATUS_IN_SESSION = 2,
    BCM_OMCI_VOIP_LINE_STATUS_VOICE_SERVER_STATUS_FAILED_REGISTRATION_ICMP_ERROR = 3,
    BCM_OMCI_VOIP_LINE_STATUS_VOICE_SERVER_STATUS_FAILED_REGISTRATION_FAILED_TCP = 4,
    BCM_OMCI_VOIP_LINE_STATUS_VOICE_SERVER_STATUS_FAILED_REGISTRATION_FAILED_AUTHENTICATION = 5,
    BCM_OMCI_VOIP_LINE_STATUS_VOICE_SERVER_STATUS_FAILED_REGISTRATION_TIMEOUT = 6,
    BCM_OMCI_VOIP_LINE_STATUS_VOICE_SERVER_STATUS_FAILED_REGISTRATION_SERVER_FAIL_CODE = 7,
    BCM_OMCI_VOIP_LINE_STATUS_VOICE_SERVER_STATUS_FAILED_INVITE_ICMP_ERROR = 8,
    BCM_OMCI_VOIP_LINE_STATUS_VOICE_SERVER_STATUS_FAILED_INVITE_FAILED_TCP = 9,
    BCM_OMCI_VOIP_LINE_STATUS_VOICE_SERVER_STATUS_FAILED_INVITE_FAILED_AUTHENTICATION = 10,
    BCM_OMCI_VOIP_LINE_STATUS_VOICE_SERVER_STATUS_FAILED_INVITE_TIMEOUT = 11,
    BCM_OMCI_VOIP_LINE_STATUS_VOICE_SERVER_STATUS_FAILED_INVITE_SERVER_FAIL_CODE = 12,
    BCM_OMCI_VOIP_LINE_STATUS_VOICE_SERVER_STATUS_PORT_NOT_CONFIGURED = 13,
    BCM_OMCI_VOIP_LINE_STATUS_VOICE_SERVER_STATUS_CONFIG_DONE = 14,
    BCM_OMCI_VOIP_LINE_STATUS_VOICE_SERVER_STATUS_DISABLED_BY_SWITCH = 15,
    BCM_OMCI_VOIP_LINE_STATUS_VOICE_SERVER_STATUS__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_voip_line_status_voice_server_status;

typedef enum
{
    BCM_OMCI_VOIP_LINE_STATUS_PORT_SESSION_TYPE_IDLE = 0,
    BCM_OMCI_VOIP_LINE_STATUS_PORT_SESSION_TYPE_2WAY = 1,
    BCM_OMCI_VOIP_LINE_STATUS_PORT_SESSION_TYPE_3WAY = 2,
    BCM_OMCI_VOIP_LINE_STATUS_PORT_SESSION_TYPE_FAX_MODEM = 3,
    BCM_OMCI_VOIP_LINE_STATUS_PORT_SESSION_TYPE_TELEMETRY = 4,
    BCM_OMCI_VOIP_LINE_STATUS_PORT_SESSION_TYPE_CONFERENCE = 5,
    BCM_OMCI_VOIP_LINE_STATUS_PORT_SESSION_TYPE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_voip_line_status_port_session_type;

typedef enum
{
    BCM_OMCI_VOIP_LINE_STATUS_LINE_STATE_IDLE_ON_HOOK = 0,
    BCM_OMCI_VOIP_LINE_STATUS_LINE_STATE_OFF_HOOK_DIAL_TONE = 1,
    BCM_OMCI_VOIP_LINE_STATUS_LINE_STATE_DIALING = 2,
    BCM_OMCI_VOIP_LINE_STATUS_LINE_STATE_RINGING = 3,
    BCM_OMCI_VOIP_LINE_STATUS_LINE_STATE_AUDIBLE_RINGBACK = 4,
    BCM_OMCI_VOIP_LINE_STATUS_LINE_STATE_CONNECTING = 5,
    BCM_OMCI_VOIP_LINE_STATUS_LINE_STATE_CONNECTED = 6,
    BCM_OMCI_VOIP_LINE_STATUS_LINE_STATE_DISCONNECTING = 7,
    BCM_OMCI_VOIP_LINE_STATUS_LINE_STATE_ROH_NO_TONE = 8,
    BCM_OMCI_VOIP_LINE_STATUS_LINE_STATE_ROH_WITH_TONE = 9,
    BCM_OMCI_VOIP_LINE_STATUS_LINE_STATE_UNKNOWN = 10,
    BCM_OMCI_VOIP_LINE_STATUS_LINE_STATE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_voip_line_status_line_state;

typedef enum
{
    BCM_OMCI_VOIP_LINE_STATUS_EMERGENCY_CALL_STATUS_NOT_IN_PROGRESS = 0,
    BCM_OMCI_VOIP_LINE_STATUS_EMERGENCY_CALL_STATUS_IN_PROGRESS = 1,
    BCM_OMCI_VOIP_LINE_STATUS_EMERGENCY_CALL_STATUS__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_voip_line_status_emergency_call_status;


/** VoIP Line Status (9.9.11) ME cfg data */
#define BCM_OMCI_CFG_DATA_CODEC_LEN 2
#define BCM_OMCI_CFG_DATA_VOICE_SERVER_STATUS_LEN 1
#define BCM_OMCI_CFG_DATA_PORT_SESSION_TYPE_LEN 1
#define BCM_OMCI_CFG_DATA_CALL1_PACKET_PERIOD_LEN 2
#define BCM_OMCI_CFG_DATA_CALL2_PACKET_PERIOD_LEN 2
#define BCM_OMCI_CFG_DATA_CALL1_DEST_ADDRESS_LEN 25
#define BCM_OMCI_CFG_DATA_CALL2_DEST_ADDRESS_LEN 25
#define BCM_OMCI_CFG_DATA_LINE_STATE_LEN 1
#define BCM_OMCI_CFG_DATA_EMERGENCY_CALL_STATUS_LEN 1

typedef struct
{
    bcm_omci_voip_line_status_codec codec;
    bcm_omci_voip_line_status_voice_server_status voice_server_status;
    bcm_omci_voip_line_status_port_session_type port_session_type;
    uint16_t call1_packet_period;
    uint16_t call2_packet_period;
    uint8_t call1_dest_address[25];
    uint8_t call2_dest_address[25];
    bcm_omci_voip_line_status_line_state line_state;
    bcm_omci_voip_line_status_emergency_call_status emergency_call_status;
} bcm_omci_voip_line_status_cfg_data;

/** VoIP Line Status (9.9.11) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_voip_line_status_cfg_data data;
} bcm_omci_voip_line_status_cfg;

bcmos_bool bcm_omci_voip_line_status_cfg_data_bounds_check(const bcm_omci_voip_line_status_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_voip_line_status_cfg_id *failed_prop);
void bcm_omci_voip_line_status_cfg_data_set_default(bcm_omci_voip_line_status_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_voip_line_status_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_VOIP_MEDIA_PROFILE_FAX_MODE_PASSTHROUGH = 0,
    BCM_OMCI_VOIP_MEDIA_PROFILE_FAX_MODE_T38 = 1,
    BCM_OMCI_VOIP_MEDIA_PROFILE_FAX_MODE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_voip_media_profile_fax_mode;

typedef enum
{
    BCM_OMCI_VOIP_MEDIA_PROFILE_CODEC_SELECTION1_PCMU = 0,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CODEC_SELECTION1_GSM = 3,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CODEC_SELECTION1_G723 = 4,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CODEC_SELECTION1_DVI4_8KHZ = 5,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CODEC_SELECTION1_DVI4_16KHZ = 6,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CODEC_SELECTION1_LPC = 7,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CODEC_SELECTION1_PCMA = 8,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CODEC_SELECTION1_G722 = 9,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CODEC_SELECTION1_L16_2CH = 10,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CODEC_SELECTION1_L16_1CH = 11,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CODEC_SELECTION1_QCELP = 12,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CODEC_SELECTION1_CN = 13,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CODEC_SELECTION1_MPA = 14,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CODEC_SELECTION1_G728 = 15,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CODEC_SELECTION1_DVI4_11KHZ = 16,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CODEC_SELECTION1_DVI4_22KHZ = 17,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CODEC_SELECTION1_G729 = 18,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CODEC_SELECTION1__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_voip_media_profile_codec_selection1;


/** VoIP Line Status (9.9.11) ME cfg data */
#define BCM_OMCI_CFG_DATA_FAX_MODE_LEN 1
#define BCM_OMCI_CFG_DATA_VOICE_SERVICE_PROF_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_CODEC_SELECTION1_LEN 1
#define BCM_OMCI_CFG_DATA_PACKET_PERIOD1_LEN 1
#define BCM_OMCI_CFG_DATA_SILENCE_SUPRESSION1_LEN 1
#define BCM_OMCI_CFG_DATA_CODEC_SELECTION2_LEN 1
#define BCM_OMCI_CFG_DATA_PACKET_PERIOD2_LEN 1
#define BCM_OMCI_CFG_DATA_SILENCE_SUPRESSION2_LEN 1
#define BCM_OMCI_CFG_DATA_CODEC_SELECTION3_LEN 1
#define BCM_OMCI_CFG_DATA_PACKET_PERIOD3_LEN 1
#define BCM_OMCI_CFG_DATA_SILENCE_SUPRESSION3_LEN 1
#define BCM_OMCI_CFG_DATA_CODEC_SELECTION4_LEN 1
#define BCM_OMCI_CFG_DATA_PACKET_PERIOD4_LEN 1
#define BCM_OMCI_CFG_DATA_SILENCE_SUPRESSION4_LEN 1
#define BCM_OMCI_CFG_DATA_OOB_DTMF_LEN 1
#define BCM_OMCI_CFG_DATA_RTP_PROFILE_PTR_LEN 2

typedef struct
{
    bcm_omci_voip_media_profile_fax_mode fax_mode;
    uint16_t voice_service_prof_ptr;
    bcm_omci_voip_media_profile_codec_selection1 codec_selection1;
    uint8_t packet_period1;
    uint8_t silence_supression1;
    uint8_t codec_selection2;
    uint8_t packet_period2;
    uint8_t silence_supression2;
    uint8_t codec_selection3;
    uint8_t packet_period3;
    uint8_t silence_supression3;
    uint8_t codec_selection4;
    uint8_t packet_period4;
    uint8_t silence_supression4;
    uint8_t oob_dtmf;
    uint16_t rtp_profile_ptr;
} bcm_omci_voip_media_profile_cfg_data;

/** VoIP Line Status (9.9.11) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_voip_media_profile_cfg_data data;
} bcm_omci_voip_media_profile_cfg;

bcmos_bool bcm_omci_voip_media_profile_cfg_data_bounds_check(const bcm_omci_voip_media_profile_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_voip_media_profile_cfg_id *failed_prop);
void bcm_omci_voip_media_profile_cfg_data_set_default(bcm_omci_voip_media_profile_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_voip_media_profile_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);


/** SIP User Data (9.9.2) ME cfg data */
#define BCM_OMCI_CFG_DATA_SIP_AGENT_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_USER_PART_AOR_LEN 2
#define BCM_OMCI_CFG_DATA_SIP_DISPLAY_NAME_LEN 25
#define BCM_OMCI_CFG_DATA_USERNAME_PASSWORD_LEN 2
#define BCM_OMCI_CFG_DATA_VOICEMAIL_SERVER_URI_LEN 2
#define BCM_OMCI_CFG_DATA_VOICEMAIL_SUBSCRIPTION_EXP_TIME_LEN 4
#define BCM_OMCI_CFG_DATA_NETWORK_DIAL_PLAN_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_APP_SERVICE_PROF_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_FEATURE_CODE_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_PPTP_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_RELEASE_TIMER_LEN 1
#define BCM_OMCI_CFG_DATA_ROH_TIMER_LEN 1

typedef struct
{
    uint16_t sip_agent_ptr;
    uint16_t user_part_aor;
    uint8_t sip_display_name[25];
    uint16_t username_password;
    uint16_t voicemail_server_uri;
    uint32_t voicemail_subscription_exp_time;
    uint16_t network_dial_plan_ptr;
    uint16_t app_service_prof_ptr;
    uint16_t feature_code_ptr;
    uint16_t pptp_ptr;
    uint8_t release_timer;
    uint8_t roh_timer;
} bcm_omci_sip_user_data_cfg_data;

/** SIP User Data (9.9.2) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_sip_user_data_cfg_data data;
} bcm_omci_sip_user_data_cfg;

bcmos_bool bcm_omci_sip_user_data_cfg_data_bounds_check(const bcm_omci_sip_user_data_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_sip_user_data_cfg_id *failed_prop);
void bcm_omci_sip_user_data_cfg_data_set_default(bcm_omci_sip_user_data_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_sip_user_data_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_SIP_STATUS_OK = 0,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_SIP_STATUS_CONNECTED = 1,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_SIP_STATUS_FAILED_ICMP_ERROR = 2,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_SIP_STATUS_FAILED_MALFORMED_RESPONSE = 3,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_SIP_STATUS_FAILED_INADEQUATE_INFO_RESPONSE = 4,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_SIP_STATUS_FAILED_TIMEOUT = 5,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_SIP_STATUS_REDUNDANT_OFFLINE = 6,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_SIP_STATUS__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_sip_agent_config_data_sip_status;

typedef enum
{
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_SIP_TRANSMIT_CONTROL_ENABLED = 1,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_SIP_TRANSMIT_CONTROL_DISABLED = 0,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_SIP_TRANSMIT_CONTROL__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_sip_agent_config_data_sip_transmit_control;

typedef enum
{
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_SIP_URI_FORMAT_TEL_URI = 0,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_SIP_URI_FORMAT_SIP_URI = 1,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_SIP_URI_FORMAT__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_sip_agent_config_data_sip_uri_format;


/** SIP Agent Config Data (9.9.3) ME cfg data */
#define BCM_OMCI_CFG_DATA_PROXY_SERVER_ADDR_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_OUTBOUND_PROXY_ADDR_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_PRIMARY_SIP_DNS_LEN 4
#define BCM_OMCI_CFG_DATA_SECONDARY_SIP_DNS_LEN 4
#define BCM_OMCI_CFG_DATA_TCP_UDP_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_SIP_REG_EXP_TIME_LEN 4
#define BCM_OMCI_CFG_DATA_SIP_REREG_HEAD_START_TIME_LEN 4
#define BCM_OMCI_CFG_DATA_HOST_PART_URI_LEN 2
#define BCM_OMCI_CFG_DATA_SIP_STATUS_LEN 1
#define BCM_OMCI_CFG_DATA_SIP_REGISTRAR_LEN 2
#define BCM_OMCI_CFG_DATA_SOFTSWITCH_LEN 4
#define BCM_OMCI_CFG_DATA_SIP_RESPONSE_TABLE_LEN 5
#define BCM_OMCI_CFG_DATA_SIP_TRANSMIT_CONTROL_LEN 1
#define BCM_OMCI_CFG_DATA_SIP_URI_FORMAT_LEN 1
#define BCM_OMCI_CFG_DATA_REDUNDANT_SIP_AGENT_PTR_LEN 2

typedef struct
{
    uint16_t response_code;
    uint8_t tone;
    uint16_t text_message;
} bcm_omci_sip_agent_config_data_sip_response_table;


typedef struct
{
    uint16_t proxy_server_addr_ptr;
    uint16_t outbound_proxy_addr_ptr;
    uint32_t primary_sip_dns;
    uint32_t secondary_sip_dns;
    uint16_t tcp_udp_ptr;
    uint32_t sip_reg_exp_time;
    uint32_t sip_rereg_head_start_time;
    uint16_t host_part_uri;
    bcm_omci_sip_agent_config_data_sip_status sip_status;
    uint16_t sip_registrar;
    uint32_t softswitch;
    bcm_omci_sip_agent_config_data_sip_response_table sip_response_table;
    bcm_omci_sip_agent_config_data_sip_transmit_control sip_transmit_control;
    bcm_omci_sip_agent_config_data_sip_uri_format sip_uri_format;
    uint16_t redundant_sip_agent_ptr;
} bcm_omci_sip_agent_config_data_cfg_data;

/** SIP Agent Config Data (9.9.3) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_sip_agent_config_data_cfg_data data;
} bcm_omci_sip_agent_config_data_cfg;

bcmos_bool bcm_omci_sip_agent_config_data_cfg_data_bounds_check(const bcm_omci_sip_agent_config_data_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_sip_agent_config_data_cfg_id *failed_prop);
void bcm_omci_sip_agent_config_data_cfg_data_set_default(bcm_omci_sip_agent_config_data_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_sip_agent_config_data_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);


/** Network Address (9.12.3) ME cfg data */
#define BCM_OMCI_CFG_DATA_SECURITY_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_ADDRESS_PTR_LEN 2

typedef struct
{
    uint16_t security_ptr;
    uint16_t address_ptr;
} bcm_omci_network_address_cfg_data;

/** Network Address (9.12.3) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_network_address_cfg_data data;
} bcm_omci_network_address_cfg;

bcmos_bool bcm_omci_network_address_cfg_data_bounds_check(const bcm_omci_network_address_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_network_address_cfg_id *failed_prop);
void bcm_omci_network_address_cfg_data_set_default(bcm_omci_network_address_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_network_address_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);


/** Large String (9.12.5) ME cfg data */
#define BCM_OMCI_CFG_DATA_NUMBER_OF_PARTS_LEN 1
#define BCM_OMCI_CFG_DATA_PART1_LEN 25
#define BCM_OMCI_CFG_DATA_PART2_LEN 25
#define BCM_OMCI_CFG_DATA_PART3_LEN 25
#define BCM_OMCI_CFG_DATA_PART4_LEN 25
#define BCM_OMCI_CFG_DATA_PART5_LEN 25
#define BCM_OMCI_CFG_DATA_PART6_LEN 25
#define BCM_OMCI_CFG_DATA_PART7_LEN 25
#define BCM_OMCI_CFG_DATA_PART8_LEN 25
#define BCM_OMCI_CFG_DATA_PART9_LEN 25
#define BCM_OMCI_CFG_DATA_PART10_LEN 25
#define BCM_OMCI_CFG_DATA_PART11_LEN 25
#define BCM_OMCI_CFG_DATA_PART12_LEN 25
#define BCM_OMCI_CFG_DATA_PART13_LEN 25
#define BCM_OMCI_CFG_DATA_PART14_LEN 25
#define BCM_OMCI_CFG_DATA_PART15_LEN 25

typedef struct
{
    uint8_t number_of_parts;
    uint8_t part1[25];
    uint8_t part2[25];
    uint8_t part3[25];
    uint8_t part4[25];
    uint8_t part5[25];
    uint8_t part6[25];
    uint8_t part7[25];
    uint8_t part8[25];
    uint8_t part9[25];
    uint8_t part10[25];
    uint8_t part11[25];
    uint8_t part12[25];
    uint8_t part13[25];
    uint8_t part14[25];
    uint8_t part15[25];
} bcm_omci_large_string_cfg_data;

/** Large String (9.12.5) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_large_string_cfg_data data;
} bcm_omci_large_string_cfg;

bcmos_bool bcm_omci_large_string_cfg_data_bounds_check(const bcm_omci_large_string_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_large_string_cfg_id *failed_prop);
void bcm_omci_large_string_cfg_data_set_default(bcm_omci_large_string_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_large_string_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_VALIDATION_SCHEME_DISABLED = 0,
    BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_VALIDATION_SCHEME_MD5 = 1,
    BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_VALIDATION_SCHEME_BASIC = 3,
    BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_VALIDATION_SCHEME__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_authentication_security_method_validation_scheme;


/** Authentication Security Method (9.12.4) ME cfg data */
#define BCM_OMCI_CFG_DATA_VALIDATION_SCHEME_LEN 1
#define BCM_OMCI_CFG_DATA_USERNAME1_LEN 25
#define BCM_OMCI_CFG_DATA_PASSWORD_LEN 25
#define BCM_OMCI_CFG_DATA_REALM_LEN 25
#define BCM_OMCI_CFG_DATA_USERNAME2_LEN 25

typedef struct
{
    bcm_omci_authentication_security_method_validation_scheme validation_scheme;
    uint8_t username1[25];
    uint8_t password[25];
    uint8_t realm[25];
    uint8_t username2[25];
} bcm_omci_authentication_security_method_cfg_data;

/** Authentication Security Method (9.12.4) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_authentication_security_method_cfg_data data;
} bcm_omci_authentication_security_method_cfg;

bcmos_bool bcm_omci_authentication_security_method_cfg_data_bounds_check(const bcm_omci_authentication_security_method_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_authentication_security_method_cfg_id *failed_prop);
void bcm_omci_authentication_security_method_cfg_data_set_default(bcm_omci_authentication_security_method_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_authentication_security_method_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_VOICE_SERVICE_PROFILE_ANNOUNCEMENT_TYPE_SILENCE = 1,
    BCM_OMCI_VOICE_SERVICE_PROFILE_ANNOUNCEMENT_TYPE_REORDER_TONE = 2,
    BCM_OMCI_VOICE_SERVICE_PROFILE_ANNOUNCEMENT_TYPE_FAST_BUSY = 3,
    BCM_OMCI_VOICE_SERVICE_PROFILE_ANNOUNCEMENT_TYPE_VOICE_ANNOUNCEMENT = 4,
    BCM_OMCI_VOICE_SERVICE_PROFILE_ANNOUNCEMENT_TYPE_UNSPECIFIED = 255,
    BCM_OMCI_VOICE_SERVICE_PROFILE_ANNOUNCEMENT_TYPE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_voice_service_profile_announcement_type;

typedef enum
{
    BCM_OMCI_VOICE_SERVICE_PROFILE_ECHO_CANCEL_ENABLED = 1,
    BCM_OMCI_VOICE_SERVICE_PROFILE_ECHO_CANCEL_DISABLED = 0,
    BCM_OMCI_VOICE_SERVICE_PROFILE_ECHO_CANCEL__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_voice_service_profile_echo_cancel;


/** Voice Service Profile (9.9.6) ME cfg data */
#define BCM_OMCI_CFG_DATA_ANNOUNCEMENT_TYPE_LEN 1
#define BCM_OMCI_CFG_DATA_JITTER_TARGET_LEN 2
#define BCM_OMCI_CFG_DATA_JITTER_BUFFER_MAX_LEN 2
#define BCM_OMCI_CFG_DATA_ECHO_CANCEL_LEN 1
#define BCM_OMCI_CFG_DATA_PSTN_PROTOCOL_VARIANT_LEN 2
#define BCM_OMCI_CFG_DATA_DTMF_DIGIT_LEVELS_LEN 2
#define BCM_OMCI_CFG_DATA_DTMF_DIGIT_DURATION_LEN 2
#define BCM_OMCI_CFG_DATA_HOOK_FLASH_MIN_TIME_LEN 2
#define BCM_OMCI_CFG_DATA_HOOK_FLASH_MAX_TIME_LEN 2
#define BCM_OMCI_CFG_DATA_TONE_PATTERN_TABLE_LEN 20
#define BCM_OMCI_CFG_DATA_TONE_EVENT_TABLE_LEN 7
#define BCM_OMCI_CFG_DATA_RINGING_PATTERN_TABLE_LEN 5
#define BCM_OMCI_CFG_DATA_RINGING_EVENT_TABLE_LEN 7
#define BCM_OMCI_CFG_DATA_NETWORK_SPECIFIC_EXT_PTR_LEN 2

typedef struct
{
    uint8_t index;
    uint8_t tone_on;
    uint16_t frequency1;
    uint8_t power1;
    uint16_t frequency2;
    uint8_t power2;
    uint16_t frequency3;
    uint8_t power3;
    uint16_t frequency4;
    uint8_t power4;
    uint16_t modulation_frequency;
    uint8_t modulation_power;
    uint16_t duration;
    uint8_t next_entry;
} bcm_omci_voice_service_profile_tone_pattern_table;


typedef struct
{
    uint8_t event;
    uint8_t tone_pattern;
    uint16_t tone_file;
    uint8_t tone_file_repetitions;
    uint16_t reserved;
} bcm_omci_voice_service_profile_tone_event_table;


typedef struct
{
    uint8_t index;
    uint8_t ringing_on;
    uint16_t duration;
    uint8_t next_entry;
} bcm_omci_voice_service_profile_ringing_pattern_table;


typedef struct
{
    uint8_t event;
    uint8_t ringing_pattern;
    uint16_t ringing_file;
    uint8_t ringing_file_repetitions;
    uint16_t ringing_text;
} bcm_omci_voice_service_profile_ringing_event_table;


typedef struct
{
    bcm_omci_voice_service_profile_announcement_type announcement_type;
    uint16_t jitter_target;
    uint16_t jitter_buffer_max;
    bcm_omci_voice_service_profile_echo_cancel echo_cancel;
    uint16_t pstn_protocol_variant;
    uint16_t dtmf_digit_levels;
    uint16_t dtmf_digit_duration;
    uint16_t hook_flash_min_time;
    uint16_t hook_flash_max_time;
    bcm_omci_voice_service_profile_tone_pattern_table tone_pattern_table;
    bcm_omci_voice_service_profile_tone_event_table tone_event_table;
    bcm_omci_voice_service_profile_ringing_pattern_table ringing_pattern_table;
    bcm_omci_voice_service_profile_ringing_event_table ringing_event_table;
    uint16_t network_specific_ext_ptr;
} bcm_omci_voice_service_profile_cfg_data;

/** Voice Service Profile (9.9.6) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_voice_service_profile_cfg_data data;
} bcm_omci_voice_service_profile_cfg;

bcmos_bool bcm_omci_voice_service_profile_cfg_data_bounds_check(const bcm_omci_voice_service_profile_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_voice_service_profile_cfg_id *failed_prop);
void bcm_omci_voice_service_profile_cfg_data_set_default(bcm_omci_voice_service_profile_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_voice_service_profile_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_VOIP_CONFIG_DATA_AVAILABLE_SIGNALLING_PROTOCOLS_SIP = 1,
    BCM_OMCI_VOIP_CONFIG_DATA_AVAILABLE_SIGNALLING_PROTOCOLS_H248 = 2,
    BCM_OMCI_VOIP_CONFIG_DATA_AVAILABLE_SIGNALLING_PROTOCOLS_MGCP = 3,
    BCM_OMCI_VOIP_CONFIG_DATA_AVAILABLE_SIGNALLING_PROTOCOLS__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_voip_config_data_available_signalling_protocols;

typedef enum
{
    BCM_OMCI_VOIP_CONFIG_DATA_SIGNALLING_PROTOCOL_USED_SIP = 1,
    BCM_OMCI_VOIP_CONFIG_DATA_SIGNALLING_PROTOCOL_USED_H248 = 2,
    BCM_OMCI_VOIP_CONFIG_DATA_SIGNALLING_PROTOCOL_USED_MGCP = 3,
    BCM_OMCI_VOIP_CONFIG_DATA_SIGNALLING_PROTOCOL_USED_NON_OMCI = 255,
    BCM_OMCI_VOIP_CONFIG_DATA_SIGNALLING_PROTOCOL_USED__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_voip_config_data_signalling_protocol_used;

typedef enum
{
    BCM_OMCI_VOIP_CONFIG_DATA_AVAILABLE_VOIP_CONFIG_METHODS_OMCI = 1,
    BCM_OMCI_VOIP_CONFIG_DATA_AVAILABLE_VOIP_CONFIG_METHODS_CONFIG_FILE = 2,
    BCM_OMCI_VOIP_CONFIG_DATA_AVAILABLE_VOIP_CONFIG_METHODS_TR069 = 3,
    BCM_OMCI_VOIP_CONFIG_DATA_AVAILABLE_VOIP_CONFIG_METHODS_SIP = 4,
    BCM_OMCI_VOIP_CONFIG_DATA_AVAILABLE_VOIP_CONFIG_METHODS__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_voip_config_data_available_voip_config_methods;

typedef enum
{
    BCM_OMCI_VOIP_CONFIG_DATA_VOIP_CONFIG_METHOD_USED_OMCI = 1,
    BCM_OMCI_VOIP_CONFIG_DATA_VOIP_CONFIG_METHOD_USED_CONFIG_FILE = 2,
    BCM_OMCI_VOIP_CONFIG_DATA_VOIP_CONFIG_METHOD_USED_TR069 = 3,
    BCM_OMCI_VOIP_CONFIG_DATA_VOIP_CONFIG_METHOD_USED_SIP = 4,
    BCM_OMCI_VOIP_CONFIG_DATA_VOIP_CONFIG_METHOD_USED__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_voip_config_data_voip_config_method_used;

typedef enum
{
    BCM_OMCI_VOIP_CONFIG_DATA_VOIP_CONFIG_STATE_INACTIVE = 0,
    BCM_OMCI_VOIP_CONFIG_DATA_VOIP_CONFIG_STATE_ACTIVE = 1,
    BCM_OMCI_VOIP_CONFIG_DATA_VOIP_CONFIG_STATE_INITIALIZING = 2,
    BCM_OMCI_VOIP_CONFIG_DATA_VOIP_CONFIG_STATE_FAULT = 3,
    BCM_OMCI_VOIP_CONFIG_DATA_VOIP_CONFIG_STATE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_voip_config_data_voip_config_state;


/** VoIP config data (9.9.18) ME cfg data */
#define BCM_OMCI_CFG_DATA_AVAILABLE_SIGNALLING_PROTOCOLS_LEN 1
#define BCM_OMCI_CFG_DATA_SIGNALLING_PROTOCOL_USED_LEN 1
#define BCM_OMCI_CFG_DATA_AVAILABLE_VOIP_CONFIG_METHODS_LEN 4
#define BCM_OMCI_CFG_DATA_VOIP_CONFIG_METHOD_USED_LEN 1
#define BCM_OMCI_CFG_DATA_VOICE_CONFIG_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_VOIP_CONFIG_STATE_LEN 1
#define BCM_OMCI_CFG_DATA_RETRIEVE_PROFILE_LEN 1
#define BCM_OMCI_CFG_DATA_PROFILE_VERSION_LEN 25

typedef struct
{
    bcm_omci_voip_config_data_available_signalling_protocols available_signalling_protocols;
    bcm_omci_voip_config_data_signalling_protocol_used signalling_protocol_used;
    bcm_omci_voip_config_data_available_voip_config_methods available_voip_config_methods;
    bcm_omci_voip_config_data_voip_config_method_used voip_config_method_used;
    uint16_t voice_config_ptr;
    bcm_omci_voip_config_data_voip_config_state voip_config_state;
    uint8_t retrieve_profile;
    uint8_t profile_version[25];
} bcm_omci_voip_config_data_cfg_data;

/** VoIP config data (9.9.18) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_voip_config_data_cfg_data data;
} bcm_omci_voip_config_data_cfg;

bcmos_bool bcm_omci_voip_config_data_cfg_data_bounds_check(const bcm_omci_voip_config_data_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_voip_config_data_cfg_id *failed_prop);
void bcm_omci_voip_config_data_cfg_data_set_default(bcm_omci_voip_config_data_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_voip_config_data_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_VOIP_VOICE_CTP_SIGNALLING_CODE_LOOP_START = 1,
    BCM_OMCI_VOIP_VOICE_CTP_SIGNALLING_CODE_GROUND_START = 2,
    BCM_OMCI_VOIP_VOICE_CTP_SIGNALLING_CODE_LOOP_REVERSE_BATTERY = 3,
    BCM_OMCI_VOIP_VOICE_CTP_SIGNALLING_CODE_COIN_FIRST = 4,
    BCM_OMCI_VOIP_VOICE_CTP_SIGNALLING_CODE_DIAL_TONE_FIRST = 5,
    BCM_OMCI_VOIP_VOICE_CTP_SIGNALLING_CODE_MULTI_PARTY = 6,
    BCM_OMCI_VOIP_VOICE_CTP_SIGNALLING_CODE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_voip_voice_ctp_signalling_code;


/** VoIP voice CTP (9.9.4) ME cfg data */
#define BCM_OMCI_CFG_DATA_USER_PROTOCOL_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_PPTP_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_VOICE_MEDIA_PROFILE_PTR_LEN 2
#define BCM_OMCI_CFG_DATA_SIGNALLING_CODE_LEN 1

typedef struct
{
    uint16_t user_protocol_ptr;
    uint16_t pptp_ptr;
    uint16_t voice_media_profile_ptr;
    bcm_omci_voip_voice_ctp_signalling_code signalling_code;
} bcm_omci_voip_voice_ctp_cfg_data;

/** VoIP voice CTP (9.9.4) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_voip_voice_ctp_cfg_data data;
} bcm_omci_voip_voice_ctp_cfg;

bcmos_bool bcm_omci_voip_voice_ctp_cfg_data_bounds_check(const bcm_omci_voip_voice_ctp_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_voip_voice_ctp_cfg_id *failed_prop);
void bcm_omci_voip_voice_ctp_cfg_data_set_default(bcm_omci_voip_voice_ctp_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_voip_voice_ctp_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);


/** TCP/UDP config data (9.4.3) ME cfg data */
#define BCM_OMCI_CFG_DATA_PORT_ID_LEN 2
#define BCM_OMCI_CFG_DATA_PROTOCOL_LEN 1
#define BCM_OMCI_CFG_DATA_TOS_LEN 1
#define BCM_OMCI_CFG_DATA_IP_HOST_PTR_LEN 2

typedef struct
{
    uint16_t port_id;
    uint8_t protocol;
    uint8_t tos;
    uint16_t ip_host_ptr;
} bcm_omci_tcp_udp_config_data_cfg_data;

/** TCP/UDP config data (9.4.3) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_tcp_udp_config_data_cfg_data data;
} bcm_omci_tcp_udp_config_data_cfg;

bcmos_bool bcm_omci_tcp_udp_config_data_cfg_data_bounds_check(const bcm_omci_tcp_udp_config_data_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_tcp_udp_config_data_cfg_id *failed_prop);
void bcm_omci_tcp_udp_config_data_cfg_data_set_default(bcm_omci_tcp_udp_config_data_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_tcp_udp_config_data_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_DIAL_PLAN_FORMAT_UNDEFINED = 0,
    BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_DIAL_PLAN_FORMAT_H248 = 1,
    BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_DIAL_PLAN_FORMAT_MGCP = 2,
    BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_DIAL_PLAN_FORMAT_VENDOR = 3,
    BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_DIAL_PLAN_FORMAT__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_network_dial_plan_table_dial_plan_format;


/** Network dial plan table (9.9.10) ME cfg data */
#define BCM_OMCI_CFG_DATA_DIAL_PLAN_NUMBER_LEN 2
#define BCM_OMCI_CFG_DATA_DIAL_PLAN_TABLE_MAX_SIZE_LEN 2
#define BCM_OMCI_CFG_DATA_CRITICAL_DIAL_TIMEOUT_LEN 2
#define BCM_OMCI_CFG_DATA_PARTIAL_DIAL_TIMEOUT_LEN 2
#define BCM_OMCI_CFG_DATA_DIAL_PLAN_FORMAT_LEN 1
#define BCM_OMCI_CFG_DATA_DIAL_PLAN_TABLE_LEN 30

typedef struct
{
    uint8_t dial_plan_id;
    uint8_t action;
    uint8_t dial_plan_token[28];
} bcm_omci_network_dial_plan_table_dial_plan_table;


typedef struct
{
    uint16_t dial_plan_number;
    uint16_t dial_plan_table_max_size;
    uint16_t critical_dial_timeout;
    uint16_t partial_dial_timeout;
    bcm_omci_network_dial_plan_table_dial_plan_format dial_plan_format;
    bcm_omci_network_dial_plan_table_dial_plan_table dial_plan_table;
} bcm_omci_network_dial_plan_table_cfg_data;

/** Network dial plan table (9.9.10) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_network_dial_plan_table_cfg_data data;
} bcm_omci_network_dial_plan_table_cfg;

bcmos_bool bcm_omci_network_dial_plan_table_cfg_data_bounds_check(const bcm_omci_network_dial_plan_table_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_network_dial_plan_table_cfg_id *failed_prop);
void bcm_omci_network_dial_plan_table_cfg_data_set_default(bcm_omci_network_dial_plan_table_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_network_dial_plan_table_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);


/** RTP profile data (9.9.7) ME cfg data */
#define BCM_OMCI_CFG_DATA_LOCAL_PORT_MIN_LEN 2
#define BCM_OMCI_CFG_DATA_LOCAL_PORT_MAX_LEN 2
#define BCM_OMCI_CFG_DATA_DSCP_MARK_LEN 1
#define BCM_OMCI_CFG_DATA_PIGGYBACK_EVENTS_LEN 1
#define BCM_OMCI_CFG_DATA_TONE_EVENTS_LEN 1
#define BCM_OMCI_CFG_DATA_DTMF_EVENTS_LEN 1
#define BCM_OMCI_CFG_DATA_CAS_EVENTS_LEN 1
#define BCM_OMCI_CFG_DATA_IP_HOST_CONFIG_PTR_LEN 2

typedef struct
{
    uint16_t local_port_min;
    uint16_t local_port_max;
    uint8_t dscp_mark;
    uint8_t piggyback_events;
    uint8_t tone_events;
    uint8_t dtmf_events;
    uint8_t cas_events;
    uint16_t ip_host_config_ptr;
} bcm_omci_rtp_profile_data_cfg_data;

/** RTP profile data (9.9.7) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_rtp_profile_data_cfg_data data;
} bcm_omci_rtp_profile_data_cfg;

bcmos_bool bcm_omci_rtp_profile_data_cfg_data_bounds_check(const bcm_omci_rtp_profile_data_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_rtp_profile_data_cfg_id *failed_prop);
void bcm_omci_rtp_profile_data_cfg_data_set_default(bcm_omci_rtp_profile_data_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_rtp_profile_data_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_POTS_UNI_ADMIN_STATE_UNLOCK = 0,
    BCM_OMCI_POTS_UNI_ADMIN_STATE_LOCK = 1,
    BCM_OMCI_POTS_UNI_ADMIN_STATE_SHUTDOWN = 2,
    BCM_OMCI_POTS_UNI_ADMIN_STATE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_pots_uni_admin_state;

typedef enum
{
    BCM_OMCI_POTS_UNI_IMPEDANCE_600_OHMS = 0,
    BCM_OMCI_POTS_UNI_IMPEDANCE_900_OHMS = 1,
    BCM_OMCI_POTS_UNI_IMPEDANCE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_pots_uni_impedance;

typedef enum
{
    BCM_OMCI_POTS_UNI_OPER_STATE_ENABLED = 0,
    BCM_OMCI_POTS_UNI_OPER_STATE_DISABLED = 1,
    BCM_OMCI_POTS_UNI_OPER_STATE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_pots_uni_oper_state;

typedef enum
{
    BCM_OMCI_POTS_UNI_HOOK_STATE_ON_HOOK = 0,
    BCM_OMCI_POTS_UNI_HOOK_STATE_OFF_HOOK = 1,
    BCM_OMCI_POTS_UNI_HOOK_STATE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_pots_uni_hook_state;


/** Physical path termination point POTS UNI (9.9.1) ME cfg data */
#define BCM_OMCI_CFG_DATA_ADMIN_STATE_LEN 1
#define BCM_OMCI_CFG_DATA_DEPRECATED1_LEN 2
#define BCM_OMCI_CFG_DATA_ARC_LEN 1
#define BCM_OMCI_CFG_DATA_ARC_INTERVAL_LEN 1
#define BCM_OMCI_CFG_DATA_IMPEDANCE_LEN 1
#define BCM_OMCI_CFG_DATA_TRANSMISSION_PATH_LEN 1
#define BCM_OMCI_CFG_DATA_RX_GAIN_LEN 1
#define BCM_OMCI_CFG_DATA_TX_GAIN_LEN 1
#define BCM_OMCI_CFG_DATA_OPER_STATE_LEN 1
#define BCM_OMCI_CFG_DATA_HOOK_STATE_LEN 1
#define BCM_OMCI_CFG_DATA_HOLDOVER_TIME_LEN 2
#define BCM_OMCI_CFG_DATA_NOMINAL_FEED_VOLTAGE_LEN 1

typedef struct
{
    bcm_omci_pots_uni_admin_state admin_state;
    uint16_t deprecated1;
    uint8_t arc;
    uint8_t arc_interval;
    bcm_omci_pots_uni_impedance impedance;
    uint8_t transmission_path;
    uint8_t rx_gain;
    uint8_t tx_gain;
    bcm_omci_pots_uni_oper_state oper_state;
    bcm_omci_pots_uni_hook_state hook_state;
    uint16_t holdover_time;
    uint8_t nominal_feed_voltage;
} bcm_omci_pots_uni_cfg_data;

/** Physical path termination point POTS UNI (9.9.1) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_pots_uni_cfg_data data;
} bcm_omci_pots_uni_cfg;

bcmos_bool bcm_omci_pots_uni_cfg_data_bounds_check(const bcm_omci_pots_uni_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_pots_uni_cfg_id *failed_prop);
void bcm_omci_pots_uni_cfg_data_set_default(bcm_omci_pots_uni_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_pots_uni_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_CIRCUIT_PACK_OPER_STATE_ENABLED = 0,
    BCM_OMCI_CIRCUIT_PACK_OPER_STATE_DISABLED = 1,
    BCM_OMCI_CIRCUIT_PACK_OPER_STATE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_circuit_pack_oper_state;

typedef enum
{
    BCM_OMCI_CIRCUIT_PACK_BRIDGED_OR_IP_BRIDGED = 0,
    BCM_OMCI_CIRCUIT_PACK_BRIDGED_OR_IP_ROUTED = 1,
    BCM_OMCI_CIRCUIT_PACK_BRIDGED_OR_IP_BRIDGED_AND_ROUTED = 2,
    BCM_OMCI_CIRCUIT_PACK_BRIDGED_OR_IP__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_circuit_pack_bridged_or_ip;

typedef enum
{
    BCM_OMCI_CIRCUIT_PACK_CARD_CONFIG_DS1 = 0,
    BCM_OMCI_CIRCUIT_PACK_CARD_CONFIG_E1 = 1,
    BCM_OMCI_CIRCUIT_PACK_CARD_CONFIG_J1 = 2,
    BCM_OMCI_CIRCUIT_PACK_CARD_CONFIG__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_circuit_pack_card_config;


/** Circuit pack (9.1.6) ME cfg data */
#define BCM_OMCI_CFG_DATA_TYPE_LEN 1
#define BCM_OMCI_CFG_DATA_NUMBER_OF_PORTS_LEN 1
#define BCM_OMCI_CFG_DATA_SERIAL_NUMBER_LEN 8
#define BCM_OMCI_CFG_DATA_VERSION_LEN 14
#define BCM_OMCI_CFG_DATA_VENDOR_ID_LEN 4
#define BCM_OMCI_CFG_DATA_ADMIN_STATE_LEN 1
#define BCM_OMCI_CFG_DATA_OPER_STATE_LEN 1
#define BCM_OMCI_CFG_DATA_BRIDGED_OR_IP_LEN 1
#define BCM_OMCI_CFG_DATA_EQUIP_ID_LEN 20
#define BCM_OMCI_CFG_DATA_CARD_CONFIG_LEN 1
#define BCM_OMCI_CFG_DATA_TCONT_BUFFER_NUMBER_LEN 1
#define BCM_OMCI_CFG_DATA_PRIORITY_QUEUE_NUMBER_LEN 1
#define BCM_OMCI_CFG_DATA_TRAFFIC_SCHED_NUMBER_LEN 1
#define BCM_OMCI_CFG_DATA_POWER_SHED_OVERRIDE_LEN 4

typedef struct
{
    uint8_t type;
    uint8_t number_of_ports;
    uint8_t serial_number[8];
    uint8_t version[14];
    uint8_t vendor_id[4];
    uint8_t admin_state;
    bcm_omci_circuit_pack_oper_state oper_state;
    bcm_omci_circuit_pack_bridged_or_ip bridged_or_ip;
    uint8_t equip_id[20];
    bcm_omci_circuit_pack_card_config card_config;
    uint8_t tcont_buffer_number;
    uint8_t priority_queue_number;
    uint8_t traffic_sched_number;
    uint32_t power_shed_override;
} bcm_omci_circuit_pack_cfg_data;

/** Circuit pack (9.1.6) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_circuit_pack_cfg_data data;
} bcm_omci_circuit_pack_cfg;

bcmos_bool bcm_omci_circuit_pack_cfg_data_bounds_check(const bcm_omci_circuit_pack_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_circuit_pack_cfg_id *failed_prop);
void bcm_omci_circuit_pack_cfg_data_set_default(bcm_omci_circuit_pack_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_circuit_pack_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_ENHANCED_SECURITY_CONTROL_BROADCAST_KEY_TABLE_ROW_CONTROL_SET_ROW = 0,
    BCM_OMCI_ENHANCED_SECURITY_CONTROL_BROADCAST_KEY_TABLE_ROW_CONTROL_CLEAR_ROW = 1,
    BCM_OMCI_ENHANCED_SECURITY_CONTROL_BROADCAST_KEY_TABLE_ROW_CONTROL_CLEAR_TABLE = 2,
    BCM_OMCI_ENHANCED_SECURITY_CONTROL_BROADCAST_KEY_TABLE_ROW_CONTROL__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_enhanced_security_control_broadcast_key_table_row_control;

/** Enhanced Security Control (9.13.11) ME cfg data */
#define BCM_OMCI_CFG_DATA_CRYPTO_CAPABILITIES_LEN 16
#define BCM_OMCI_CFG_DATA_OLT_RANDOM_CHALLENGE_TABLE_LEN 17
#define BCM_OMCI_CFG_DATA_OLT_CHALLENGE_STATUS_LEN 1
#define BCM_OMCI_CFG_DATA_ONU_SELECTED_CRYPTO_CAPABILITIES_LEN 1
#define BCM_OMCI_CFG_DATA_ONU_RANDOM_CHALLENGE_TABLE_LEN 16
#define BCM_OMCI_CFG_DATA_ONU_AUTH_RESULT_TABLE_LEN 16
#define BCM_OMCI_CFG_DATA_OLT_AUTH_RESULT_TABLE_LEN 17
#define BCM_OMCI_CFG_DATA_OLT_RESULT_STATUS_LEN 1
#define BCM_OMCI_CFG_DATA_ONU_AUTH_STATUS_LEN 1
#define BCM_OMCI_CFG_DATA_MASTER_SESSION_KEY_NAME_LEN 16
#define BCM_OMCI_CFG_DATA_BROADCAST_KEY_TABLE_LEN 18
#define BCM_OMCI_CFG_DATA_EFFECTIVE_KEY_LENGTH_LEN 2

typedef struct
{
    uint8_t row_number;
    uint8_t content[16];
} bcm_omci_enhanced_security_control_olt_random_challenge_table;


typedef struct
{
    uint8_t content[16];
} bcm_omci_enhanced_security_control_onu_random_challenge_table;


typedef struct
{
    uint8_t content[16];
} bcm_omci_enhanced_security_control_onu_auth_result_table;


typedef struct
{
    uint8_t row_number;
    uint8_t content[16];
} bcm_omci_enhanced_security_control_olt_auth_result_table;


typedef struct
{
    bcm_omci_enhanced_security_control_broadcast_key_table_row_control row_control;
    uint8_t row_number;
    uint8_t content[16];
} bcm_omci_enhanced_security_control_broadcast_key_table;


typedef struct
{
    uint8_t crypto_capabilities[16];
    bcm_omci_enhanced_security_control_olt_random_challenge_table olt_random_challenge_table;
    uint8_t olt_challenge_status;
    uint8_t onu_selected_crypto_capabilities;
    bcm_omci_enhanced_security_control_onu_random_challenge_table onu_random_challenge_table;
    bcm_omci_enhanced_security_control_onu_auth_result_table onu_auth_result_table;
    bcm_omci_enhanced_security_control_olt_auth_result_table olt_auth_result_table;
    uint8_t olt_result_status;
    uint8_t onu_auth_status;
    uint8_t master_session_key_name[16];
    bcm_omci_enhanced_security_control_broadcast_key_table broadcast_key_table;
    uint16_t effective_key_length;
} bcm_omci_enhanced_security_control_cfg_data;

/** Enhanced Security Control (9.13.11) ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_enhanced_security_control_cfg_data data;
} bcm_omci_enhanced_security_control_cfg;

bcmos_bool bcm_omci_enhanced_security_control_cfg_data_bounds_check(const bcm_omci_enhanced_security_control_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_enhanced_security_control_cfg_id *failed_prop);
void bcm_omci_enhanced_security_control_cfg_data_set_default(bcm_omci_enhanced_security_control_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_enhanced_security_control_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);

typedef enum
{
    BCM_OMCI_TRAFFIC_DESCRIPTOR_COLOUR_MODE_COLUR_BLIND = 0,
    BCM_OMCI_TRAFFIC_DESCRIPTOR_COLOUR_MODE_COLUR_AWARE = 1,
    BCM_OMCI_TRAFFIC_DESCRIPTOR_COLOUR_MODE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_traffic_descriptor_colour_mode;

typedef enum
{
    BCM_OMCI_TRAFFIC_DESCRIPTOR_ING_COLOR_MARKING_NO_MARKING = 0,
    BCM_OMCI_TRAFFIC_DESCRIPTOR_ING_COLOR_MARKING_DEI = 2,
    BCM_OMCI_TRAFFIC_DESCRIPTOR_ING_COLOR_MARKING_PCP_8P0D = 3,
    BCM_OMCI_TRAFFIC_DESCRIPTOR_ING_COLOR_MARKING_PCP_7P1D = 4,
    BCM_OMCI_TRAFFIC_DESCRIPTOR_ING_COLOR_MARKING_PCP_6P2D = 5,
    BCM_OMCI_TRAFFIC_DESCRIPTOR_ING_COLOR_MARKING_PCP_5P3D = 6,
    BCM_OMCI_TRAFFIC_DESCRIPTOR_ING_COLOR_MARKING_DSCP_AF_CLASS = 7,
    BCM_OMCI_TRAFFIC_DESCRIPTOR_ING_COLOR_MARKING__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_traffic_descriptor_ing_color_marking;

typedef enum
{
    BCM_OMCI_TRAFFIC_DESCRIPTOR_EG_COLOR_MARKING_NO_MARKING = 0,
    BCM_OMCI_TRAFFIC_DESCRIPTOR_EG_COLOR_MARKING_INTERNAL_MARKING_ONLY = 1,
    BCM_OMCI_TRAFFIC_DESCRIPTOR_EG_COLOR_MARKING_DEI = 2,
    BCM_OMCI_TRAFFIC_DESCRIPTOR_EG_COLOR_MARKING_PCP_8P0D = 3,
    BCM_OMCI_TRAFFIC_DESCRIPTOR_EG_COLOR_MARKING_PCP_7P1D = 4,
    BCM_OMCI_TRAFFIC_DESCRIPTOR_EG_COLOR_MARKING_PCP_6P2D = 5,
    BCM_OMCI_TRAFFIC_DESCRIPTOR_EG_COLOR_MARKING_PCP_5P3D = 6,
    BCM_OMCI_TRAFFIC_DESCRIPTOR_EG_COLOR_MARKING_DSCP_AF_CLASS = 7,
    BCM_OMCI_TRAFFIC_DESCRIPTOR_EG_COLOR_MARKING__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_traffic_descriptor_eg_color_marking;

typedef enum
{
    BCM_OMCI_TRAFFIC_DESCRIPTOR_METER_TYPE_NOT_SPECIFIED = 0,
    BCM_OMCI_TRAFFIC_DESCRIPTOR_METER_TYPE_RFC_4115 = 1,
    BCM_OMCI_TRAFFIC_DESCRIPTOR_METER_TYPE_RFC_2698 = 2,
    BCM_OMCI_TRAFFIC_DESCRIPTOR_METER_TYPE__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_traffic_descriptor_meter_type;


/** traffic descriptor profiles ME cfg data */
#define BCM_OMCI_CFG_DATA_CIR_LEN 4
#define BCM_OMCI_CFG_DATA_PIR_LEN 4
#define BCM_OMCI_CFG_DATA_CBS_LEN 4
#define BCM_OMCI_CFG_DATA_PBS_LEN 4
#define BCM_OMCI_CFG_DATA_COLOUR_MODE_LEN 1
#define BCM_OMCI_CFG_DATA_ING_COLOR_MARKING_LEN 1
#define BCM_OMCI_CFG_DATA_EG_COLOR_MARKING_LEN 1
#define BCM_OMCI_CFG_DATA_METER_TYPE_LEN 1

typedef struct
{
    uint32_t cir;
    uint32_t pir;
    uint32_t cbs;
    uint32_t pbs;
    bcm_omci_traffic_descriptor_colour_mode colour_mode;
    bcm_omci_traffic_descriptor_ing_color_marking ing_color_marking;
    bcm_omci_traffic_descriptor_eg_color_marking eg_color_marking;
    bcm_omci_traffic_descriptor_meter_type meter_type;
} bcm_omci_traffic_descriptor_cfg_data;

/** traffic descriptor profiles ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_traffic_descriptor_cfg_data data;
} bcm_omci_traffic_descriptor_cfg;

bcmos_bool bcm_omci_traffic_descriptor_cfg_data_bounds_check(const bcm_omci_traffic_descriptor_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_traffic_descriptor_cfg_id *failed_prop);
void bcm_omci_traffic_descriptor_cfg_data_set_default(bcm_omci_traffic_descriptor_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_traffic_descriptor_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);


/** Ethernet Frame Extended PM ME cfg data */
#define BCM_OMCI_CFG_DATA_INTERVAL_END_TIME_LEN 1
#define BCM_OMCI_CFG_DATA_CONTROL_BLOCK_LEN 16
#define BCM_OMCI_CFG_DATA_DROP_EVENTS_LEN 8
#define BCM_OMCI_CFG_DATA_OCTETS_LEN 8
#define BCM_OMCI_CFG_DATA_FRAMES_LEN 8
#define BCM_OMCI_CFG_DATA_BROADCAST_FRAMES_LEN 8
#define BCM_OMCI_CFG_DATA_MULTICAST_FRAMES_LEN 8
#define BCM_OMCI_CFG_DATA_CRC_ERRORED_FRAMES_LEN 8
#define BCM_OMCI_CFG_DATA_UNDERSIZE_FRAMES_LEN 8
#define BCM_OMCI_CFG_DATA_OVERSIZE_FRAMES_LEN 8
#define BCM_OMCI_CFG_DATA_FRAMES_64OCTETS_LEN 8
#define BCM_OMCI_CFG_DATA_FRAMES_65_TO_127_OCTETS_LEN 8
#define BCM_OMCI_CFG_DATA_FRAMES_128_TO_255_OCTETS_LEN 8
#define BCM_OMCI_CFG_DATA_FRAMES_256_TO_511_OCTETS_LEN 8
#define BCM_OMCI_CFG_DATA_FRAMES_512_TO_1023_OCTETS_LEN 8
#define BCM_OMCI_CFG_DATA_FRAMES_1024_TO_1518_OCTETS_LEN 8

typedef struct
{
    uint16_t threshold_data_id;
    uint16_t parent_me_class;
    uint16_t parent_me_instance;
    uint16_t accumulation_disbale;
    uint16_t tca_disable;
    uint16_t control_fields;
    uint16_t tci;
    uint16_t reserved;
} bcm_omci_eth_frame_extended_pm_64_control_block;


typedef struct
{
    uint8_t interval_end_time;
    bcm_omci_eth_frame_extended_pm_64_control_block control_block;
    uint8_t drop_events[8];
    uint8_t octets[8];
    uint8_t frames[8];
    uint8_t broadcast_frames[8];
    uint8_t multicast_frames[8];
    uint8_t crc_errored_frames[8];
    uint8_t undersize_frames[8];
    uint8_t oversize_frames[8];
    uint8_t frames_64octets[8];
    uint8_t frames_65_to_127_octets[8];
    uint8_t frames_128_to_255_octets[8];
    uint8_t frames_256_to_511_octets[8];
    uint8_t frames_512_to_1023_octets[8];
    uint8_t frames_1024_to_1518_octets[8];
} bcm_omci_eth_frame_extended_pm_64_cfg_data;

/** Ethernet Frame Extended PM ME cfg */
typedef struct
{
    bcm_omci_me_hdr hdr;
    bcm_omci_eth_frame_extended_pm_64_cfg_data data;
} bcm_omci_eth_frame_extended_pm_64_cfg;

bcmos_bool bcm_omci_eth_frame_extended_pm_64_cfg_data_bounds_check(const bcm_omci_eth_frame_extended_pm_64_cfg_data *me, bcm_omci_presence_mask fields_present, bcm_omci_eth_frame_extended_pm_64_cfg_id *failed_prop);
void bcm_omci_eth_frame_extended_pm_64_cfg_data_set_default(bcm_omci_eth_frame_extended_pm_64_cfg_data *me, bcm_omci_presence_mask fields_present);
bcmos_bool bcm_omci_eth_frame_extended_pm_64_key_bounds_check(const bcm_omci_me_key *me, bcm_omci_presence_mask fields_present, bcm_omci_me_key_id *failed_prop);


#endif
