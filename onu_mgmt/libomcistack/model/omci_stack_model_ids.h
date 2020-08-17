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

#ifndef _OMCI_STACK_MODEL_IDS_H_
#define _OMCI_STACK_MODEL_IDS_H_

typedef enum
{
    BCM_OMCI_ME_KEY_ID_LOGICAL_PON = 0,
    BCM_OMCI_ME_KEY_ID_PON_ONU_ID,
    BCM_OMCI_ME_KEY_ID_ENTITY_CLASS,
    BCM_OMCI_ME_KEY_ID_ENTITY_INSTANCE,
    BCM_OMCI_ME_KEY_ID__NUM_OF
} bcm_omci_me_key_id;


/** Identifiers for all attributes contained in GAL Ethernet Profile ME */
typedef enum bcm_omci_gal_eth_prof_cfg_id
{
    BCM_OMCI_GAL_ETH_PROF_CFG_ID_MAX_GEM_PAYLOAD_SIZE = 0, /* Max GEM payload Size */
    BCM_OMCI_GAL_ETH_PROF_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_gal_eth_prof_cfg_id;

/** Identifiers for all attributes contained in GEM Interworking Termination Point ME */
typedef enum bcm_omci_gem_iw_tp_cfg_id
{
    BCM_OMCI_GEM_IW_TP_CFG_ID_GEM_PORT_NET_CTP_CONN_PTR = 0, /* GEM port network CTP connectivity pointer */
    BCM_OMCI_GEM_IW_TP_CFG_ID_IW_OPT = 1, /* Interworking option */
    BCM_OMCI_GEM_IW_TP_CFG_ID_SVC_PROF_PTR = 2, /* Service profile pointer */
    BCM_OMCI_GEM_IW_TP_CFG_ID_IW_TP_PTR = 3, /* Interworking termination point pointer */
    BCM_OMCI_GEM_IW_TP_CFG_ID_PPTP_COUNT = 4, /* PPTP Counter */
    BCM_OMCI_GEM_IW_TP_CFG_ID_OPER_STATE = 5, /* Operational State */
    BCM_OMCI_GEM_IW_TP_CFG_ID_GAL_PROF_PTR = 6, /* GAL Profile Pointer */
    BCM_OMCI_GEM_IW_TP_CFG_ID_GAL_LPBK_CONFIG = 7, /* GAL Loopback Config */
    BCM_OMCI_GEM_IW_TP_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_gem_iw_tp_cfg_id;

/** Identifiers for all attributes contained in GEM Port Network CTP ME */
typedef enum bcm_omci_gem_port_net_ctp_cfg_id
{
    BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_PORT_ID = 0, /* Port ID */
    BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TCONT_PTR = 1, /* TCONT Pointer */
    BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_DIRECTION = 2, /* Direction */
    BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_MGMT_PTR_US = 3, /* Traffic Management Pointer for US */
    BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_DESC_PROF_PTR_US = 4, /* Traffic Descriptor Profile Pointer for US */
    BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_UNI_COUNT = 5, /* Uni counter */
    BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_PRI_QUEUE_PTR_DS = 6, /* Priority Queue Pointer for downstream */
    BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_ENCRYPTION_STATE = 7, /* Encryption State */
    BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_DESC_PROF_PTR_DS = 8, /* Traffic Descriptor profile pointer for DS */
    BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_ENCRYPTION_KEY_RING = 9, /* Encryption Key Ring */
    BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_gem_port_net_ctp_cfg_id;

/** Identifiers for all attributes contained in IEEE 802.1p mapper service profile ME */
typedef enum bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_id
{
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_TP_PTR = 0, /* TP pointer */
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_0 = 1, /* Interwork TP pointer for P-bit priority 0: */
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_1 = 2, /* Interwork TP pointer for P-bit priority 1 */
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_2 = 3, /* Interwork TP pointer for P-bit priority 2 */
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_3 = 4, /* Interwork TP pointer for P-bit priority 3 */
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_4 = 5, /* Interwork TP pointer for P-bit priority 4 */
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_5 = 6, /* Interwork TP pointer for P-bit priority 5 */
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_6 = 7, /* Interwork TP pointer for P-bit priority 6 */
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_7 = 8, /* Interwork TP pointer for P-bit priority 7 */
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_UNMARKED_FRAME_OPT = 9, /* Unmarked Frame option */
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_DSCP_TO_PBIT_MAPPING = 10, /* DSCP to P-bit mapping */
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_DEFAULT_PBIT_ASSUMPTION = 11, /* Default P-bit assumption */
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_MAPPER_TP_TYPE = 12, /* TP Type */
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_id;

/** Identifiers for all attributes contained in MAC Bridge Port Configuration Data ME */
typedef enum bcm_omci_mac_bridge_port_config_data_cfg_id
{
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_BRIDGE_ID_PTR = 0, /* Bridge Id Pointer */
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_NUM = 1, /* Port num */
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_TP_TYPE = 2, /* TP Type */
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_TP_PTR = 3, /* TP Pointer */
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_PRI = 4, /* Port Priority */
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_PATH_COST = 5, /* Port Path Cost */
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_SPANNING_TREE_IND = 6, /* Port Path Cost */
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_DEPRECATED_1 = 7, /* Deprecated 1 */
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_DEPRECATED_2 = 8, /* Deprecated 2 */
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_MAC_ADDR = 9, /* Port MAC Addr */
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_OUTBOUND_TD_PTR = 10, /* Outbound TD Pointer */
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_INBOUND_TD_PTR = 11, /* Inbound TD Pointer */
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_MAC_LEARNING_DEPTH = 12, /* MAC Learning Depth */
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_mac_bridge_port_config_data_cfg_id;

/** Identifiers for all attributes contained in MAC Bridge Service Profile ME */
typedef enum bcm_omci_mac_bridge_svc_prof_cfg_id
{
    BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_SPANNING_TREE_IND = 0, /* Spanning Tree Indication (bool) */
    BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_LEARNING_IND = 1, /* Learning Indication (bool) */
    BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_PORT_BRIDGING_IND = 2, /* Port Bridging Indication (bool) */
    BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_PRI = 3, /* Priority */
    BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_MAX_AGE = 4, /* Max Age */
    BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_HELLO_TIME = 5, /* Hello Time */
    BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_FORWARD_DELAY = 6, /* Forward Delay */
    BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_UNKNOWN_MAC_ADDR_DISCARD = 7, /* Unknown MAC Address Discard (Bool) */
    BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_MAC_LEARNING_DEPTH = 8, /* MAC Learning Depth */
    BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_DYNAMIC_FILTERING_AGEING_TIME = 9, /* Dynamic Filtering Ageing Time */
    BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_mac_bridge_svc_prof_cfg_id;

/** Identifiers for all attributes contained in VLAN Tagging Filter Data ME */
typedef enum bcm_omci_vlan_tag_filter_data_cfg_id
{
    BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_VLAN_FILTER_LIST = 0, /* VLAN Filter List */
    BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_FORWARD_OPER = 1, /* Forward Operation */
    BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_NUM_OF_ENTRIES = 2, /* number of entries */
    BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_vlan_tag_filter_data_cfg_id;

/** Identifiers for all attributes contained in T-CONT ME */
typedef enum bcm_omci_tcont_cfg_id
{
    BCM_OMCI_TCONT_CFG_ID_ALLOC_ID = 0, /* Alloc-ID */
    BCM_OMCI_TCONT_CFG_ID_DEPRECATED = 1, /* Deprecated */
    BCM_OMCI_TCONT_CFG_ID_POLICY = 2, /* Policy */
    BCM_OMCI_TCONT_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_tcont_cfg_id;

/** Identifiers for all attributes contained in Extended VLAN Tagging Operation Configuration Data ME */
typedef enum bcm_omci_ext_vlan_tag_oper_config_data_cfg_id
{
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_ASSOC_TYPE = 0, /* Association Type */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_RX_FRAME_VLAN_TAG_OPER_TABLE_MAX_SIZE = 1, /* Rx Frame VLAN Tagging Operation Table Max Size */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_INPUT_TPID = 2, /* Input TPID */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_OUTPUT_TPID = 3, /* Output TPID */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_DS_MODE = 4, /* Downstream Mode */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_RX_FRAME_VLAN_TAG_OPER_TABLE = 5, /* Downstream Mode */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_ASSOC_ME_PTR = 6, /* Associated ME Pointer */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_DSCP_TO_PBIT_MAPPING = 7, /* DSCP to P-bit Mapping */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_ext_vlan_tag_oper_config_data_cfg_id;

/** Identifiers for all attributes contained in priority queue-G ME */
typedef enum bcm_omci_priority_queue_g_cfg_id
{
    BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_QUEUE_CONFIG_OPT = 0, /* Queue configuration option */
    BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_MAX_QUEUE_SIZE = 1, /* Maximum queue size */
    BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_ALLOCATED_QUEUE_SIZE = 2, /* Allocated queue size */
    BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DISCARD_COUNTER_RESET_INTERVAL = 3, /* Discard-block counter reset interval */
    BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DISCARD_THRESHOLD = 4, /* Threshold value for discarded blocks due to buffer overflow */
    BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_RELATED_PORT = 5, /* Related port */
    BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_TRAFFIC_SCHEDULER_PTR = 6, /* Traffic scheduler pointer */
    BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_WEIGHT = 7, /* Weight */
    BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_OPER = 8, /* Back pressure operation */
    BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_TIME = 9, /* Back pressure time */
    BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_OCCUR_QUEUE_THR = 10, /* Back pressure occur queue threshold */
    BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_CLEAR_QUEUE_THR = 11, /* Back pressure clear queue threshold */
    BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_PACKET_DROP_QUEUE_THR = 12, /* Packet drop queue thr */
    BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_PACKET_DROP_MAX_P = 13, /* Packet drop max_p */
    BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_QUEUE_DROP_W_Q = 14, /* Queue drop w_q */
    BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DROP_PRECEDENCE_COLOUR_MARKING = 15, /* Drop precedence colour marking */
    BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_priority_queue_g_cfg_id;

/** Identifiers for all attributes contained in Multicast GEM interworking termination point ME */
typedef enum bcm_omci_mcast_gem_iw_tp_cfg_id
{
    BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_GEM_PORT_NET_CTP_CONN_PTR = 0, /* GEM port network CTP connectivity pointer */
    BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IW_OPT = 1, /* Interworking option */
    BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_SVC_PROF_PTR = 2, /* Service profile pointer */
    BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_NOT_USED_1 = 3, /* Not used 1 */
    BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_PPTP_COUNTER = 4, /* PPTP Counter */
    BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_OPER_STATE = 5, /* Operational state */
    BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_GAL_PROF_PTR = 6, /* GAL profile pointer */
    BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_NOT_USED_2 = 7, /* Not used 2 */
    BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IPV_4_MCAST_ADDR_TABLE = 8, /* IPv4 multicast address table */
    BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IPV_6_MCAST_ADDR_TABLE = 9, /* IPv6 multicast address table */
    BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_mcast_gem_iw_tp_cfg_id;

/** Identifiers for all attributes contained in Multicast Operations Profile ME */
typedef enum bcm_omci_mcast_operations_profile_cfg_id
{
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IGMP_VERSION = 0, /* IGMP version */
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IGMP_FUNCTION = 1, /* IGMP function */
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IMMEDIATE_LEAVE = 2, /* Immediate leave */
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_TCI = 3, /* Upstream IGMP TCI */
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_TAG_CONTROL = 4, /* Upstream IGMP tag control */
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_RATE = 5, /* Upstream IGMP rate */
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_DYNAMIC_ACCESS_CONTROL_LIST_TABLE = 6, /* Dynamic access control list table */
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_STATIC_ACCESS_CONTROL_LIST_TABLE = 7, /* Static access control list table */
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_LOST_GROUPS_LIST_TABLE = 8, /* Lost groups list table */
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_ROBUSTNESS = 9, /* Robustness */
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERIER_IP_ADDRESS = 10, /* Querier IP address */
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERY_INTERVAL = 11, /* query_interval */
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERY_MAX_RESPONSE_TIME = 12, /* Query max response time */
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_LAST_MEMBER_QUERY_INTERVAL = 13, /* Last member query interval */
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UNAUTH_JOIN_REQUEST_BEHAVIOUR = 14, /* Unauthorized join request behaviour */
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_DS_IGMP_AND_MULTICAST_TCI = 15, /* Downstream IGMP and multicast TCI */
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_mcast_operations_profile_cfg_id;

/** Identifiers for all attributes contained in Multicast subscriber config info ME */
typedef enum bcm_omci_mcast_subscriber_config_info_cfg_id
{
    BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_ME_TYPE = 0, /* ME Type */
    BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MCAST_OPERATIONS_PROF_PTR = 1, /* Multicast operations profile pointer */
    BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MAX_SIMULTANEOUS_GROUPS = 2, /* Max simultaneous groups */
    BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MAX_MULTICAST_BW = 3, /* Max multicast bandwidth */
    BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_BW_ENFORCEMENT = 4, /* Bandwidth enforcement */
    BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MCAST_SVC_PKG_TABLE = 5, /* Multicast service package table */
    BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_ALLOWED_PREVIEW_GROUPS_TABLE = 6, /* Allowed preview groups table */
    BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_mcast_subscriber_config_info_cfg_id;

/** Identifiers for all attributes contained in PPTP Ethernet UNI ME */
typedef enum bcm_omci_pptp_eth_uni_cfg_id
{
    BCM_OMCI_PPTP_ETH_UNI_CFG_ID_EXPECTED_TYPE = 0, /* Expected Type */
    BCM_OMCI_PPTP_ETH_UNI_CFG_ID_SENSED_TYPE = 1, /* Sensed Type */
    BCM_OMCI_PPTP_ETH_UNI_CFG_ID_AUTO_DETECTION_CONFIG = 2, /* Auto Detection Configuration */
    BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ETHERNET_LOOPBACK_CONFIG = 3, /* Ethernet loopback configuration */
    BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ADMIN_STATE = 4, /* Administrative State */
    BCM_OMCI_PPTP_ETH_UNI_CFG_ID_OPER_STATE = 5, /* Operational State */
    BCM_OMCI_PPTP_ETH_UNI_CFG_ID_CONFIG_IND = 6, /* Config Indication */
    BCM_OMCI_PPTP_ETH_UNI_CFG_ID_MAX_FRAME_SIZE = 7, /* Max frame size */
    BCM_OMCI_PPTP_ETH_UNI_CFG_ID_DTE_OR_DCE_IND = 8, /* DTE or DCE ind */
    BCM_OMCI_PPTP_ETH_UNI_CFG_ID_PAUSE_TIME = 9, /* Pause time */
    BCM_OMCI_PPTP_ETH_UNI_CFG_ID_BRIDGED_OR_IP_IND = 10, /* Bridged or IP ind */
    BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ARC = 11, /* ARC */
    BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ARC_INTERVAL = 12, /* ARC interval */
    BCM_OMCI_PPTP_ETH_UNI_CFG_ID_PPPOE_FILTER = 13, /* PPPoE filter */
    BCM_OMCI_PPTP_ETH_UNI_CFG_ID_POWER_CONTROL = 14, /* Power control */
    BCM_OMCI_PPTP_ETH_UNI_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_pptp_eth_uni_cfg_id;

/** Identifiers for all attributes contained in Virtual Ethernet Interface Point ME */
typedef enum bcm_omci_virtual_eth_intf_point_cfg_id
{
    BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_ADMIN_STATE = 0, /* Admin state */
    BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_OPER_STATE = 1, /* Operational state */
    BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_INTERDOMAIN_NAME = 2, /* Interdomain Name */
    BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_TCP_UDP_PTR = 3, /* TCP/UDP pointer */
    BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_IANA_ASSIGNED_PORT = 4, /* IANA Assigned port */
    BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_virtual_eth_intf_point_cfg_id;

/** Identifiers for all attributes contained in ONU data ME */
typedef enum bcm_omci_onu_data_cfg_id
{
    BCM_OMCI_ONU_DATA_CFG_ID_MIB_DATA_SYNC = 0,
    BCM_OMCI_ONU_DATA_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_onu_data_cfg_id;

/** Identifiers for all attributes contained in ONU-G (9.1.1) ME */
typedef enum bcm_omci_onu_g_cfg_id
{
    BCM_OMCI_ONU_G_CFG_ID_VENDOR_ID = 0, /* 4 MS bytes of ONU serial number */
    BCM_OMCI_ONU_G_CFG_ID_VERSION = 1, /* ONU version string by the vendor */
    BCM_OMCI_ONU_G_CFG_ID_SERIAL_NUMBER = 2, /* Serial number */
    BCM_OMCI_ONU_G_CFG_ID_TRAFFIC_MANAGEMENT = 3,
    BCM_OMCI_ONU_G_CFG_ID_DEPRECATED0 = 4,
    BCM_OMCI_ONU_G_CFG_ID_BATTERY_BACKUP = 5,
    BCM_OMCI_ONU_G_CFG_ID_ADMIN_STATE = 6,
    BCM_OMCI_ONU_G_CFG_ID_OPER_STATE = 7,
    BCM_OMCI_ONU_G_CFG_ID_SURVIVAL_TIME = 8,
    BCM_OMCI_ONU_G_CFG_ID_LOGICAL_ONU_ID = 9,
    BCM_OMCI_ONU_G_CFG_ID_LOGICAL_PASSWORD = 10,
    BCM_OMCI_ONU_G_CFG_ID_CREDENTIALS_STATUS = 11,
    BCM_OMCI_ONU_G_CFG_ID_EXTENDED_TC_OPTIONS = 12,
    BCM_OMCI_ONU_G_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_onu_g_cfg_id;

/** Identifiers for all attributes contained in ONU2-G (9.1.2) ME */
typedef enum bcm_omci_onu2_g_cfg_id
{
    BCM_OMCI_ONU2_G_CFG_ID_EQUIPMENT_ID = 0,
    BCM_OMCI_ONU2_G_CFG_ID_OMCC_VERSION = 1,
    BCM_OMCI_ONU2_G_CFG_ID_VENDOR_PRODUCT_CODE = 2,
    BCM_OMCI_ONU2_G_CFG_ID_SECURITY_CAPABILITY = 3,
    BCM_OMCI_ONU2_G_CFG_ID_SECURITY_MODE = 4,
    BCM_OMCI_ONU2_G_CFG_ID_TOTAL_PRIORITY_QUEUE_NUMBER = 5,
    BCM_OMCI_ONU2_G_CFG_ID_TOTAL_TRAF_SCHED_NUMBER = 6,
    BCM_OMCI_ONU2_G_CFG_ID_DEPRECATED0 = 7,
    BCM_OMCI_ONU2_G_CFG_ID_TOTAL_GEM_PORT_NUMBER = 8,
    BCM_OMCI_ONU2_G_CFG_ID_SYS_UP_TIME = 9, /* In 10ms intervals */
    BCM_OMCI_ONU2_G_CFG_ID_CONNECTIVITY_CAPABILITY = 10,
    BCM_OMCI_ONU2_G_CFG_ID_CONNECTIVITY_MODE = 11,
    BCM_OMCI_ONU2_G_CFG_ID_QOS_CONFIG_FLEXIBILITY = 12, /* Actually it is an enum */
    BCM_OMCI_ONU2_G_CFG_ID_PRIORITY_QUEUE_SCALE_FACTOR = 13,
    BCM_OMCI_ONU2_G_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_onu2_g_cfg_id;

/** Identifiers for all attributes contained in Software image (9.1.4) ME */
typedef enum bcm_omci_sw_image_cfg_id
{
    BCM_OMCI_SW_IMAGE_CFG_ID_VERSION = 0,
    BCM_OMCI_SW_IMAGE_CFG_ID_IS_COMMITTED = 1,
    BCM_OMCI_SW_IMAGE_CFG_ID_IS_ACTIVE = 2,
    BCM_OMCI_SW_IMAGE_CFG_ID_IS_VALID = 3,
    BCM_OMCI_SW_IMAGE_CFG_ID_PRODUCT_CODE = 4,
    BCM_OMCI_SW_IMAGE_CFG_ID_IMAGE_HASH = 5,
    BCM_OMCI_SW_IMAGE_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_sw_image_cfg_id;

/** Identifiers for all attributes contained in ANI-G (9.2.1) ME */
typedef enum bcm_omci_ani_g_cfg_id
{
    BCM_OMCI_ANI_G_CFG_ID_SR_INDICATION = 0,
    BCM_OMCI_ANI_G_CFG_ID_TOTAL_TCONT_NUMBER = 1,
    BCM_OMCI_ANI_G_CFG_ID_GEM_BLOCK_LENGTH = 2,
    BCM_OMCI_ANI_G_CFG_ID_PIGGY_BACK_DBA_REPORTING = 3,
    BCM_OMCI_ANI_G_CFG_ID_DEPRECATED = 4,
    BCM_OMCI_ANI_G_CFG_ID_SF_THRESHOLD = 5,
    BCM_OMCI_ANI_G_CFG_ID_SD_THRESHOLD = 6,
    BCM_OMCI_ANI_G_CFG_ID_ARC = 7,
    BCM_OMCI_ANI_G_CFG_ID_ARC_INTERVAL = 8,
    BCM_OMCI_ANI_G_CFG_ID_OPTICAL_SIGNAL_LEVEL = 9,
    BCM_OMCI_ANI_G_CFG_ID_LOWER_OPTICAL_THRESHOLD = 10,
    BCM_OMCI_ANI_G_CFG_ID_UPPER_OPTICAL_THRESHOLD = 11,
    BCM_OMCI_ANI_G_CFG_ID_ONU_RESPONSE_TIME = 12,
    BCM_OMCI_ANI_G_CFG_ID_TRANSMIT_OPTICAL_LEVEL = 13,
    BCM_OMCI_ANI_G_CFG_ID_LOWER_TRANSMIT_POWER_THRESHOLD = 14,
    BCM_OMCI_ANI_G_CFG_ID_UPPER_TRANSMIT_POWER_THRESHOLD = 15,
    BCM_OMCI_ANI_G_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_ani_g_cfg_id;

/** Identifiers for all attributes contained in GEM Port Network CTP PM(9.2.13) ME */
typedef enum bcm_omci_gem_port_net_ctp_pm_cfg_id
{
    BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_INTERVAL_END_TIME = 0,
    BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_THRESHOLD_DATA = 1,
    BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_TX_GEM_FRAMES = 2,
    BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_RX_GEM_FRAMES = 3,
    BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_RX_PAYLOAD_BYTES = 4,
    BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_TX_PAYLOAD_BYTES = 5,
    BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_ENCRY_KEY_ERRORS = 6,
    BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_gem_port_net_ctp_pm_cfg_id;

/** Identifiers for all attributes contained in ETH FRAME UPSTREAM PM(9.3.30) ME */
typedef enum bcm_omci_eth_frame_upstream_pm_cfg_id
{
    BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_INTERVAL_END_TIME = 0,
    BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_THRESHOLD_DATA = 1,
    BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_DROP_EVENTS = 2,
    BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_OCTETS = 3,
    BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS = 4,
    BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_BROADCAST_PACKETS = 5,
    BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_MULTICAST_PACKETS = 6,
    BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_CRC_ERRORED_PACKETS = 7,
    BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_UNDERSIZE_PACKETS = 8,
    BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_OVERSIZE_PACKETS = 9,
    BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_64_OCTETS = 10,
    BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_65_127_OCTETS = 11,
    BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_128_255_OCTETS = 12,
    BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_256_511_OCTETS = 13,
    BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_512_1023_OCTETS = 14,
    BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_1024_1518_OCTETS = 15,
    BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_eth_frame_upstream_pm_cfg_id;

/** Identifiers for all attributes contained in ETH FRAME DOWNSTREAM PM(9.3.31) ME */
typedef enum bcm_omci_eth_frame_downstream_pm_cfg_id
{
    BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_INTERVAL_END_TIME = 0,
    BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_THRESHOLD_DATA = 1,
    BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_DROP_EVENTS = 2,
    BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_OCTETS = 3,
    BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS = 4,
    BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_BROADCAST_PACKETS = 5,
    BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_MULTICAST_PACKETS = 6,
    BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_CRC_ERRORED_PACKETS = 7,
    BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_UNDERSIZE_PACKETS = 8,
    BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_OVERSIZE_PACKETS = 9,
    BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_64_OCTETS = 10,
    BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_65_127_OCTETS = 11,
    BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_128_255_OCTETS = 12,
    BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_256_511_OCTETS = 13,
    BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_512_1023_OCTETS = 14,
    BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_1024_1518_OCTETS = 15,
    BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_eth_frame_downstream_pm_cfg_id;

/** Identifiers for all attributes contained in FEC PERFORMANCE PM DATA(9.2.9) ME */
typedef enum bcm_omci_fec_pm_cfg_id
{
    BCM_OMCI_FEC_PM_CFG_ID_INTERVAL_END_TIME = 0,
    BCM_OMCI_FEC_PM_CFG_ID_THRESHOLD_DATA = 1,
    BCM_OMCI_FEC_PM_CFG_ID_CORRECTED_BYTES = 2,
    BCM_OMCI_FEC_PM_CFG_ID_CORRECTED_CODE_WORDS = 3,
    BCM_OMCI_FEC_PM_CFG_ID_UNCORRECTABLE_CODE_WORDS = 4,
    BCM_OMCI_FEC_PM_CFG_ID_TOTAL_CODE_WORDS = 5,
    BCM_OMCI_FEC_PM_CFG_ID_FEC_SECONDS = 6,
    BCM_OMCI_FEC_PM_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_fec_pm_cfg_id;

/** Identifiers for all attributes contained in XG-PON TC PERFORMANCE PM DATA(9.2.15) ME */
typedef enum bcm_omci_xgpon_tc_pm_cfg_id
{
    BCM_OMCI_XGPON_TC_PM_CFG_ID_INTERVAL_END_TIME = 0,
    BCM_OMCI_XGPON_TC_PM_CFG_ID_THRESHOLD_DATA = 1,
    BCM_OMCI_XGPON_TC_PM_CFG_ID_PSBD_HEC_ERROR_COUNT = 2,
    BCM_OMCI_XGPON_TC_PM_CFG_ID_XGTC_HEC_ERROR_COUNT = 3,
    BCM_OMCI_XGPON_TC_PM_CFG_ID_UNKNOWN_PROFILE_COUNT = 4,
    BCM_OMCI_XGPON_TC_PM_CFG_ID_TRANSMITTED_XGEM_FRAMES = 5,
    BCM_OMCI_XGPON_TC_PM_CFG_ID_FRAGMENT_XGEM_FRAMES = 6,
    BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_HEC_LOST_WORDS_COUNT = 7,
    BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_KEY_ERRORS = 8,
    BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_HEC_ERROR_COUNT = 9,
    BCM_OMCI_XGPON_TC_PM_CFG_ID_TX_BYTES_IN_NON_IDLE_XGEM_FRAMES = 10,
    BCM_OMCI_XGPON_TC_PM_CFG_ID_RX_BYTES_IN_NON_IDLE_XGEM_FRAMES = 11,
    BCM_OMCI_XGPON_TC_PM_CFG_ID_LODS_EVENT_COUNT = 12,
    BCM_OMCI_XGPON_TC_PM_CFG_ID_LODS_EVENT_RESTORED_COUNT = 13,
    BCM_OMCI_XGPON_TC_PM_CFG_ID_ONU_REACTIVATION_BY_LODS_EVENTS = 14,
    BCM_OMCI_XGPON_TC_PM_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_xgpon_tc_pm_cfg_id;

/** Identifiers for all attributes contained in IP Host Config Data (9.4.1) ME */
typedef enum bcm_omci_ip_host_config_data_cfg_id
{
    BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_IP_OPTIONS = 0, /* Bit map that enables/disables IP-related options */
    BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_MAC_ADDR = 1, /* MAC Address */
    BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_ONU_ID = 2, /* ONU identifier */
    BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_IP_ADDRESS = 3,
    BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_MASK = 4,
    BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_GATEWAY = 5,
    BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_PRIMARY_DNS = 6,
    BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_SECONDARY_DNS = 7,
    BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_ADDRESS = 8,
    BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_MASK = 9,
    BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_GATEWAY = 10,
    BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_PRIMARY_DNS = 11,
    BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_SECONDARY_DNS = 12,
    BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_DOMAIN_NAME = 13,
    BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_HOST_NAME = 14,
    BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_RELAY_AGENT_OPTIONS = 15,
    BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_ip_host_config_data_cfg_id;

/** Identifiers for all attributes contained in VoIP Line Status (9.9.11) ME */
typedef enum bcm_omci_voip_line_status_cfg_id
{
    BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CODEC = 0, /* VoIP codec used */
    BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_VOICE_SERVER_STATUS = 1, /* VoIP server status */
    BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_PORT_SESSION_TYPE = 2, /* Port Session Type */
    BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL1_PACKET_PERIOD = 3,
    BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL2_PACKET_PERIOD = 4,
    BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL1_DEST_ADDRESS = 5,
    BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL2_DEST_ADDRESS = 6,
    BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_LINE_STATE = 7, /* Port Session Type */
    BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_EMERGENCY_CALL_STATUS = 8,
    BCM_OMCI_VOIP_LINE_STATUS_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_voip_line_status_cfg_id;

/** Identifiers for all attributes contained in VoIP Line Status (9.9.11) ME */
typedef enum bcm_omci_voip_media_profile_cfg_id
{
    BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_FAX_MODE = 0,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_VOICE_SERVICE_PROF_PTR = 1,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION1 = 2,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD1 = 3,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION1 = 4,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION2 = 5,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD2 = 6,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION2 = 7,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION3 = 8,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD3 = 9,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION3 = 10,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION4 = 11,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD4 = 12,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION4 = 13,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_OOB_DTMF = 14,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_RTP_PROFILE_PTR = 15,
    BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_voip_media_profile_cfg_id;

/** Identifiers for all attributes contained in SIP User Data (9.9.2) ME */
typedef enum bcm_omci_sip_user_data_cfg_id
{
    BCM_OMCI_SIP_USER_DATA_CFG_ID_SIP_AGENT_PTR = 0,
    BCM_OMCI_SIP_USER_DATA_CFG_ID_USER_PART_AOR = 1,
    BCM_OMCI_SIP_USER_DATA_CFG_ID_SIP_DISPLAY_NAME = 2,
    BCM_OMCI_SIP_USER_DATA_CFG_ID_USERNAME_PASSWORD = 3,
    BCM_OMCI_SIP_USER_DATA_CFG_ID_VOICEMAIL_SERVER_URI = 4,
    BCM_OMCI_SIP_USER_DATA_CFG_ID_VOICEMAIL_SUBSCRIPTION_EXP_TIME = 5,
    BCM_OMCI_SIP_USER_DATA_CFG_ID_NETWORK_DIAL_PLAN_PTR = 6,
    BCM_OMCI_SIP_USER_DATA_CFG_ID_APP_SERVICE_PROF_PTR = 7,
    BCM_OMCI_SIP_USER_DATA_CFG_ID_FEATURE_CODE_PTR = 8,
    BCM_OMCI_SIP_USER_DATA_CFG_ID_PPTP_PTR = 9,
    BCM_OMCI_SIP_USER_DATA_CFG_ID_RELEASE_TIMER = 10,
    BCM_OMCI_SIP_USER_DATA_CFG_ID_ROH_TIMER = 11,
    BCM_OMCI_SIP_USER_DATA_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_sip_user_data_cfg_id;

/** Identifiers for all attributes contained in SIP Agent Config Data (9.9.3) ME */
typedef enum bcm_omci_sip_agent_config_data_cfg_id
{
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_PROXY_SERVER_ADDR_PTR = 0,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_OUTBOUND_PROXY_ADDR_PTR = 1,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_PRIMARY_SIP_DNS = 2,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SECONDARY_SIP_DNS = 3,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_TCP_UDP_PTR = 4,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REG_EXP_TIME = 5,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REREG_HEAD_START_TIME = 6,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_HOST_PART_URI = 7,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_STATUS = 8,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REGISTRAR = 9,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SOFTSWITCH = 10,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_RESPONSE_TABLE = 11,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_TRANSMIT_CONTROL = 12,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_URI_FORMAT = 13,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_REDUNDANT_SIP_AGENT_PTR = 14,
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_sip_agent_config_data_cfg_id;

/** Identifiers for all attributes contained in Network Address (9.12.3) ME */
typedef enum bcm_omci_network_address_cfg_id
{
    BCM_OMCI_NETWORK_ADDRESS_CFG_ID_SECURITY_PTR = 0,
    BCM_OMCI_NETWORK_ADDRESS_CFG_ID_ADDRESS_PTR = 1,
    BCM_OMCI_NETWORK_ADDRESS_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_network_address_cfg_id;

/** Identifiers for all attributes contained in Large String (9.12.5) ME */
typedef enum bcm_omci_large_string_cfg_id
{
    BCM_OMCI_LARGE_STRING_CFG_ID_NUMBER_OF_PARTS = 0,
    BCM_OMCI_LARGE_STRING_CFG_ID_PART1 = 1,
    BCM_OMCI_LARGE_STRING_CFG_ID_PART2 = 2,
    BCM_OMCI_LARGE_STRING_CFG_ID_PART3 = 3,
    BCM_OMCI_LARGE_STRING_CFG_ID_PART4 = 4,
    BCM_OMCI_LARGE_STRING_CFG_ID_PART5 = 5,
    BCM_OMCI_LARGE_STRING_CFG_ID_PART6 = 6,
    BCM_OMCI_LARGE_STRING_CFG_ID_PART7 = 7,
    BCM_OMCI_LARGE_STRING_CFG_ID_PART8 = 8,
    BCM_OMCI_LARGE_STRING_CFG_ID_PART9 = 9,
    BCM_OMCI_LARGE_STRING_CFG_ID_PART10 = 10,
    BCM_OMCI_LARGE_STRING_CFG_ID_PART11 = 11,
    BCM_OMCI_LARGE_STRING_CFG_ID_PART12 = 12,
    BCM_OMCI_LARGE_STRING_CFG_ID_PART13 = 13,
    BCM_OMCI_LARGE_STRING_CFG_ID_PART14 = 14,
    BCM_OMCI_LARGE_STRING_CFG_ID_PART15 = 15,
    BCM_OMCI_LARGE_STRING_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_large_string_cfg_id;

/** Identifiers for all attributes contained in Authentication Security Method (9.12.4) ME */
typedef enum bcm_omci_authentication_security_method_cfg_id
{
    BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_VALIDATION_SCHEME = 0,
    BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_USERNAME1 = 1,
    BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_PASSWORD = 2,
    BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_REALM = 3,
    BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_USERNAME2 = 4,
    BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_authentication_security_method_cfg_id;

/** Identifiers for all attributes contained in Voice Service Profile (9.9.6) ME */
typedef enum bcm_omci_voice_service_profile_cfg_id
{
    BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_ANNOUNCEMENT_TYPE = 0,
    BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_JITTER_TARGET = 1,
    BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_JITTER_BUFFER_MAX = 2,
    BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_ECHO_CANCEL = 3,
    BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_PSTN_PROTOCOL_VARIANT = 4,
    BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_DTMF_DIGIT_LEVELS = 5,
    BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_DTMF_DIGIT_DURATION = 6,
    BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_HOOK_FLASH_MIN_TIME = 7,
    BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_HOOK_FLASH_MAX_TIME = 8,
    BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_TONE_PATTERN_TABLE = 9,
    BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_TONE_EVENT_TABLE = 10,
    BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_RINGING_PATTERN_TABLE = 11,
    BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_RINGING_EVENT_TABLE = 12,
    BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_NETWORK_SPECIFIC_EXT_PTR = 13,
    BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_voice_service_profile_cfg_id;

/** Identifiers for all attributes contained in VoIP config data (9.9.18) ME */
typedef enum bcm_omci_voip_config_data_cfg_id
{
    BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_AVAILABLE_SIGNALLING_PROTOCOLS = 0,
    BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_SIGNALLING_PROTOCOL_USED = 1,
    BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_AVAILABLE_VOIP_CONFIG_METHODS = 2,
    BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOIP_CONFIG_METHOD_USED = 3,
    BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOICE_CONFIG_PTR = 4,
    BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOIP_CONFIG_STATE = 5,
    BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_RETRIEVE_PROFILE = 6,
    BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_PROFILE_VERSION = 7,
    BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_voip_config_data_cfg_id;

/** Identifiers for all attributes contained in VoIP voice CTP (9.9.4) ME */
typedef enum bcm_omci_voip_voice_ctp_cfg_id
{
    BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_USER_PROTOCOL_PTR = 0,
    BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_PPTP_PTR = 1,
    BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_VOICE_MEDIA_PROFILE_PTR = 2,
    BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_SIGNALLING_CODE = 3,
    BCM_OMCI_VOIP_VOICE_CTP_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_voip_voice_ctp_cfg_id;

/** Identifiers for all attributes contained in TCP/UDP config data (9.4.3) ME */
typedef enum bcm_omci_tcp_udp_config_data_cfg_id
{
    BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_PORT_ID = 0,
    BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_PROTOCOL = 1,
    BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_TOS = 2,
    BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_IP_HOST_PTR = 3,
    BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_tcp_udp_config_data_cfg_id;

/** Identifiers for all attributes contained in Network dial plan table (9.9.10) ME */
typedef enum bcm_omci_network_dial_plan_table_cfg_id
{
    BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_NUMBER = 0,
    BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_TABLE_MAX_SIZE = 1,
    BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_CRITICAL_DIAL_TIMEOUT = 2,
    BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_PARTIAL_DIAL_TIMEOUT = 3,
    BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_FORMAT = 4,
    BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_TABLE = 5, /* Dial plan table */
    BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_network_dial_plan_table_cfg_id;

/** Identifiers for all attributes contained in RTP profile data (9.9.7) ME */
typedef enum bcm_omci_rtp_profile_data_cfg_id
{
    BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_LOCAL_PORT_MIN = 0,
    BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_LOCAL_PORT_MAX = 1,
    BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_DSCP_MARK = 2,
    BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_PIGGYBACK_EVENTS = 3,
    BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_TONE_EVENTS = 4,
    BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_DTMF_EVENTS = 5,
    BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_CAS_EVENTS = 6,
    BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_IP_HOST_CONFIG_PTR = 7,
    BCM_OMCI_RTP_PROFILE_DATA_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_rtp_profile_data_cfg_id;

/** Identifiers for all attributes contained in Physical path termination point POTS UNI (9.9.1) ME */
typedef enum bcm_omci_pots_uni_cfg_id
{
    BCM_OMCI_POTS_UNI_CFG_ID_ADMIN_STATE = 0, /* Admin state */
    BCM_OMCI_POTS_UNI_CFG_ID_DEPRECATED1 = 1,
    BCM_OMCI_POTS_UNI_CFG_ID_ARC = 2, /* See A 1.4.3 */
    BCM_OMCI_POTS_UNI_CFG_ID_ARC_INTERVAL = 3, /* See A.1.4.3 */
    BCM_OMCI_POTS_UNI_CFG_ID_IMPEDANCE = 4,
    BCM_OMCI_POTS_UNI_CFG_ID_TRANSMISSION_PATH = 5,
    BCM_OMCI_POTS_UNI_CFG_ID_RX_GAIN = 6,
    BCM_OMCI_POTS_UNI_CFG_ID_TX_GAIN = 7,
    BCM_OMCI_POTS_UNI_CFG_ID_OPER_STATE = 8,
    BCM_OMCI_POTS_UNI_CFG_ID_HOOK_STATE = 9,
    BCM_OMCI_POTS_UNI_CFG_ID_HOLDOVER_TIME = 10,
    BCM_OMCI_POTS_UNI_CFG_ID_NOMINAL_FEED_VOLTAGE = 11,
    BCM_OMCI_POTS_UNI_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_pots_uni_cfg_id;

/** Identifiers for all attributes contained in Circuit pack (9.1.6) ME */
typedef enum bcm_omci_circuit_pack_cfg_id
{
    BCM_OMCI_CIRCUIT_PACK_CFG_ID_TYPE = 0, /* Table 9.1.5-1 */
    BCM_OMCI_CIRCUIT_PACK_CFG_ID_NUMBER_OF_PORTS = 1,
    BCM_OMCI_CIRCUIT_PACK_CFG_ID_SERIAL_NUMBER = 2,
    BCM_OMCI_CIRCUIT_PACK_CFG_ID_VERSION = 3,
    BCM_OMCI_CIRCUIT_PACK_CFG_ID_VENDOR_ID = 4,
    BCM_OMCI_CIRCUIT_PACK_CFG_ID_ADMIN_STATE = 5, /* Admin state */
    BCM_OMCI_CIRCUIT_PACK_CFG_ID_OPER_STATE = 6,
    BCM_OMCI_CIRCUIT_PACK_CFG_ID_BRIDGED_OR_IP = 7,
    BCM_OMCI_CIRCUIT_PACK_CFG_ID_EQUIP_ID = 8,
    BCM_OMCI_CIRCUIT_PACK_CFG_ID_CARD_CONFIG = 9,
    BCM_OMCI_CIRCUIT_PACK_CFG_ID_TCONT_BUFFER_NUMBER = 10,
    BCM_OMCI_CIRCUIT_PACK_CFG_ID_PRIORITY_QUEUE_NUMBER = 11,
    BCM_OMCI_CIRCUIT_PACK_CFG_ID_TRAFFIC_SCHED_NUMBER = 12,
    BCM_OMCI_CIRCUIT_PACK_CFG_ID_POWER_SHED_OVERRIDE = 13,
    BCM_OMCI_CIRCUIT_PACK_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_circuit_pack_cfg_id;

/** Identifiers for all attributes contained in Enhanced Security Control (9.13.11) ME */
typedef enum bcm_omci_enhanced_security_control_cfg_id
{
    BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_CRYPTO_CAPABILITIES = 0,
    BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_RANDOM_CHALLENGE_TABLE = 1,
    BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_CHALLENGE_STATUS = 2,
    BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_SELECTED_CRYPTO_CAPABILITIES = 3,
    BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_RANDOM_CHALLENGE_TABLE = 4,
    BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_AUTH_RESULT_TABLE = 5,
    BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_AUTH_RESULT_TABLE = 6,
    BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_RESULT_STATUS = 7,
    BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_AUTH_STATUS = 8,
    BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_MASTER_SESSION_KEY_NAME = 9,
    BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_BROADCAST_KEY_TABLE = 10,
    BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_EFFECTIVE_KEY_LENGTH = 11,
    BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID__NUM_OF /**< Number of enum entries, not an entry itself. */
} bcm_omci_enhanced_security_control_cfg_id;

/** Identifiers for all objects in the system. */
typedef enum
{
    BCM_OMCI_OBJ_ID__BEGIN,
    BCM_OMCI_GAL_ETH_PROF_OBJ_ID = 1, /* GAL Ethernet Profile */
    BCM_OMCI_GEM_IW_TP_OBJ_ID = 2, /* GEM Interworking Termination Point */
    BCM_OMCI_GEM_PORT_NET_CTP_OBJ_ID = 3, /* GEM Port Network CTP */
    BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_OBJ_ID = 4, /* IEEE 802.1p mapper service profile */
    BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_OBJ_ID = 5, /* MAC Bridge Port Configuration Data */
    BCM_OMCI_MAC_BRIDGE_SVC_PROF_OBJ_ID = 6, /* MAC Bridge Service Profile */
    BCM_OMCI_VLAN_TAG_FILTER_DATA_OBJ_ID = 7, /* VLAN Tagging Filter Data */
    BCM_OMCI_TCONT_OBJ_ID = 8, /* T-CONT */
    BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_OBJ_ID = 9, /* Extended VLAN Tagging Operation Configuration Data */
    BCM_OMCI_PRIORITY_QUEUE_G_OBJ_ID = 10, /* priority queue-G */
    BCM_OMCI_MCAST_GEM_IW_TP_OBJ_ID = 11, /* Multicast GEM interworking termination point */
    BCM_OMCI_MCAST_OPERATIONS_PROFILE_OBJ_ID = 12, /* Multicast Operations Profile */
    BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_OBJ_ID = 13, /* Multicast subscriber config info */
    BCM_OMCI_PPTP_ETH_UNI_OBJ_ID = 14, /* PPTP Ethernet UNI */
    BCM_OMCI_VIRTUAL_ETH_INTF_POINT_OBJ_ID = 15, /* Virtual Ethernet Interface Point */
    BCM_OMCI_ONU_DATA_OBJ_ID = 16, /* ONU data */
    BCM_OMCI_ONU_G_OBJ_ID = 17, /* ONU-G (9.1.1) */
    BCM_OMCI_ONU2_G_OBJ_ID = 18, /* ONU2-G (9.1.2) */
    BCM_OMCI_SW_IMAGE_OBJ_ID = 19, /* Software image (9.1.4) */
    BCM_OMCI_ANI_G_OBJ_ID = 20, /* ANI-G (9.2.1) */
    BCM_OMCI_GEM_PORT_NET_CTP_PM_OBJ_ID = 21, /* GEM Port Network CTP PM(9.2.13) */
    BCM_OMCI_ETH_FRAME_UPSTREAM_PM_OBJ_ID = 22, /* ETH FRAME UPSTREAM PM(9.3.30) */
    BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_OBJ_ID = 23, /* ETH FRAME DOWNSTREAM PM(9.3.31) */
    BCM_OMCI_FEC_PM_OBJ_ID = 24, /* FEC PERFORMANCE PM DATA(9.2.9) */
    BCM_OMCI_XGPON_TC_PM_OBJ_ID = 25, /* XG-PON TC PERFORMANCE PM DATA(9.2.15) */
    BCM_OMCI_IP_HOST_CONFIG_DATA_OBJ_ID = 26, /* IP Host Config Data (9.4.1) */
    BCM_OMCI_VOIP_LINE_STATUS_OBJ_ID = 27, /* VoIP Line Status (9.9.11) */
    BCM_OMCI_VOIP_MEDIA_PROFILE_OBJ_ID = 28, /* VoIP Line Status (9.9.11) */
    BCM_OMCI_SIP_USER_DATA_OBJ_ID = 29, /* SIP User Data (9.9.2) */
    BCM_OMCI_SIP_AGENT_CONFIG_DATA_OBJ_ID = 30, /* SIP Agent Config Data (9.9.3) */
    BCM_OMCI_NETWORK_ADDRESS_OBJ_ID = 31, /* Network Address (9.12.3) */
    BCM_OMCI_LARGE_STRING_OBJ_ID = 32, /* Large String (9.12.5) */
    BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_OBJ_ID = 33, /* Authentication Security Method (9.12.4) */
    BCM_OMCI_VOICE_SERVICE_PROFILE_OBJ_ID = 34, /* Voice Service Profile (9.9.6) */
    BCM_OMCI_VOIP_CONFIG_DATA_OBJ_ID = 35, /* VoIP config data (9.9.18) */
    BCM_OMCI_VOIP_VOICE_CTP_OBJ_ID = 36, /* VoIP voice CTP (9.9.4) */
    BCM_OMCI_TCP_UDP_CONFIG_DATA_OBJ_ID = 37, /* TCP/UDP config data (9.4.3) */
    BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_OBJ_ID = 38, /* Network dial plan table (9.9.10) */
    BCM_OMCI_RTP_PROFILE_DATA_OBJ_ID = 39, /* RTP profile data (9.9.7) */
    BCM_OMCI_POTS_UNI_OBJ_ID = 40, /* Physical path termination point POTS UNI (9.9.1) */
    BCM_OMCI_CIRCUIT_PACK_OBJ_ID = 41, /* Circuit pack (9.1.6) */
    BCM_OMCI_ENHANCED_SECURITY_CONTROL_OBJ_ID = 42, /* Enhanced Security Control (9.13.11) */
    BCM_OMCI_OBJ_ID__NUM_OF  /**< Number of enum entries, not an entry itself. */
} bcm_omci_obj_id;

#define bcm_omci_gal_eth_prof_obj_id BCM_OMCI_GAL_ETH_PROF_OBJ_ID
#define bcm_omci_gem_iw_tp_obj_id BCM_OMCI_GEM_IW_TP_OBJ_ID
#define bcm_omci_gem_port_net_ctp_obj_id BCM_OMCI_GEM_PORT_NET_CTP_OBJ_ID
#define bcm_omci_ieee_8021_p_mapper_svc_prof_obj_id BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_OBJ_ID
#define bcm_omci_mac_bridge_port_config_data_obj_id BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_OBJ_ID
#define bcm_omci_mac_bridge_svc_prof_obj_id BCM_OMCI_MAC_BRIDGE_SVC_PROF_OBJ_ID
#define bcm_omci_vlan_tag_filter_data_obj_id BCM_OMCI_VLAN_TAG_FILTER_DATA_OBJ_ID
#define bcm_omci_tcont_obj_id BCM_OMCI_TCONT_OBJ_ID
#define bcm_omci_ext_vlan_tag_oper_config_data_obj_id BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_OBJ_ID
#define bcm_omci_priority_queue_g_obj_id BCM_OMCI_PRIORITY_QUEUE_G_OBJ_ID
#define bcm_omci_mcast_gem_iw_tp_obj_id BCM_OMCI_MCAST_GEM_IW_TP_OBJ_ID
#define bcm_omci_mcast_operations_profile_obj_id BCM_OMCI_MCAST_OPERATIONS_PROFILE_OBJ_ID
#define bcm_omci_mcast_subscriber_config_info_obj_id BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_OBJ_ID
#define bcm_omci_pptp_eth_uni_obj_id BCM_OMCI_PPTP_ETH_UNI_OBJ_ID
#define bcm_omci_virtual_eth_intf_point_obj_id BCM_OMCI_VIRTUAL_ETH_INTF_POINT_OBJ_ID
#define bcm_omci_onu_data_obj_id BCM_OMCI_ONU_DATA_OBJ_ID
#define bcm_omci_onu_g_obj_id BCM_OMCI_ONU_G_OBJ_ID
#define bcm_omci_onu2_g_obj_id BCM_OMCI_ONU2_G_OBJ_ID
#define bcm_omci_sw_image_obj_id BCM_OMCI_SW_IMAGE_OBJ_ID
#define bcm_omci_ani_g_obj_id BCM_OMCI_ANI_G_OBJ_ID
#define bcm_omci_gem_port_net_ctp_pm_obj_id BCM_OMCI_GEM_PORT_NET_CTP_PM_OBJ_ID
#define bcm_omci_eth_frame_upstream_pm_obj_id BCM_OMCI_ETH_FRAME_UPSTREAM_PM_OBJ_ID
#define bcm_omci_eth_frame_downstream_pm_obj_id BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_OBJ_ID
#define bcm_omci_fec_pm_obj_id BCM_OMCI_FEC_PM_OBJ_ID
#define bcm_omci_xgpon_tc_pm_obj_id BCM_OMCI_XGPON_TC_PM_OBJ_ID
#define bcm_omci_ip_host_config_data_obj_id BCM_OMCI_IP_HOST_CONFIG_DATA_OBJ_ID
#define bcm_omci_voip_line_status_obj_id BCM_OMCI_VOIP_LINE_STATUS_OBJ_ID
#define bcm_omci_voip_media_profile_obj_id BCM_OMCI_VOIP_MEDIA_PROFILE_OBJ_ID
#define bcm_omci_sip_user_data_obj_id BCM_OMCI_SIP_USER_DATA_OBJ_ID
#define bcm_omci_sip_agent_config_data_obj_id BCM_OMCI_SIP_AGENT_CONFIG_DATA_OBJ_ID
#define bcm_omci_network_address_obj_id BCM_OMCI_NETWORK_ADDRESS_OBJ_ID
#define bcm_omci_large_string_obj_id BCM_OMCI_LARGE_STRING_OBJ_ID
#define bcm_omci_authentication_security_method_obj_id BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_OBJ_ID
#define bcm_omci_voice_service_profile_obj_id BCM_OMCI_VOICE_SERVICE_PROFILE_OBJ_ID
#define bcm_omci_voip_config_data_obj_id BCM_OMCI_VOIP_CONFIG_DATA_OBJ_ID
#define bcm_omci_voip_voice_ctp_obj_id BCM_OMCI_VOIP_VOICE_CTP_OBJ_ID
#define bcm_omci_tcp_udp_config_data_obj_id BCM_OMCI_TCP_UDP_CONFIG_DATA_OBJ_ID
#define bcm_omci_network_dial_plan_table_obj_id BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_OBJ_ID
#define bcm_omci_rtp_profile_data_obj_id BCM_OMCI_RTP_PROFILE_DATA_OBJ_ID
#define bcm_omci_pots_uni_obj_id BCM_OMCI_POTS_UNI_OBJ_ID
#define bcm_omci_circuit_pack_obj_id BCM_OMCI_CIRCUIT_PACK_OBJ_ID
#define bcm_omci_enhanced_security_control_obj_id BCM_OMCI_ENHANCED_SECURITY_CONTROL_OBJ_ID

#define bcm_omci_me_key_id_all_properties BCM_OMCI_ME_KEY_ID__NUM_OF
#define bcm_omci_me_key_id_logical_pon BCM_OMCI_ME_KEY_ID_LOGICAL_PON
#define bcm_omci_me_key_id_pon_onu_id BCM_OMCI_ME_KEY_ID_PON_ONU_ID
#define bcm_omci_me_key_id_entity_class BCM_OMCI_ME_KEY_ID_ENTITY_CLASS
#define bcm_omci_me_key_id_entity_instance BCM_OMCI_ME_KEY_ID_ENTITY_INSTANCE

/* GAL Ethernet Profile */
#define bcm_omci_gal_eth_prof_cfg_id_max_gem_payload_size BCM_OMCI_GAL_ETH_PROF_CFG_ID_MAX_GEM_PAYLOAD_SIZE
#define bcm_omci_gal_eth_prof_cfg_id_all_properties BCM_OMCI_GAL_ETH_PROF_CFG_ID__NUM_OF

/* GEM Interworking Termination Point */
#define bcm_omci_gem_iw_tp_cfg_id_gem_port_net_ctp_conn_ptr BCM_OMCI_GEM_IW_TP_CFG_ID_GEM_PORT_NET_CTP_CONN_PTR
#define bcm_omci_gem_iw_tp_cfg_id_iw_opt BCM_OMCI_GEM_IW_TP_CFG_ID_IW_OPT
#define bcm_omci_gem_iw_tp_cfg_id_svc_prof_ptr BCM_OMCI_GEM_IW_TP_CFG_ID_SVC_PROF_PTR
#define bcm_omci_gem_iw_tp_cfg_id_iw_tp_ptr BCM_OMCI_GEM_IW_TP_CFG_ID_IW_TP_PTR
#define bcm_omci_gem_iw_tp_cfg_id_pptp_count BCM_OMCI_GEM_IW_TP_CFG_ID_PPTP_COUNT
#define bcm_omci_gem_iw_tp_cfg_id_oper_state BCM_OMCI_GEM_IW_TP_CFG_ID_OPER_STATE
#define bcm_omci_gem_iw_tp_cfg_id_gal_prof_ptr BCM_OMCI_GEM_IW_TP_CFG_ID_GAL_PROF_PTR
#define bcm_omci_gem_iw_tp_cfg_id_gal_lpbk_config BCM_OMCI_GEM_IW_TP_CFG_ID_GAL_LPBK_CONFIG
#define bcm_omci_gem_iw_tp_cfg_id_all_properties BCM_OMCI_GEM_IW_TP_CFG_ID__NUM_OF

/* GEM Port Network CTP */
#define bcm_omci_gem_port_net_ctp_cfg_id_port_id BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_PORT_ID
#define bcm_omci_gem_port_net_ctp_cfg_id_tcont_ptr BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TCONT_PTR
#define bcm_omci_gem_port_net_ctp_cfg_id_direction BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_DIRECTION
#define bcm_omci_gem_port_net_ctp_cfg_id_traffic_mgmt_ptr_us BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_MGMT_PTR_US
#define bcm_omci_gem_port_net_ctp_cfg_id_traffic_desc_prof_ptr_us BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_DESC_PROF_PTR_US
#define bcm_omci_gem_port_net_ctp_cfg_id_uni_count BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_UNI_COUNT
#define bcm_omci_gem_port_net_ctp_cfg_id_pri_queue_ptr_ds BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_PRI_QUEUE_PTR_DS
#define bcm_omci_gem_port_net_ctp_cfg_id_encryption_state BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_ENCRYPTION_STATE
#define bcm_omci_gem_port_net_ctp_cfg_id_traffic_desc_prof_ptr_ds BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_DESC_PROF_PTR_DS
#define bcm_omci_gem_port_net_ctp_cfg_id_encryption_key_ring BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_ENCRYPTION_KEY_RING
#define bcm_omci_gem_port_net_ctp_cfg_id_all_properties BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID__NUM_OF

/* IEEE 802.1p mapper service profile */
#define bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_id_tp_ptr BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_TP_PTR
#define bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_id_interwork_tp_ptr_pri_0 BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_0
#define bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_id_interwork_tp_ptr_pri_1 BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_1
#define bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_id_interwork_tp_ptr_pri_2 BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_2
#define bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_id_interwork_tp_ptr_pri_3 BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_3
#define bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_id_interwork_tp_ptr_pri_4 BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_4
#define bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_id_interwork_tp_ptr_pri_5 BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_5
#define bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_id_interwork_tp_ptr_pri_6 BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_6
#define bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_id_interwork_tp_ptr_pri_7 BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_7
#define bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_id_unmarked_frame_opt BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_UNMARKED_FRAME_OPT
#define bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_id_dscp_to_pbit_mapping BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_DSCP_TO_PBIT_MAPPING
#define bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_id_default_pbit_assumption BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_DEFAULT_PBIT_ASSUMPTION
#define bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_id_mapper_tp_type BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_MAPPER_TP_TYPE
#define bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_id_all_properties BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID__NUM_OF

/* MAC Bridge Port Configuration Data */
#define bcm_omci_mac_bridge_port_config_data_cfg_id_bridge_id_ptr BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_BRIDGE_ID_PTR
#define bcm_omci_mac_bridge_port_config_data_cfg_id_port_num BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_NUM
#define bcm_omci_mac_bridge_port_config_data_cfg_id_tp_type BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_TP_TYPE
#define bcm_omci_mac_bridge_port_config_data_cfg_id_tp_ptr BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_TP_PTR
#define bcm_omci_mac_bridge_port_config_data_cfg_id_port_pri BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_PRI
#define bcm_omci_mac_bridge_port_config_data_cfg_id_port_path_cost BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_PATH_COST
#define bcm_omci_mac_bridge_port_config_data_cfg_id_port_spanning_tree_ind BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_SPANNING_TREE_IND
#define bcm_omci_mac_bridge_port_config_data_cfg_id_deprecated_1 BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_DEPRECATED_1
#define bcm_omci_mac_bridge_port_config_data_cfg_id_deprecated_2 BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_DEPRECATED_2
#define bcm_omci_mac_bridge_port_config_data_cfg_id_port_mac_addr BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_MAC_ADDR
#define bcm_omci_mac_bridge_port_config_data_cfg_id_outbound_td_ptr BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_OUTBOUND_TD_PTR
#define bcm_omci_mac_bridge_port_config_data_cfg_id_inbound_td_ptr BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_INBOUND_TD_PTR
#define bcm_omci_mac_bridge_port_config_data_cfg_id_mac_learning_depth BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_MAC_LEARNING_DEPTH
#define bcm_omci_mac_bridge_port_config_data_cfg_id_all_properties BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID__NUM_OF

/* MAC Bridge Service Profile */
#define bcm_omci_mac_bridge_svc_prof_cfg_id_spanning_tree_ind BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_SPANNING_TREE_IND
#define bcm_omci_mac_bridge_svc_prof_cfg_id_learning_ind BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_LEARNING_IND
#define bcm_omci_mac_bridge_svc_prof_cfg_id_port_bridging_ind BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_PORT_BRIDGING_IND
#define bcm_omci_mac_bridge_svc_prof_cfg_id_pri BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_PRI
#define bcm_omci_mac_bridge_svc_prof_cfg_id_max_age BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_MAX_AGE
#define bcm_omci_mac_bridge_svc_prof_cfg_id_hello_time BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_HELLO_TIME
#define bcm_omci_mac_bridge_svc_prof_cfg_id_forward_delay BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_FORWARD_DELAY
#define bcm_omci_mac_bridge_svc_prof_cfg_id_unknown_mac_addr_discard BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_UNKNOWN_MAC_ADDR_DISCARD
#define bcm_omci_mac_bridge_svc_prof_cfg_id_mac_learning_depth BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_MAC_LEARNING_DEPTH
#define bcm_omci_mac_bridge_svc_prof_cfg_id_dynamic_filtering_ageing_time BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_DYNAMIC_FILTERING_AGEING_TIME
#define bcm_omci_mac_bridge_svc_prof_cfg_id_all_properties BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID__NUM_OF

/* VLAN Tagging Filter Data */
#define bcm_omci_vlan_tag_filter_data_cfg_id_vlan_filter_list BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_VLAN_FILTER_LIST
#define bcm_omci_vlan_tag_filter_data_cfg_id_forward_oper BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_FORWARD_OPER
#define bcm_omci_vlan_tag_filter_data_cfg_id_num_of_entries BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_NUM_OF_ENTRIES
#define bcm_omci_vlan_tag_filter_data_cfg_id_all_properties BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID__NUM_OF

/* T-CONT */
#define bcm_omci_tcont_cfg_id_alloc_id BCM_OMCI_TCONT_CFG_ID_ALLOC_ID
#define bcm_omci_tcont_cfg_id_deprecated BCM_OMCI_TCONT_CFG_ID_DEPRECATED
#define bcm_omci_tcont_cfg_id_policy BCM_OMCI_TCONT_CFG_ID_POLICY
#define bcm_omci_tcont_cfg_id_all_properties BCM_OMCI_TCONT_CFG_ID__NUM_OF

/* Extended VLAN Tagging Operation Configuration Data */
#define bcm_omci_ext_vlan_tag_oper_config_data_cfg_id_assoc_type BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_ASSOC_TYPE
#define bcm_omci_ext_vlan_tag_oper_config_data_cfg_id_rx_frame_vlan_tag_oper_table_max_size BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_RX_FRAME_VLAN_TAG_OPER_TABLE_MAX_SIZE
#define bcm_omci_ext_vlan_tag_oper_config_data_cfg_id_input_tpid BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_INPUT_TPID
#define bcm_omci_ext_vlan_tag_oper_config_data_cfg_id_output_tpid BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_OUTPUT_TPID
#define bcm_omci_ext_vlan_tag_oper_config_data_cfg_id_ds_mode BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_DS_MODE
#define bcm_omci_ext_vlan_tag_oper_config_data_cfg_id_rx_frame_vlan_tag_oper_table BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_RX_FRAME_VLAN_TAG_OPER_TABLE
#define bcm_omci_ext_vlan_tag_oper_config_data_cfg_id_assoc_me_ptr BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_ASSOC_ME_PTR
#define bcm_omci_ext_vlan_tag_oper_config_data_cfg_id_dscp_to_pbit_mapping BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_DSCP_TO_PBIT_MAPPING
#define bcm_omci_ext_vlan_tag_oper_config_data_cfg_id_all_properties BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID__NUM_OF

/* priority queue-G */
#define bcm_omci_priority_queue_g_cfg_id_queue_config_opt BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_QUEUE_CONFIG_OPT
#define bcm_omci_priority_queue_g_cfg_id_max_queue_size BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_MAX_QUEUE_SIZE
#define bcm_omci_priority_queue_g_cfg_id_allocated_queue_size BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_ALLOCATED_QUEUE_SIZE
#define bcm_omci_priority_queue_g_cfg_id_discard_counter_reset_interval BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DISCARD_COUNTER_RESET_INTERVAL
#define bcm_omci_priority_queue_g_cfg_id_discard_threshold BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DISCARD_THRESHOLD
#define bcm_omci_priority_queue_g_cfg_id_related_port BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_RELATED_PORT
#define bcm_omci_priority_queue_g_cfg_id_traffic_scheduler_ptr BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_TRAFFIC_SCHEDULER_PTR
#define bcm_omci_priority_queue_g_cfg_id_weight BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_WEIGHT
#define bcm_omci_priority_queue_g_cfg_id_back_pressure_oper BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_OPER
#define bcm_omci_priority_queue_g_cfg_id_back_pressure_time BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_TIME
#define bcm_omci_priority_queue_g_cfg_id_back_pressure_occur_queue_thr BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_OCCUR_QUEUE_THR
#define bcm_omci_priority_queue_g_cfg_id_back_pressure_clear_queue_thr BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_CLEAR_QUEUE_THR
#define bcm_omci_priority_queue_g_cfg_id_packet_drop_queue_thr BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_PACKET_DROP_QUEUE_THR
#define bcm_omci_priority_queue_g_cfg_id_packet_drop_max_p BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_PACKET_DROP_MAX_P
#define bcm_omci_priority_queue_g_cfg_id_queue_drop_w_q BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_QUEUE_DROP_W_Q
#define bcm_omci_priority_queue_g_cfg_id_drop_precedence_colour_marking BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DROP_PRECEDENCE_COLOUR_MARKING
#define bcm_omci_priority_queue_g_cfg_id_all_properties BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID__NUM_OF

/* Multicast GEM interworking termination point */
#define bcm_omci_mcast_gem_iw_tp_cfg_id_gem_port_net_ctp_conn_ptr BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_GEM_PORT_NET_CTP_CONN_PTR
#define bcm_omci_mcast_gem_iw_tp_cfg_id_iw_opt BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IW_OPT
#define bcm_omci_mcast_gem_iw_tp_cfg_id_svc_prof_ptr BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_SVC_PROF_PTR
#define bcm_omci_mcast_gem_iw_tp_cfg_id_not_used_1 BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_NOT_USED_1
#define bcm_omci_mcast_gem_iw_tp_cfg_id_pptp_counter BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_PPTP_COUNTER
#define bcm_omci_mcast_gem_iw_tp_cfg_id_oper_state BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_OPER_STATE
#define bcm_omci_mcast_gem_iw_tp_cfg_id_gal_prof_ptr BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_GAL_PROF_PTR
#define bcm_omci_mcast_gem_iw_tp_cfg_id_not_used_2 BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_NOT_USED_2
#define bcm_omci_mcast_gem_iw_tp_cfg_id_ipv_4_mcast_addr_table BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IPV_4_MCAST_ADDR_TABLE
#define bcm_omci_mcast_gem_iw_tp_cfg_id_ipv_6_mcast_addr_table BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IPV_6_MCAST_ADDR_TABLE
#define bcm_omci_mcast_gem_iw_tp_cfg_id_all_properties BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID__NUM_OF

/* Multicast Operations Profile */
#define bcm_omci_mcast_operations_profile_cfg_id_igmp_version BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IGMP_VERSION
#define bcm_omci_mcast_operations_profile_cfg_id_igmp_function BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IGMP_FUNCTION
#define bcm_omci_mcast_operations_profile_cfg_id_immediate_leave BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IMMEDIATE_LEAVE
#define bcm_omci_mcast_operations_profile_cfg_id_upstream_igmp_tci BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_TCI
#define bcm_omci_mcast_operations_profile_cfg_id_upstream_igmp_tag_control BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_TAG_CONTROL
#define bcm_omci_mcast_operations_profile_cfg_id_upstream_igmp_rate BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_RATE
#define bcm_omci_mcast_operations_profile_cfg_id_dynamic_access_control_list_table BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_DYNAMIC_ACCESS_CONTROL_LIST_TABLE
#define bcm_omci_mcast_operations_profile_cfg_id_static_access_control_list_table BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_STATIC_ACCESS_CONTROL_LIST_TABLE
#define bcm_omci_mcast_operations_profile_cfg_id_lost_groups_list_table BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_LOST_GROUPS_LIST_TABLE
#define bcm_omci_mcast_operations_profile_cfg_id_robustness BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_ROBUSTNESS
#define bcm_omci_mcast_operations_profile_cfg_id_querier_ip_address BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERIER_IP_ADDRESS
#define bcm_omci_mcast_operations_profile_cfg_id_query_interval BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERY_INTERVAL
#define bcm_omci_mcast_operations_profile_cfg_id_query_max_response_time BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERY_MAX_RESPONSE_TIME
#define bcm_omci_mcast_operations_profile_cfg_id_last_member_query_interval BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_LAST_MEMBER_QUERY_INTERVAL
#define bcm_omci_mcast_operations_profile_cfg_id_unauth_join_request_behaviour BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UNAUTH_JOIN_REQUEST_BEHAVIOUR
#define bcm_omci_mcast_operations_profile_cfg_id_ds_igmp_and_multicast_tci BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_DS_IGMP_AND_MULTICAST_TCI
#define bcm_omci_mcast_operations_profile_cfg_id_all_properties BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID__NUM_OF

/* Multicast subscriber config info */
#define bcm_omci_mcast_subscriber_config_info_cfg_id_me_type BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_ME_TYPE
#define bcm_omci_mcast_subscriber_config_info_cfg_id_mcast_operations_prof_ptr BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MCAST_OPERATIONS_PROF_PTR
#define bcm_omci_mcast_subscriber_config_info_cfg_id_max_simultaneous_groups BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MAX_SIMULTANEOUS_GROUPS
#define bcm_omci_mcast_subscriber_config_info_cfg_id_max_multicast_bw BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MAX_MULTICAST_BW
#define bcm_omci_mcast_subscriber_config_info_cfg_id_bw_enforcement BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_BW_ENFORCEMENT
#define bcm_omci_mcast_subscriber_config_info_cfg_id_mcast_svc_pkg_table BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MCAST_SVC_PKG_TABLE
#define bcm_omci_mcast_subscriber_config_info_cfg_id_allowed_preview_groups_table BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_ALLOWED_PREVIEW_GROUPS_TABLE
#define bcm_omci_mcast_subscriber_config_info_cfg_id_all_properties BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID__NUM_OF

/* PPTP Ethernet UNI */
#define bcm_omci_pptp_eth_uni_cfg_id_expected_type BCM_OMCI_PPTP_ETH_UNI_CFG_ID_EXPECTED_TYPE
#define bcm_omci_pptp_eth_uni_cfg_id_sensed_type BCM_OMCI_PPTP_ETH_UNI_CFG_ID_SENSED_TYPE
#define bcm_omci_pptp_eth_uni_cfg_id_auto_detection_config BCM_OMCI_PPTP_ETH_UNI_CFG_ID_AUTO_DETECTION_CONFIG
#define bcm_omci_pptp_eth_uni_cfg_id_ethernet_loopback_config BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ETHERNET_LOOPBACK_CONFIG
#define bcm_omci_pptp_eth_uni_cfg_id_admin_state BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ADMIN_STATE
#define bcm_omci_pptp_eth_uni_cfg_id_oper_state BCM_OMCI_PPTP_ETH_UNI_CFG_ID_OPER_STATE
#define bcm_omci_pptp_eth_uni_cfg_id_config_ind BCM_OMCI_PPTP_ETH_UNI_CFG_ID_CONFIG_IND
#define bcm_omci_pptp_eth_uni_cfg_id_max_frame_size BCM_OMCI_PPTP_ETH_UNI_CFG_ID_MAX_FRAME_SIZE
#define bcm_omci_pptp_eth_uni_cfg_id_dte_or_dce_ind BCM_OMCI_PPTP_ETH_UNI_CFG_ID_DTE_OR_DCE_IND
#define bcm_omci_pptp_eth_uni_cfg_id_pause_time BCM_OMCI_PPTP_ETH_UNI_CFG_ID_PAUSE_TIME
#define bcm_omci_pptp_eth_uni_cfg_id_bridged_or_ip_ind BCM_OMCI_PPTP_ETH_UNI_CFG_ID_BRIDGED_OR_IP_IND
#define bcm_omci_pptp_eth_uni_cfg_id_arc BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ARC
#define bcm_omci_pptp_eth_uni_cfg_id_arc_interval BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ARC_INTERVAL
#define bcm_omci_pptp_eth_uni_cfg_id_pppoe_filter BCM_OMCI_PPTP_ETH_UNI_CFG_ID_PPPOE_FILTER
#define bcm_omci_pptp_eth_uni_cfg_id_power_control BCM_OMCI_PPTP_ETH_UNI_CFG_ID_POWER_CONTROL
#define bcm_omci_pptp_eth_uni_cfg_id_all_properties BCM_OMCI_PPTP_ETH_UNI_CFG_ID__NUM_OF

/* Virtual Ethernet Interface Point */
#define bcm_omci_virtual_eth_intf_point_cfg_id_admin_state BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_ADMIN_STATE
#define bcm_omci_virtual_eth_intf_point_cfg_id_oper_state BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_OPER_STATE
#define bcm_omci_virtual_eth_intf_point_cfg_id_interdomain_name BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_INTERDOMAIN_NAME
#define bcm_omci_virtual_eth_intf_point_cfg_id_tcp_udp_ptr BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_TCP_UDP_PTR
#define bcm_omci_virtual_eth_intf_point_cfg_id_iana_assigned_port BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_IANA_ASSIGNED_PORT
#define bcm_omci_virtual_eth_intf_point_cfg_id_all_properties BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID__NUM_OF

/* ONU data */
#define bcm_omci_onu_data_cfg_id_mib_data_sync BCM_OMCI_ONU_DATA_CFG_ID_MIB_DATA_SYNC
#define bcm_omci_onu_data_cfg_id_all_properties BCM_OMCI_ONU_DATA_CFG_ID__NUM_OF

/* ONU-G (9.1.1) */
#define bcm_omci_onu_g_cfg_id_vendor_id BCM_OMCI_ONU_G_CFG_ID_VENDOR_ID
#define bcm_omci_onu_g_cfg_id_version BCM_OMCI_ONU_G_CFG_ID_VERSION
#define bcm_omci_onu_g_cfg_id_serial_number BCM_OMCI_ONU_G_CFG_ID_SERIAL_NUMBER
#define bcm_omci_onu_g_cfg_id_traffic_management BCM_OMCI_ONU_G_CFG_ID_TRAFFIC_MANAGEMENT
#define bcm_omci_onu_g_cfg_id_deprecated0 BCM_OMCI_ONU_G_CFG_ID_DEPRECATED0
#define bcm_omci_onu_g_cfg_id_battery_backup BCM_OMCI_ONU_G_CFG_ID_BATTERY_BACKUP
#define bcm_omci_onu_g_cfg_id_admin_state BCM_OMCI_ONU_G_CFG_ID_ADMIN_STATE
#define bcm_omci_onu_g_cfg_id_oper_state BCM_OMCI_ONU_G_CFG_ID_OPER_STATE
#define bcm_omci_onu_g_cfg_id_survival_time BCM_OMCI_ONU_G_CFG_ID_SURVIVAL_TIME
#define bcm_omci_onu_g_cfg_id_logical_onu_id BCM_OMCI_ONU_G_CFG_ID_LOGICAL_ONU_ID
#define bcm_omci_onu_g_cfg_id_logical_password BCM_OMCI_ONU_G_CFG_ID_LOGICAL_PASSWORD
#define bcm_omci_onu_g_cfg_id_credentials_status BCM_OMCI_ONU_G_CFG_ID_CREDENTIALS_STATUS
#define bcm_omci_onu_g_cfg_id_extended_tc_options BCM_OMCI_ONU_G_CFG_ID_EXTENDED_TC_OPTIONS
#define bcm_omci_onu_g_cfg_id_all_properties BCM_OMCI_ONU_G_CFG_ID__NUM_OF

/* ONU2-G (9.1.2) */
#define bcm_omci_onu2_g_cfg_id_equipment_id BCM_OMCI_ONU2_G_CFG_ID_EQUIPMENT_ID
#define bcm_omci_onu2_g_cfg_id_omcc_version BCM_OMCI_ONU2_G_CFG_ID_OMCC_VERSION
#define bcm_omci_onu2_g_cfg_id_vendor_product_code BCM_OMCI_ONU2_G_CFG_ID_VENDOR_PRODUCT_CODE
#define bcm_omci_onu2_g_cfg_id_security_capability BCM_OMCI_ONU2_G_CFG_ID_SECURITY_CAPABILITY
#define bcm_omci_onu2_g_cfg_id_security_mode BCM_OMCI_ONU2_G_CFG_ID_SECURITY_MODE
#define bcm_omci_onu2_g_cfg_id_total_priority_queue_number BCM_OMCI_ONU2_G_CFG_ID_TOTAL_PRIORITY_QUEUE_NUMBER
#define bcm_omci_onu2_g_cfg_id_total_traf_sched_number BCM_OMCI_ONU2_G_CFG_ID_TOTAL_TRAF_SCHED_NUMBER
#define bcm_omci_onu2_g_cfg_id_deprecated0 BCM_OMCI_ONU2_G_CFG_ID_DEPRECATED0
#define bcm_omci_onu2_g_cfg_id_total_gem_port_number BCM_OMCI_ONU2_G_CFG_ID_TOTAL_GEM_PORT_NUMBER
#define bcm_omci_onu2_g_cfg_id_sys_up_time BCM_OMCI_ONU2_G_CFG_ID_SYS_UP_TIME
#define bcm_omci_onu2_g_cfg_id_connectivity_capability BCM_OMCI_ONU2_G_CFG_ID_CONNECTIVITY_CAPABILITY
#define bcm_omci_onu2_g_cfg_id_connectivity_mode BCM_OMCI_ONU2_G_CFG_ID_CONNECTIVITY_MODE
#define bcm_omci_onu2_g_cfg_id_qos_config_flexibility BCM_OMCI_ONU2_G_CFG_ID_QOS_CONFIG_FLEXIBILITY
#define bcm_omci_onu2_g_cfg_id_priority_queue_scale_factor BCM_OMCI_ONU2_G_CFG_ID_PRIORITY_QUEUE_SCALE_FACTOR
#define bcm_omci_onu2_g_cfg_id_all_properties BCM_OMCI_ONU2_G_CFG_ID__NUM_OF

/* Software image (9.1.4) */
#define bcm_omci_sw_image_cfg_id_version BCM_OMCI_SW_IMAGE_CFG_ID_VERSION
#define bcm_omci_sw_image_cfg_id_is_committed BCM_OMCI_SW_IMAGE_CFG_ID_IS_COMMITTED
#define bcm_omci_sw_image_cfg_id_is_active BCM_OMCI_SW_IMAGE_CFG_ID_IS_ACTIVE
#define bcm_omci_sw_image_cfg_id_is_valid BCM_OMCI_SW_IMAGE_CFG_ID_IS_VALID
#define bcm_omci_sw_image_cfg_id_product_code BCM_OMCI_SW_IMAGE_CFG_ID_PRODUCT_CODE
#define bcm_omci_sw_image_cfg_id_image_hash BCM_OMCI_SW_IMAGE_CFG_ID_IMAGE_HASH
#define bcm_omci_sw_image_cfg_id_all_properties BCM_OMCI_SW_IMAGE_CFG_ID__NUM_OF

/* ANI-G (9.2.1) */
#define bcm_omci_ani_g_cfg_id_sr_indication BCM_OMCI_ANI_G_CFG_ID_SR_INDICATION
#define bcm_omci_ani_g_cfg_id_total_tcont_number BCM_OMCI_ANI_G_CFG_ID_TOTAL_TCONT_NUMBER
#define bcm_omci_ani_g_cfg_id_gem_block_length BCM_OMCI_ANI_G_CFG_ID_GEM_BLOCK_LENGTH
#define bcm_omci_ani_g_cfg_id_piggy_back_dba_reporting BCM_OMCI_ANI_G_CFG_ID_PIGGY_BACK_DBA_REPORTING
#define bcm_omci_ani_g_cfg_id_deprecated BCM_OMCI_ANI_G_CFG_ID_DEPRECATED
#define bcm_omci_ani_g_cfg_id_sf_threshold BCM_OMCI_ANI_G_CFG_ID_SF_THRESHOLD
#define bcm_omci_ani_g_cfg_id_sd_threshold BCM_OMCI_ANI_G_CFG_ID_SD_THRESHOLD
#define bcm_omci_ani_g_cfg_id_arc BCM_OMCI_ANI_G_CFG_ID_ARC
#define bcm_omci_ani_g_cfg_id_arc_interval BCM_OMCI_ANI_G_CFG_ID_ARC_INTERVAL
#define bcm_omci_ani_g_cfg_id_optical_signal_level BCM_OMCI_ANI_G_CFG_ID_OPTICAL_SIGNAL_LEVEL
#define bcm_omci_ani_g_cfg_id_lower_optical_threshold BCM_OMCI_ANI_G_CFG_ID_LOWER_OPTICAL_THRESHOLD
#define bcm_omci_ani_g_cfg_id_upper_optical_threshold BCM_OMCI_ANI_G_CFG_ID_UPPER_OPTICAL_THRESHOLD
#define bcm_omci_ani_g_cfg_id_onu_response_time BCM_OMCI_ANI_G_CFG_ID_ONU_RESPONSE_TIME
#define bcm_omci_ani_g_cfg_id_transmit_optical_level BCM_OMCI_ANI_G_CFG_ID_TRANSMIT_OPTICAL_LEVEL
#define bcm_omci_ani_g_cfg_id_lower_transmit_power_threshold BCM_OMCI_ANI_G_CFG_ID_LOWER_TRANSMIT_POWER_THRESHOLD
#define bcm_omci_ani_g_cfg_id_upper_transmit_power_threshold BCM_OMCI_ANI_G_CFG_ID_UPPER_TRANSMIT_POWER_THRESHOLD
#define bcm_omci_ani_g_cfg_id_all_properties BCM_OMCI_ANI_G_CFG_ID__NUM_OF

/* GEM Port Network CTP PM(9.2.13) */
#define bcm_omci_gem_port_net_ctp_pm_cfg_id_interval_end_time BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_INTERVAL_END_TIME
#define bcm_omci_gem_port_net_ctp_pm_cfg_id_threshold_data BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_THRESHOLD_DATA
#define bcm_omci_gem_port_net_ctp_pm_cfg_id_tx_gem_frames BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_TX_GEM_FRAMES
#define bcm_omci_gem_port_net_ctp_pm_cfg_id_rx_gem_frames BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_RX_GEM_FRAMES
#define bcm_omci_gem_port_net_ctp_pm_cfg_id_rx_payload_bytes BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_RX_PAYLOAD_BYTES
#define bcm_omci_gem_port_net_ctp_pm_cfg_id_tx_payload_bytes BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_TX_PAYLOAD_BYTES
#define bcm_omci_gem_port_net_ctp_pm_cfg_id_encry_key_errors BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_ENCRY_KEY_ERRORS
#define bcm_omci_gem_port_net_ctp_pm_cfg_id_all_properties BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID__NUM_OF

/* ETH FRAME UPSTREAM PM(9.3.30) */
#define bcm_omci_eth_frame_upstream_pm_cfg_id_interval_end_time BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_INTERVAL_END_TIME
#define bcm_omci_eth_frame_upstream_pm_cfg_id_threshold_data BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_THRESHOLD_DATA
#define bcm_omci_eth_frame_upstream_pm_cfg_id_up_drop_events BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_DROP_EVENTS
#define bcm_omci_eth_frame_upstream_pm_cfg_id_up_octets BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_OCTETS
#define bcm_omci_eth_frame_upstream_pm_cfg_id_up_packets BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS
#define bcm_omci_eth_frame_upstream_pm_cfg_id_up_broadcast_packets BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_BROADCAST_PACKETS
#define bcm_omci_eth_frame_upstream_pm_cfg_id_up_multicast_packets BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_MULTICAST_PACKETS
#define bcm_omci_eth_frame_upstream_pm_cfg_id_up_crc_errored_packets BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_CRC_ERRORED_PACKETS
#define bcm_omci_eth_frame_upstream_pm_cfg_id_up_undersize_packets BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_UNDERSIZE_PACKETS
#define bcm_omci_eth_frame_upstream_pm_cfg_id_up_oversize_packets BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_OVERSIZE_PACKETS
#define bcm_omci_eth_frame_upstream_pm_cfg_id_up_packets_64_octets BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_64_OCTETS
#define bcm_omci_eth_frame_upstream_pm_cfg_id_up_packets_65_127_octets BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_65_127_OCTETS
#define bcm_omci_eth_frame_upstream_pm_cfg_id_up_packets_128_255_octets BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_128_255_OCTETS
#define bcm_omci_eth_frame_upstream_pm_cfg_id_up_packets_256_511_octets BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_256_511_OCTETS
#define bcm_omci_eth_frame_upstream_pm_cfg_id_up_packets_512_1023_octets BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_512_1023_OCTETS
#define bcm_omci_eth_frame_upstream_pm_cfg_id_up_packets_1024_1518_octets BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_1024_1518_OCTETS
#define bcm_omci_eth_frame_upstream_pm_cfg_id_all_properties BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID__NUM_OF

/* ETH FRAME DOWNSTREAM PM(9.3.31) */
#define bcm_omci_eth_frame_downstream_pm_cfg_id_interval_end_time BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_INTERVAL_END_TIME
#define bcm_omci_eth_frame_downstream_pm_cfg_id_threshold_data BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_THRESHOLD_DATA
#define bcm_omci_eth_frame_downstream_pm_cfg_id_dn_drop_events BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_DROP_EVENTS
#define bcm_omci_eth_frame_downstream_pm_cfg_id_dn_octets BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_OCTETS
#define bcm_omci_eth_frame_downstream_pm_cfg_id_dn_packets BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS
#define bcm_omci_eth_frame_downstream_pm_cfg_id_dn_broadcast_packets BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_BROADCAST_PACKETS
#define bcm_omci_eth_frame_downstream_pm_cfg_id_dn_multicast_packets BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_MULTICAST_PACKETS
#define bcm_omci_eth_frame_downstream_pm_cfg_id_dn_crc_errored_packets BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_CRC_ERRORED_PACKETS
#define bcm_omci_eth_frame_downstream_pm_cfg_id_dn_undersize_packets BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_UNDERSIZE_PACKETS
#define bcm_omci_eth_frame_downstream_pm_cfg_id_dn_oversize_packets BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_OVERSIZE_PACKETS
#define bcm_omci_eth_frame_downstream_pm_cfg_id_dn_packets_64_octets BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_64_OCTETS
#define bcm_omci_eth_frame_downstream_pm_cfg_id_dn_packets_65_127_octets BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_65_127_OCTETS
#define bcm_omci_eth_frame_downstream_pm_cfg_id_dn_packets_128_255_octets BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_128_255_OCTETS
#define bcm_omci_eth_frame_downstream_pm_cfg_id_dn_packets_256_511_octets BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_256_511_OCTETS
#define bcm_omci_eth_frame_downstream_pm_cfg_id_dn_packets_512_1023_octets BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_512_1023_OCTETS
#define bcm_omci_eth_frame_downstream_pm_cfg_id_dn_packets_1024_1518_octets BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_1024_1518_OCTETS
#define bcm_omci_eth_frame_downstream_pm_cfg_id_all_properties BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID__NUM_OF

/* FEC PERFORMANCE PM DATA(9.2.9) */
#define bcm_omci_fec_pm_cfg_id_interval_end_time BCM_OMCI_FEC_PM_CFG_ID_INTERVAL_END_TIME
#define bcm_omci_fec_pm_cfg_id_threshold_data BCM_OMCI_FEC_PM_CFG_ID_THRESHOLD_DATA
#define bcm_omci_fec_pm_cfg_id_corrected_bytes BCM_OMCI_FEC_PM_CFG_ID_CORRECTED_BYTES
#define bcm_omci_fec_pm_cfg_id_corrected_code_words BCM_OMCI_FEC_PM_CFG_ID_CORRECTED_CODE_WORDS
#define bcm_omci_fec_pm_cfg_id_uncorrectable_code_words BCM_OMCI_FEC_PM_CFG_ID_UNCORRECTABLE_CODE_WORDS
#define bcm_omci_fec_pm_cfg_id_total_code_words BCM_OMCI_FEC_PM_CFG_ID_TOTAL_CODE_WORDS
#define bcm_omci_fec_pm_cfg_id_fec_seconds BCM_OMCI_FEC_PM_CFG_ID_FEC_SECONDS
#define bcm_omci_fec_pm_cfg_id_all_properties BCM_OMCI_FEC_PM_CFG_ID__NUM_OF

/* XG-PON TC PERFORMANCE PM DATA(9.2.15) */
#define bcm_omci_xgpon_tc_pm_cfg_id_interval_end_time BCM_OMCI_XGPON_TC_PM_CFG_ID_INTERVAL_END_TIME
#define bcm_omci_xgpon_tc_pm_cfg_id_threshold_data BCM_OMCI_XGPON_TC_PM_CFG_ID_THRESHOLD_DATA
#define bcm_omci_xgpon_tc_pm_cfg_id_psbd_hec_error_count BCM_OMCI_XGPON_TC_PM_CFG_ID_PSBD_HEC_ERROR_COUNT
#define bcm_omci_xgpon_tc_pm_cfg_id_xgtc_hec_error_count BCM_OMCI_XGPON_TC_PM_CFG_ID_XGTC_HEC_ERROR_COUNT
#define bcm_omci_xgpon_tc_pm_cfg_id_unknown_profile_count BCM_OMCI_XGPON_TC_PM_CFG_ID_UNKNOWN_PROFILE_COUNT
#define bcm_omci_xgpon_tc_pm_cfg_id_transmitted_xgem_frames BCM_OMCI_XGPON_TC_PM_CFG_ID_TRANSMITTED_XGEM_FRAMES
#define bcm_omci_xgpon_tc_pm_cfg_id_fragment_xgem_frames BCM_OMCI_XGPON_TC_PM_CFG_ID_FRAGMENT_XGEM_FRAMES
#define bcm_omci_xgpon_tc_pm_cfg_id_xgem_hec_lost_words_count BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_HEC_LOST_WORDS_COUNT
#define bcm_omci_xgpon_tc_pm_cfg_id_xgem_key_errors BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_KEY_ERRORS
#define bcm_omci_xgpon_tc_pm_cfg_id_xgem_hec_error_count BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_HEC_ERROR_COUNT
#define bcm_omci_xgpon_tc_pm_cfg_id_tx_bytes_in_non_idle_xgem_frames BCM_OMCI_XGPON_TC_PM_CFG_ID_TX_BYTES_IN_NON_IDLE_XGEM_FRAMES
#define bcm_omci_xgpon_tc_pm_cfg_id_rx_bytes_in_non_idle_xgem_frames BCM_OMCI_XGPON_TC_PM_CFG_ID_RX_BYTES_IN_NON_IDLE_XGEM_FRAMES
#define bcm_omci_xgpon_tc_pm_cfg_id_lods_event_count BCM_OMCI_XGPON_TC_PM_CFG_ID_LODS_EVENT_COUNT
#define bcm_omci_xgpon_tc_pm_cfg_id_lods_event_restored_count BCM_OMCI_XGPON_TC_PM_CFG_ID_LODS_EVENT_RESTORED_COUNT
#define bcm_omci_xgpon_tc_pm_cfg_id_onu_reactivation_by_lods_events BCM_OMCI_XGPON_TC_PM_CFG_ID_ONU_REACTIVATION_BY_LODS_EVENTS
#define bcm_omci_xgpon_tc_pm_cfg_id_all_properties BCM_OMCI_XGPON_TC_PM_CFG_ID__NUM_OF

/* IP Host Config Data (9.4.1) */
#define bcm_omci_ip_host_config_data_cfg_id_ip_options BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_IP_OPTIONS
#define bcm_omci_ip_host_config_data_cfg_id_mac_addr BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_MAC_ADDR
#define bcm_omci_ip_host_config_data_cfg_id_onu_id BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_ONU_ID
#define bcm_omci_ip_host_config_data_cfg_id_ip_address BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_IP_ADDRESS
#define bcm_omci_ip_host_config_data_cfg_id_mask BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_MASK
#define bcm_omci_ip_host_config_data_cfg_id_gateway BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_GATEWAY
#define bcm_omci_ip_host_config_data_cfg_id_primary_dns BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_PRIMARY_DNS
#define bcm_omci_ip_host_config_data_cfg_id_secondary_dns BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_SECONDARY_DNS
#define bcm_omci_ip_host_config_data_cfg_id_current_address BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_ADDRESS
#define bcm_omci_ip_host_config_data_cfg_id_current_mask BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_MASK
#define bcm_omci_ip_host_config_data_cfg_id_current_gateway BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_GATEWAY
#define bcm_omci_ip_host_config_data_cfg_id_current_primary_dns BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_PRIMARY_DNS
#define bcm_omci_ip_host_config_data_cfg_id_current_secondary_dns BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_SECONDARY_DNS
#define bcm_omci_ip_host_config_data_cfg_id_domain_name BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_DOMAIN_NAME
#define bcm_omci_ip_host_config_data_cfg_id_host_name BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_HOST_NAME
#define bcm_omci_ip_host_config_data_cfg_id_relay_agent_options BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_RELAY_AGENT_OPTIONS
#define bcm_omci_ip_host_config_data_cfg_id_all_properties BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID__NUM_OF

/* VoIP Line Status (9.9.11) */
#define bcm_omci_voip_line_status_cfg_id_codec BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CODEC
#define bcm_omci_voip_line_status_cfg_id_voice_server_status BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_VOICE_SERVER_STATUS
#define bcm_omci_voip_line_status_cfg_id_port_session_type BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_PORT_SESSION_TYPE
#define bcm_omci_voip_line_status_cfg_id_call1_packet_period BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL1_PACKET_PERIOD
#define bcm_omci_voip_line_status_cfg_id_call2_packet_period BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL2_PACKET_PERIOD
#define bcm_omci_voip_line_status_cfg_id_call1_dest_address BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL1_DEST_ADDRESS
#define bcm_omci_voip_line_status_cfg_id_call2_dest_address BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL2_DEST_ADDRESS
#define bcm_omci_voip_line_status_cfg_id_line_state BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_LINE_STATE
#define bcm_omci_voip_line_status_cfg_id_emergency_call_status BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_EMERGENCY_CALL_STATUS
#define bcm_omci_voip_line_status_cfg_id_all_properties BCM_OMCI_VOIP_LINE_STATUS_CFG_ID__NUM_OF

/* VoIP Line Status (9.9.11) */
#define bcm_omci_voip_media_profile_cfg_id_fax_mode BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_FAX_MODE
#define bcm_omci_voip_media_profile_cfg_id_voice_service_prof_ptr BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_VOICE_SERVICE_PROF_PTR
#define bcm_omci_voip_media_profile_cfg_id_codec_selection1 BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION1
#define bcm_omci_voip_media_profile_cfg_id_packet_period1 BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD1
#define bcm_omci_voip_media_profile_cfg_id_silence_supression1 BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION1
#define bcm_omci_voip_media_profile_cfg_id_codec_selection2 BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION2
#define bcm_omci_voip_media_profile_cfg_id_packet_period2 BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD2
#define bcm_omci_voip_media_profile_cfg_id_silence_supression2 BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION2
#define bcm_omci_voip_media_profile_cfg_id_codec_selection3 BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION3
#define bcm_omci_voip_media_profile_cfg_id_packet_period3 BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD3
#define bcm_omci_voip_media_profile_cfg_id_silence_supression3 BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION3
#define bcm_omci_voip_media_profile_cfg_id_codec_selection4 BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION4
#define bcm_omci_voip_media_profile_cfg_id_packet_period4 BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD4
#define bcm_omci_voip_media_profile_cfg_id_silence_supression4 BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION4
#define bcm_omci_voip_media_profile_cfg_id_oob_dtmf BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_OOB_DTMF
#define bcm_omci_voip_media_profile_cfg_id_rtp_profile_ptr BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_RTP_PROFILE_PTR
#define bcm_omci_voip_media_profile_cfg_id_all_properties BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID__NUM_OF

/* SIP User Data (9.9.2) */
#define bcm_omci_sip_user_data_cfg_id_sip_agent_ptr BCM_OMCI_SIP_USER_DATA_CFG_ID_SIP_AGENT_PTR
#define bcm_omci_sip_user_data_cfg_id_user_part_aor BCM_OMCI_SIP_USER_DATA_CFG_ID_USER_PART_AOR
#define bcm_omci_sip_user_data_cfg_id_sip_display_name BCM_OMCI_SIP_USER_DATA_CFG_ID_SIP_DISPLAY_NAME
#define bcm_omci_sip_user_data_cfg_id_username_password BCM_OMCI_SIP_USER_DATA_CFG_ID_USERNAME_PASSWORD
#define bcm_omci_sip_user_data_cfg_id_voicemail_server_uri BCM_OMCI_SIP_USER_DATA_CFG_ID_VOICEMAIL_SERVER_URI
#define bcm_omci_sip_user_data_cfg_id_voicemail_subscription_exp_time BCM_OMCI_SIP_USER_DATA_CFG_ID_VOICEMAIL_SUBSCRIPTION_EXP_TIME
#define bcm_omci_sip_user_data_cfg_id_network_dial_plan_ptr BCM_OMCI_SIP_USER_DATA_CFG_ID_NETWORK_DIAL_PLAN_PTR
#define bcm_omci_sip_user_data_cfg_id_app_service_prof_ptr BCM_OMCI_SIP_USER_DATA_CFG_ID_APP_SERVICE_PROF_PTR
#define bcm_omci_sip_user_data_cfg_id_feature_code_ptr BCM_OMCI_SIP_USER_DATA_CFG_ID_FEATURE_CODE_PTR
#define bcm_omci_sip_user_data_cfg_id_pptp_ptr BCM_OMCI_SIP_USER_DATA_CFG_ID_PPTP_PTR
#define bcm_omci_sip_user_data_cfg_id_release_timer BCM_OMCI_SIP_USER_DATA_CFG_ID_RELEASE_TIMER
#define bcm_omci_sip_user_data_cfg_id_roh_timer BCM_OMCI_SIP_USER_DATA_CFG_ID_ROH_TIMER
#define bcm_omci_sip_user_data_cfg_id_all_properties BCM_OMCI_SIP_USER_DATA_CFG_ID__NUM_OF

/* SIP Agent Config Data (9.9.3) */
#define bcm_omci_sip_agent_config_data_cfg_id_proxy_server_addr_ptr BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_PROXY_SERVER_ADDR_PTR
#define bcm_omci_sip_agent_config_data_cfg_id_outbound_proxy_addr_ptr BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_OUTBOUND_PROXY_ADDR_PTR
#define bcm_omci_sip_agent_config_data_cfg_id_primary_sip_dns BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_PRIMARY_SIP_DNS
#define bcm_omci_sip_agent_config_data_cfg_id_secondary_sip_dns BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SECONDARY_SIP_DNS
#define bcm_omci_sip_agent_config_data_cfg_id_tcp_udp_ptr BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_TCP_UDP_PTR
#define bcm_omci_sip_agent_config_data_cfg_id_sip_reg_exp_time BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REG_EXP_TIME
#define bcm_omci_sip_agent_config_data_cfg_id_sip_rereg_head_start_time BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REREG_HEAD_START_TIME
#define bcm_omci_sip_agent_config_data_cfg_id_host_part_uri BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_HOST_PART_URI
#define bcm_omci_sip_agent_config_data_cfg_id_sip_status BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_STATUS
#define bcm_omci_sip_agent_config_data_cfg_id_sip_registrar BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REGISTRAR
#define bcm_omci_sip_agent_config_data_cfg_id_softswitch BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SOFTSWITCH
#define bcm_omci_sip_agent_config_data_cfg_id_sip_response_table BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_RESPONSE_TABLE
#define bcm_omci_sip_agent_config_data_cfg_id_sip_transmit_control BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_TRANSMIT_CONTROL
#define bcm_omci_sip_agent_config_data_cfg_id_sip_uri_format BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_URI_FORMAT
#define bcm_omci_sip_agent_config_data_cfg_id_redundant_sip_agent_ptr BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_REDUNDANT_SIP_AGENT_PTR
#define bcm_omci_sip_agent_config_data_cfg_id_all_properties BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID__NUM_OF

/* Network Address (9.12.3) */
#define bcm_omci_network_address_cfg_id_security_ptr BCM_OMCI_NETWORK_ADDRESS_CFG_ID_SECURITY_PTR
#define bcm_omci_network_address_cfg_id_address_ptr BCM_OMCI_NETWORK_ADDRESS_CFG_ID_ADDRESS_PTR
#define bcm_omci_network_address_cfg_id_all_properties BCM_OMCI_NETWORK_ADDRESS_CFG_ID__NUM_OF

/* Large String (9.12.5) */
#define bcm_omci_large_string_cfg_id_number_of_parts BCM_OMCI_LARGE_STRING_CFG_ID_NUMBER_OF_PARTS
#define bcm_omci_large_string_cfg_id_part1 BCM_OMCI_LARGE_STRING_CFG_ID_PART1
#define bcm_omci_large_string_cfg_id_part2 BCM_OMCI_LARGE_STRING_CFG_ID_PART2
#define bcm_omci_large_string_cfg_id_part3 BCM_OMCI_LARGE_STRING_CFG_ID_PART3
#define bcm_omci_large_string_cfg_id_part4 BCM_OMCI_LARGE_STRING_CFG_ID_PART4
#define bcm_omci_large_string_cfg_id_part5 BCM_OMCI_LARGE_STRING_CFG_ID_PART5
#define bcm_omci_large_string_cfg_id_part6 BCM_OMCI_LARGE_STRING_CFG_ID_PART6
#define bcm_omci_large_string_cfg_id_part7 BCM_OMCI_LARGE_STRING_CFG_ID_PART7
#define bcm_omci_large_string_cfg_id_part8 BCM_OMCI_LARGE_STRING_CFG_ID_PART8
#define bcm_omci_large_string_cfg_id_part9 BCM_OMCI_LARGE_STRING_CFG_ID_PART9
#define bcm_omci_large_string_cfg_id_part10 BCM_OMCI_LARGE_STRING_CFG_ID_PART10
#define bcm_omci_large_string_cfg_id_part11 BCM_OMCI_LARGE_STRING_CFG_ID_PART11
#define bcm_omci_large_string_cfg_id_part12 BCM_OMCI_LARGE_STRING_CFG_ID_PART12
#define bcm_omci_large_string_cfg_id_part13 BCM_OMCI_LARGE_STRING_CFG_ID_PART13
#define bcm_omci_large_string_cfg_id_part14 BCM_OMCI_LARGE_STRING_CFG_ID_PART14
#define bcm_omci_large_string_cfg_id_part15 BCM_OMCI_LARGE_STRING_CFG_ID_PART15
#define bcm_omci_large_string_cfg_id_all_properties BCM_OMCI_LARGE_STRING_CFG_ID__NUM_OF

/* Authentication Security Method (9.12.4) */
#define bcm_omci_authentication_security_method_cfg_id_validation_scheme BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_VALIDATION_SCHEME
#define bcm_omci_authentication_security_method_cfg_id_username1 BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_USERNAME1
#define bcm_omci_authentication_security_method_cfg_id_password BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_PASSWORD
#define bcm_omci_authentication_security_method_cfg_id_realm BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_REALM
#define bcm_omci_authentication_security_method_cfg_id_username2 BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_USERNAME2
#define bcm_omci_authentication_security_method_cfg_id_all_properties BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID__NUM_OF

/* Voice Service Profile (9.9.6) */
#define bcm_omci_voice_service_profile_cfg_id_announcement_type BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_ANNOUNCEMENT_TYPE
#define bcm_omci_voice_service_profile_cfg_id_jitter_target BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_JITTER_TARGET
#define bcm_omci_voice_service_profile_cfg_id_jitter_buffer_max BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_JITTER_BUFFER_MAX
#define bcm_omci_voice_service_profile_cfg_id_echo_cancel BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_ECHO_CANCEL
#define bcm_omci_voice_service_profile_cfg_id_pstn_protocol_variant BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_PSTN_PROTOCOL_VARIANT
#define bcm_omci_voice_service_profile_cfg_id_dtmf_digit_levels BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_DTMF_DIGIT_LEVELS
#define bcm_omci_voice_service_profile_cfg_id_dtmf_digit_duration BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_DTMF_DIGIT_DURATION
#define bcm_omci_voice_service_profile_cfg_id_hook_flash_min_time BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_HOOK_FLASH_MIN_TIME
#define bcm_omci_voice_service_profile_cfg_id_hook_flash_max_time BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_HOOK_FLASH_MAX_TIME
#define bcm_omci_voice_service_profile_cfg_id_tone_pattern_table BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_TONE_PATTERN_TABLE
#define bcm_omci_voice_service_profile_cfg_id_tone_event_table BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_TONE_EVENT_TABLE
#define bcm_omci_voice_service_profile_cfg_id_ringing_pattern_table BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_RINGING_PATTERN_TABLE
#define bcm_omci_voice_service_profile_cfg_id_ringing_event_table BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_RINGING_EVENT_TABLE
#define bcm_omci_voice_service_profile_cfg_id_network_specific_ext_ptr BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_NETWORK_SPECIFIC_EXT_PTR
#define bcm_omci_voice_service_profile_cfg_id_all_properties BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID__NUM_OF

/* VoIP config data (9.9.18) */
#define bcm_omci_voip_config_data_cfg_id_available_signalling_protocols BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_AVAILABLE_SIGNALLING_PROTOCOLS
#define bcm_omci_voip_config_data_cfg_id_signalling_protocol_used BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_SIGNALLING_PROTOCOL_USED
#define bcm_omci_voip_config_data_cfg_id_available_voip_config_methods BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_AVAILABLE_VOIP_CONFIG_METHODS
#define bcm_omci_voip_config_data_cfg_id_voip_config_method_used BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOIP_CONFIG_METHOD_USED
#define bcm_omci_voip_config_data_cfg_id_voice_config_ptr BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOICE_CONFIG_PTR
#define bcm_omci_voip_config_data_cfg_id_voip_config_state BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOIP_CONFIG_STATE
#define bcm_omci_voip_config_data_cfg_id_retrieve_profile BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_RETRIEVE_PROFILE
#define bcm_omci_voip_config_data_cfg_id_profile_version BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_PROFILE_VERSION
#define bcm_omci_voip_config_data_cfg_id_all_properties BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID__NUM_OF

/* VoIP voice CTP (9.9.4) */
#define bcm_omci_voip_voice_ctp_cfg_id_user_protocol_ptr BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_USER_PROTOCOL_PTR
#define bcm_omci_voip_voice_ctp_cfg_id_pptp_ptr BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_PPTP_PTR
#define bcm_omci_voip_voice_ctp_cfg_id_voice_media_profile_ptr BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_VOICE_MEDIA_PROFILE_PTR
#define bcm_omci_voip_voice_ctp_cfg_id_signalling_code BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_SIGNALLING_CODE
#define bcm_omci_voip_voice_ctp_cfg_id_all_properties BCM_OMCI_VOIP_VOICE_CTP_CFG_ID__NUM_OF

/* TCP/UDP config data (9.4.3) */
#define bcm_omci_tcp_udp_config_data_cfg_id_port_id BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_PORT_ID
#define bcm_omci_tcp_udp_config_data_cfg_id_protocol BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_PROTOCOL
#define bcm_omci_tcp_udp_config_data_cfg_id_tos BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_TOS
#define bcm_omci_tcp_udp_config_data_cfg_id_ip_host_ptr BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_IP_HOST_PTR
#define bcm_omci_tcp_udp_config_data_cfg_id_all_properties BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID__NUM_OF

/* Network dial plan table (9.9.10) */
#define bcm_omci_network_dial_plan_table_cfg_id_dial_plan_number BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_NUMBER
#define bcm_omci_network_dial_plan_table_cfg_id_dial_plan_table_max_size BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_TABLE_MAX_SIZE
#define bcm_omci_network_dial_plan_table_cfg_id_critical_dial_timeout BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_CRITICAL_DIAL_TIMEOUT
#define bcm_omci_network_dial_plan_table_cfg_id_partial_dial_timeout BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_PARTIAL_DIAL_TIMEOUT
#define bcm_omci_network_dial_plan_table_cfg_id_dial_plan_format BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_FORMAT
#define bcm_omci_network_dial_plan_table_cfg_id_dial_plan_table BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_TABLE
#define bcm_omci_network_dial_plan_table_cfg_id_all_properties BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID__NUM_OF

/* RTP profile data (9.9.7) */
#define bcm_omci_rtp_profile_data_cfg_id_local_port_min BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_LOCAL_PORT_MIN
#define bcm_omci_rtp_profile_data_cfg_id_local_port_max BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_LOCAL_PORT_MAX
#define bcm_omci_rtp_profile_data_cfg_id_dscp_mark BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_DSCP_MARK
#define bcm_omci_rtp_profile_data_cfg_id_piggyback_events BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_PIGGYBACK_EVENTS
#define bcm_omci_rtp_profile_data_cfg_id_tone_events BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_TONE_EVENTS
#define bcm_omci_rtp_profile_data_cfg_id_dtmf_events BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_DTMF_EVENTS
#define bcm_omci_rtp_profile_data_cfg_id_cas_events BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_CAS_EVENTS
#define bcm_omci_rtp_profile_data_cfg_id_ip_host_config_ptr BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_IP_HOST_CONFIG_PTR
#define bcm_omci_rtp_profile_data_cfg_id_all_properties BCM_OMCI_RTP_PROFILE_DATA_CFG_ID__NUM_OF

/* Physical path termination point POTS UNI (9.9.1) */
#define bcm_omci_pots_uni_cfg_id_admin_state BCM_OMCI_POTS_UNI_CFG_ID_ADMIN_STATE
#define bcm_omci_pots_uni_cfg_id_deprecated1 BCM_OMCI_POTS_UNI_CFG_ID_DEPRECATED1
#define bcm_omci_pots_uni_cfg_id_arc BCM_OMCI_POTS_UNI_CFG_ID_ARC
#define bcm_omci_pots_uni_cfg_id_arc_interval BCM_OMCI_POTS_UNI_CFG_ID_ARC_INTERVAL
#define bcm_omci_pots_uni_cfg_id_impedance BCM_OMCI_POTS_UNI_CFG_ID_IMPEDANCE
#define bcm_omci_pots_uni_cfg_id_transmission_path BCM_OMCI_POTS_UNI_CFG_ID_TRANSMISSION_PATH
#define bcm_omci_pots_uni_cfg_id_rx_gain BCM_OMCI_POTS_UNI_CFG_ID_RX_GAIN
#define bcm_omci_pots_uni_cfg_id_tx_gain BCM_OMCI_POTS_UNI_CFG_ID_TX_GAIN
#define bcm_omci_pots_uni_cfg_id_oper_state BCM_OMCI_POTS_UNI_CFG_ID_OPER_STATE
#define bcm_omci_pots_uni_cfg_id_hook_state BCM_OMCI_POTS_UNI_CFG_ID_HOOK_STATE
#define bcm_omci_pots_uni_cfg_id_holdover_time BCM_OMCI_POTS_UNI_CFG_ID_HOLDOVER_TIME
#define bcm_omci_pots_uni_cfg_id_nominal_feed_voltage BCM_OMCI_POTS_UNI_CFG_ID_NOMINAL_FEED_VOLTAGE
#define bcm_omci_pots_uni_cfg_id_all_properties BCM_OMCI_POTS_UNI_CFG_ID__NUM_OF

/* Circuit pack (9.1.6) */
#define bcm_omci_circuit_pack_cfg_id_type BCM_OMCI_CIRCUIT_PACK_CFG_ID_TYPE
#define bcm_omci_circuit_pack_cfg_id_number_of_ports BCM_OMCI_CIRCUIT_PACK_CFG_ID_NUMBER_OF_PORTS
#define bcm_omci_circuit_pack_cfg_id_serial_number BCM_OMCI_CIRCUIT_PACK_CFG_ID_SERIAL_NUMBER
#define bcm_omci_circuit_pack_cfg_id_version BCM_OMCI_CIRCUIT_PACK_CFG_ID_VERSION
#define bcm_omci_circuit_pack_cfg_id_vendor_id BCM_OMCI_CIRCUIT_PACK_CFG_ID_VENDOR_ID
#define bcm_omci_circuit_pack_cfg_id_admin_state BCM_OMCI_CIRCUIT_PACK_CFG_ID_ADMIN_STATE
#define bcm_omci_circuit_pack_cfg_id_oper_state BCM_OMCI_CIRCUIT_PACK_CFG_ID_OPER_STATE
#define bcm_omci_circuit_pack_cfg_id_bridged_or_ip BCM_OMCI_CIRCUIT_PACK_CFG_ID_BRIDGED_OR_IP
#define bcm_omci_circuit_pack_cfg_id_equip_id BCM_OMCI_CIRCUIT_PACK_CFG_ID_EQUIP_ID
#define bcm_omci_circuit_pack_cfg_id_card_config BCM_OMCI_CIRCUIT_PACK_CFG_ID_CARD_CONFIG
#define bcm_omci_circuit_pack_cfg_id_tcont_buffer_number BCM_OMCI_CIRCUIT_PACK_CFG_ID_TCONT_BUFFER_NUMBER
#define bcm_omci_circuit_pack_cfg_id_priority_queue_number BCM_OMCI_CIRCUIT_PACK_CFG_ID_PRIORITY_QUEUE_NUMBER
#define bcm_omci_circuit_pack_cfg_id_traffic_sched_number BCM_OMCI_CIRCUIT_PACK_CFG_ID_TRAFFIC_SCHED_NUMBER
#define bcm_omci_circuit_pack_cfg_id_power_shed_override BCM_OMCI_CIRCUIT_PACK_CFG_ID_POWER_SHED_OVERRIDE
#define bcm_omci_circuit_pack_cfg_id_all_properties BCM_OMCI_CIRCUIT_PACK_CFG_ID__NUM_OF

/* Enhanced Security Control (9.13.11) */
#define bcm_omci_enhanced_security_control_cfg_id_crypto_capabilities BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_CRYPTO_CAPABILITIES
#define bcm_omci_enhanced_security_control_cfg_id_olt_random_challenge_table BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_RANDOM_CHALLENGE_TABLE
#define bcm_omci_enhanced_security_control_cfg_id_olt_challenge_status BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_CHALLENGE_STATUS
#define bcm_omci_enhanced_security_control_cfg_id_onu_selected_crypto_capabilities BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_SELECTED_CRYPTO_CAPABILITIES
#define bcm_omci_enhanced_security_control_cfg_id_onu_random_challenge_table BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_RANDOM_CHALLENGE_TABLE
#define bcm_omci_enhanced_security_control_cfg_id_onu_auth_result_table BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_AUTH_RESULT_TABLE
#define bcm_omci_enhanced_security_control_cfg_id_olt_auth_result_table BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_AUTH_RESULT_TABLE
#define bcm_omci_enhanced_security_control_cfg_id_olt_result_status BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_RESULT_STATUS
#define bcm_omci_enhanced_security_control_cfg_id_onu_auth_status BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_AUTH_STATUS
#define bcm_omci_enhanced_security_control_cfg_id_master_session_key_name BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_MASTER_SESSION_KEY_NAME
#define bcm_omci_enhanced_security_control_cfg_id_broadcast_key_table BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_BROADCAST_KEY_TABLE
#define bcm_omci_enhanced_security_control_cfg_id_effective_key_length BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_EFFECTIVE_KEY_LENGTH
#define bcm_omci_enhanced_security_control_cfg_id_all_properties BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID__NUM_OF


/* ME class Ids */
typedef enum
{
    BCM_OMCI_ME_CLASS_VAL__BEGIN,
    BCM_OMCI_ME_CLASS_VAL_GAL_ETH_PROF = 272,
    BCM_OMCI_ME_CLASS_VAL_GEM_IW_TP = 266,
    BCM_OMCI_ME_CLASS_VAL_GEM_PORT_NET_CTP = 268,
    BCM_OMCI_ME_CLASS_VAL_IEEE_8021_P_MAPPER_SVC_PROF = 130,
    BCM_OMCI_ME_CLASS_VAL_MAC_BRIDGE_PORT_CONFIG_DATA = 47,
    BCM_OMCI_ME_CLASS_VAL_MAC_BRIDGE_SVC_PROF = 45,
    BCM_OMCI_ME_CLASS_VAL_VLAN_TAG_FILTER_DATA = 84,
    BCM_OMCI_ME_CLASS_VAL_TCONT = 262,
    BCM_OMCI_ME_CLASS_VAL_EXT_VLAN_TAG_OPER_CONFIG_DATA = 171,
    BCM_OMCI_ME_CLASS_VAL_PRIORITY_QUEUE_G = 277,
    BCM_OMCI_ME_CLASS_VAL_MCAST_GEM_IW_TP = 281,
    BCM_OMCI_ME_CLASS_VAL_MCAST_OPERATIONS_PROFILE = 309,
    BCM_OMCI_ME_CLASS_VAL_MCAST_SUBSCRIBER_CONFIG_INFO = 310,
    BCM_OMCI_ME_CLASS_VAL_PPTP_ETH_UNI = 11,
    BCM_OMCI_ME_CLASS_VAL_VIRTUAL_ETH_INTF_POINT = 329,
    BCM_OMCI_ME_CLASS_VAL_ONU_DATA = 2,
    BCM_OMCI_ME_CLASS_VAL_ONU_G = 256,
    BCM_OMCI_ME_CLASS_VAL_ONU2_G = 257,
    BCM_OMCI_ME_CLASS_VAL_SW_IMAGE = 7,
    BCM_OMCI_ME_CLASS_VAL_ANI_G = 263,
    BCM_OMCI_ME_CLASS_VAL_GEM_PORT_NET_CTP_PM = 341,
    BCM_OMCI_ME_CLASS_VAL_ETH_FRAME_UPSTREAM_PM = 322,
    BCM_OMCI_ME_CLASS_VAL_ETH_FRAME_DOWNSTREAM_PM = 321,
    BCM_OMCI_ME_CLASS_VAL_FEC_PM = 312,
    BCM_OMCI_ME_CLASS_VAL_XGPON_TC_PM = 344,
    BCM_OMCI_ME_CLASS_VAL_IP_HOST_CONFIG_DATA = 134,
    BCM_OMCI_ME_CLASS_VAL_VOIP_LINE_STATUS = 141,
    BCM_OMCI_ME_CLASS_VAL_VOIP_MEDIA_PROFILE = 142,
    BCM_OMCI_ME_CLASS_VAL_SIP_USER_DATA = 153,
    BCM_OMCI_ME_CLASS_VAL_SIP_AGENT_CONFIG_DATA = 150,
    BCM_OMCI_ME_CLASS_VAL_NETWORK_ADDRESS = 137,
    BCM_OMCI_ME_CLASS_VAL_LARGE_STRING = 157,
    BCM_OMCI_ME_CLASS_VAL_AUTHENTICATION_SECURITY_METHOD = 148,
    BCM_OMCI_ME_CLASS_VAL_VOICE_SERVICE_PROFILE = 58,
    BCM_OMCI_ME_CLASS_VAL_VOIP_CONFIG_DATA = 138,
    BCM_OMCI_ME_CLASS_VAL_VOIP_VOICE_CTP = 139,
    BCM_OMCI_ME_CLASS_VAL_TCP_UDP_CONFIG_DATA = 136,
    BCM_OMCI_ME_CLASS_VAL_NETWORK_DIAL_PLAN_TABLE = 145,
    BCM_OMCI_ME_CLASS_VAL_RTP_PROFILE_DATA = 143,
    BCM_OMCI_ME_CLASS_VAL_POTS_UNI = 53,
    BCM_OMCI_ME_CLASS_VAL_CIRCUIT_PACK = 6,
    BCM_OMCI_ME_CLASS_VAL_ENHANCED_SECURITY_CONTROL = 332,
    BCM_OMCI_ME_CLASS_VAL__END = 401 /*reserved start range in spec */
} bcm_omci_me_class_val;

#define bcm_omci_me_class_val_gal_eth_prof BCM_OMCI_ME_CLASS_VAL_GAL_ETH_PROF
#define bcm_omci_me_class_val_gem_iw_tp BCM_OMCI_ME_CLASS_VAL_GEM_IW_TP
#define bcm_omci_me_class_val_gem_port_net_ctp BCM_OMCI_ME_CLASS_VAL_GEM_PORT_NET_CTP
#define bcm_omci_me_class_val_ieee_8021_p_mapper_svc_prof BCM_OMCI_ME_CLASS_VAL_IEEE_8021_P_MAPPER_SVC_PROF
#define bcm_omci_me_class_val_mac_bridge_port_config_data BCM_OMCI_ME_CLASS_VAL_MAC_BRIDGE_PORT_CONFIG_DATA
#define bcm_omci_me_class_val_mac_bridge_svc_prof BCM_OMCI_ME_CLASS_VAL_MAC_BRIDGE_SVC_PROF
#define bcm_omci_me_class_val_vlan_tag_filter_data BCM_OMCI_ME_CLASS_VAL_VLAN_TAG_FILTER_DATA
#define bcm_omci_me_class_val_tcont BCM_OMCI_ME_CLASS_VAL_TCONT
#define bcm_omci_me_class_val_ext_vlan_tag_oper_config_data BCM_OMCI_ME_CLASS_VAL_EXT_VLAN_TAG_OPER_CONFIG_DATA
#define bcm_omci_me_class_val_priority_queue_g BCM_OMCI_ME_CLASS_VAL_PRIORITY_QUEUE_G
#define bcm_omci_me_class_val_mcast_gem_iw_tp BCM_OMCI_ME_CLASS_VAL_MCAST_GEM_IW_TP
#define bcm_omci_me_class_val_mcast_operations_profile BCM_OMCI_ME_CLASS_VAL_MCAST_OPERATIONS_PROFILE
#define bcm_omci_me_class_val_mcast_subscriber_config_info BCM_OMCI_ME_CLASS_VAL_MCAST_SUBSCRIBER_CONFIG_INFO
#define bcm_omci_me_class_val_pptp_eth_uni BCM_OMCI_ME_CLASS_VAL_PPTP_ETH_UNI
#define bcm_omci_me_class_val_virtual_eth_intf_point BCM_OMCI_ME_CLASS_VAL_VIRTUAL_ETH_INTF_POINT
#define bcm_omci_me_class_val_onu_data BCM_OMCI_ME_CLASS_VAL_ONU_DATA
#define bcm_omci_me_class_val_onu_g BCM_OMCI_ME_CLASS_VAL_ONU_G
#define bcm_omci_me_class_val_onu2_g BCM_OMCI_ME_CLASS_VAL_ONU2_G
#define bcm_omci_me_class_val_sw_image BCM_OMCI_ME_CLASS_VAL_SW_IMAGE
#define bcm_omci_me_class_val_ani_g BCM_OMCI_ME_CLASS_VAL_ANI_G
#define bcm_omci_me_class_val_gem_port_net_ctp_pm BCM_OMCI_ME_CLASS_VAL_GEM_PORT_NET_CTP_PM
#define bcm_omci_me_class_val_eth_frame_upstream_pm BCM_OMCI_ME_CLASS_VAL_ETH_FRAME_UPSTREAM_PM
#define bcm_omci_me_class_val_eth_frame_downstream_pm BCM_OMCI_ME_CLASS_VAL_ETH_FRAME_DOWNSTREAM_PM
#define bcm_omci_me_class_val_fec_pm BCM_OMCI_ME_CLASS_VAL_FEC_PM
#define bcm_omci_me_class_val_xgpon_tc_pm BCM_OMCI_ME_CLASS_VAL_XGPON_TC_PM
#define bcm_omci_me_class_val_ip_host_config_data BCM_OMCI_ME_CLASS_VAL_IP_HOST_CONFIG_DATA
#define bcm_omci_me_class_val_voip_line_status BCM_OMCI_ME_CLASS_VAL_VOIP_LINE_STATUS
#define bcm_omci_me_class_val_voip_media_profile BCM_OMCI_ME_CLASS_VAL_VOIP_MEDIA_PROFILE
#define bcm_omci_me_class_val_sip_user_data BCM_OMCI_ME_CLASS_VAL_SIP_USER_DATA
#define bcm_omci_me_class_val_sip_agent_config_data BCM_OMCI_ME_CLASS_VAL_SIP_AGENT_CONFIG_DATA
#define bcm_omci_me_class_val_network_address BCM_OMCI_ME_CLASS_VAL_NETWORK_ADDRESS
#define bcm_omci_me_class_val_large_string BCM_OMCI_ME_CLASS_VAL_LARGE_STRING
#define bcm_omci_me_class_val_authentication_security_method BCM_OMCI_ME_CLASS_VAL_AUTHENTICATION_SECURITY_METHOD
#define bcm_omci_me_class_val_voice_service_profile BCM_OMCI_ME_CLASS_VAL_VOICE_SERVICE_PROFILE
#define bcm_omci_me_class_val_voip_config_data BCM_OMCI_ME_CLASS_VAL_VOIP_CONFIG_DATA
#define bcm_omci_me_class_val_voip_voice_ctp BCM_OMCI_ME_CLASS_VAL_VOIP_VOICE_CTP
#define bcm_omci_me_class_val_tcp_udp_config_data BCM_OMCI_ME_CLASS_VAL_TCP_UDP_CONFIG_DATA
#define bcm_omci_me_class_val_network_dial_plan_table BCM_OMCI_ME_CLASS_VAL_NETWORK_DIAL_PLAN_TABLE
#define bcm_omci_me_class_val_rtp_profile_data BCM_OMCI_ME_CLASS_VAL_RTP_PROFILE_DATA
#define bcm_omci_me_class_val_pots_uni BCM_OMCI_ME_CLASS_VAL_POTS_UNI
#define bcm_omci_me_class_val_circuit_pack BCM_OMCI_ME_CLASS_VAL_CIRCUIT_PACK
#define bcm_omci_me_class_val_enhanced_security_control BCM_OMCI_ME_CLASS_VAL_ENHANCED_SECURITY_CONTROL

extern char *bcm_omci_me_class_val_str[];
extern char *bcm_omci_obj_type_str[];

#endif

