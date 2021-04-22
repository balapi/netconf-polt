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
 * @file omci_svc_adapter_bcm_omci.h
 * @brief This file has all the definitions and function prototypes to be used for the BCM stack adapter
 */

#ifndef _OMCI_SVC_ADAPTER_BCM_OMCI_H_
#define _OMCI_SVC_ADAPTER_BCM_OMCI_H_

#include <bcmos_system.h>
#include <bcmolt_api.h>
#include <onu_mgmt_model_types.h>

#include "omci_stack_api.h"


/************************************************************************************
 * Below are stack specific definitions.
************************************************************************************/

/************************  BCM OMCI specifics *****************************************/

#define OMCI_SVC_OMCI_MAX_ATTR_COUNT_IN_ME  BCM_OMCI_MAX_ATTR_COUNT_IN_ME

/** @brief the following definitions map OMCI svc attrId to Broadcom stack specific attr Ids */
#define OMCI_SVC_OMCI_ATTR_ID_NONE                      0
#define OMCI_SVC_OMCI_ATTR_ID_MAX_GEM_PAYLOAD_SIZE      BCM_OMCI_GAL_ETH_PROF_CFG_ID_MAX_GEM_PAYLOAD_SIZE /* = 0,  Max GEM payload Size */

#define OMCI_SVC_OMCI_ATTR_ID_GEM_PORT_NET_CTP_CON_PTR      BCM_OMCI_GEM_IW_TP_CFG_ID_GEM_PORT_NET_CTP_CONN_PTR /* = 0,  GEM port network CTP connectivity pointer */
#define OMCI_SVC_OMCI_ATTR_ID_IW_OPT        BCM_OMCI_GEM_IW_TP_CFG_ID_IW_OPT /* = 1,  Interworking option */
#define OMCI_SVC_OMCI_ATTR_ID_SVC_PROF_PTR      BCM_OMCI_GEM_IW_TP_CFG_ID_SVC_PROF_PTR /* = 2,  Service profile pointer */
#define OMCI_SVC_OMCI_ATTR_ID_IW_TP_PTR     BCM_OMCI_GEM_IW_TP_CFG_ID_IW_TP_PTR /* = 3,  Interworking termination point pointer */
#define OMCI_SVC_OMCI_ATTR_ID_PPTP_COUNT        BCM_OMCI_GEM_IW_TP_CFG_ID_PPTP_COUNT /* = 4,  PPTP Counter */
#define OMCI_SVC_OMCI_ATTR_ID_OPER_STATE        BCM_OMCI_GEM_IW_TP_CFG_ID_OPER_STATE /* = 5,  Operational State */
#define OMCI_SVC_OMCI_ATTR_ID_GAL_PROF_PTR      BCM_OMCI_GEM_IW_TP_CFG_ID_GAL_PROF_PTR /* = 6,  GAL Profile Pointer */
#define OMCI_SVC_OMCI_ATTR_ID_GAL_LPBK_CONFIG       BCM_OMCI_GEM_IW_TP_CFG_ID_GAL_LPBK_CONFIG /* = 7,  GAL Loopback Config */

#define OMCI_SVC_OMCI_ATTR_ID_PORT_ID_VALUE     BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_PORT_ID /* = 0,  Port ID */
#define OMCI_SVC_OMCI_ATTR_ID_TCONT_PTR     BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TCONT_PTR /* = 1,  TCONT Pointer */
#define OMCI_SVC_OMCI_ATTR_ID_DIRECTION     BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_DIRECTION /* = 2,  Direction */
#define OMCI_SVC_OMCI_ATTR_ID_TRAFFIC_MGMT_PTR_US       BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_MGMT_PTR_US /* = 3,  Traffic Management Pointer for US */
#define OMCI_SVC_OMCI_ATTR_ID_TRAFFIC_DESC_PROF_PTR_US      BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_DESC_PROF_PTR_US /* = 4,  Traffic Descriptor Profile Pointer for US */
#define OMCI_SVC_OMCI_ATTR_ID_UNI_COUNT     BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_UNI_COUNT /* = 5,  Uni counter */
#define OMCI_SVC_OMCI_ATTR_ID_PRI_QUEUE_PTR_DS      BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_PRI_QUEUE_PTR_DS /* = 6,  Priority Queue Pointer for downstream */
#define OMCI_SVC_OMCI_ATTR_ID_ENCRYPTION_STATE      BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_ENCRYPTION_STATE /* = 7,  Encryption State */
#define OMCI_SVC_OMCI_ATTR_ID_TRAFFIC_DESC_PROF_PTR_DS      BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_DESC_PROF_PTR_DS /* = 8,  Traffic Descriptor profile pointer for DS */
#define OMCI_SVC_OMCI_ATTR_ID_ENCRYPTION_KEY_RING           BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_ENCRYPTION_KEY_RING /* = 9,  Encryption Key Ring */

#define OMCI_SVC_OMCI_ATTR_ID_MAPPER_SVC_PROF_TP_PTR        BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_TP_PTR /* = 0,  TP pointer */
#define OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI0     BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_0 /* = 1,  Interwork TP pointer for P-bit priority 0: */
#define OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI1     BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_1 /* = 2,  Interwork TP pointer for P-bit priority 1 */
#define OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI2     BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_2 /* = 3,  Interwork TP pointer for P-bit priority 2 */
#define OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI3     BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_3 /* = 4,  Interwork TP pointer for P-bit priority 3 */
#define OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI4     BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_4 /* = 5,  Interwork TP pointer for P-bit priority 4 */
#define OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI5     BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_5 /* = 6,  Interwork TP pointer for P-bit priority 5 */
#define OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI6     BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_6 /* = 7,  Interwork TP pointer for P-bit priority 6 */
#define OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI7     BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_7 /* = 8,  Interwork TP pointer for P-bit priority 7 */
#define OMCI_SVC_OMCI_ATTR_ID_UNMARKED_FRAME_OPT        BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_UNMARKED_FRAME_OPT /* = 9,  Unmarked Frame option */
#define OMCI_SVC_OMCI_ATTR_ID_MAPPER_SVC_PROF_DSCP_TO_P_BIT_MAPPING     BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_DSCP_TO_PBIT_MAPPING /* = 10,  DSCP to P-bit mapping */
#define OMCI_SVC_OMCI_ATTR_ID_DEFAULT_P_BIT_MARKING     BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_DEFAULT_PBIT_ASSUMPTION /* = 11,  Default P-bit assumption */
#define OMCI_SVC_OMCI_ATTR_ID_MAPPER_TP_TYPE        BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_MAPPER_TP_TYPE /* = 12,  TP Type */

#define OMCI_SVC_OMCI_ATTR_ID_BRIDGE_ID_PTR     BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_BRIDGE_ID_PTR /* = 0,  Bridge Id Pointer */
#define OMCI_SVC_OMCI_ATTR_ID_PORT_NUM      BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_NUM /* = 1,  Port num */
#define OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_PORT_TP_TYPE       BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_TP_TYPE /* = 2,  TP Type */
#define OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_PORT_TP_PTR        BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_TP_PTR /* = 3,  TP Pointer */
#define OMCI_SVC_OMCI_ATTR_ID_PORT_PRI      BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_PRI /* = 4,  Port Priority */
#define OMCI_SVC_OMCI_ATTR_ID_PORT_PATH_COST        BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_PATH_COST /* = 5,  Port Path Cost */
#define OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_PORT_CONFIG_DATA_PORT_SPANNING_TREE_IND        BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_SPANNING_TREE_IND /* = 6, Port Spanning Tree Ind */
#define OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_DEPRECATED_1       BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_DEPRECATED_1 /* = 7,  Deprecated 1 */
#define OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_DEPRECATED_2       BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_DEPRECATED_2 /* = 8,  Deprecated 2 */
#define OMCI_SVC_OMCI_ATTR_ID_PORT_MAC_ADDR     BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_MAC_ADDR /* = 9,  Port MAC Addr */
#define OMCI_SVC_OMCI_ATTR_ID_INBOUND_TD_PTR        BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_OUTBOUND_TD_PTR /* = 10,  Outbound TD Pointer */
#define OMCI_SVC_OMCI_ATTR_ID_OUT_TD_PTR        BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_INBOUND_TD_PTR /* = 11,  Inbound TD Pointer */
#define OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_PORT_CONFIG_MAC_LEARNING_DEPTH     BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_MAC_LEARNING_DEPTH /* = 12,  MAC Learning Depth */

#define OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_SVC_PROF_PORT_SPANNING_TREE_IND        BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_SPANNING_TREE_IND /* = 0,  Spanning Tree Indication (bool) */
#define OMCI_SVC_OMCI_ATTR_ID_LEARNING_IND      BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_LEARNING_IND /* = 1,  Learning Indication (bool) */
#define OMCI_SVC_OMCI_ATTR_ID_PORT_BRIDGING_IND     BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_PORT_BRIDGING_IND /* = 2,  Port Bridging Indication (bool) */
#define OMCI_SVC_OMCI_ATTR_ID_PRI       BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_PRI /* = 3,  Priority */
#define OMCI_SVC_OMCI_ATTR_ID_MAX_AGE       BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_MAX_AGE /* = 4,  Max Age */
#define OMCI_SVC_OMCI_ATTR_ID_HELLO_TIME        BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_HELLO_TIME /* = 5,  Hello Time */
#define OMCI_SVC_OMCI_ATTR_ID_FORWARD_DELAY     BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_FORWARD_DELAY /* = 6,  Forward Delay */
#define OMCI_SVC_OMCI_ATTR_ID_UNKNOWN_MAC_ADDR_DISCARD      BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_UNKNOWN_MAC_ADDR_DISCARD /* = 7,  Unknown MAC Address Discard (Bool) */
#define OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_SVC_PROF_MAC_LEARNING_DEPTH        BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_MAC_LEARNING_DEPTH /* = 8,  MAC Learning Depth */
#define OMCI_SVC_OMCI_ATTR_ID_DYNAMIC_FILTERING_AGEING_TIME     BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_DYNAMIC_FILTERING_AGEING_TIME /* = 9,  Dynamic Filtering Ageing Time */

#define OMCI_SVC_OMCI_ATTR_ID_VLAN_FILTER_TABLE     BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_VLAN_FILTER_LIST /* = 0,  VLAN Filter List */
#define OMCI_SVC_OMCI_ATTR_ID_FORWARD_OPER      BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_FORWARD_OPER /* = 1,  Forward Operation */
#define OMCI_SVC_OMCI_ATTR_ID_NO_OF_ENTRIES     BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_NUM_OF_ENTRIES /* = 2,  number of entries */

#define OMCI_SVC_OMCI_ATTR_ID_ALLOC_ID      BCM_OMCI_TCONT_CFG_ID_ALLOC_ID /* = 0,  Alloc-ID */
#define OMCI_SVC_OMCI_ATTR_ID_TCONT_DEPERCATED      BCM_OMCI_TCONT_CFG_ID_DEPRECATED /* = 1,  Deprecated */
#define OMCI_SVC_OMCI_ATTR_ID_POLICY        BCM_OMCI_TCONT_CFG_ID_POLICY /* = 2,  Policy */

#define OMCI_SVC_OMCI_ATTR_ID_ASSOC_TYPE        BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_ASSOC_TYPE /* = 0,  Association Type */
#define OMCI_SVC_OMCI_ATTR_ID_RX_FRAME_VLAN_TAG_OPER_TABLE_MAX_SIZE     BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_RX_FRAME_VLAN_TAG_OPER_TABLE_MAX_SIZE /* = 1,  Rx Frame VLAN Tagging Operation Table Max Size */
#define OMCI_SVC_OMCI_ATTR_ID_INPUT_TPID        BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_INPUT_TPID /* = 2,  Input TPID */
#define OMCI_SVC_OMCI_ATTR_ID_OUTPUT_TPID       BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_OUTPUT_TPID /* = 3,  Output TPID */
#define OMCI_SVC_OMCI_ATTR_ID_DS_MODE       BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_DS_MODE /* = 4,  Downstream Mode */
#define OMCI_SVC_OMCI_ATTR_ID_RX_FRAME_VLAN_TAG_OPER_TABLE      BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_RX_FRAME_VLAN_TAG_OPER_TABLE /* = 5,  Downstream Mode */
#define OMCI_SVC_OMCI_ATTR_ID_ASSOC_ME_PTR      BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_ASSOC_ME_PTR /* = 6,  Associated ME Pointer */
#define OMCI_SVC_OMCI_ATTR_ID_EXT_VLAN_TAG_DSCP_TO_P_BIT_MAPPING        BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_DSCP_TO_PBIT_MAPPING /* = 7,  DSCP to P-bit Mapping */

#define OMCI_SVC_OMCI_ATTR_ID_QUEUE_CONFIG_OPT      BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_QUEUE_CONFIG_OPT /* = 0,  Queue configuration option */
#define OMCI_SVC_OMCI_ATTR_ID_MAX_QUEUE_SIZE        BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_MAX_QUEUE_SIZE /* = 1,  Maximum queue size */
#define OMCI_SVC_OMCI_ATTR_ID_ALLOCATED_QUEUE_SIZE      BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_ALLOCATED_QUEUE_SIZE /* = 2,  Allocated queue size */
#define OMCI_SVC_OMCI_ATTR_ID_DISCARD_COUNT_RESET_INTERVAL      BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DISCARD_COUNTER_RESET_INTERVAL /* = 3,  Discard-block counter reset interval */
#define OMCI_SVC_OMCI_ATTR_ID_DISCARD_THR       BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DISCARD_THRESHOLD /* = 4,  Threshold value for discarded blocks due to buffer overflow */
#define OMCI_SVC_OMCI_ATTR_ID_RELATED_PORT      BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_RELATED_PORT /* = 5,  Related port */
#define OMCI_SVC_OMCI_ATTR_ID_TRAFFIC_SCHED_G_PTR       BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_TRAFFIC_SCHEDULER_PTR /* = 6,  Traffic scheduler pointer */
#define OMCI_SVC_OMCI_ATTR_ID_WEIGHT        BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_WEIGHT /* = 7,  Weight */
#define OMCI_SVC_OMCI_ATTR_ID_BP_OPER       BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_OPER /* = 8,  Back pressure operation */
#define OMCI_SVC_OMCI_ATTR_ID_BP_TIME       BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_TIME /* = 9,  Back pressure time */
#define OMCI_SVC_OMCI_ATTR_ID_BP_OCCUR_QUEUE_THR        BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_OCCUR_QUEUE_THR /* = 10,  Back pressure occur queue threshold */
#define OMCI_SVC_OMCI_ATTR_ID_BP_CLEAR_QUEUE_THR        BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_CLEAR_QUEUE_THR /* = 11,  Back pressure clear queue threshold */
#define OMCI_SVC_OMCI_ATTR_ID_PACKET_DROP_QUEUE_THRS        BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_PACKET_DROP_QUEUE_THR /* = 12,  Packet drop queue thr */
#define OMCI_SVC_OMCI_ATTR_ID_PACKET_DROP_MAX_P     BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_PACKET_DROP_MAX_P /* = 13,  Packet drop max_p */
#define OMCI_SVC_OMCI_ATTR_ID_QUEUE_DROP_WQ     BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_QUEUE_DROP_W_Q /* = 14,  Queue drop w_q */
#define OMCI_SVC_OMCI_ATTR_ID_DROP_PRECEDENCE_COLOUR_MARKING        BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DROP_PRECEDENCE_COLOUR_MARKING /* = 15,  Drop precedence colour marking */

#define OMCI_SVC_OMCI_ATTR_ID_MCAST_GEM_PORT_NET_CTP_CON_PTR        BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_GEM_PORT_NET_CTP_CONN_PTR /* = 0,  GEM port network CTP connectivity pointer */
#define OMCI_SVC_OMCI_ATTR_ID_MCAST_IW_OPT      BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IW_OPT /* = 1,  Interworking option */
#define OMCI_SVC_OMCI_ATTR_ID_MCAST_SVC_PROF_PTR        BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_SVC_PROF_PTR /* = 2,  Service profile pointer */
#define OMCI_SVC_OMCI_ATTR_ID_MCAST_GEM_IW_TP_NOT_USED_1        BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_NOT_USED_1 /* = 3,  Not used 1 */
#define OMCI_SVC_OMCI_ATTR_ID_MCAST_PPTP_COUNT      BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_PPTP_COUNTER /* = 4,  PPTP Counter */
#define OMCI_SVC_OMCI_ATTR_ID_MCAST_OPER_STATE      BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_OPER_STATE /* = 5,  Operational state */
#define OMCI_SVC_OMCI_ATTR_ID_MCAST_GAL_PROF_PTR        BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_GAL_PROF_PTR /* = 6,  GAL profile pointer */
#define OMCI_SVC_OMCI_ATTR_ID_MCAST_GEM_IW_TP_NOT_USED_2        BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_NOT_USED_2 /* = 7,  Not used 2 */
#define OMCI_SVC_OMCI_ATTR_ID_IPV4_MCAST_ADDR_TABLE     BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IPV_4_MCAST_ADDR_TABLE /* = 8,  IPv4 multicast address table */
#define OMCI_SVC_OMCI_ATTR_ID_IPV6_MCAST_ADDR_TABLE     BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IPV_6_MCAST_ADDR_TABLE /* = 9,  IPv6 multicast address table */

#define OMCI_SVC_OMCI_ATTR_ID_IGMP_VERSION      BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IGMP_VERSION /* = 0,  IGMP version */
#define OMCI_SVC_OMCI_ATTR_ID_IGMP_FUNC     BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IGMP_FUNCTION /* = 1,  IGMP function */
#define OMCI_SVC_OMCI_ATTR_ID_IMMEDIATE_LEAVE       BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IMMEDIATE_LEAVE /* = 2,  Immediate leave */
#define OMCI_SVC_OMCI_ATTR_ID_US_IGMP_TCI       BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_TCI /* = 3,  Upstream IGMP TCI */
#define OMCI_SVC_OMCI_ATTR_ID_US_IGMP_TAG_CONTROL       BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_TAG_CONTROL /* = 4,  Upstream IGMP tag control */
#define OMCI_SVC_OMCI_ATTR_ID_US_IGMP_RATE      BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_RATE /* = 5,  Upstream IGMP rate */
#define OMCI_SVC_OMCI_ATTR_ID_DYNAMIC_ACCESS_CONTROL_LIST_TABLE     BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_DYNAMIC_ACCESS_CONTROL_LIST_TABLE /* = 6,  Dynamic access control list table */
#define OMCI_SVC_OMCI_ATTR_ID_STATIC_ACCESS_CONTROL_LIST_TABLE      BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_STATIC_ACCESS_CONTROL_LIST_TABLE /* = 7,  Static access control list table */
#define OMCI_SVC_OMCI_ATTR_ID_LOST_GROUP_LIST_TABLE     BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_LOST_GROUPS_LIST_TABLE /* = 8,  Lost groups list table */
#define OMCI_SVC_OMCI_ATTR_ID_ROBUSTNESS        BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_ROBUSTNESS /* = 9,  Robustness */
#define OMCI_SVC_OMCI_ATTR_ID_QUERIER_IP_ADDR       BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERIER_IP_ADDRESS /* = 10,  Querier IP address */
#define OMCI_SVC_OMCI_ATTR_ID_QUERY_INTERVAL        BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERY_INTERVAL /* = 11,  query_interval */
#define OMCI_SVC_OMCI_ATTR_ID_QUERY_MAX_RSP_TIME        BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERY_MAX_RESPONSE_TIME /* = 12,  Query max response time */
#define OMCI_SVC_OMCI_ATTR_ID_LAST_MEMBER_QUERY_INTERVAL        BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_LAST_MEMBER_QUERY_INTERVAL /* = 13,  Last member query interval */
#define OMCI_SVC_OMCI_ATTR_ID_UNAUTHORIZED_JOIN_REQ_BEHAVIOUR       BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UNAUTH_JOIN_REQUEST_BEHAVIOUR /* = 14,  Unauthorized join request behaviour */
#define OMCI_SVC_OMCI_ATTR_ID_DS_IGMP_AND_MCAST_TCI     BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_DS_IGMP_AND_MULTICAST_TCI /* = 15,  Downstream IGMP and multicast TCI */

#define OMCI_SVC_OMCI_ATTR_ID_ME_TYPE       BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_ME_TYPE /* = 0,  ME Type */
#define OMCI_SVC_OMCI_ATTR_ID_MCAST_OPER_S_PROF_PTR     BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MCAST_OPERATIONS_PROF_PTR /* = 1,  Multicast operations profile pointer */
#define OMCI_SVC_OMCI_ATTR_ID_MAX_SIMULTANEOUS_GROUPS       BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MAX_SIMULTANEOUS_GROUPS /* = 2,  Max simultaneous groups */
#define OMCI_SVC_OMCI_ATTR_ID_MAX_MCAST_BW      BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MAX_MULTICAST_BW /* = 3,  Max multicast bandwidth */
#define OMCI_SVC_OMCI_ATTR_ID_BW_ENFORCEMENT        BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_BW_ENFORCEMENT /* = 4,  Bandwidth enforcement */
#define OMCI_SVC_OMCI_ATTR_ID_MCAST_SVC_PKG_TABLE       BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MCAST_SVC_PKG_TABLE /* = 5,  Multicast service package table */
#define OMCI_SVC_OMCI_ATTR_ID_ALLOWED_PREVIEW_GROUPS_TABLE      BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_ALLOWED_PREVIEW_GROUPS_TABLE /* = 6,  Allowed preview groups table */



/** stack specific ret and result enums */
typedef bcm_omci_result  omci_svc_omci_result;
BCMOLT_TYPE2INT(bcm_omci_result, bcmos_errno, extern);
#define omci_svc_omci_result2bcmos_errno_conv       bcm_omci_result2bcmos_errno_conv

#define OMCI_SVC_OMCI_MSG_LEN_MAX                   BCM_OMCI_FORMAT_BASE_MSG_LEN

/** well known values used in omci svc layer */
/* ext vlan tag */
#define OMCI_SVC_OMCI_EXT_VLAN_DS_MODE_INVERSE      BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_DS_MODE_US_INVERSE
#define OMCI_SVC_OMCI_EXT_VLAN_DS_MODE_MATCH_INVERSE_ON_VID_DEFAULT_FORWARD      BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_DS_MODE_MATCH_INVERSE_ON_VID_DEFAULT_FORWARD
#define OMCI_SVC_OMCI_EXT_VLAN_DS_MODE_MATCH_INVERSE_ON_VID_DEFAULT_DISCARD      BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_DS_MODE_MATCH_INVERSE_ON_VID_DEFAULT_DISCARD

#define OMCI_SVC_OMCI_EXT_VLAN_ASSOC_TYPE_ETH_FLOW_TP           BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_ASSOC_TYPE_ETH_FLOW_TP
#define OMCI_SVC_OMCI_EXT_VLAN_ASSOC_TYPE_VIRTUAL_ETH_INTF      BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_ASSOC_TYPE_VEIP

#define OMCI_SVC_OMCI_TP_TYPE_PPTP_ETH_UNI          BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_TP_TYPE_PHY_PATH_TP_ETH_UNI
#define OMCI_SVC_OMCI_TP_TYPE_VIRTUAL_ETH_INTF      BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_TP_TYPE_VIRTUAL_ETH_INTERFACE_POINT
#define OMCI_SVC_OMCI_TP_TYPE_MCAST_GEM_IW_TP       BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_TP_TYPE_MULTICAST_GEM_INTERWORKING_TP
#define OMCI_SVC_OMCI_TP_TYPE_8021_P_MAP_SVC_PROF   BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_TP_TYPE_IEEE_8021_P_MAPPER_SVC_PROF
#define OMCI_SVC_OMCI_TP_TYPE_GEM_IW_TP             BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_TP_TYPE_GEM_INTERWORKING_TP

#define OMCI_SVC_OMCI_8021_P_TP_TYPE_NULL           BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_MAPPER_TP_TYPE_BRIDGING_MAPPING

#define OMCI_SVC_OMCI_IW_OPT_802_1P_MAPPER          BCM_OMCI_GEM_IW_TP_IW_OPT_IEEE_8021_P_MAPPER
#define OMCI_SVC_OMCI_IW_OPT_MAC_BRIDGED_VLAN       BCM_OMCI_GEM_IW_TP_IW_OPT_MAC_BRIDGED_LAN
#define OMCI_SVC_OMCI_IW_OPT_DS_BROADCAST           BCM_OMCI_GEM_IW_TP_IW_OPT_DS_BROADCAST

/* mcast operations profile */
#define OMCI_SVC_OMCI_IGMP_VERSION_V3               BCM_OMCI_MCAST_OPERATIONS_PROFILE_IGMP_VERSION_IGMP_VERSION_3
#define OMCI_SVC_OMCI_MLD_VERSION_V2                BCM_OMCI_MCAST_OPERATIONS_PROFILE_IGMP_VERSION_MLD_VERSION_2 
#define OMCI_SVC_OMCI_IGMP_FUNC_TRANSPARENT_IGMP_SNOOPING   BCM_OMCI_MCAST_OPERATIONS_PROFILE_IGMP_FUNCTION_TRANSPARENT_IGMP_SNOOPING
#define OMCI_SVC_OMCI_US_IGMP_TAG_CTRL_AS_IS        BCM_OMCI_MCAST_OPERATIONS_PROFILE_UPSTREAM_IGMP_TAG_CONTROL_PASS_IGMP_MLD_TRANSPARENT

#define OMCI_SVC_OMCI_MCAST_SBR_ASSOC_TYPE_MAC_BPCD BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_ME_TYPE_MAC_BRIDGE_PORT_CONFIG_DATA

#define OMCI_SVC_OMCI_LINK_STATE_DOWN               BCM_OMCI_LINK_STATE_DOWN

/* omci result well known values */
#define OMCI_SVC_OMCI_RESULT_CMD_SUCCESS            BCM_OMCI_RESULT_CMD_PROC_SUCCESS
#define OMCI_SVC_OMCI_RESULT_MORE                   BCM_OMCI_RESULT_IND_MORE
#define OMCI_SVC_OMCI_RESULT_LAST                   BCM_OMCI_RESULT_IND_LAST


/** get ME class Id str */
#define OMCI_SVC_OMCI_ME_CLASS_ID_STR(_class_id)    BCM_OMCI_ME_CLASS_VAL_STR(_class_id)
/** get OMCI Result str */
#define omci_svc_omci_result2str_conv               bcm_omci_result2str_conv

uint16_t omci_svc_omci_assign_op_ref (bcmolt_oltid olt_id, uint8_t pon_id, uint8_t onu_id);

/**************** OMCI svc layer -> Stack:  Requests *********************/
bcmos_errno omci_svc_omci_gal_eth_prof_me_create (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... );

bcmos_errno omci_svc_omci_ext_vlan_tag_oper_config_data_me_create (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... );
bcmos_errno omci_svc_omci_ext_vlan_tag_oper_config_data_me_set (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... );

bcmos_errno omci_svc_omci_mac_bridge_svc_prof_me_create (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... );
bcmos_errno omci_svc_omci_mac_bridge_port_config_data_me_create (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... );

bcmos_errno omci_svc_omci_mcast_operations_profile_me_create (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... );
bcmos_errno omci_svc_omci_mcast_operations_profile_me_set (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... );
bcmos_errno omci_svc_omci_mcast_operations_profile_me_delete(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id);

bcmos_errno omci_svc_omci_mcast_subscriber_config_info_me_create(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... );
bcmos_errno omci_svc_omci_mcast_subscriber_config_info_me_delete (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id);

bcmos_errno omci_svc_omci_tcont_me_set (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... );

bcmos_errno omci_svc_omci_gem_port_net_ctp_me_create (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... );

bcmos_errno omci_svc_omci_ieee_8021_p_mapper_svc_prof_me_create (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... );
bcmos_errno omci_svc_omci_ieee_8021_p_mapper_svc_prof_me_set (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... );

bcmos_errno omci_svc_omci_gem_iw_tp_me_create (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... );

bcmos_errno omci_svc_omci_mcast_gem_iw_tp_me_create (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... );



#endif //_OMCI_SVC_ADAPTER_BCM_OMCI_H_
