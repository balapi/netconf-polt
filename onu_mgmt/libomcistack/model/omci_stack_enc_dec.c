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

#include <bcmos_system.h>
#include <bcmos_errno.h>
#ifdef ENABLE_LOG
#include "bcm_dev_log.h"
#endif
#include "omci_stack_buf.h"
#include "omci_stack_me_hdr.h"
#include "omci_stack_model_types.h"
#include "omci_stack_model_funcs.h"
#include "omci_stack_enc_dec.h"
#include "omci_stack_api.h"
#include "omci_stack_common.h"
#include "omci_stack_internal.h"
#include "omci_stack_protocol_prop.h"
#include "omci_stack_me_tl_intf.h"

/* ME and attrib properties */
bcm_omci_me_protocol_properties me_and_attr_properties_arr[BCM_OMCI_OBJ_ID__NUM_OF] =
{
    [BCM_OMCI_GAL_ETH_PROF_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_GAL_ETH_PROF_CFG_ID_MAX_GEM_PAYLOAD_SIZE] =
            {
                .attr_name = "max_gem_payload_size",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
        },
        .num_properties = BCM_OMCI_GAL_ETH_PROF_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_GEM_IW_TP_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_GEM_IW_TP_CFG_ID_GEM_PORT_NET_CTP_CONN_PTR] =
            {
                .attr_name = "gem_port_net_ctp_conn_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_GEM_IW_TP_CFG_ID_IW_OPT] =
            {
                .attr_name = "iw_opt",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_GEM_IW_TP_CFG_ID_SVC_PROF_PTR] =
            {
                .attr_name = "svc_prof_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_GEM_IW_TP_CFG_ID_IW_TP_PTR] =
            {
                .attr_name = "iw_tp_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_GEM_IW_TP_CFG_ID_PPTP_COUNT] =
            {
                .attr_name = "pptp_count",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_GEM_IW_TP_CFG_ID_OPER_STATE] =
            {
                .attr_name = "oper_state",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_GEM_IW_TP_CFG_ID_GAL_PROF_PTR] =
            {
                .attr_name = "gal_prof_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_GEM_IW_TP_CFG_ID_GAL_LPBK_CONFIG] =
            {
                .attr_name = "gal_lpbk_config",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
        },
        .num_properties = BCM_OMCI_GEM_IW_TP_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_GEM_PORT_NET_CTP_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_PORT_ID] =
            {
                .attr_name = "port_id",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TCONT_PTR] =
            {
                .attr_name = "tcont_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_DIRECTION] =
            {
                .attr_name = "direction",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_MGMT_PTR_US] =
            {
                .attr_name = "traffic_mgmt_ptr_us",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_DESC_PROF_PTR_US] =
            {
                .attr_name = "traffic_desc_prof_ptr_us",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_UNI_COUNT] =
            {
                .attr_name = "uni_count",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_PRI_QUEUE_PTR_DS] =
            {
                .attr_name = "pri_queue_ptr_ds",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_ENCRYPTION_STATE] =
            {
                .attr_name = "encryption_state",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_DESC_PROF_PTR_DS] =
            {
                .attr_name = "traffic_desc_prof_ptr_ds",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_ENCRYPTION_KEY_RING] =
            {
                .attr_name = "encryption_key_ring",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
        },
        .num_properties = BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_TP_PTR] =
            {
                .attr_name = "tp_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_0] =
            {
                .attr_name = "interwork_tp_ptr_pri_0",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_1] =
            {
                .attr_name = "interwork_tp_ptr_pri_1",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_2] =
            {
                .attr_name = "interwork_tp_ptr_pri_2",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_3] =
            {
                .attr_name = "interwork_tp_ptr_pri_3",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_4] =
            {
                .attr_name = "interwork_tp_ptr_pri_4",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_5] =
            {
                .attr_name = "interwork_tp_ptr_pri_5",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_6] =
            {
                .attr_name = "interwork_tp_ptr_pri_6",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_7] =
            {
                .attr_name = "interwork_tp_ptr_pri_7",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_UNMARKED_FRAME_OPT] =
            {
                .attr_name = "unmarked_frame_opt",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_DSCP_TO_PBIT_MAPPING] =
            {
                .attr_name = "dscp_to_pbit_mapping",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 24
            },
            [BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_DEFAULT_PBIT_ASSUMPTION] =
            {
                .attr_name = "default_pbit_assumption",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_MAPPER_TP_TYPE] =
            {
                .attr_name = "mapper_tp_type",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
        },
        .num_properties = BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_BRIDGE_ID_PTR] =
            {
                .attr_name = "bridge_id_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_NUM] =
            {
                .attr_name = "port_num",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_TP_TYPE] =
            {
                .attr_name = "tp_type",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_TP_PTR] =
            {
                .attr_name = "tp_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_PRI] =
            {
                .attr_name = "port_pri",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_PATH_COST] =
            {
                .attr_name = "port_path_cost",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_SPANNING_TREE_IND] =
            {
                .attr_name = "port_spanning_tree_ind",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_DEPRECATED_1] =
            {
                .attr_name = "deprecated_1",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_DEPRECATED_2] =
            {
                .attr_name = "deprecated_2",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_MAC_ADDR] =
            {
                .attr_name = "port_mac_addr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 6
            },
            [BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_OUTBOUND_TD_PTR] =
            {
                .attr_name = "outbound_td_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_INBOUND_TD_PTR] =
            {
                .attr_name = "inbound_td_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_MAC_LEARNING_DEPTH] =
            {
                .attr_name = "mac_learning_depth",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
        },
        .num_properties = BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_MAC_BRIDGE_SVC_PROF_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_SPANNING_TREE_IND] =
            {
                .attr_name = "spanning_tree_ind",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_LEARNING_IND] =
            {
                .attr_name = "learning_ind",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_PORT_BRIDGING_IND] =
            {
                .attr_name = "port_bridging_ind",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_PRI] =
            {
                .attr_name = "pri",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_MAX_AGE] =
            {
                .attr_name = "max_age",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_HELLO_TIME] =
            {
                .attr_name = "hello_time",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_FORWARD_DELAY] =
            {
                .attr_name = "forward_delay",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_UNKNOWN_MAC_ADDR_DISCARD] =
            {
                .attr_name = "unknown_mac_addr_discard",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_MAC_LEARNING_DEPTH] =
            {
                .attr_name = "mac_learning_depth",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_DYNAMIC_FILTERING_AGEING_TIME] =
            {
                .attr_name = "dynamic_filtering_ageing_time",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
        },
        .num_properties = BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_VLAN_TAG_FILTER_DATA_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_VLAN_FILTER_LIST] =
            {
                .attr_name = "vlan_filter_list",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 24
            },
            [BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_FORWARD_OPER] =
            {
                .attr_name = "forward_oper",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_NUM_OF_ENTRIES] =
            {
                .attr_name = "num_of_entries",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
        },
        .num_properties = BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_TCONT_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_TCONT_CFG_ID_ALLOC_ID] =
            {
                .attr_name = "alloc_id",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_TCONT_CFG_ID_DEPRECATED] =
            {
                .attr_name = "deprecated",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_TCONT_CFG_ID_POLICY] =
            {
                .attr_name = "policy",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
        },
        .num_properties = BCM_OMCI_TCONT_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_ASSOC_TYPE] =
            {
                .attr_name = "assoc_type",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_RX_FRAME_VLAN_TAG_OPER_TABLE_MAX_SIZE] =
            {
                .attr_name = "rx_frame_vlan_tag_oper_table_max_size",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_INPUT_TPID] =
            {
                .attr_name = "input_tpid",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_OUTPUT_TPID] =
            {
                .attr_name = "output_tpid",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_DS_MODE] =
            {
                .attr_name = "ds_mode",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_RX_FRAME_VLAN_TAG_OPER_TABLE] =
            {
                .attr_name = "rx_frame_vlan_tag_oper_table",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 16
            },
            [BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_ASSOC_ME_PTR] =
            {
                .attr_name = "assoc_me_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_DSCP_TO_PBIT_MAPPING] =
            {
                .attr_name = "dscp_to_pbit_mapping",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 24
            },
        },
        .num_properties = BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_PRIORITY_QUEUE_G_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_QUEUE_CONFIG_OPT] =
            {
                .attr_name = "queue_config_opt",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_MAX_QUEUE_SIZE] =
            {
                .attr_name = "max_queue_size",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_ALLOCATED_QUEUE_SIZE] =
            {
                .attr_name = "allocated_queue_size",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DISCARD_COUNTER_RESET_INTERVAL] =
            {
                .attr_name = "discard_counter_reset_interval",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DISCARD_THRESHOLD] =
            {
                .attr_name = "discard_threshold",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_RELATED_PORT] =
            {
                .attr_name = "related_port",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_TRAFFIC_SCHEDULER_PTR] =
            {
                .attr_name = "traffic_scheduler_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_WEIGHT] =
            {
                .attr_name = "weight",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_OPER] =
            {
                .attr_name = "back_pressure_oper",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_TIME] =
            {
                .attr_name = "back_pressure_time",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_OCCUR_QUEUE_THR] =
            {
                .attr_name = "back_pressure_occur_queue_thr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_CLEAR_QUEUE_THR] =
            {
                .attr_name = "back_pressure_clear_queue_thr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_PACKET_DROP_QUEUE_THR] =
            {
                .attr_name = "packet_drop_queue_thr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 8
            },
            [BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_PACKET_DROP_MAX_P] =
            {
                .attr_name = "packet_drop_max_p",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_QUEUE_DROP_W_Q] =
            {
                .attr_name = "queue_drop_w_q",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DROP_PRECEDENCE_COLOUR_MARKING] =
            {
                .attr_name = "drop_precedence_colour_marking",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
        },
        .num_properties = BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_MCAST_GEM_IW_TP_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_GEM_PORT_NET_CTP_CONN_PTR] =
            {
                .attr_name = "gem_port_net_ctp_conn_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IW_OPT] =
            {
                .attr_name = "iw_opt",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_SVC_PROF_PTR] =
            {
                .attr_name = "svc_prof_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_NOT_USED_1] =
            {
                .attr_name = "not_used_1",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_PPTP_COUNTER] =
            {
                .attr_name = "pptp_counter",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_OPER_STATE] =
            {
                .attr_name = "oper_state",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_GAL_PROF_PTR] =
            {
                .attr_name = "gal_prof_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_NOT_USED_2] =
            {
                .attr_name = "not_used_2",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IPV_4_MCAST_ADDR_TABLE] =
            {
                .attr_name = "ipv_4_mcast_addr_table",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 12
            },
            [BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IPV_6_MCAST_ADDR_TABLE] =
            {
                .attr_name = "ipv_6_mcast_addr_table",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 24
            },
        },
        .num_properties = BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET_NEXT),
    },
    [BCM_OMCI_MCAST_OPERATIONS_PROFILE_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IGMP_VERSION] =
            {
                .attr_name = "igmp_version",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IGMP_FUNCTION] =
            {
                .attr_name = "igmp_function",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IMMEDIATE_LEAVE] =
            {
                .attr_name = "immediate_leave",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_TCI] =
            {
                .attr_name = "upstream_igmp_tci",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_TAG_CONTROL] =
            {
                .attr_name = "upstream_igmp_tag_control",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_RATE] =
            {
                .attr_name = "upstream_igmp_rate",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
            [BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_DYNAMIC_ACCESS_CONTROL_LIST_TABLE] =
            {
                .attr_name = "dynamic_access_control_list_table",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 24
            },
            [BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_STATIC_ACCESS_CONTROL_LIST_TABLE] =
            {
                .attr_name = "static_access_control_list_table",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 24
            },
            [BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_LOST_GROUPS_LIST_TABLE] =
            {
                .attr_name = "lost_groups_list_table",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 10
            },
            [BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_ROBUSTNESS] =
            {
                .attr_name = "robustness",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERIER_IP_ADDRESS] =
            {
                .attr_name = "querier_ip_address",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
            [BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERY_INTERVAL] =
            {
                .attr_name = "query_interval",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
            [BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERY_MAX_RESPONSE_TIME] =
            {
                .attr_name = "query_max_response_time",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
            [BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_LAST_MEMBER_QUERY_INTERVAL] =
            {
                .attr_name = "last_member_query_interval",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UNAUTH_JOIN_REQUEST_BEHAVIOUR] =
            {
                .attr_name = "unauth_join_request_behaviour",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_DS_IGMP_AND_MULTICAST_TCI] =
            {
                .attr_name = "ds_igmp_and_multicast_tci",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 3
            },
        },
        .num_properties = BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET_NEXT) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_TEST),
    },
    [BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_ME_TYPE] =
            {
                .attr_name = "me_type",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MCAST_OPERATIONS_PROF_PTR] =
            {
                .attr_name = "mcast_operations_prof_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MAX_SIMULTANEOUS_GROUPS] =
            {
                .attr_name = "max_simultaneous_groups",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MAX_MULTICAST_BW] =
            {
                .attr_name = "max_multicast_bw",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
            [BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_BW_ENFORCEMENT] =
            {
                .attr_name = "bw_enforcement",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MCAST_SVC_PKG_TABLE] =
            {
                .attr_name = "mcast_svc_pkg_table",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 20
            },
            [BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_ALLOWED_PREVIEW_GROUPS_TABLE] =
            {
                .attr_name = "allowed_preview_groups_table",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 24
            },
        },
        .num_properties = BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET_NEXT) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_TEST),
    },
    [BCM_OMCI_PPTP_ETH_UNI_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_PPTP_ETH_UNI_CFG_ID_EXPECTED_TYPE] =
            {
                .attr_name = "expected_type",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_PPTP_ETH_UNI_CFG_ID_SENSED_TYPE] =
            {
                .attr_name = "sensed_type",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_PPTP_ETH_UNI_CFG_ID_AUTO_DETECTION_CONFIG] =
            {
                .attr_name = "auto_detection_config",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ETHERNET_LOOPBACK_CONFIG] =
            {
                .attr_name = "ethernet_loopback_config",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ADMIN_STATE] =
            {
                .attr_name = "admin_state",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_PPTP_ETH_UNI_CFG_ID_OPER_STATE] =
            {
                .attr_name = "oper_state",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_PPTP_ETH_UNI_CFG_ID_CONFIG_IND] =
            {
                .attr_name = "config_ind",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_PPTP_ETH_UNI_CFG_ID_MAX_FRAME_SIZE] =
            {
                .attr_name = "max_frame_size",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_PPTP_ETH_UNI_CFG_ID_DTE_OR_DCE_IND] =
            {
                .attr_name = "dte_or_dce_ind",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_PPTP_ETH_UNI_CFG_ID_PAUSE_TIME] =
            {
                .attr_name = "pause_time",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_PPTP_ETH_UNI_CFG_ID_BRIDGED_OR_IP_IND] =
            {
                .attr_name = "bridged_or_ip_ind",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ARC] =
            {
                .attr_name = "arc",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ARC_INTERVAL] =
            {
                .attr_name = "arc_interval",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_PPTP_ETH_UNI_CFG_ID_PPPOE_FILTER] =
            {
                .attr_name = "pppoe_filter",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_PPTP_ETH_UNI_CFG_ID_POWER_CONTROL] =
            {
                .attr_name = "power_control",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
        },
        .num_properties = BCM_OMCI_PPTP_ETH_UNI_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_VIRTUAL_ETH_INTF_POINT_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_ADMIN_STATE] =
            {
                .attr_name = "admin_state",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_OPER_STATE] =
            {
                .attr_name = "oper_state",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_INTERDOMAIN_NAME] =
            {
                .attr_name = "interdomain_name",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 25
            },
            [BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_TCP_UDP_PTR] =
            {
                .attr_name = "tcp_udp_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_IANA_ASSIGNED_PORT] =
            {
                .attr_name = "iana_assigned_port",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
        },
        .num_properties = BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_ONU_DATA_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_ONU_DATA_CFG_ID_MIB_DATA_SYNC] =
            {
                .attr_name = "mib_data_sync",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
        },
        .num_properties = BCM_OMCI_ONU_DATA_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_REBOOT),
    },
    [BCM_OMCI_ONU_G_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_ONU_G_CFG_ID_VENDOR_ID] =
            {
                .attr_name = "vendor_id",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ONU_G_CFG_ID_VERSION] =
            {
                .attr_name = "version",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 14
            },
            [BCM_OMCI_ONU_G_CFG_ID_SERIAL_NUMBER] =
            {
                .attr_name = "serial_number",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 8
            },
            [BCM_OMCI_ONU_G_CFG_ID_TRAFFIC_MANAGEMENT] =
            {
                .attr_name = "traffic_management",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_ONU_G_CFG_ID_DEPRECATED0] =
            {
                .attr_name = "deprecated0",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_ONU_G_CFG_ID_BATTERY_BACKUP] =
            {
                .attr_name = "battery_backup",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_ONU_G_CFG_ID_ADMIN_STATE] =
            {
                .attr_name = "admin_state",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_ONU_G_CFG_ID_OPER_STATE] =
            {
                .attr_name = "oper_state",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_ONU_G_CFG_ID_SURVIVAL_TIME] =
            {
                .attr_name = "survival_time",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_ONU_G_CFG_ID_LOGICAL_ONU_ID] =
            {
                .attr_name = "logical_onu_id",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 24
            },
            [BCM_OMCI_ONU_G_CFG_ID_LOGICAL_PASSWORD] =
            {
                .attr_name = "logical_password",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 12
            },
            [BCM_OMCI_ONU_G_CFG_ID_CREDENTIALS_STATUS] =
            {
                .attr_name = "credentials_status",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_ONU_G_CFG_ID_EXTENDED_TC_OPTIONS] =
            {
                .attr_name = "extended_tc_options",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
        },
        .num_properties = BCM_OMCI_ONU_G_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SYNC_TIME),
    },
    [BCM_OMCI_ONU2_G_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_ONU2_G_CFG_ID_EQUIPMENT_ID] =
            {
                .attr_name = "equipment_id",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 20
            },
            [BCM_OMCI_ONU2_G_CFG_ID_OMCC_VERSION] =
            {
                .attr_name = "omcc_version",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_ONU2_G_CFG_ID_VENDOR_PRODUCT_CODE] =
            {
                .attr_name = "vendor_product_code",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_ONU2_G_CFG_ID_SECURITY_CAPABILITY] =
            {
                .attr_name = "security_capability",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_ONU2_G_CFG_ID_SECURITY_MODE] =
            {
                .attr_name = "security_mode",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_ONU2_G_CFG_ID_TOTAL_PRIORITY_QUEUE_NUMBER] =
            {
                .attr_name = "total_priority_queue_number",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_ONU2_G_CFG_ID_TOTAL_TRAF_SCHED_NUMBER] =
            {
                .attr_name = "total_traf_sched_number",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_ONU2_G_CFG_ID_DEPRECATED0] =
            {
                .attr_name = "deprecated0",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_ONU2_G_CFG_ID_TOTAL_GEM_PORT_NUMBER] =
            {
                .attr_name = "total_gem_port_number",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_ONU2_G_CFG_ID_SYS_UP_TIME] =
            {
                .attr_name = "sys_up_time",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
            [BCM_OMCI_ONU2_G_CFG_ID_CONNECTIVITY_CAPABILITY] =
            {
                .attr_name = "connectivity_capability",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_ONU2_G_CFG_ID_CONNECTIVITY_MODE] =
            {
                .attr_name = "connectivity_mode",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_ONU2_G_CFG_ID_QOS_CONFIG_FLEXIBILITY] =
            {
                .attr_name = "qos_config_flexibility",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_ONU2_G_CFG_ID_PRIORITY_QUEUE_SCALE_FACTOR] =
            {
                .attr_name = "priority_queue_scale_factor",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
        },
        .num_properties = BCM_OMCI_ONU2_G_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_SW_IMAGE_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_SW_IMAGE_CFG_ID_VERSION] =
            {
                .attr_name = "version",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 14
            },
            [BCM_OMCI_SW_IMAGE_CFG_ID_IS_COMMITTED] =
            {
                .attr_name = "is_committed",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_SW_IMAGE_CFG_ID_IS_ACTIVE] =
            {
                .attr_name = "is_active",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_SW_IMAGE_CFG_ID_IS_VALID] =
            {
                .attr_name = "is_valid",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_SW_IMAGE_CFG_ID_PRODUCT_CODE] =
            {
                .attr_name = "product_code",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 25
            },
            [BCM_OMCI_SW_IMAGE_CFG_ID_IMAGE_HASH] =
            {
                .attr_name = "image_hash",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 16
            },
        },
        .num_properties = BCM_OMCI_SW_IMAGE_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_START_SW_DOWNLOAD) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DOWNLOAD_SECTION) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_END_SW_DOWNLOAD) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_ACTIVATE_SW) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_COMMIT_SW),
    },
    [BCM_OMCI_ANI_G_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_ANI_G_CFG_ID_SR_INDICATION] =
            {
                .attr_name = "sr_indication",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_ANI_G_CFG_ID_TOTAL_TCONT_NUMBER] =
            {
                .attr_name = "total_tcont_number",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_ANI_G_CFG_ID_GEM_BLOCK_LENGTH] =
            {
                .attr_name = "gem_block_length",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_ANI_G_CFG_ID_PIGGY_BACK_DBA_REPORTING] =
            {
                .attr_name = "piggy_back_dba_reporting",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_ANI_G_CFG_ID_DEPRECATED] =
            {
                .attr_name = "deprecated",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_ANI_G_CFG_ID_SF_THRESHOLD] =
            {
                .attr_name = "sf_threshold",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_ANI_G_CFG_ID_SD_THRESHOLD] =
            {
                .attr_name = "sd_threshold",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_ANI_G_CFG_ID_ARC] =
            {
                .attr_name = "arc",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_ANI_G_CFG_ID_ARC_INTERVAL] =
            {
                .attr_name = "arc_interval",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_ANI_G_CFG_ID_OPTICAL_SIGNAL_LEVEL] =
            {
                .attr_name = "optical_signal_level",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_ANI_G_CFG_ID_LOWER_OPTICAL_THRESHOLD] =
            {
                .attr_name = "lower_optical_threshold",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_ANI_G_CFG_ID_UPPER_OPTICAL_THRESHOLD] =
            {
                .attr_name = "upper_optical_threshold",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_ANI_G_CFG_ID_ONU_RESPONSE_TIME] =
            {
                .attr_name = "onu_response_time",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_ANI_G_CFG_ID_TRANSMIT_OPTICAL_LEVEL] =
            {
                .attr_name = "transmit_optical_level",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_ANI_G_CFG_ID_LOWER_TRANSMIT_POWER_THRESHOLD] =
            {
                .attr_name = "lower_transmit_power_threshold",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_ANI_G_CFG_ID_UPPER_TRANSMIT_POWER_THRESHOLD] =
            {
                .attr_name = "upper_transmit_power_threshold",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
        },
        .num_properties = BCM_OMCI_ANI_G_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_TEST),
    },
    [BCM_OMCI_GEM_PORT_NET_CTP_PM_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_INTERVAL_END_TIME] =
            {
                .attr_name = "interval_end_time",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_THRESHOLD_DATA] =
            {
                .attr_name = "threshold_data",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_TX_GEM_FRAMES] =
            {
                .attr_name = "tx_gem_frames",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_RX_GEM_FRAMES] =
            {
                .attr_name = "rx_gem_frames",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_RX_PAYLOAD_BYTES] =
            {
                .attr_name = "rx_payload_bytes",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 8
            },
            [BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_TX_PAYLOAD_BYTES] =
            {
                .attr_name = "tx_payload_bytes",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 8
            },
            [BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_ENCRY_KEY_ERRORS] =
            {
                .attr_name = "encry_key_errors",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
        },
        .num_properties = BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_ETH_FRAME_UPSTREAM_PM_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_INTERVAL_END_TIME] =
            {
                .attr_name = "interval_end_time",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_THRESHOLD_DATA] =
            {
                .attr_name = "threshold_data",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_DROP_EVENTS] =
            {
                .attr_name = "up_drop_events",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_OCTETS] =
            {
                .attr_name = "up_octets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS] =
            {
                .attr_name = "up_packets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_BROADCAST_PACKETS] =
            {
                .attr_name = "up_broadcast_packets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_MULTICAST_PACKETS] =
            {
                .attr_name = "up_multicast_packets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_CRC_ERRORED_PACKETS] =
            {
                .attr_name = "up_crc_errored_packets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_UNDERSIZE_PACKETS] =
            {
                .attr_name = "up_undersize_packets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_OVERSIZE_PACKETS] =
            {
                .attr_name = "up_oversize_packets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_64_OCTETS] =
            {
                .attr_name = "up_packets_64_octets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_65_127_OCTETS] =
            {
                .attr_name = "up_packets_65_127_octets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_128_255_OCTETS] =
            {
                .attr_name = "up_packets_128_255_octets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_256_511_OCTETS] =
            {
                .attr_name = "up_packets_256_511_octets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_512_1023_OCTETS] =
            {
                .attr_name = "up_packets_512_1023_octets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_1024_1518_OCTETS] =
            {
                .attr_name = "up_packets_1024_1518_octets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
        },
        .num_properties = BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_INTERVAL_END_TIME] =
            {
                .attr_name = "interval_end_time",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_THRESHOLD_DATA] =
            {
                .attr_name = "threshold_data",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_DROP_EVENTS] =
            {
                .attr_name = "dn_drop_events",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_OCTETS] =
            {
                .attr_name = "dn_octets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS] =
            {
                .attr_name = "dn_packets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_BROADCAST_PACKETS] =
            {
                .attr_name = "dn_broadcast_packets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_MULTICAST_PACKETS] =
            {
                .attr_name = "dn_multicast_packets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_CRC_ERRORED_PACKETS] =
            {
                .attr_name = "dn_crc_errored_packets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_UNDERSIZE_PACKETS] =
            {
                .attr_name = "dn_undersize_packets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_OVERSIZE_PACKETS] =
            {
                .attr_name = "dn_oversize_packets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_64_OCTETS] =
            {
                .attr_name = "dn_packets_64_octets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_65_127_OCTETS] =
            {
                .attr_name = "dn_packets_65_127_octets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_128_255_OCTETS] =
            {
                .attr_name = "dn_packets_128_255_octets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_256_511_OCTETS] =
            {
                .attr_name = "dn_packets_256_511_octets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_512_1023_OCTETS] =
            {
                .attr_name = "dn_packets_512_1023_octets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_1024_1518_OCTETS] =
            {
                .attr_name = "dn_packets_1024_1518_octets",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
        },
        .num_properties = BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_FEC_PM_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_FEC_PM_CFG_ID_INTERVAL_END_TIME] =
            {
                .attr_name = "interval_end_time",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_FEC_PM_CFG_ID_THRESHOLD_DATA] =
            {
                .attr_name = "threshold_data",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_FEC_PM_CFG_ID_CORRECTED_BYTES] =
            {
                .attr_name = "corrected_bytes",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_FEC_PM_CFG_ID_CORRECTED_CODE_WORDS] =
            {
                .attr_name = "corrected_code_words",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_FEC_PM_CFG_ID_UNCORRECTABLE_CODE_WORDS] =
            {
                .attr_name = "uncorrectable_code_words",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_FEC_PM_CFG_ID_TOTAL_CODE_WORDS] =
            {
                .attr_name = "total_code_words",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_FEC_PM_CFG_ID_FEC_SECONDS] =
            {
                .attr_name = "fec_seconds",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
        },
        .num_properties = BCM_OMCI_FEC_PM_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_XGPON_TC_PM_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_XGPON_TC_PM_CFG_ID_INTERVAL_END_TIME] =
            {
                .attr_name = "interval_end_time",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_XGPON_TC_PM_CFG_ID_THRESHOLD_DATA] =
            {
                .attr_name = "threshold_data",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_XGPON_TC_PM_CFG_ID_PSBD_HEC_ERROR_COUNT] =
            {
                .attr_name = "psbd_hec_error_count",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
            [BCM_OMCI_XGPON_TC_PM_CFG_ID_XGTC_HEC_ERROR_COUNT] =
            {
                .attr_name = "xgtc_hec_error_count",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
            [BCM_OMCI_XGPON_TC_PM_CFG_ID_UNKNOWN_PROFILE_COUNT] =
            {
                .attr_name = "unknown_profile_count",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
            [BCM_OMCI_XGPON_TC_PM_CFG_ID_TRANSMITTED_XGEM_FRAMES] =
            {
                .attr_name = "transmitted_xgem_frames",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_XGPON_TC_PM_CFG_ID_FRAGMENT_XGEM_FRAMES] =
            {
                .attr_name = "fragment_xgem_frames",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
            [BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_HEC_LOST_WORDS_COUNT] =
            {
                .attr_name = "xgem_hec_lost_words_count",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
            [BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_KEY_ERRORS] =
            {
                .attr_name = "xgem_key_errors",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_HEC_ERROR_COUNT] =
            {
                .attr_name = "xgem_hec_error_count",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_XGPON_TC_PM_CFG_ID_TX_BYTES_IN_NON_IDLE_XGEM_FRAMES] =
            {
                .attr_name = "tx_bytes_in_non_idle_xgem_frames",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 8
            },
            [BCM_OMCI_XGPON_TC_PM_CFG_ID_RX_BYTES_IN_NON_IDLE_XGEM_FRAMES] =
            {
                .attr_name = "rx_bytes_in_non_idle_xgem_frames",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 8
            },
            [BCM_OMCI_XGPON_TC_PM_CFG_ID_LODS_EVENT_COUNT] =
            {
                .attr_name = "lods_event_count",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
            [BCM_OMCI_XGPON_TC_PM_CFG_ID_LODS_EVENT_RESTORED_COUNT] =
            {
                .attr_name = "lods_event_restored_count",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
            [BCM_OMCI_XGPON_TC_PM_CFG_ID_ONU_REACTIVATION_BY_LODS_EVENTS] =
            {
                .attr_name = "onu_reactivation_by_lods_events",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
        },
        .num_properties = BCM_OMCI_XGPON_TC_PM_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_IP_HOST_CONFIG_DATA_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_IP_OPTIONS] =
            {
                .attr_name = "ip_options",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_MAC_ADDR] =
            {
                .attr_name = "mac_addr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 6
            },
            [BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_ONU_ID] =
            {
                .attr_name = "onu_id",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_IP_ADDRESS] =
            {
                .attr_name = "ip_address",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_MASK] =
            {
                .attr_name = "mask",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_GATEWAY] =
            {
                .attr_name = "gateway",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_PRIMARY_DNS] =
            {
                .attr_name = "primary_dns",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_SECONDARY_DNS] =
            {
                .attr_name = "secondary_dns",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_ADDRESS] =
            {
                .attr_name = "current_address",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
            [BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_MASK] =
            {
                .attr_name = "current_mask",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
            [BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_GATEWAY] =
            {
                .attr_name = "current_gateway",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
            [BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_PRIMARY_DNS] =
            {
                .attr_name = "current_primary_dns",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
            [BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_SECONDARY_DNS] =
            {
                .attr_name = "current_secondary_dns",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
            [BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_DOMAIN_NAME] =
            {
                .attr_name = "domain_name",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_HOST_NAME] =
            {
                .attr_name = "host_name",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_RELAY_AGENT_OPTIONS] =
            {
                .attr_name = "relay_agent_options",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
        },
        .num_properties = BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_TEST),
    },
    [BCM_OMCI_VOIP_LINE_STATUS_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CODEC] =
            {
                .attr_name = "codec",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_VOICE_SERVER_STATUS] =
            {
                .attr_name = "voice_server_status",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_PORT_SESSION_TYPE] =
            {
                .attr_name = "port_session_type",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL1_PACKET_PERIOD] =
            {
                .attr_name = "call1_packet_period",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL2_PACKET_PERIOD] =
            {
                .attr_name = "call2_packet_period",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL1_DEST_ADDRESS] =
            {
                .attr_name = "call1_dest_address",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL2_DEST_ADDRESS] =
            {
                .attr_name = "call2_dest_address",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_LINE_STATE] =
            {
                .attr_name = "line_state",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_EMERGENCY_CALL_STATUS] =
            {
                .attr_name = "emergency_call_status",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
        },
        .num_properties = BCM_OMCI_VOIP_LINE_STATUS_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_VOIP_MEDIA_PROFILE_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_FAX_MODE] =
            {
                .attr_name = "fax_mode",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_VOICE_SERVICE_PROF_PTR] =
            {
                .attr_name = "voice_service_prof_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION1] =
            {
                .attr_name = "codec_selection1",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD1] =
            {
                .attr_name = "packet_period1",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION1] =
            {
                .attr_name = "silence_supression1",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION2] =
            {
                .attr_name = "codec_selection2",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD2] =
            {
                .attr_name = "packet_period2",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION2] =
            {
                .attr_name = "silence_supression2",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION3] =
            {
                .attr_name = "codec_selection3",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD3] =
            {
                .attr_name = "packet_period3",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION3] =
            {
                .attr_name = "silence_supression3",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION4] =
            {
                .attr_name = "codec_selection4",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD4] =
            {
                .attr_name = "packet_period4",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION4] =
            {
                .attr_name = "silence_supression4",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_OOB_DTMF] =
            {
                .attr_name = "oob_dtmf",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_RTP_PROFILE_PTR] =
            {
                .attr_name = "rtp_profile_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
        },
        .num_properties = BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_SIP_USER_DATA_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_SIP_USER_DATA_CFG_ID_SIP_AGENT_PTR] =
            {
                .attr_name = "sip_agent_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_SIP_USER_DATA_CFG_ID_USER_PART_AOR] =
            {
                .attr_name = "user_part_aor",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_SIP_USER_DATA_CFG_ID_SIP_DISPLAY_NAME] =
            {
                .attr_name = "sip_display_name",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_SIP_USER_DATA_CFG_ID_USERNAME_PASSWORD] =
            {
                .attr_name = "username_password",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_SIP_USER_DATA_CFG_ID_VOICEMAIL_SERVER_URI] =
            {
                .attr_name = "voicemail_server_uri",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_SIP_USER_DATA_CFG_ID_VOICEMAIL_SUBSCRIPTION_EXP_TIME] =
            {
                .attr_name = "voicemail_subscription_exp_time",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_SIP_USER_DATA_CFG_ID_NETWORK_DIAL_PLAN_PTR] =
            {
                .attr_name = "network_dial_plan_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_SIP_USER_DATA_CFG_ID_APP_SERVICE_PROF_PTR] =
            {
                .attr_name = "app_service_prof_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_SIP_USER_DATA_CFG_ID_FEATURE_CODE_PTR] =
            {
                .attr_name = "feature_code_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_SIP_USER_DATA_CFG_ID_PPTP_PTR] =
            {
                .attr_name = "pptp_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_SIP_USER_DATA_CFG_ID_RELEASE_TIMER] =
            {
                .attr_name = "release_timer",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_SIP_USER_DATA_CFG_ID_ROH_TIMER] =
            {
                .attr_name = "roh_timer",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
        },
        .num_properties = BCM_OMCI_SIP_USER_DATA_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_SIP_AGENT_CONFIG_DATA_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_PROXY_SERVER_ADDR_PTR] =
            {
                .attr_name = "proxy_server_addr_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_OUTBOUND_PROXY_ADDR_PTR] =
            {
                .attr_name = "outbound_proxy_addr_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_PRIMARY_SIP_DNS] =
            {
                .attr_name = "primary_sip_dns",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SECONDARY_SIP_DNS] =
            {
                .attr_name = "secondary_sip_dns",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_TCP_UDP_PTR] =
            {
                .attr_name = "tcp_udp_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REG_EXP_TIME] =
            {
                .attr_name = "sip_reg_exp_time",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REREG_HEAD_START_TIME] =
            {
                .attr_name = "sip_rereg_head_start_time",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_HOST_PART_URI] =
            {
                .attr_name = "host_part_uri",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_STATUS] =
            {
                .attr_name = "sip_status",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REGISTRAR] =
            {
                .attr_name = "sip_registrar",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SOFTSWITCH] =
            {
                .attr_name = "softswitch",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_RESPONSE_TABLE] =
            {
                .attr_name = "sip_response_table",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 5
            },
            [BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_TRANSMIT_CONTROL] =
            {
                .attr_name = "sip_transmit_control",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_URI_FORMAT] =
            {
                .attr_name = "sip_uri_format",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_REDUNDANT_SIP_AGENT_PTR] =
            {
                .attr_name = "redundant_sip_agent_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
        },
        .num_properties = BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_NETWORK_ADDRESS_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_NETWORK_ADDRESS_CFG_ID_SECURITY_PTR] =
            {
                .attr_name = "security_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_NETWORK_ADDRESS_CFG_ID_ADDRESS_PTR] =
            {
                .attr_name = "address_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
        },
        .num_properties = BCM_OMCI_NETWORK_ADDRESS_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_LARGE_STRING_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_LARGE_STRING_CFG_ID_NUMBER_OF_PARTS] =
            {
                .attr_name = "number_of_parts",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_LARGE_STRING_CFG_ID_PART1] =
            {
                .attr_name = "part1",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_LARGE_STRING_CFG_ID_PART2] =
            {
                .attr_name = "part2",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_LARGE_STRING_CFG_ID_PART3] =
            {
                .attr_name = "part3",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_LARGE_STRING_CFG_ID_PART4] =
            {
                .attr_name = "part4",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_LARGE_STRING_CFG_ID_PART5] =
            {
                .attr_name = "part5",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_LARGE_STRING_CFG_ID_PART6] =
            {
                .attr_name = "part6",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_LARGE_STRING_CFG_ID_PART7] =
            {
                .attr_name = "part7",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_LARGE_STRING_CFG_ID_PART8] =
            {
                .attr_name = "part8",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_LARGE_STRING_CFG_ID_PART9] =
            {
                .attr_name = "part9",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_LARGE_STRING_CFG_ID_PART10] =
            {
                .attr_name = "part10",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_LARGE_STRING_CFG_ID_PART11] =
            {
                .attr_name = "part11",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_LARGE_STRING_CFG_ID_PART12] =
            {
                .attr_name = "part12",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_LARGE_STRING_CFG_ID_PART13] =
            {
                .attr_name = "part13",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_LARGE_STRING_CFG_ID_PART14] =
            {
                .attr_name = "part14",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_LARGE_STRING_CFG_ID_PART15] =
            {
                .attr_name = "part15",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
        },
        .num_properties = BCM_OMCI_LARGE_STRING_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_VALIDATION_SCHEME] =
            {
                .attr_name = "validation_scheme",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_USERNAME1] =
            {
                .attr_name = "username1",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_PASSWORD] =
            {
                .attr_name = "password",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_REALM] =
            {
                .attr_name = "realm",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
            [BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_USERNAME2] =
            {
                .attr_name = "username2",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 25
            },
        },
        .num_properties = BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_VOICE_SERVICE_PROFILE_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_ANNOUNCEMENT_TYPE] =
            {
                .attr_name = "announcement_type",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_JITTER_TARGET] =
            {
                .attr_name = "jitter_target",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_JITTER_BUFFER_MAX] =
            {
                .attr_name = "jitter_buffer_max",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_ECHO_CANCEL] =
            {
                .attr_name = "echo_cancel",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_PSTN_PROTOCOL_VARIANT] =
            {
                .attr_name = "pstn_protocol_variant",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_DTMF_DIGIT_LEVELS] =
            {
                .attr_name = "dtmf_digit_levels",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_DTMF_DIGIT_DURATION] =
            {
                .attr_name = "dtmf_digit_duration",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_HOOK_FLASH_MIN_TIME] =
            {
                .attr_name = "hook_flash_min_time",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_HOOK_FLASH_MAX_TIME] =
            {
                .attr_name = "hook_flash_max_time",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_TONE_PATTERN_TABLE] =
            {
                .attr_name = "tone_pattern_table",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 20
            },
            [BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_TONE_EVENT_TABLE] =
            {
                .attr_name = "tone_event_table",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 7
            },
            [BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_RINGING_PATTERN_TABLE] =
            {
                .attr_name = "ringing_pattern_table",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 5
            },
            [BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_RINGING_EVENT_TABLE] =
            {
                .attr_name = "ringing_event_table",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 7
            },
            [BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_NETWORK_SPECIFIC_EXT_PTR] =
            {
                .attr_name = "network_specific_ext_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
        },
        .num_properties = BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_VOIP_CONFIG_DATA_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_AVAILABLE_SIGNALLING_PROTOCOLS] =
            {
                .attr_name = "available_signalling_protocols",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_SIGNALLING_PROTOCOL_USED] =
            {
                .attr_name = "signalling_protocol_used",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_AVAILABLE_VOIP_CONFIG_METHODS] =
            {
                .attr_name = "available_voip_config_methods",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 4
            },
            [BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOIP_CONFIG_METHOD_USED] =
            {
                .attr_name = "voip_config_method_used",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOICE_CONFIG_PTR] =
            {
                .attr_name = "voice_config_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOIP_CONFIG_STATE] =
            {
                .attr_name = "voip_config_state",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_RETRIEVE_PROFILE] =
            {
                .attr_name = "retrieve_profile",
                .attr_access_type  = ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_PROFILE_VERSION] =
            {
                .attr_name = "profile_version",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 25
            },
        },
        .num_properties = BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_VOIP_VOICE_CTP_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_USER_PROTOCOL_PTR] =
            {
                .attr_name = "user_protocol_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_PPTP_PTR] =
            {
                .attr_name = "pptp_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_VOICE_MEDIA_PROFILE_PTR] =
            {
                .attr_name = "voice_media_profile_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_SIGNALLING_CODE] =
            {
                .attr_name = "signalling_code",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
        },
        .num_properties = BCM_OMCI_VOIP_VOICE_CTP_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_TCP_UDP_CONFIG_DATA_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_PORT_ID] =
            {
                .attr_name = "port_id",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_PROTOCOL] =
            {
                .attr_name = "protocol",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_TOS] =
            {
                .attr_name = "tos",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_IP_HOST_PTR] =
            {
                .attr_name = "ip_host_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
        },
        .num_properties = BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_NUMBER] =
            {
                .attr_name = "dial_plan_number",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_TABLE_MAX_SIZE] =
            {
                .attr_name = "dial_plan_table_max_size",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_CRITICAL_DIAL_TIMEOUT] =
            {
                .attr_name = "critical_dial_timeout",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_PARTIAL_DIAL_TIMEOUT] =
            {
                .attr_name = "partial_dial_timeout",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_FORMAT] =
            {
                .attr_name = "dial_plan_format",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_TABLE] =
            {
                .attr_name = "dial_plan_table",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 30
            },
        },
        .num_properties = BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET_NEXT),
    },
    [BCM_OMCI_RTP_PROFILE_DATA_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_LOCAL_PORT_MIN] =
            {
                .attr_name = "local_port_min",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 2
            },
            [BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_LOCAL_PORT_MAX] =
            {
                .attr_name = "local_port_max",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_DSCP_MARK] =
            {
                .attr_name = "dscp_mark",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_PIGGYBACK_EVENTS] =
            {
                .attr_name = "piggyback_events",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_TONE_EVENTS] =
            {
                .attr_name = "tone_events",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_DTMF_EVENTS] =
            {
                .attr_name = "dtmf_events",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_CAS_EVENTS] =
            {
                .attr_name = "cas_events",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_IP_HOST_CONFIG_PTR] =
            {
                .attr_name = "ip_host_config_ptr",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
        },
        .num_properties = BCM_OMCI_RTP_PROFILE_DATA_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_POTS_UNI_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_POTS_UNI_CFG_ID_ADMIN_STATE] =
            {
                .attr_name = "admin_state",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_POTS_UNI_CFG_ID_DEPRECATED1] =
            {
                .attr_name = "deprecated1",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_POTS_UNI_CFG_ID_ARC] =
            {
                .attr_name = "arc",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_POTS_UNI_CFG_ID_ARC_INTERVAL] =
            {
                .attr_name = "arc_interval",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_POTS_UNI_CFG_ID_IMPEDANCE] =
            {
                .attr_name = "impedance",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_POTS_UNI_CFG_ID_TRANSMISSION_PATH] =
            {
                .attr_name = "transmission_path",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_POTS_UNI_CFG_ID_RX_GAIN] =
            {
                .attr_name = "rx_gain",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_POTS_UNI_CFG_ID_TX_GAIN] =
            {
                .attr_name = "tx_gain",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_POTS_UNI_CFG_ID_OPER_STATE] =
            {
                .attr_name = "oper_state",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_POTS_UNI_CFG_ID_HOOK_STATE] =
            {
                .attr_name = "hook_state",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_POTS_UNI_CFG_ID_HOLDOVER_TIME] =
            {
                .attr_name = "holdover_time",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
            [BCM_OMCI_POTS_UNI_CFG_ID_NOMINAL_FEED_VOLTAGE] =
            {
                .attr_name = "nominal_feed_voltage",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
        },
        .num_properties = BCM_OMCI_POTS_UNI_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_TEST),
    },
    [BCM_OMCI_CIRCUIT_PACK_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_CIRCUIT_PACK_CFG_ID_TYPE] =
            {
                .attr_name = "type",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_CIRCUIT_PACK_CFG_ID_NUMBER_OF_PORTS] =
            {
                .attr_name = "number_of_ports",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_CIRCUIT_PACK_CFG_ID_SERIAL_NUMBER] =
            {
                .attr_name = "serial_number",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 8
            },
            [BCM_OMCI_CIRCUIT_PACK_CFG_ID_VERSION] =
            {
                .attr_name = "version",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 14
            },
            [BCM_OMCI_CIRCUIT_PACK_CFG_ID_VENDOR_ID] =
            {
                .attr_name = "vendor_id",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
            [BCM_OMCI_CIRCUIT_PACK_CFG_ID_ADMIN_STATE] =
            {
                .attr_name = "admin_state",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_CIRCUIT_PACK_CFG_ID_OPER_STATE] =
            {
                .attr_name = "oper_state",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_CIRCUIT_PACK_CFG_ID_BRIDGED_OR_IP] =
            {
                .attr_name = "bridged_or_ip",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 1
            },
            [BCM_OMCI_CIRCUIT_PACK_CFG_ID_EQUIP_ID] =
            {
                .attr_name = "equip_id",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 20
            },
            [BCM_OMCI_CIRCUIT_PACK_CFG_ID_CARD_CONFIG] =
            {
                .attr_name = "card_config",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE | ATTR_ACCESS_TYPE_SET_BY_CREATE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_CIRCUIT_PACK_CFG_ID_TCONT_BUFFER_NUMBER] =
            {
                .attr_name = "tcont_buffer_number",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_CIRCUIT_PACK_CFG_ID_PRIORITY_QUEUE_NUMBER] =
            {
                .attr_name = "priority_queue_number",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_CIRCUIT_PACK_CFG_ID_TRAFFIC_SCHED_NUMBER] =
            {
                .attr_name = "traffic_sched_number",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_CIRCUIT_PACK_CFG_ID_POWER_SHED_OVERRIDE] =
            {
                .attr_name = "power_shed_override",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 4
            },
        },
        .num_properties = BCM_OMCI_CIRCUIT_PACK_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_CREATE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_DELETE) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET),
    },
    [BCM_OMCI_ENHANCED_SECURITY_CONTROL_OBJ_ID] =
    {
        .me_attr_properties =
        {
            [BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_CRYPTO_CAPABILITIES] =
            {
                .attr_name = "crypto_capabilities",
                .attr_access_type  = ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 16
            },
            [BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_RANDOM_CHALLENGE_TABLE] =
            {
                .attr_name = "olt_random_challenge_table",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 17
            },
            [BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_CHALLENGE_STATUS] =
            {
                .attr_name = "olt_challenge_status",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_SELECTED_CRYPTO_CAPABILITIES] =
            {
                .attr_name = "onu_selected_crypto_capabilities",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_RANDOM_CHALLENGE_TABLE] =
            {
                .attr_name = "onu_random_challenge_table",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 16
            },
            [BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_AUTH_RESULT_TABLE] =
            {
                .attr_name = "onu_auth_result_table",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 16
            },
            [BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_AUTH_RESULT_TABLE] =
            {
                .attr_name = "olt_auth_result_table",
                .attr_access_type  = ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 17
            },
            [BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_RESULT_STATUS] =
            {
                .attr_name = "olt_result_status",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_AUTH_STATUS] =
            {
                .attr_name = "onu_auth_status",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 1
            },
            [BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_MASTER_SESSION_KEY_NAME] =
            {
                .attr_name = "master_session_key_name",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_MANDATORY,
                .attr_len = 16
            },
            [BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_BROADCAST_KEY_TABLE] =
            {
                .attr_name = "broadcast_key_table",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ | ATTR_ACCESS_TYPE_WRITE,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 18
            },
            [BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_EFFECTIVE_KEY_LENGTH] =
            {
                .attr_name = "effective_key_length",
                .attr_access_type  = ATTR_ACCESS_TYPE_READ,
                .attr_present_type = ATTR_TYPE_OPTIONAL,
                .attr_len = 2
            },
        },
        .num_properties = BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID__NUM_OF,
        .me_supported_action_mask = BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_SET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET) | BCM_OMCI_ME_ACTION_MASK(BCM_OMCI_MSG_TYPE_GET_NEXT),
    },
};

char *bcm_omci_me_class_val_str[] =
{
    [BCM_OMCI_ME_CLASS_VAL__BEGIN]  "ME_CLASS_VAL_INVALID",
    [BCM_OMCI_ME_CLASS_VAL_GAL_ETH_PROF]  "gal_eth_prof",
    [BCM_OMCI_ME_CLASS_VAL_GEM_IW_TP]  "gem_iw_tp",
    [BCM_OMCI_ME_CLASS_VAL_GEM_PORT_NET_CTP]  "gem_port_net_ctp",
    [BCM_OMCI_ME_CLASS_VAL_IEEE_8021_P_MAPPER_SVC_PROF]  "ieee_8021_p_mapper_svc_prof",
    [BCM_OMCI_ME_CLASS_VAL_MAC_BRIDGE_PORT_CONFIG_DATA]  "mac_bridge_port_config_data",
    [BCM_OMCI_ME_CLASS_VAL_MAC_BRIDGE_SVC_PROF]  "mac_bridge_svc_prof",
    [BCM_OMCI_ME_CLASS_VAL_VLAN_TAG_FILTER_DATA]  "vlan_tag_filter_data",
    [BCM_OMCI_ME_CLASS_VAL_TCONT]  "tcont",
    [BCM_OMCI_ME_CLASS_VAL_EXT_VLAN_TAG_OPER_CONFIG_DATA]  "ext_vlan_tag_oper_config_data",
    [BCM_OMCI_ME_CLASS_VAL_PRIORITY_QUEUE_G]  "priority_queue_g",
    [BCM_OMCI_ME_CLASS_VAL_MCAST_GEM_IW_TP]  "mcast_gem_iw_tp",
    [BCM_OMCI_ME_CLASS_VAL_MCAST_OPERATIONS_PROFILE]  "mcast_operations_profile",
    [BCM_OMCI_ME_CLASS_VAL_MCAST_SUBSCRIBER_CONFIG_INFO]  "mcast_subscriber_config_info",
    [BCM_OMCI_ME_CLASS_VAL_PPTP_ETH_UNI]  "pptp_eth_uni",
    [BCM_OMCI_ME_CLASS_VAL_VIRTUAL_ETH_INTF_POINT]  "virtual_eth_intf_point",
    [BCM_OMCI_ME_CLASS_VAL_ONU_DATA]  "onu_data",
    [BCM_OMCI_ME_CLASS_VAL_ONU_G]  "onu_g",
    [BCM_OMCI_ME_CLASS_VAL_ONU2_G]  "onu2_g",
    [BCM_OMCI_ME_CLASS_VAL_SW_IMAGE]  "sw_image",
    [BCM_OMCI_ME_CLASS_VAL_ANI_G]  "ani_g",
    [BCM_OMCI_ME_CLASS_VAL_GEM_PORT_NET_CTP_PM]  "gem_port_net_ctp_pm",
    [BCM_OMCI_ME_CLASS_VAL_ETH_FRAME_UPSTREAM_PM]  "eth_frame_upstream_pm",
    [BCM_OMCI_ME_CLASS_VAL_ETH_FRAME_DOWNSTREAM_PM]  "eth_frame_downstream_pm",
    [BCM_OMCI_ME_CLASS_VAL_FEC_PM]  "fec_pm",
    [BCM_OMCI_ME_CLASS_VAL_XGPON_TC_PM]  "xgpon_tc_pm",
    [BCM_OMCI_ME_CLASS_VAL_IP_HOST_CONFIG_DATA]  "ip_host_config_data",
    [BCM_OMCI_ME_CLASS_VAL_VOIP_LINE_STATUS]  "voip_line_status",
    [BCM_OMCI_ME_CLASS_VAL_VOIP_MEDIA_PROFILE]  "voip_media_profile",
    [BCM_OMCI_ME_CLASS_VAL_SIP_USER_DATA]  "sip_user_data",
    [BCM_OMCI_ME_CLASS_VAL_SIP_AGENT_CONFIG_DATA]  "sip_agent_config_data",
    [BCM_OMCI_ME_CLASS_VAL_NETWORK_ADDRESS]  "network_address",
    [BCM_OMCI_ME_CLASS_VAL_LARGE_STRING]  "large_string",
    [BCM_OMCI_ME_CLASS_VAL_AUTHENTICATION_SECURITY_METHOD]  "authentication_security_method",
    [BCM_OMCI_ME_CLASS_VAL_VOICE_SERVICE_PROFILE]  "voice_service_profile",
    [BCM_OMCI_ME_CLASS_VAL_VOIP_CONFIG_DATA]  "voip_config_data",
    [BCM_OMCI_ME_CLASS_VAL_VOIP_VOICE_CTP]  "voip_voice_ctp",
    [BCM_OMCI_ME_CLASS_VAL_TCP_UDP_CONFIG_DATA]  "tcp_udp_config_data",
    [BCM_OMCI_ME_CLASS_VAL_NETWORK_DIAL_PLAN_TABLE]  "network_dial_plan_table",
    [BCM_OMCI_ME_CLASS_VAL_RTP_PROFILE_DATA]  "rtp_profile_data",
    [BCM_OMCI_ME_CLASS_VAL_POTS_UNI]  "pots_uni",
    [BCM_OMCI_ME_CLASS_VAL_CIRCUIT_PACK]  "circuit_pack",
    [BCM_OMCI_ME_CLASS_VAL_ENHANCED_SECURITY_CONTROL]  "enhanced_security_control",
    /* Additional MEs which are not defined in object model */
    [BCM_OMCI_ME_CLASS_VAL__END] "ME_CLASS_VAL__END"
};

char *bcm_omci_obj_type_str[] =
{
    [BCM_OMCI_OBJ_ID__BEGIN]  "ME_CLASS_VAL_INVALID",
    [BCM_OMCI_GAL_ETH_PROF_OBJ_ID]  "gal_eth_prof",
    [BCM_OMCI_GEM_IW_TP_OBJ_ID]  "gem_iw_tp",
    [BCM_OMCI_GEM_PORT_NET_CTP_OBJ_ID]  "gem_port_net_ctp",
    [BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_OBJ_ID]  "ieee_8021_p_mapper_svc_prof",
    [BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_OBJ_ID]  "mac_bridge_port_config_data",
    [BCM_OMCI_MAC_BRIDGE_SVC_PROF_OBJ_ID]  "mac_bridge_svc_prof",
    [BCM_OMCI_VLAN_TAG_FILTER_DATA_OBJ_ID]  "vlan_tag_filter_data",
    [BCM_OMCI_TCONT_OBJ_ID]  "tcont",
    [BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_OBJ_ID]  "ext_vlan_tag_oper_config_data",
    [BCM_OMCI_PRIORITY_QUEUE_G_OBJ_ID]  "priority_queue_g",
    [BCM_OMCI_MCAST_GEM_IW_TP_OBJ_ID]  "mcast_gem_iw_tp",
    [BCM_OMCI_MCAST_OPERATIONS_PROFILE_OBJ_ID]  "mcast_operations_profile",
    [BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_OBJ_ID]  "mcast_subscriber_config_info",
    [BCM_OMCI_PPTP_ETH_UNI_OBJ_ID]  "pptp_eth_uni",
    [BCM_OMCI_VIRTUAL_ETH_INTF_POINT_OBJ_ID]  "virtual_eth_intf_point",
    [BCM_OMCI_ONU_DATA_OBJ_ID]  "onu_data",
    [BCM_OMCI_ONU_G_OBJ_ID]  "onu_g",
    [BCM_OMCI_ONU2_G_OBJ_ID]  "onu2_g",
    [BCM_OMCI_SW_IMAGE_OBJ_ID]  "sw_image",
    [BCM_OMCI_ANI_G_OBJ_ID]  "ani_g",
    [BCM_OMCI_GEM_PORT_NET_CTP_PM_OBJ_ID]  "gem_port_net_ctp_pm",
    [BCM_OMCI_ETH_FRAME_UPSTREAM_PM_OBJ_ID]  "eth_frame_upstream_pm",
    [BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_OBJ_ID]  "eth_frame_downstream_pm",
    [BCM_OMCI_FEC_PM_OBJ_ID]  "fec_pm",
    [BCM_OMCI_XGPON_TC_PM_OBJ_ID]  "xgpon_tc_pm",
    [BCM_OMCI_IP_HOST_CONFIG_DATA_OBJ_ID]  "ip_host_config_data",
    [BCM_OMCI_VOIP_LINE_STATUS_OBJ_ID]  "voip_line_status",
    [BCM_OMCI_VOIP_MEDIA_PROFILE_OBJ_ID]  "voip_media_profile",
    [BCM_OMCI_SIP_USER_DATA_OBJ_ID]  "sip_user_data",
    [BCM_OMCI_SIP_AGENT_CONFIG_DATA_OBJ_ID]  "sip_agent_config_data",
    [BCM_OMCI_NETWORK_ADDRESS_OBJ_ID]  "network_address",
    [BCM_OMCI_LARGE_STRING_OBJ_ID]  "large_string",
    [BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_OBJ_ID]  "authentication_security_method",
    [BCM_OMCI_VOICE_SERVICE_PROFILE_OBJ_ID]  "voice_service_profile",
    [BCM_OMCI_VOIP_CONFIG_DATA_OBJ_ID]  "voip_config_data",
    [BCM_OMCI_VOIP_VOICE_CTP_OBJ_ID]  "voip_voice_ctp",
    [BCM_OMCI_TCP_UDP_CONFIG_DATA_OBJ_ID]  "tcp_udp_config_data",
    [BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_OBJ_ID]  "network_dial_plan_table",
    [BCM_OMCI_RTP_PROFILE_DATA_OBJ_ID]  "rtp_profile_data",
    [BCM_OMCI_POTS_UNI_OBJ_ID]  "pots_uni",
    [BCM_OMCI_CIRCUIT_PACK_OBJ_ID]  "circuit_pack",
    [BCM_OMCI_ENHANCED_SECURITY_CONTROL_OBJ_ID]  "enhanced_security_control",
    /* Additional MEs which are not defined in object model */
    [BCM_OMCI_OBJ_ID__NUM_OF] "OBJ_ID__END"
};

/* Maps entity class to cfg object id. */
bcm_omci_me_class_val2bcm_omci_obj_id_t bcm_omci_me_class_val2bcm_omci_obj_id[] =
{
    {BCM_OMCI_ME_CLASS_VAL_GAL_ETH_PROF, BCM_OMCI_GAL_ETH_PROF_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_GEM_IW_TP, BCM_OMCI_GEM_IW_TP_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_GEM_PORT_NET_CTP, BCM_OMCI_GEM_PORT_NET_CTP_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_IEEE_8021_P_MAPPER_SVC_PROF, BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_MAC_BRIDGE_PORT_CONFIG_DATA, BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_MAC_BRIDGE_SVC_PROF, BCM_OMCI_MAC_BRIDGE_SVC_PROF_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_VLAN_TAG_FILTER_DATA, BCM_OMCI_VLAN_TAG_FILTER_DATA_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_TCONT, BCM_OMCI_TCONT_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_EXT_VLAN_TAG_OPER_CONFIG_DATA, BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_PRIORITY_QUEUE_G, BCM_OMCI_PRIORITY_QUEUE_G_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_MCAST_GEM_IW_TP, BCM_OMCI_MCAST_GEM_IW_TP_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_MCAST_OPERATIONS_PROFILE, BCM_OMCI_MCAST_OPERATIONS_PROFILE_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_MCAST_SUBSCRIBER_CONFIG_INFO, BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_PPTP_ETH_UNI, BCM_OMCI_PPTP_ETH_UNI_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_VIRTUAL_ETH_INTF_POINT, BCM_OMCI_VIRTUAL_ETH_INTF_POINT_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_ONU_DATA, BCM_OMCI_ONU_DATA_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_ONU_G, BCM_OMCI_ONU_G_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_ONU2_G, BCM_OMCI_ONU2_G_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_SW_IMAGE, BCM_OMCI_SW_IMAGE_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_ANI_G, BCM_OMCI_ANI_G_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_GEM_PORT_NET_CTP_PM, BCM_OMCI_GEM_PORT_NET_CTP_PM_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_ETH_FRAME_UPSTREAM_PM, BCM_OMCI_ETH_FRAME_UPSTREAM_PM_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_ETH_FRAME_DOWNSTREAM_PM, BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_FEC_PM, BCM_OMCI_FEC_PM_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_XGPON_TC_PM, BCM_OMCI_XGPON_TC_PM_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_IP_HOST_CONFIG_DATA, BCM_OMCI_IP_HOST_CONFIG_DATA_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_VOIP_LINE_STATUS, BCM_OMCI_VOIP_LINE_STATUS_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_VOIP_MEDIA_PROFILE, BCM_OMCI_VOIP_MEDIA_PROFILE_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_SIP_USER_DATA, BCM_OMCI_SIP_USER_DATA_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_SIP_AGENT_CONFIG_DATA, BCM_OMCI_SIP_AGENT_CONFIG_DATA_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_NETWORK_ADDRESS, BCM_OMCI_NETWORK_ADDRESS_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_LARGE_STRING, BCM_OMCI_LARGE_STRING_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_AUTHENTICATION_SECURITY_METHOD, BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_VOICE_SERVICE_PROFILE, BCM_OMCI_VOICE_SERVICE_PROFILE_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_VOIP_CONFIG_DATA, BCM_OMCI_VOIP_CONFIG_DATA_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_VOIP_VOICE_CTP, BCM_OMCI_VOIP_VOICE_CTP_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_TCP_UDP_CONFIG_DATA, BCM_OMCI_TCP_UDP_CONFIG_DATA_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_NETWORK_DIAL_PLAN_TABLE, BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_RTP_PROFILE_DATA, BCM_OMCI_RTP_PROFILE_DATA_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_POTS_UNI, BCM_OMCI_POTS_UNI_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_CIRCUIT_PACK, BCM_OMCI_CIRCUIT_PACK_OBJ_ID},
    {BCM_OMCI_ME_CLASS_VAL_ENHANCED_SECURITY_CONTROL, BCM_OMCI_ENHANCED_SECURITY_CONTROL_OBJ_ID},
    {-1}
};

/* Maps object id to entity class. */
bcm_omci_obj_id2bcm_omci_me_class_val_t bcm_omci_obj_id2bcm_omci_me_class_val[] =
{
    {BCM_OMCI_GAL_ETH_PROF_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_GAL_ETH_PROF},
    {BCM_OMCI_GEM_IW_TP_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_GEM_IW_TP},
    {BCM_OMCI_GEM_PORT_NET_CTP_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_GEM_PORT_NET_CTP},
    {BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_IEEE_8021_P_MAPPER_SVC_PROF},
    {BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_MAC_BRIDGE_PORT_CONFIG_DATA},
    {BCM_OMCI_MAC_BRIDGE_SVC_PROF_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_MAC_BRIDGE_SVC_PROF},
    {BCM_OMCI_VLAN_TAG_FILTER_DATA_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_VLAN_TAG_FILTER_DATA},
    {BCM_OMCI_TCONT_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_TCONT},
    {BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_EXT_VLAN_TAG_OPER_CONFIG_DATA},
    {BCM_OMCI_PRIORITY_QUEUE_G_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_PRIORITY_QUEUE_G},
    {BCM_OMCI_MCAST_GEM_IW_TP_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_MCAST_GEM_IW_TP},
    {BCM_OMCI_MCAST_OPERATIONS_PROFILE_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_MCAST_OPERATIONS_PROFILE},
    {BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_MCAST_SUBSCRIBER_CONFIG_INFO},
    {BCM_OMCI_PPTP_ETH_UNI_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_PPTP_ETH_UNI},
    {BCM_OMCI_VIRTUAL_ETH_INTF_POINT_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_VIRTUAL_ETH_INTF_POINT},
    {BCM_OMCI_ONU_DATA_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_ONU_DATA},
    {BCM_OMCI_ONU_G_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_ONU_G},
    {BCM_OMCI_ONU2_G_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_ONU2_G},
    {BCM_OMCI_SW_IMAGE_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_SW_IMAGE},
    {BCM_OMCI_ANI_G_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_ANI_G},
    {BCM_OMCI_GEM_PORT_NET_CTP_PM_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_GEM_PORT_NET_CTP_PM},
    {BCM_OMCI_ETH_FRAME_UPSTREAM_PM_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_ETH_FRAME_UPSTREAM_PM},
    {BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_ETH_FRAME_DOWNSTREAM_PM},
    {BCM_OMCI_FEC_PM_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_FEC_PM},
    {BCM_OMCI_XGPON_TC_PM_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_XGPON_TC_PM},
    {BCM_OMCI_IP_HOST_CONFIG_DATA_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_IP_HOST_CONFIG_DATA},
    {BCM_OMCI_VOIP_LINE_STATUS_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_VOIP_LINE_STATUS},
    {BCM_OMCI_VOIP_MEDIA_PROFILE_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_VOIP_MEDIA_PROFILE},
    {BCM_OMCI_SIP_USER_DATA_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_SIP_USER_DATA},
    {BCM_OMCI_SIP_AGENT_CONFIG_DATA_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_SIP_AGENT_CONFIG_DATA},
    {BCM_OMCI_NETWORK_ADDRESS_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_NETWORK_ADDRESS},
    {BCM_OMCI_LARGE_STRING_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_LARGE_STRING},
    {BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_AUTHENTICATION_SECURITY_METHOD},
    {BCM_OMCI_VOICE_SERVICE_PROFILE_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_VOICE_SERVICE_PROFILE},
    {BCM_OMCI_VOIP_CONFIG_DATA_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_VOIP_CONFIG_DATA},
    {BCM_OMCI_VOIP_VOICE_CTP_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_VOIP_VOICE_CTP},
    {BCM_OMCI_TCP_UDP_CONFIG_DATA_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_TCP_UDP_CONFIG_DATA},
    {BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_NETWORK_DIAL_PLAN_TABLE},
    {BCM_OMCI_RTP_PROFILE_DATA_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_RTP_PROFILE_DATA},
    {BCM_OMCI_POTS_UNI_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_POTS_UNI},
    {BCM_OMCI_CIRCUIT_PACK_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_CIRCUIT_PACK},
    {BCM_OMCI_ENHANCED_SECURITY_CONTROL_OBJ_ID, BCM_OMCI_ME_CLASS_VAL_ENHANCED_SECURITY_CONTROL},
    {-1}
};

/* GAL Ethernet Profile */
static bcmos_errno bcm_omci_me_gal_eth_prof_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_gal_eth_prof_cfg_encode(const bcm_omci_gal_eth_prof_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_gal_eth_prof_cfg_data_decode(bcm_omci_gal_eth_prof_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* GEM Interworking Termination Point */
static bcmos_errno bcm_omci_me_gem_iw_tp_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_gem_iw_tp_cfg_encode(const bcm_omci_gem_iw_tp_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_gem_iw_tp_cfg_data_decode(bcm_omci_gem_iw_tp_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* GEM Port Network CTP */
static bcmos_errno bcm_omci_me_gem_port_net_ctp_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_gem_port_net_ctp_cfg_encode(const bcm_omci_gem_port_net_ctp_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_gem_port_net_ctp_cfg_data_decode(bcm_omci_gem_port_net_ctp_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* IEEE 802.1p mapper service profile */
static bcmos_errno bcm_omci_me_ieee_8021_p_mapper_svc_prof_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_ieee_8021_p_mapper_svc_prof_cfg_encode(const bcm_omci_ieee_8021_p_mapper_svc_prof_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_data_decode(bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* MAC Bridge Port Configuration Data */
static bcmos_errno bcm_omci_me_mac_bridge_port_config_data_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_mac_bridge_port_config_data_cfg_encode(const bcm_omci_mac_bridge_port_config_data_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_mac_bridge_port_config_data_cfg_data_decode(bcm_omci_mac_bridge_port_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* MAC Bridge Service Profile */
static bcmos_errno bcm_omci_me_mac_bridge_svc_prof_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_mac_bridge_svc_prof_cfg_encode(const bcm_omci_mac_bridge_svc_prof_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_mac_bridge_svc_prof_cfg_data_decode(bcm_omci_mac_bridge_svc_prof_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* VLAN Tagging Filter Data */
static bcmos_errno bcm_omci_me_vlan_tag_filter_data_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_vlan_tag_filter_data_cfg_encode(const bcm_omci_vlan_tag_filter_data_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_vlan_tag_filter_data_cfg_data_decode(bcm_omci_vlan_tag_filter_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* T-CONT */
static bcmos_errno bcm_omci_me_tcont_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_tcont_cfg_encode(const bcm_omci_tcont_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_tcont_cfg_data_decode(bcm_omci_tcont_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* Extended VLAN Tagging Operation Configuration Data */
static bcmos_errno bcm_omci_me_ext_vlan_tag_oper_config_data_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_ext_vlan_tag_oper_config_data_cfg_encode(const bcm_omci_ext_vlan_tag_oper_config_data_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_ext_vlan_tag_oper_config_data_cfg_data_decode(bcm_omci_ext_vlan_tag_oper_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* priority queue-G */
static bcmos_errno bcm_omci_me_priority_queue_g_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_priority_queue_g_cfg_encode(const bcm_omci_priority_queue_g_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_priority_queue_g_cfg_data_decode(bcm_omci_priority_queue_g_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* Multicast GEM interworking termination point */
static bcmos_errno bcm_omci_me_mcast_gem_iw_tp_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_mcast_gem_iw_tp_cfg_encode(const bcm_omci_mcast_gem_iw_tp_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_mcast_gem_iw_tp_cfg_data_decode(bcm_omci_mcast_gem_iw_tp_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* Multicast Operations Profile */
static bcmos_errno bcm_omci_me_mcast_operations_profile_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_mcast_operations_profile_cfg_encode(const bcm_omci_mcast_operations_profile_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_mcast_operations_profile_cfg_data_decode(bcm_omci_mcast_operations_profile_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* Multicast subscriber config info */
static bcmos_errno bcm_omci_me_mcast_subscriber_config_info_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_mcast_subscriber_config_info_cfg_encode(const bcm_omci_mcast_subscriber_config_info_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_mcast_subscriber_config_info_cfg_data_decode(bcm_omci_mcast_subscriber_config_info_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* PPTP Ethernet UNI */
static bcmos_errno bcm_omci_me_pptp_eth_uni_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_pptp_eth_uni_cfg_encode(const bcm_omci_pptp_eth_uni_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_pptp_eth_uni_cfg_data_decode(bcm_omci_pptp_eth_uni_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* Virtual Ethernet Interface Point */
static bcmos_errno bcm_omci_me_virtual_eth_intf_point_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_virtual_eth_intf_point_cfg_encode(const bcm_omci_virtual_eth_intf_point_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_virtual_eth_intf_point_cfg_data_decode(bcm_omci_virtual_eth_intf_point_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* ONU data */
static bcmos_errno bcm_omci_me_onu_data_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_onu_data_cfg_encode(const bcm_omci_onu_data_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_onu_data_cfg_data_decode(bcm_omci_onu_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* ONU-G (9.1.1) */
static bcmos_errno bcm_omci_me_onu_g_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_onu_g_cfg_encode(const bcm_omci_onu_g_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_onu_g_cfg_data_decode(bcm_omci_onu_g_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* ONU2-G (9.1.2) */
static bcmos_errno bcm_omci_me_onu2_g_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_onu2_g_cfg_encode(const bcm_omci_onu2_g_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_onu2_g_cfg_data_decode(bcm_omci_onu2_g_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* Software image (9.1.4) */
static bcmos_errno bcm_omci_me_sw_image_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_sw_image_cfg_encode(const bcm_omci_sw_image_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_sw_image_cfg_data_decode(bcm_omci_sw_image_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* ANI-G (9.2.1) */
static bcmos_errno bcm_omci_me_ani_g_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_ani_g_cfg_encode(const bcm_omci_ani_g_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_ani_g_cfg_data_decode(bcm_omci_ani_g_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* GEM Port Network CTP PM(9.2.13) */
static bcmos_errno bcm_omci_me_gem_port_net_ctp_pm_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_gem_port_net_ctp_pm_cfg_encode(const bcm_omci_gem_port_net_ctp_pm_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_gem_port_net_ctp_pm_cfg_data_decode(bcm_omci_gem_port_net_ctp_pm_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* ETH FRAME UPSTREAM PM(9.3.30) */
static bcmos_errno bcm_omci_me_eth_frame_upstream_pm_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_eth_frame_upstream_pm_cfg_encode(const bcm_omci_eth_frame_upstream_pm_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_eth_frame_upstream_pm_cfg_data_decode(bcm_omci_eth_frame_upstream_pm_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* ETH FRAME DOWNSTREAM PM(9.3.31) */
static bcmos_errno bcm_omci_me_eth_frame_downstream_pm_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_eth_frame_downstream_pm_cfg_encode(const bcm_omci_eth_frame_downstream_pm_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_eth_frame_downstream_pm_cfg_data_decode(bcm_omci_eth_frame_downstream_pm_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* FEC PERFORMANCE PM DATA(9.2.9) */
static bcmos_errno bcm_omci_me_fec_pm_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_fec_pm_cfg_encode(const bcm_omci_fec_pm_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_fec_pm_cfg_data_decode(bcm_omci_fec_pm_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* XG-PON TC PERFORMANCE PM DATA(9.2.15) */
static bcmos_errno bcm_omci_me_xgpon_tc_pm_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_xgpon_tc_pm_cfg_encode(const bcm_omci_xgpon_tc_pm_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_xgpon_tc_pm_cfg_data_decode(bcm_omci_xgpon_tc_pm_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* IP Host Config Data (9.4.1) */
static bcmos_errno bcm_omci_me_ip_host_config_data_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_ip_host_config_data_cfg_encode(const bcm_omci_ip_host_config_data_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_ip_host_config_data_cfg_data_decode(bcm_omci_ip_host_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* VoIP Line Status (9.9.11) */
static bcmos_errno bcm_omci_me_voip_line_status_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_voip_line_status_cfg_encode(const bcm_omci_voip_line_status_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_voip_line_status_cfg_data_decode(bcm_omci_voip_line_status_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* VoIP Line Status (9.9.11) */
static bcmos_errno bcm_omci_me_voip_media_profile_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_voip_media_profile_cfg_encode(const bcm_omci_voip_media_profile_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_voip_media_profile_cfg_data_decode(bcm_omci_voip_media_profile_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* SIP User Data (9.9.2) */
static bcmos_errno bcm_omci_me_sip_user_data_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_sip_user_data_cfg_encode(const bcm_omci_sip_user_data_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_sip_user_data_cfg_data_decode(bcm_omci_sip_user_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* SIP Agent Config Data (9.9.3) */
static bcmos_errno bcm_omci_me_sip_agent_config_data_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_sip_agent_config_data_cfg_encode(const bcm_omci_sip_agent_config_data_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_sip_agent_config_data_cfg_data_decode(bcm_omci_sip_agent_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* Network Address (9.12.3) */
static bcmos_errno bcm_omci_me_network_address_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_network_address_cfg_encode(const bcm_omci_network_address_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_network_address_cfg_data_decode(bcm_omci_network_address_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* Large String (9.12.5) */
static bcmos_errno bcm_omci_me_large_string_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_large_string_cfg_encode(const bcm_omci_large_string_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_large_string_cfg_data_decode(bcm_omci_large_string_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* Authentication Security Method (9.12.4) */
static bcmos_errno bcm_omci_me_authentication_security_method_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_authentication_security_method_cfg_encode(const bcm_omci_authentication_security_method_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_authentication_security_method_cfg_data_decode(bcm_omci_authentication_security_method_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* Voice Service Profile (9.9.6) */
static bcmos_errno bcm_omci_me_voice_service_profile_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_voice_service_profile_cfg_encode(const bcm_omci_voice_service_profile_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_voice_service_profile_cfg_data_decode(bcm_omci_voice_service_profile_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* VoIP config data (9.9.18) */
static bcmos_errno bcm_omci_me_voip_config_data_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_voip_config_data_cfg_encode(const bcm_omci_voip_config_data_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_voip_config_data_cfg_data_decode(bcm_omci_voip_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* VoIP voice CTP (9.9.4) */
static bcmos_errno bcm_omci_me_voip_voice_ctp_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_voip_voice_ctp_cfg_encode(const bcm_omci_voip_voice_ctp_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_voip_voice_ctp_cfg_data_decode(bcm_omci_voip_voice_ctp_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* TCP/UDP config data (9.4.3) */
static bcmos_errno bcm_omci_me_tcp_udp_config_data_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_tcp_udp_config_data_cfg_encode(const bcm_omci_tcp_udp_config_data_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_tcp_udp_config_data_cfg_data_decode(bcm_omci_tcp_udp_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* Network dial plan table (9.9.10) */
static bcmos_errno bcm_omci_me_network_dial_plan_table_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_network_dial_plan_table_cfg_encode(const bcm_omci_network_dial_plan_table_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_network_dial_plan_table_cfg_data_decode(bcm_omci_network_dial_plan_table_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* RTP profile data (9.9.7) */
static bcmos_errno bcm_omci_me_rtp_profile_data_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_rtp_profile_data_cfg_encode(const bcm_omci_rtp_profile_data_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_rtp_profile_data_cfg_data_decode(bcm_omci_rtp_profile_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* Physical path termination point POTS UNI (9.9.1) */
static bcmos_errno bcm_omci_me_pots_uni_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_pots_uni_cfg_encode(const bcm_omci_pots_uni_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_pots_uni_cfg_data_decode(bcm_omci_pots_uni_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* Circuit pack (9.1.6) */
static bcmos_errno bcm_omci_me_circuit_pack_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_circuit_pack_cfg_encode(const bcm_omci_circuit_pack_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_circuit_pack_cfg_data_decode(bcm_omci_circuit_pack_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
/* Enhanced Security Control (9.13.11) */
static bcmos_errno bcm_omci_me_enhanced_security_control_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg);
static bcmos_bool _bcm_omci_me_enhanced_security_control_cfg_encode(const bcm_omci_enhanced_security_control_cfg *p_me_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type);
static bcmos_bool bcm_omci_enhanced_security_control_cfg_data_decode(bcm_omci_enhanced_security_control_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* get cfg struct length based on obj id */
uint16_t bcm_omci_me_cfg_get_struct_length(bcm_omci_obj_id me_cfg_obj_id)
{
    switch (me_cfg_obj_id)
    {
    case BCM_OMCI_GAL_ETH_PROF_OBJ_ID:
        return sizeof(bcm_omci_gal_eth_prof_cfg);
    case BCM_OMCI_GEM_IW_TP_OBJ_ID:
        return sizeof(bcm_omci_gem_iw_tp_cfg);
    case BCM_OMCI_GEM_PORT_NET_CTP_OBJ_ID:
        return sizeof(bcm_omci_gem_port_net_ctp_cfg);
    case BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_OBJ_ID:
        return sizeof(bcm_omci_ieee_8021_p_mapper_svc_prof_cfg);
    case BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_OBJ_ID:
        return sizeof(bcm_omci_mac_bridge_port_config_data_cfg);
    case BCM_OMCI_MAC_BRIDGE_SVC_PROF_OBJ_ID:
        return sizeof(bcm_omci_mac_bridge_svc_prof_cfg);
    case BCM_OMCI_VLAN_TAG_FILTER_DATA_OBJ_ID:
        return sizeof(bcm_omci_vlan_tag_filter_data_cfg);
    case BCM_OMCI_TCONT_OBJ_ID:
        return sizeof(bcm_omci_tcont_cfg);
    case BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_OBJ_ID:
        return sizeof(bcm_omci_ext_vlan_tag_oper_config_data_cfg);
    case BCM_OMCI_PRIORITY_QUEUE_G_OBJ_ID:
        return sizeof(bcm_omci_priority_queue_g_cfg);
    case BCM_OMCI_MCAST_GEM_IW_TP_OBJ_ID:
        return sizeof(bcm_omci_mcast_gem_iw_tp_cfg);
    case BCM_OMCI_MCAST_OPERATIONS_PROFILE_OBJ_ID:
        return sizeof(bcm_omci_mcast_operations_profile_cfg);
    case BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_OBJ_ID:
        return sizeof(bcm_omci_mcast_subscriber_config_info_cfg);
    case BCM_OMCI_PPTP_ETH_UNI_OBJ_ID:
        return sizeof(bcm_omci_pptp_eth_uni_cfg);
    case BCM_OMCI_VIRTUAL_ETH_INTF_POINT_OBJ_ID:
        return sizeof(bcm_omci_virtual_eth_intf_point_cfg);
    case BCM_OMCI_ONU_DATA_OBJ_ID:
        return sizeof(bcm_omci_onu_data_cfg);
    case BCM_OMCI_ONU_G_OBJ_ID:
        return sizeof(bcm_omci_onu_g_cfg);
    case BCM_OMCI_ONU2_G_OBJ_ID:
        return sizeof(bcm_omci_onu2_g_cfg);
    case BCM_OMCI_SW_IMAGE_OBJ_ID:
        return sizeof(bcm_omci_sw_image_cfg);
    case BCM_OMCI_ANI_G_OBJ_ID:
        return sizeof(bcm_omci_ani_g_cfg);
    case BCM_OMCI_GEM_PORT_NET_CTP_PM_OBJ_ID:
        return sizeof(bcm_omci_gem_port_net_ctp_pm_cfg);
    case BCM_OMCI_ETH_FRAME_UPSTREAM_PM_OBJ_ID:
        return sizeof(bcm_omci_eth_frame_upstream_pm_cfg);
    case BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_OBJ_ID:
        return sizeof(bcm_omci_eth_frame_downstream_pm_cfg);
    case BCM_OMCI_FEC_PM_OBJ_ID:
        return sizeof(bcm_omci_fec_pm_cfg);
    case BCM_OMCI_XGPON_TC_PM_OBJ_ID:
        return sizeof(bcm_omci_xgpon_tc_pm_cfg);
    case BCM_OMCI_IP_HOST_CONFIG_DATA_OBJ_ID:
        return sizeof(bcm_omci_ip_host_config_data_cfg);
    case BCM_OMCI_VOIP_LINE_STATUS_OBJ_ID:
        return sizeof(bcm_omci_voip_line_status_cfg);
    case BCM_OMCI_VOIP_MEDIA_PROFILE_OBJ_ID:
        return sizeof(bcm_omci_voip_media_profile_cfg);
    case BCM_OMCI_SIP_USER_DATA_OBJ_ID:
        return sizeof(bcm_omci_sip_user_data_cfg);
    case BCM_OMCI_SIP_AGENT_CONFIG_DATA_OBJ_ID:
        return sizeof(bcm_omci_sip_agent_config_data_cfg);
    case BCM_OMCI_NETWORK_ADDRESS_OBJ_ID:
        return sizeof(bcm_omci_network_address_cfg);
    case BCM_OMCI_LARGE_STRING_OBJ_ID:
        return sizeof(bcm_omci_large_string_cfg);
    case BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_OBJ_ID:
        return sizeof(bcm_omci_authentication_security_method_cfg);
    case BCM_OMCI_VOICE_SERVICE_PROFILE_OBJ_ID:
        return sizeof(bcm_omci_voice_service_profile_cfg);
    case BCM_OMCI_VOIP_CONFIG_DATA_OBJ_ID:
        return sizeof(bcm_omci_voip_config_data_cfg);
    case BCM_OMCI_VOIP_VOICE_CTP_OBJ_ID:
        return sizeof(bcm_omci_voip_voice_ctp_cfg);
    case BCM_OMCI_TCP_UDP_CONFIG_DATA_OBJ_ID:
        return sizeof(bcm_omci_tcp_udp_config_data_cfg);
    case BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_OBJ_ID:
        return sizeof(bcm_omci_network_dial_plan_table_cfg);
    case BCM_OMCI_RTP_PROFILE_DATA_OBJ_ID:
        return sizeof(bcm_omci_rtp_profile_data_cfg);
    case BCM_OMCI_POTS_UNI_OBJ_ID:
        return sizeof(bcm_omci_pots_uni_cfg);
    case BCM_OMCI_CIRCUIT_PACK_OBJ_ID:
        return sizeof(bcm_omci_circuit_pack_cfg);
    case BCM_OMCI_ENHANCED_SECURITY_CONTROL_OBJ_ID:
        return sizeof(bcm_omci_enhanced_security_control_cfg);
    default:
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : unsupported me cfg obj id = %d\n",
            __FUNCTION__, me_cfg_obj_id);
        break;
    }

    return 0;
}

/* Dispatcher routine to call copy partial */
bcmos_errno bcm_omci_me_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg, bcm_omci_obj_id obj_type)
{
    switch (obj_type)
    {
    case BCM_OMCI_GAL_ETH_PROF_OBJ_ID:
        return bcm_omci_me_gal_eth_prof_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_GEM_IW_TP_OBJ_ID:
        return bcm_omci_me_gem_iw_tp_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_GEM_PORT_NET_CTP_OBJ_ID:
        return bcm_omci_me_gem_port_net_ctp_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_OBJ_ID:
        return bcm_omci_me_ieee_8021_p_mapper_svc_prof_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_OBJ_ID:
        return bcm_omci_me_mac_bridge_port_config_data_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_MAC_BRIDGE_SVC_PROF_OBJ_ID:
        return bcm_omci_me_mac_bridge_svc_prof_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_VLAN_TAG_FILTER_DATA_OBJ_ID:
        return bcm_omci_me_vlan_tag_filter_data_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_TCONT_OBJ_ID:
        return bcm_omci_me_tcont_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_OBJ_ID:
        return bcm_omci_me_ext_vlan_tag_oper_config_data_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_PRIORITY_QUEUE_G_OBJ_ID:
        return bcm_omci_me_priority_queue_g_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_MCAST_GEM_IW_TP_OBJ_ID:
        return bcm_omci_me_mcast_gem_iw_tp_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_MCAST_OPERATIONS_PROFILE_OBJ_ID:
        return bcm_omci_me_mcast_operations_profile_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_OBJ_ID:
        return bcm_omci_me_mcast_subscriber_config_info_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_PPTP_ETH_UNI_OBJ_ID:
        return bcm_omci_me_pptp_eth_uni_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_VIRTUAL_ETH_INTF_POINT_OBJ_ID:
        return bcm_omci_me_virtual_eth_intf_point_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_ONU_DATA_OBJ_ID:
        return bcm_omci_me_onu_data_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_ONU_G_OBJ_ID:
        return bcm_omci_me_onu_g_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_ONU2_G_OBJ_ID:
        return bcm_omci_me_onu2_g_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_SW_IMAGE_OBJ_ID:
        return bcm_omci_me_sw_image_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_ANI_G_OBJ_ID:
        return bcm_omci_me_ani_g_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_GEM_PORT_NET_CTP_PM_OBJ_ID:
        return bcm_omci_me_gem_port_net_ctp_pm_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_ETH_FRAME_UPSTREAM_PM_OBJ_ID:
        return bcm_omci_me_eth_frame_upstream_pm_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_OBJ_ID:
        return bcm_omci_me_eth_frame_downstream_pm_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_FEC_PM_OBJ_ID:
        return bcm_omci_me_fec_pm_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_XGPON_TC_PM_OBJ_ID:
        return bcm_omci_me_xgpon_tc_pm_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_IP_HOST_CONFIG_DATA_OBJ_ID:
        return bcm_omci_me_ip_host_config_data_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_VOIP_LINE_STATUS_OBJ_ID:
        return bcm_omci_me_voip_line_status_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_VOIP_MEDIA_PROFILE_OBJ_ID:
        return bcm_omci_me_voip_media_profile_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_SIP_USER_DATA_OBJ_ID:
        return bcm_omci_me_sip_user_data_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_SIP_AGENT_CONFIG_DATA_OBJ_ID:
        return bcm_omci_me_sip_agent_config_data_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_NETWORK_ADDRESS_OBJ_ID:
        return bcm_omci_me_network_address_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_LARGE_STRING_OBJ_ID:
        return bcm_omci_me_large_string_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_OBJ_ID:
        return bcm_omci_me_authentication_security_method_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_VOICE_SERVICE_PROFILE_OBJ_ID:
        return bcm_omci_me_voice_service_profile_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_VOIP_CONFIG_DATA_OBJ_ID:
        return bcm_omci_me_voip_config_data_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_VOIP_VOICE_CTP_OBJ_ID:
        return bcm_omci_me_voip_voice_ctp_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_TCP_UDP_CONFIG_DATA_OBJ_ID:
        return bcm_omci_me_tcp_udp_config_data_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_OBJ_ID:
        return bcm_omci_me_network_dial_plan_table_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_RTP_PROFILE_DATA_OBJ_ID:
        return bcm_omci_me_rtp_profile_data_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_POTS_UNI_OBJ_ID:
        return bcm_omci_me_pots_uni_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_CIRCUIT_PACK_OBJ_ID:
        return bcm_omci_me_circuit_pack_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    case BCM_OMCI_ENHANCED_SECURITY_CONTROL_OBJ_ID:
        return bcm_omci_me_enhanced_security_control_cfg_copy_partial(src_me_cfg, dst_me_cfg);
    default:
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s: unsupported ME obj id = %d\n", __FUNCTION__, obj_type);
        return BCM_ERR_NOT_SUPPORTED;
    }

    return BCM_ERR_NOT_SUPPORTED;
}

/* GAL Ethernet Profile */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_gal_eth_prof_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_gal_eth_prof_cfg *p_src_me_gal_eth_prof_cfg = (const bcm_omci_gal_eth_prof_cfg *)src_me_cfg;
    bcm_omci_gal_eth_prof_cfg *p_dst_me_gal_eth_prof_cfg = (bcm_omci_gal_eth_prof_cfg *)dst_me_cfg;

    p_dst_me_gal_eth_prof_cfg->hdr.presence_mask |= p_src_me_gal_eth_prof_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_gal_eth_prof_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_GAL_ETH_PROF_CFG_ID_MAX_GEM_PAYLOAD_SIZE)) != 0)
    {
        p_dst_me_gal_eth_prof_cfg->data.max_gem_payload_size = p_src_me_gal_eth_prof_cfg->data.max_gem_payload_size;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_gal_eth_prof_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_gal_eth_prof_cfg *p_me_gal_eth_prof_cfg = (const bcm_omci_gal_eth_prof_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_gal_eth_prof_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_GAL_ETH_PROF_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_gal_eth_prof_cfg);

    if (BCMOS_TRUE != bcm_omci_gal_eth_prof_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_gal_eth_prof_cfg_data_bounds_check(&p_me_gal_eth_prof_cfg->data, p_me_gal_eth_prof_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_gal_eth_prof_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_gal_eth_prof_cfg_encode(p_me_gal_eth_prof_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_gal_eth_prof_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_gal_eth_prof_cfg *p_me_gal_eth_prof_cfg = (bcm_omci_gal_eth_prof_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_gal_eth_prof_cfg_data_decode(&p_me_gal_eth_prof_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_gal_eth_prof_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_gal_eth_prof_cfg *p_me_gal_eth_prof_cfg = (const bcm_omci_gal_eth_prof_cfg *)me_hdr;
    const bcm_omci_gal_eth_prof_cfg_data *p_me_cfg_data = &p_me_gal_eth_prof_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_gal_eth_prof_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_gal_eth_prof_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_GAL_ETH_PROF_CFG_ID_MAX_GEM_PAYLOAD_SIZE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tmax_gem_payload_size:\t%u\n", p_me_cfg_data->max_gem_payload_size);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_gal_eth_prof_cfg_data_encode(const bcm_omci_gal_eth_prof_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_gal_eth_prof_cfg_data_encode(const bcm_omci_gal_eth_prof_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_GAL_ETH_PROF_CFG_ID_MAX_GEM_PAYLOAD_SIZE)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->max_gem_payload_size))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_gal_eth_prof_cfg_encode(const bcm_omci_gal_eth_prof_cfg *p_me_gal_eth_prof_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_gal_eth_prof_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_gal_eth_prof_cfg_data_encode(&p_me_gal_eth_prof_cfg->data, p_bcm_buf, p_me_gal_eth_prof_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_gal_eth_prof_cfg_data_decode(bcm_omci_gal_eth_prof_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_GAL_ETH_PROF_CFG_ID_MAX_GEM_PAYLOAD_SIZE)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->max_gem_payload_size))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* GEM Interworking Termination Point */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_gem_iw_tp_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_gem_iw_tp_cfg *p_src_me_gem_iw_tp_cfg = (const bcm_omci_gem_iw_tp_cfg *)src_me_cfg;
    bcm_omci_gem_iw_tp_cfg *p_dst_me_gem_iw_tp_cfg = (bcm_omci_gem_iw_tp_cfg *)dst_me_cfg;

    p_dst_me_gem_iw_tp_cfg->hdr.presence_mask |= p_src_me_gem_iw_tp_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_gem_iw_tp_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_GEM_PORT_NET_CTP_CONN_PTR)) != 0)
    {
        p_dst_me_gem_iw_tp_cfg->data.gem_port_net_ctp_conn_ptr = p_src_me_gem_iw_tp_cfg->data.gem_port_net_ctp_conn_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_IW_OPT)) != 0)
    {
        p_dst_me_gem_iw_tp_cfg->data.iw_opt = p_src_me_gem_iw_tp_cfg->data.iw_opt;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_SVC_PROF_PTR)) != 0)
    {
        p_dst_me_gem_iw_tp_cfg->data.svc_prof_ptr = p_src_me_gem_iw_tp_cfg->data.svc_prof_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_IW_TP_PTR)) != 0)
    {
        p_dst_me_gem_iw_tp_cfg->data.iw_tp_ptr = p_src_me_gem_iw_tp_cfg->data.iw_tp_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_PPTP_COUNT)) != 0)
    {
        p_dst_me_gem_iw_tp_cfg->data.pptp_count = p_src_me_gem_iw_tp_cfg->data.pptp_count;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_OPER_STATE)) != 0)
    {
        p_dst_me_gem_iw_tp_cfg->data.oper_state = p_src_me_gem_iw_tp_cfg->data.oper_state;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_GAL_PROF_PTR)) != 0)
    {
        p_dst_me_gem_iw_tp_cfg->data.gal_prof_ptr = p_src_me_gem_iw_tp_cfg->data.gal_prof_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_GAL_LPBK_CONFIG)) != 0)
    {
        p_dst_me_gem_iw_tp_cfg->data.gal_lpbk_config = p_src_me_gem_iw_tp_cfg->data.gal_lpbk_config;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_gem_iw_tp_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_gem_iw_tp_cfg *p_me_gem_iw_tp_cfg = (const bcm_omci_gem_iw_tp_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_gem_iw_tp_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_GEM_IW_TP_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_gem_iw_tp_cfg);

    if (BCMOS_TRUE != bcm_omci_gem_iw_tp_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_gem_iw_tp_cfg_data_bounds_check(&p_me_gem_iw_tp_cfg->data, p_me_gem_iw_tp_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_gem_iw_tp_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_gem_iw_tp_cfg_encode(p_me_gem_iw_tp_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_gem_iw_tp_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_gem_iw_tp_cfg *p_me_gem_iw_tp_cfg = (bcm_omci_gem_iw_tp_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_gem_iw_tp_cfg_data_decode(&p_me_gem_iw_tp_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_gem_iw_tp_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_gem_iw_tp_cfg *p_me_gem_iw_tp_cfg = (const bcm_omci_gem_iw_tp_cfg *)me_hdr;
    const bcm_omci_gem_iw_tp_cfg_data *p_me_cfg_data = &p_me_gem_iw_tp_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_gem_iw_tp_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_gem_iw_tp_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_GEM_PORT_NET_CTP_CONN_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tgem_port_net_ctp_conn_ptr:\t%u\n", p_me_cfg_data->gem_port_net_ctp_conn_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_IW_OPT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tiw_opt:\t%u\n", p_me_cfg_data->iw_opt);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_SVC_PROF_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsvc_prof_ptr:\t%u\n", p_me_cfg_data->svc_prof_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_IW_TP_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tiw_tp_ptr:\t%u\n", p_me_cfg_data->iw_tp_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_PPTP_COUNT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpptp_count:\t%u\n", p_me_cfg_data->pptp_count);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_OPER_STATE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\toper_state:\t%u\n", p_me_cfg_data->oper_state);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_GAL_PROF_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tgal_prof_ptr:\t%u\n", p_me_cfg_data->gal_prof_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_GAL_LPBK_CONFIG)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tgal_lpbk_config:\t%u\n", p_me_cfg_data->gal_lpbk_config);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_gem_iw_tp_cfg_data_encode(const bcm_omci_gem_iw_tp_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_gem_iw_tp_cfg_data_encode(const bcm_omci_gem_iw_tp_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_GEM_PORT_NET_CTP_CONN_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->gem_port_net_ctp_conn_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_IW_OPT)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->iw_opt))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_SVC_PROF_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->svc_prof_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_IW_TP_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->iw_tp_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_PPTP_COUNT)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->pptp_count))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_OPER_STATE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->oper_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_GAL_PROF_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->gal_prof_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_GAL_LPBK_CONFIG)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->gal_lpbk_config))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_gem_iw_tp_cfg_encode(const bcm_omci_gem_iw_tp_cfg *p_me_gem_iw_tp_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_gem_iw_tp_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_gem_iw_tp_cfg_data_encode(&p_me_gem_iw_tp_cfg->data, p_bcm_buf, p_me_gem_iw_tp_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_gem_iw_tp_cfg_data_decode(bcm_omci_gem_iw_tp_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_GEM_PORT_NET_CTP_CONN_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->gem_port_net_ctp_conn_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_IW_OPT)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->iw_opt))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_SVC_PROF_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->svc_prof_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_IW_TP_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->iw_tp_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_PPTP_COUNT)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->pptp_count))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_OPER_STATE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->oper_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_GAL_PROF_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->gal_prof_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_IW_TP_CFG_ID_GAL_LPBK_CONFIG)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->gal_lpbk_config))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* GEM Port Network CTP */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_gem_port_net_ctp_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_gem_port_net_ctp_cfg *p_src_me_gem_port_net_ctp_cfg = (const bcm_omci_gem_port_net_ctp_cfg *)src_me_cfg;
    bcm_omci_gem_port_net_ctp_cfg *p_dst_me_gem_port_net_ctp_cfg = (bcm_omci_gem_port_net_ctp_cfg *)dst_me_cfg;

    p_dst_me_gem_port_net_ctp_cfg->hdr.presence_mask |= p_src_me_gem_port_net_ctp_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_gem_port_net_ctp_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_PORT_ID)) != 0)
    {
        p_dst_me_gem_port_net_ctp_cfg->data.port_id = p_src_me_gem_port_net_ctp_cfg->data.port_id;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TCONT_PTR)) != 0)
    {
        p_dst_me_gem_port_net_ctp_cfg->data.tcont_ptr = p_src_me_gem_port_net_ctp_cfg->data.tcont_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_DIRECTION)) != 0)
    {
        p_dst_me_gem_port_net_ctp_cfg->data.direction = p_src_me_gem_port_net_ctp_cfg->data.direction;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_MGMT_PTR_US)) != 0)
    {
        p_dst_me_gem_port_net_ctp_cfg->data.traffic_mgmt_ptr_us = p_src_me_gem_port_net_ctp_cfg->data.traffic_mgmt_ptr_us;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_DESC_PROF_PTR_US)) != 0)
    {
        p_dst_me_gem_port_net_ctp_cfg->data.traffic_desc_prof_ptr_us = p_src_me_gem_port_net_ctp_cfg->data.traffic_desc_prof_ptr_us;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_UNI_COUNT)) != 0)
    {
        p_dst_me_gem_port_net_ctp_cfg->data.uni_count = p_src_me_gem_port_net_ctp_cfg->data.uni_count;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_PRI_QUEUE_PTR_DS)) != 0)
    {
        p_dst_me_gem_port_net_ctp_cfg->data.pri_queue_ptr_ds = p_src_me_gem_port_net_ctp_cfg->data.pri_queue_ptr_ds;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_ENCRYPTION_STATE)) != 0)
    {
        p_dst_me_gem_port_net_ctp_cfg->data.encryption_state = p_src_me_gem_port_net_ctp_cfg->data.encryption_state;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_DESC_PROF_PTR_DS)) != 0)
    {
        p_dst_me_gem_port_net_ctp_cfg->data.traffic_desc_prof_ptr_ds = p_src_me_gem_port_net_ctp_cfg->data.traffic_desc_prof_ptr_ds;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_ENCRYPTION_KEY_RING)) != 0)
    {
        p_dst_me_gem_port_net_ctp_cfg->data.encryption_key_ring = p_src_me_gem_port_net_ctp_cfg->data.encryption_key_ring;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_gem_port_net_ctp_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_gem_port_net_ctp_cfg *p_me_gem_port_net_ctp_cfg = (const bcm_omci_gem_port_net_ctp_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_gem_port_net_ctp_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_gem_port_net_ctp_cfg);

    if (BCMOS_TRUE != bcm_omci_gem_port_net_ctp_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_gem_port_net_ctp_cfg_data_bounds_check(&p_me_gem_port_net_ctp_cfg->data, p_me_gem_port_net_ctp_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_gem_port_net_ctp_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_gem_port_net_ctp_cfg_encode(p_me_gem_port_net_ctp_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_gem_port_net_ctp_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_gem_port_net_ctp_cfg *p_me_gem_port_net_ctp_cfg = (bcm_omci_gem_port_net_ctp_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_gem_port_net_ctp_cfg_data_decode(&p_me_gem_port_net_ctp_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_gem_port_net_ctp_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_gem_port_net_ctp_cfg *p_me_gem_port_net_ctp_cfg = (const bcm_omci_gem_port_net_ctp_cfg *)me_hdr;
    const bcm_omci_gem_port_net_ctp_cfg_data *p_me_cfg_data = &p_me_gem_port_net_ctp_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_gem_port_net_ctp_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_gem_port_net_ctp_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_PORT_ID)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tport_id:\t%u\n", p_me_cfg_data->port_id);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TCONT_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttcont_ptr:\t%u\n", p_me_cfg_data->tcont_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_DIRECTION)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdirection:\t%u\n", p_me_cfg_data->direction);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_MGMT_PTR_US)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttraffic_mgmt_ptr_us:\t%u\n", p_me_cfg_data->traffic_mgmt_ptr_us);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_DESC_PROF_PTR_US)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttraffic_desc_prof_ptr_us:\t%u\n", p_me_cfg_data->traffic_desc_prof_ptr_us);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_UNI_COUNT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tuni_count:\t%u\n", p_me_cfg_data->uni_count);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_PRI_QUEUE_PTR_DS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpri_queue_ptr_ds:\t%u\n", p_me_cfg_data->pri_queue_ptr_ds);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_ENCRYPTION_STATE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tencryption_state:\t%u\n", p_me_cfg_data->encryption_state);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_DESC_PROF_PTR_DS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttraffic_desc_prof_ptr_ds:\t%u\n", p_me_cfg_data->traffic_desc_prof_ptr_ds);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_ENCRYPTION_KEY_RING)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tencryption_key_ring:\t%u\n", p_me_cfg_data->encryption_key_ring);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_gem_port_net_ctp_cfg_data_encode(const bcm_omci_gem_port_net_ctp_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_gem_port_net_ctp_cfg_data_encode(const bcm_omci_gem_port_net_ctp_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_PORT_ID)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->port_id))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TCONT_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->tcont_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_DIRECTION)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->direction))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_MGMT_PTR_US)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->traffic_mgmt_ptr_us))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_DESC_PROF_PTR_US)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->traffic_desc_prof_ptr_us))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_UNI_COUNT)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->uni_count))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_PRI_QUEUE_PTR_DS)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->pri_queue_ptr_ds))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_ENCRYPTION_STATE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->encryption_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_DESC_PROF_PTR_DS)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->traffic_desc_prof_ptr_ds))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_ENCRYPTION_KEY_RING)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->encryption_key_ring))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_gem_port_net_ctp_cfg_encode(const bcm_omci_gem_port_net_ctp_cfg *p_me_gem_port_net_ctp_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_gem_port_net_ctp_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_gem_port_net_ctp_cfg_data_encode(&p_me_gem_port_net_ctp_cfg->data, p_bcm_buf, p_me_gem_port_net_ctp_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_gem_port_net_ctp_cfg_data_decode(bcm_omci_gem_port_net_ctp_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_PORT_ID)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->port_id))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TCONT_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->tcont_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_DIRECTION)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->direction))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_MGMT_PTR_US)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->traffic_mgmt_ptr_us))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_DESC_PROF_PTR_US)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->traffic_desc_prof_ptr_us))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_UNI_COUNT)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->uni_count))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_PRI_QUEUE_PTR_DS)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->pri_queue_ptr_ds))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_ENCRYPTION_STATE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->encryption_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_TRAFFIC_DESC_PROF_PTR_DS)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->traffic_desc_prof_ptr_ds))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_CFG_ID_ENCRYPTION_KEY_RING)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->encryption_key_ring))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* IEEE 802.1p mapper service profile */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_ieee_8021_p_mapper_svc_prof_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_ieee_8021_p_mapper_svc_prof_cfg *p_src_me_ieee_8021_p_mapper_svc_prof_cfg = (const bcm_omci_ieee_8021_p_mapper_svc_prof_cfg *)src_me_cfg;
    bcm_omci_ieee_8021_p_mapper_svc_prof_cfg *p_dst_me_ieee_8021_p_mapper_svc_prof_cfg = (bcm_omci_ieee_8021_p_mapper_svc_prof_cfg *)dst_me_cfg;

    p_dst_me_ieee_8021_p_mapper_svc_prof_cfg->hdr.presence_mask |= p_src_me_ieee_8021_p_mapper_svc_prof_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_ieee_8021_p_mapper_svc_prof_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_TP_PTR)) != 0)
    {
        p_dst_me_ieee_8021_p_mapper_svc_prof_cfg->data.tp_ptr = p_src_me_ieee_8021_p_mapper_svc_prof_cfg->data.tp_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_0)) != 0)
    {
        p_dst_me_ieee_8021_p_mapper_svc_prof_cfg->data.interwork_tp_ptr_pri_0 = p_src_me_ieee_8021_p_mapper_svc_prof_cfg->data.interwork_tp_ptr_pri_0;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_1)) != 0)
    {
        p_dst_me_ieee_8021_p_mapper_svc_prof_cfg->data.interwork_tp_ptr_pri_1 = p_src_me_ieee_8021_p_mapper_svc_prof_cfg->data.interwork_tp_ptr_pri_1;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_2)) != 0)
    {
        p_dst_me_ieee_8021_p_mapper_svc_prof_cfg->data.interwork_tp_ptr_pri_2 = p_src_me_ieee_8021_p_mapper_svc_prof_cfg->data.interwork_tp_ptr_pri_2;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_3)) != 0)
    {
        p_dst_me_ieee_8021_p_mapper_svc_prof_cfg->data.interwork_tp_ptr_pri_3 = p_src_me_ieee_8021_p_mapper_svc_prof_cfg->data.interwork_tp_ptr_pri_3;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_4)) != 0)
    {
        p_dst_me_ieee_8021_p_mapper_svc_prof_cfg->data.interwork_tp_ptr_pri_4 = p_src_me_ieee_8021_p_mapper_svc_prof_cfg->data.interwork_tp_ptr_pri_4;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_5)) != 0)
    {
        p_dst_me_ieee_8021_p_mapper_svc_prof_cfg->data.interwork_tp_ptr_pri_5 = p_src_me_ieee_8021_p_mapper_svc_prof_cfg->data.interwork_tp_ptr_pri_5;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_6)) != 0)
    {
        p_dst_me_ieee_8021_p_mapper_svc_prof_cfg->data.interwork_tp_ptr_pri_6 = p_src_me_ieee_8021_p_mapper_svc_prof_cfg->data.interwork_tp_ptr_pri_6;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_7)) != 0)
    {
        p_dst_me_ieee_8021_p_mapper_svc_prof_cfg->data.interwork_tp_ptr_pri_7 = p_src_me_ieee_8021_p_mapper_svc_prof_cfg->data.interwork_tp_ptr_pri_7;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_UNMARKED_FRAME_OPT)) != 0)
    {
        p_dst_me_ieee_8021_p_mapper_svc_prof_cfg->data.unmarked_frame_opt = p_src_me_ieee_8021_p_mapper_svc_prof_cfg->data.unmarked_frame_opt;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_DSCP_TO_PBIT_MAPPING)) != 0)
    {
        memcpy(p_dst_me_ieee_8021_p_mapper_svc_prof_cfg->data.dscp_to_pbit_mapping, p_src_me_ieee_8021_p_mapper_svc_prof_cfg->data.dscp_to_pbit_mapping, 24);
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_DEFAULT_PBIT_ASSUMPTION)) != 0)
    {
        p_dst_me_ieee_8021_p_mapper_svc_prof_cfg->data.default_pbit_assumption = p_src_me_ieee_8021_p_mapper_svc_prof_cfg->data.default_pbit_assumption;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_MAPPER_TP_TYPE)) != 0)
    {
        p_dst_me_ieee_8021_p_mapper_svc_prof_cfg->data.mapper_tp_type = p_src_me_ieee_8021_p_mapper_svc_prof_cfg->data.mapper_tp_type;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_ieee_8021_p_mapper_svc_prof_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_ieee_8021_p_mapper_svc_prof_cfg *p_me_ieee_8021_p_mapper_svc_prof_cfg = (const bcm_omci_ieee_8021_p_mapper_svc_prof_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_ieee_8021_p_mapper_svc_prof_cfg);

    if (BCMOS_TRUE != bcm_omci_ieee_8021_p_mapper_svc_prof_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_data_bounds_check(&p_me_ieee_8021_p_mapper_svc_prof_cfg->data, p_me_ieee_8021_p_mapper_svc_prof_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_ieee_8021_p_mapper_svc_prof_cfg_encode(p_me_ieee_8021_p_mapper_svc_prof_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_ieee_8021_p_mapper_svc_prof_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_ieee_8021_p_mapper_svc_prof_cfg *p_me_ieee_8021_p_mapper_svc_prof_cfg = (bcm_omci_ieee_8021_p_mapper_svc_prof_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_data_decode(&p_me_ieee_8021_p_mapper_svc_prof_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_ieee_8021_p_mapper_svc_prof_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_ieee_8021_p_mapper_svc_prof_cfg *p_me_ieee_8021_p_mapper_svc_prof_cfg = (const bcm_omci_ieee_8021_p_mapper_svc_prof_cfg *)me_hdr;
    const bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_data *p_me_cfg_data = &p_me_ieee_8021_p_mapper_svc_prof_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_ieee_8021_p_mapper_svc_prof_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_ieee_8021_p_mapper_svc_prof_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_TP_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttp_ptr:\t%u\n", p_me_cfg_data->tp_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_0)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tinterwork_tp_ptr_pri_0:\t%u\n", p_me_cfg_data->interwork_tp_ptr_pri_0);
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_1)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tinterwork_tp_ptr_pri_1:\t%u\n", p_me_cfg_data->interwork_tp_ptr_pri_1);
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_2)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tinterwork_tp_ptr_pri_2:\t%u\n", p_me_cfg_data->interwork_tp_ptr_pri_2);
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_3)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tinterwork_tp_ptr_pri_3:\t%u\n", p_me_cfg_data->interwork_tp_ptr_pri_3);
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_4)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tinterwork_tp_ptr_pri_4:\t%u\n", p_me_cfg_data->interwork_tp_ptr_pri_4);
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_5)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tinterwork_tp_ptr_pri_5:\t%u\n", p_me_cfg_data->interwork_tp_ptr_pri_5);
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_6)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tinterwork_tp_ptr_pri_6:\t%u\n", p_me_cfg_data->interwork_tp_ptr_pri_6);
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_7)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tinterwork_tp_ptr_pri_7:\t%u\n", p_me_cfg_data->interwork_tp_ptr_pri_7);
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_UNMARKED_FRAME_OPT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tunmarked_frame_opt:\t%u\n", p_me_cfg_data->unmarked_frame_opt);
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_DSCP_TO_PBIT_MAPPING)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdscp_to_pbit_mapping:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[0], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[1], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[2], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[3], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[4], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[5], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[6], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[7], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[8], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[9], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[10], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[11], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[12], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[13], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[14], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[15], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[16], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[17], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[18], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[19], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[20], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[21], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[22], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[23]);
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_DEFAULT_PBIT_ASSUMPTION)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdefault_pbit_assumption:\t%u\n", p_me_cfg_data->default_pbit_assumption);
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_MAPPER_TP_TYPE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tmapper_tp_type:\t%u\n", p_me_cfg_data->mapper_tp_type);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_data_encode(const bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_data_encode(const bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_TP_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->tp_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_0)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->interwork_tp_ptr_pri_0))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_1)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->interwork_tp_ptr_pri_1))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_2)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->interwork_tp_ptr_pri_2))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_3)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->interwork_tp_ptr_pri_3))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_4)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->interwork_tp_ptr_pri_4))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_5)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->interwork_tp_ptr_pri_5))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_6)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->interwork_tp_ptr_pri_6))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_7)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->interwork_tp_ptr_pri_7))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_UNMARKED_FRAME_OPT)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->unmarked_frame_opt))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_DSCP_TO_PBIT_MAPPING)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->dscp_to_pbit_mapping, 24))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_DEFAULT_PBIT_ASSUMPTION)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->default_pbit_assumption))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_MAPPER_TP_TYPE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->mapper_tp_type))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_ieee_8021_p_mapper_svc_prof_cfg_encode(const bcm_omci_ieee_8021_p_mapper_svc_prof_cfg *p_me_ieee_8021_p_mapper_svc_prof_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_ieee_8021_p_mapper_svc_prof_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_data_encode(&p_me_ieee_8021_p_mapper_svc_prof_cfg->data, p_bcm_buf, p_me_ieee_8021_p_mapper_svc_prof_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_data_decode(bcm_omci_ieee_8021_p_mapper_svc_prof_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_TP_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->tp_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_0)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->interwork_tp_ptr_pri_0))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_1)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->interwork_tp_ptr_pri_1))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_2)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->interwork_tp_ptr_pri_2))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_3)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->interwork_tp_ptr_pri_3))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_4)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->interwork_tp_ptr_pri_4))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_5)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->interwork_tp_ptr_pri_5))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_6)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->interwork_tp_ptr_pri_6))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_INTERWORK_TP_PTR_PRI_7)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->interwork_tp_ptr_pri_7))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_UNMARKED_FRAME_OPT)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->unmarked_frame_opt))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_DSCP_TO_PBIT_MAPPING)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->dscp_to_pbit_mapping, 24))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_DEFAULT_PBIT_ASSUMPTION)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->default_pbit_assumption))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_CFG_ID_MAPPER_TP_TYPE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->mapper_tp_type))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* MAC Bridge Port Configuration Data */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_mac_bridge_port_config_data_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_mac_bridge_port_config_data_cfg *p_src_me_mac_bridge_port_config_data_cfg = (const bcm_omci_mac_bridge_port_config_data_cfg *)src_me_cfg;
    bcm_omci_mac_bridge_port_config_data_cfg *p_dst_me_mac_bridge_port_config_data_cfg = (bcm_omci_mac_bridge_port_config_data_cfg *)dst_me_cfg;

    p_dst_me_mac_bridge_port_config_data_cfg->hdr.presence_mask |= p_src_me_mac_bridge_port_config_data_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_mac_bridge_port_config_data_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_BRIDGE_ID_PTR)) != 0)
    {
        p_dst_me_mac_bridge_port_config_data_cfg->data.bridge_id_ptr = p_src_me_mac_bridge_port_config_data_cfg->data.bridge_id_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_NUM)) != 0)
    {
        p_dst_me_mac_bridge_port_config_data_cfg->data.port_num = p_src_me_mac_bridge_port_config_data_cfg->data.port_num;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_TP_TYPE)) != 0)
    {
        p_dst_me_mac_bridge_port_config_data_cfg->data.tp_type = p_src_me_mac_bridge_port_config_data_cfg->data.tp_type;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_TP_PTR)) != 0)
    {
        p_dst_me_mac_bridge_port_config_data_cfg->data.tp_ptr = p_src_me_mac_bridge_port_config_data_cfg->data.tp_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_PRI)) != 0)
    {
        p_dst_me_mac_bridge_port_config_data_cfg->data.port_pri = p_src_me_mac_bridge_port_config_data_cfg->data.port_pri;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_PATH_COST)) != 0)
    {
        p_dst_me_mac_bridge_port_config_data_cfg->data.port_path_cost = p_src_me_mac_bridge_port_config_data_cfg->data.port_path_cost;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_SPANNING_TREE_IND)) != 0)
    {
        p_dst_me_mac_bridge_port_config_data_cfg->data.port_spanning_tree_ind = p_src_me_mac_bridge_port_config_data_cfg->data.port_spanning_tree_ind;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_DEPRECATED_1)) != 0)
    {
        p_dst_me_mac_bridge_port_config_data_cfg->data.deprecated_1 = p_src_me_mac_bridge_port_config_data_cfg->data.deprecated_1;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_DEPRECATED_2)) != 0)
    {
        p_dst_me_mac_bridge_port_config_data_cfg->data.deprecated_2 = p_src_me_mac_bridge_port_config_data_cfg->data.deprecated_2;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_MAC_ADDR)) != 0)
    {
        memcpy(p_dst_me_mac_bridge_port_config_data_cfg->data.port_mac_addr, p_src_me_mac_bridge_port_config_data_cfg->data.port_mac_addr, 6);
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_OUTBOUND_TD_PTR)) != 0)
    {
        p_dst_me_mac_bridge_port_config_data_cfg->data.outbound_td_ptr = p_src_me_mac_bridge_port_config_data_cfg->data.outbound_td_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_INBOUND_TD_PTR)) != 0)
    {
        p_dst_me_mac_bridge_port_config_data_cfg->data.inbound_td_ptr = p_src_me_mac_bridge_port_config_data_cfg->data.inbound_td_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_MAC_LEARNING_DEPTH)) != 0)
    {
        p_dst_me_mac_bridge_port_config_data_cfg->data.mac_learning_depth = p_src_me_mac_bridge_port_config_data_cfg->data.mac_learning_depth;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_mac_bridge_port_config_data_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_mac_bridge_port_config_data_cfg *p_me_mac_bridge_port_config_data_cfg = (const bcm_omci_mac_bridge_port_config_data_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_mac_bridge_port_config_data_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_mac_bridge_port_config_data_cfg);

    if (BCMOS_TRUE != bcm_omci_mac_bridge_port_config_data_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_mac_bridge_port_config_data_cfg_data_bounds_check(&p_me_mac_bridge_port_config_data_cfg->data, p_me_mac_bridge_port_config_data_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_mac_bridge_port_config_data_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_mac_bridge_port_config_data_cfg_encode(p_me_mac_bridge_port_config_data_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_mac_bridge_port_config_data_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_mac_bridge_port_config_data_cfg *p_me_mac_bridge_port_config_data_cfg = (bcm_omci_mac_bridge_port_config_data_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_mac_bridge_port_config_data_cfg_data_decode(&p_me_mac_bridge_port_config_data_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_mac_bridge_port_config_data_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_mac_bridge_port_config_data_cfg *p_me_mac_bridge_port_config_data_cfg = (const bcm_omci_mac_bridge_port_config_data_cfg *)me_hdr;
    const bcm_omci_mac_bridge_port_config_data_cfg_data *p_me_cfg_data = &p_me_mac_bridge_port_config_data_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_mac_bridge_port_config_data_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_mac_bridge_port_config_data_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_BRIDGE_ID_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tbridge_id_ptr:\t%u\n", p_me_cfg_data->bridge_id_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_NUM)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tport_num:\t%u\n", p_me_cfg_data->port_num);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_TP_TYPE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttp_type:\t%u\n", p_me_cfg_data->tp_type);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_TP_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttp_ptr:\t%u\n", p_me_cfg_data->tp_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_PRI)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tport_pri:\t%u\n", p_me_cfg_data->port_pri);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_PATH_COST)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tport_path_cost:\t%u\n", p_me_cfg_data->port_path_cost);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_SPANNING_TREE_IND)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tport_spanning_tree_ind:\t%u\n", p_me_cfg_data->port_spanning_tree_ind);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_DEPRECATED_1)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdeprecated_1:\t%u\n", p_me_cfg_data->deprecated_1);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_DEPRECATED_2)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdeprecated_2:\t%u\n", p_me_cfg_data->deprecated_2);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_MAC_ADDR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tport_mac_addr:\t%02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->port_mac_addr)[0], ((const uint8_t *)&p_me_cfg_data->port_mac_addr)[1], ((const uint8_t *)&p_me_cfg_data->port_mac_addr)[2], ((const uint8_t *)&p_me_cfg_data->port_mac_addr)[3], ((const uint8_t *)&p_me_cfg_data->port_mac_addr)[4], ((const uint8_t *)&p_me_cfg_data->port_mac_addr)[5]);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_OUTBOUND_TD_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\toutbound_td_ptr:\t%u\n", p_me_cfg_data->outbound_td_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_INBOUND_TD_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tinbound_td_ptr:\t%u\n", p_me_cfg_data->inbound_td_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_MAC_LEARNING_DEPTH)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tmac_learning_depth:\t%u\n", p_me_cfg_data->mac_learning_depth);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_mac_bridge_port_config_data_cfg_data_encode(const bcm_omci_mac_bridge_port_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_mac_bridge_port_config_data_cfg_data_encode(const bcm_omci_mac_bridge_port_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_BRIDGE_ID_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->bridge_id_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_NUM)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->port_num))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_TP_TYPE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->tp_type))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_TP_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->tp_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_PRI)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->port_pri))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_PATH_COST)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->port_path_cost))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_SPANNING_TREE_IND)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->port_spanning_tree_ind))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_DEPRECATED_1)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->deprecated_1))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_DEPRECATED_2)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->deprecated_2))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_MAC_ADDR)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->port_mac_addr, 6))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_OUTBOUND_TD_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->outbound_td_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_INBOUND_TD_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->inbound_td_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_MAC_LEARNING_DEPTH)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->mac_learning_depth))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_mac_bridge_port_config_data_cfg_encode(const bcm_omci_mac_bridge_port_config_data_cfg *p_me_mac_bridge_port_config_data_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_mac_bridge_port_config_data_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_mac_bridge_port_config_data_cfg_data_encode(&p_me_mac_bridge_port_config_data_cfg->data, p_bcm_buf, p_me_mac_bridge_port_config_data_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_mac_bridge_port_config_data_cfg_data_decode(bcm_omci_mac_bridge_port_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_BRIDGE_ID_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->bridge_id_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_NUM)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->port_num))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_TP_TYPE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->tp_type))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_TP_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->tp_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_PRI)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->port_pri))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_PATH_COST)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->port_path_cost))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_SPANNING_TREE_IND)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->port_spanning_tree_ind))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_DEPRECATED_1)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->deprecated_1))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_DEPRECATED_2)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->deprecated_2))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_PORT_MAC_ADDR)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->port_mac_addr, 6))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_OUTBOUND_TD_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->outbound_td_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_INBOUND_TD_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->inbound_td_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_CFG_ID_MAC_LEARNING_DEPTH)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->mac_learning_depth))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* MAC Bridge Service Profile */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_mac_bridge_svc_prof_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_mac_bridge_svc_prof_cfg *p_src_me_mac_bridge_svc_prof_cfg = (const bcm_omci_mac_bridge_svc_prof_cfg *)src_me_cfg;
    bcm_omci_mac_bridge_svc_prof_cfg *p_dst_me_mac_bridge_svc_prof_cfg = (bcm_omci_mac_bridge_svc_prof_cfg *)dst_me_cfg;

    p_dst_me_mac_bridge_svc_prof_cfg->hdr.presence_mask |= p_src_me_mac_bridge_svc_prof_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_mac_bridge_svc_prof_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_SPANNING_TREE_IND)) != 0)
    {
        p_dst_me_mac_bridge_svc_prof_cfg->data.spanning_tree_ind = p_src_me_mac_bridge_svc_prof_cfg->data.spanning_tree_ind;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_LEARNING_IND)) != 0)
    {
        p_dst_me_mac_bridge_svc_prof_cfg->data.learning_ind = p_src_me_mac_bridge_svc_prof_cfg->data.learning_ind;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_PORT_BRIDGING_IND)) != 0)
    {
        p_dst_me_mac_bridge_svc_prof_cfg->data.port_bridging_ind = p_src_me_mac_bridge_svc_prof_cfg->data.port_bridging_ind;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_PRI)) != 0)
    {
        p_dst_me_mac_bridge_svc_prof_cfg->data.pri = p_src_me_mac_bridge_svc_prof_cfg->data.pri;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_MAX_AGE)) != 0)
    {
        p_dst_me_mac_bridge_svc_prof_cfg->data.max_age = p_src_me_mac_bridge_svc_prof_cfg->data.max_age;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_HELLO_TIME)) != 0)
    {
        p_dst_me_mac_bridge_svc_prof_cfg->data.hello_time = p_src_me_mac_bridge_svc_prof_cfg->data.hello_time;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_FORWARD_DELAY)) != 0)
    {
        p_dst_me_mac_bridge_svc_prof_cfg->data.forward_delay = p_src_me_mac_bridge_svc_prof_cfg->data.forward_delay;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_UNKNOWN_MAC_ADDR_DISCARD)) != 0)
    {
        p_dst_me_mac_bridge_svc_prof_cfg->data.unknown_mac_addr_discard = p_src_me_mac_bridge_svc_prof_cfg->data.unknown_mac_addr_discard;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_MAC_LEARNING_DEPTH)) != 0)
    {
        p_dst_me_mac_bridge_svc_prof_cfg->data.mac_learning_depth = p_src_me_mac_bridge_svc_prof_cfg->data.mac_learning_depth;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_DYNAMIC_FILTERING_AGEING_TIME)) != 0)
    {
        p_dst_me_mac_bridge_svc_prof_cfg->data.dynamic_filtering_ageing_time = p_src_me_mac_bridge_svc_prof_cfg->data.dynamic_filtering_ageing_time;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_mac_bridge_svc_prof_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_mac_bridge_svc_prof_cfg *p_me_mac_bridge_svc_prof_cfg = (const bcm_omci_mac_bridge_svc_prof_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_mac_bridge_svc_prof_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_mac_bridge_svc_prof_cfg);

    if (BCMOS_TRUE != bcm_omci_mac_bridge_svc_prof_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_mac_bridge_svc_prof_cfg_data_bounds_check(&p_me_mac_bridge_svc_prof_cfg->data, p_me_mac_bridge_svc_prof_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_mac_bridge_svc_prof_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_mac_bridge_svc_prof_cfg_encode(p_me_mac_bridge_svc_prof_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_mac_bridge_svc_prof_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_mac_bridge_svc_prof_cfg *p_me_mac_bridge_svc_prof_cfg = (bcm_omci_mac_bridge_svc_prof_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_mac_bridge_svc_prof_cfg_data_decode(&p_me_mac_bridge_svc_prof_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_mac_bridge_svc_prof_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_mac_bridge_svc_prof_cfg *p_me_mac_bridge_svc_prof_cfg = (const bcm_omci_mac_bridge_svc_prof_cfg *)me_hdr;
    const bcm_omci_mac_bridge_svc_prof_cfg_data *p_me_cfg_data = &p_me_mac_bridge_svc_prof_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_mac_bridge_svc_prof_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_mac_bridge_svc_prof_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_SPANNING_TREE_IND)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tspanning_tree_ind:\t%u\n", p_me_cfg_data->spanning_tree_ind);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_LEARNING_IND)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tlearning_ind:\t%u\n", p_me_cfg_data->learning_ind);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_PORT_BRIDGING_IND)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tport_bridging_ind:\t%u\n", p_me_cfg_data->port_bridging_ind);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_PRI)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpri:\t%u\n", p_me_cfg_data->pri);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_MAX_AGE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tmax_age:\t%u\n", p_me_cfg_data->max_age);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_HELLO_TIME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\thello_time:\t%u\n", p_me_cfg_data->hello_time);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_FORWARD_DELAY)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tforward_delay:\t%u\n", p_me_cfg_data->forward_delay);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_UNKNOWN_MAC_ADDR_DISCARD)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tunknown_mac_addr_discard:\t%u\n", p_me_cfg_data->unknown_mac_addr_discard);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_MAC_LEARNING_DEPTH)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tmac_learning_depth:\t%u\n", p_me_cfg_data->mac_learning_depth);
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_DYNAMIC_FILTERING_AGEING_TIME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdynamic_filtering_ageing_time:\t%u\n", p_me_cfg_data->dynamic_filtering_ageing_time);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_mac_bridge_svc_prof_cfg_data_encode(const bcm_omci_mac_bridge_svc_prof_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_mac_bridge_svc_prof_cfg_data_encode(const bcm_omci_mac_bridge_svc_prof_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_SPANNING_TREE_IND)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->spanning_tree_ind))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_LEARNING_IND)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->learning_ind))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_PORT_BRIDGING_IND)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->port_bridging_ind))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_PRI)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->pri))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_MAX_AGE)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->max_age))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_HELLO_TIME)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->hello_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_FORWARD_DELAY)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->forward_delay))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_UNKNOWN_MAC_ADDR_DISCARD)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->unknown_mac_addr_discard))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_MAC_LEARNING_DEPTH)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->mac_learning_depth))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_DYNAMIC_FILTERING_AGEING_TIME)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->dynamic_filtering_ageing_time))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_mac_bridge_svc_prof_cfg_encode(const bcm_omci_mac_bridge_svc_prof_cfg *p_me_mac_bridge_svc_prof_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_mac_bridge_svc_prof_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_mac_bridge_svc_prof_cfg_data_encode(&p_me_mac_bridge_svc_prof_cfg->data, p_bcm_buf, p_me_mac_bridge_svc_prof_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_mac_bridge_svc_prof_cfg_data_decode(bcm_omci_mac_bridge_svc_prof_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_SPANNING_TREE_IND)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->spanning_tree_ind))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_LEARNING_IND)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->learning_ind))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_PORT_BRIDGING_IND)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->port_bridging_ind))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_PRI)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->pri))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_MAX_AGE)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->max_age))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_HELLO_TIME)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->hello_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_FORWARD_DELAY)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->forward_delay))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_UNKNOWN_MAC_ADDR_DISCARD)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->unknown_mac_addr_discard))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_MAC_LEARNING_DEPTH)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->mac_learning_depth))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MAC_BRIDGE_SVC_PROF_CFG_ID_DYNAMIC_FILTERING_AGEING_TIME)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->dynamic_filtering_ageing_time))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* VLAN Tagging Filter Data */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_vlan_tag_filter_data_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_vlan_tag_filter_data_cfg *p_src_me_vlan_tag_filter_data_cfg = (const bcm_omci_vlan_tag_filter_data_cfg *)src_me_cfg;
    bcm_omci_vlan_tag_filter_data_cfg *p_dst_me_vlan_tag_filter_data_cfg = (bcm_omci_vlan_tag_filter_data_cfg *)dst_me_cfg;

    p_dst_me_vlan_tag_filter_data_cfg->hdr.presence_mask |= p_src_me_vlan_tag_filter_data_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_vlan_tag_filter_data_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_VLAN_FILTER_LIST)) != 0)
    {
        memcpy(p_dst_me_vlan_tag_filter_data_cfg->data.vlan_filter_list, p_src_me_vlan_tag_filter_data_cfg->data.vlan_filter_list, 24);
    }
    if ((fields_present & (1ULL << BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_FORWARD_OPER)) != 0)
    {
        p_dst_me_vlan_tag_filter_data_cfg->data.forward_oper = p_src_me_vlan_tag_filter_data_cfg->data.forward_oper;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_NUM_OF_ENTRIES)) != 0)
    {
        p_dst_me_vlan_tag_filter_data_cfg->data.num_of_entries = p_src_me_vlan_tag_filter_data_cfg->data.num_of_entries;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_vlan_tag_filter_data_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_vlan_tag_filter_data_cfg *p_me_vlan_tag_filter_data_cfg = (const bcm_omci_vlan_tag_filter_data_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_vlan_tag_filter_data_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_vlan_tag_filter_data_cfg);

    if (BCMOS_TRUE != bcm_omci_vlan_tag_filter_data_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_vlan_tag_filter_data_cfg_data_bounds_check(&p_me_vlan_tag_filter_data_cfg->data, p_me_vlan_tag_filter_data_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_vlan_tag_filter_data_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_vlan_tag_filter_data_cfg_encode(p_me_vlan_tag_filter_data_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_vlan_tag_filter_data_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_vlan_tag_filter_data_cfg *p_me_vlan_tag_filter_data_cfg = (bcm_omci_vlan_tag_filter_data_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_vlan_tag_filter_data_cfg_data_decode(&p_me_vlan_tag_filter_data_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_vlan_tag_filter_data_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_vlan_tag_filter_data_cfg *p_me_vlan_tag_filter_data_cfg = (const bcm_omci_vlan_tag_filter_data_cfg *)me_hdr;
    const bcm_omci_vlan_tag_filter_data_cfg_data *p_me_cfg_data = &p_me_vlan_tag_filter_data_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_vlan_tag_filter_data_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_vlan_tag_filter_data_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_VLAN_FILTER_LIST)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tvlan_filter_list:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[0], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[1], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[2], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[3], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[4], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[5], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[6], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[7], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[8], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[9], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[10], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[11], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[12], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[13], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[14], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[15], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[16], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[17], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[18], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[19], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[20], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[21], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[22], ((const uint8_t *)&p_me_cfg_data->vlan_filter_list)[23]);
    if ((fields_present & (1ULL << BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_FORWARD_OPER)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tforward_oper:\t%u\n", p_me_cfg_data->forward_oper);
    if ((fields_present & (1ULL << BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_NUM_OF_ENTRIES)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tnum_of_entries:\t%u\n", p_me_cfg_data->num_of_entries);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_vlan_tag_filter_data_cfg_data_encode(const bcm_omci_vlan_tag_filter_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_vlan_tag_filter_data_cfg_data_encode(const bcm_omci_vlan_tag_filter_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_VLAN_FILTER_LIST)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->vlan_filter_list, 24))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_FORWARD_OPER)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->forward_oper))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_NUM_OF_ENTRIES)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->num_of_entries))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_vlan_tag_filter_data_cfg_encode(const bcm_omci_vlan_tag_filter_data_cfg *p_me_vlan_tag_filter_data_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_vlan_tag_filter_data_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_vlan_tag_filter_data_cfg_data_encode(&p_me_vlan_tag_filter_data_cfg->data, p_bcm_buf, p_me_vlan_tag_filter_data_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_vlan_tag_filter_data_cfg_data_decode(bcm_omci_vlan_tag_filter_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_VLAN_FILTER_LIST)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->vlan_filter_list, 24))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_FORWARD_OPER)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->forward_oper))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VLAN_TAG_FILTER_DATA_CFG_ID_NUM_OF_ENTRIES)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->num_of_entries))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* T-CONT */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_tcont_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_tcont_cfg *p_src_me_tcont_cfg = (const bcm_omci_tcont_cfg *)src_me_cfg;
    bcm_omci_tcont_cfg *p_dst_me_tcont_cfg = (bcm_omci_tcont_cfg *)dst_me_cfg;

    p_dst_me_tcont_cfg->hdr.presence_mask |= p_src_me_tcont_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_tcont_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_TCONT_CFG_ID_ALLOC_ID)) != 0)
    {
        p_dst_me_tcont_cfg->data.alloc_id = p_src_me_tcont_cfg->data.alloc_id;
    }
    if ((fields_present & (1ULL << BCM_OMCI_TCONT_CFG_ID_DEPRECATED)) != 0)
    {
        p_dst_me_tcont_cfg->data.deprecated = p_src_me_tcont_cfg->data.deprecated;
    }
    if ((fields_present & (1ULL << BCM_OMCI_TCONT_CFG_ID_POLICY)) != 0)
    {
        p_dst_me_tcont_cfg->data.policy = p_src_me_tcont_cfg->data.policy;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_tcont_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_tcont_cfg *p_me_tcont_cfg = (const bcm_omci_tcont_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_tcont_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_TCONT_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_tcont_cfg);

    if (BCMOS_TRUE != bcm_omci_tcont_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_tcont_cfg_data_bounds_check(&p_me_tcont_cfg->data, p_me_tcont_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_tcont_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_tcont_cfg_encode(p_me_tcont_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_tcont_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_tcont_cfg *p_me_tcont_cfg = (bcm_omci_tcont_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_tcont_cfg_data_decode(&p_me_tcont_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_tcont_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_tcont_cfg *p_me_tcont_cfg = (const bcm_omci_tcont_cfg *)me_hdr;
    const bcm_omci_tcont_cfg_data *p_me_cfg_data = &p_me_tcont_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_tcont_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_tcont_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_TCONT_CFG_ID_ALLOC_ID)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\talloc_id:\t%u\n", p_me_cfg_data->alloc_id);
    if ((fields_present & (1ULL << BCM_OMCI_TCONT_CFG_ID_DEPRECATED)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdeprecated:\t%u\n", p_me_cfg_data->deprecated);
    if ((fields_present & (1ULL << BCM_OMCI_TCONT_CFG_ID_POLICY)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpolicy:\t%u\n", p_me_cfg_data->policy);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_tcont_cfg_data_encode(const bcm_omci_tcont_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_tcont_cfg_data_encode(const bcm_omci_tcont_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_TCONT_CFG_ID_ALLOC_ID)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->alloc_id))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_TCONT_CFG_ID_DEPRECATED)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->deprecated))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_TCONT_CFG_ID_POLICY)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->policy))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_tcont_cfg_encode(const bcm_omci_tcont_cfg *p_me_tcont_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_tcont_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_tcont_cfg_data_encode(&p_me_tcont_cfg->data, p_bcm_buf, p_me_tcont_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_tcont_cfg_data_decode(bcm_omci_tcont_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_TCONT_CFG_ID_ALLOC_ID)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->alloc_id))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_TCONT_CFG_ID_DEPRECATED)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->deprecated))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_TCONT_CFG_ID_POLICY)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->policy))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* Extended VLAN Tagging Operation Configuration Data */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_ext_vlan_tag_oper_config_data_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_ext_vlan_tag_oper_config_data_cfg *p_src_me_ext_vlan_tag_oper_config_data_cfg = (const bcm_omci_ext_vlan_tag_oper_config_data_cfg *)src_me_cfg;
    bcm_omci_ext_vlan_tag_oper_config_data_cfg *p_dst_me_ext_vlan_tag_oper_config_data_cfg = (bcm_omci_ext_vlan_tag_oper_config_data_cfg *)dst_me_cfg;

    p_dst_me_ext_vlan_tag_oper_config_data_cfg->hdr.presence_mask |= p_src_me_ext_vlan_tag_oper_config_data_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_ext_vlan_tag_oper_config_data_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_ASSOC_TYPE)) != 0)
    {
        p_dst_me_ext_vlan_tag_oper_config_data_cfg->data.assoc_type = p_src_me_ext_vlan_tag_oper_config_data_cfg->data.assoc_type;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_RX_FRAME_VLAN_TAG_OPER_TABLE_MAX_SIZE)) != 0)
    {
        p_dst_me_ext_vlan_tag_oper_config_data_cfg->data.rx_frame_vlan_tag_oper_table_max_size = p_src_me_ext_vlan_tag_oper_config_data_cfg->data.rx_frame_vlan_tag_oper_table_max_size;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_INPUT_TPID)) != 0)
    {
        p_dst_me_ext_vlan_tag_oper_config_data_cfg->data.input_tpid = p_src_me_ext_vlan_tag_oper_config_data_cfg->data.input_tpid;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_OUTPUT_TPID)) != 0)
    {
        p_dst_me_ext_vlan_tag_oper_config_data_cfg->data.output_tpid = p_src_me_ext_vlan_tag_oper_config_data_cfg->data.output_tpid;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_DS_MODE)) != 0)
    {
        p_dst_me_ext_vlan_tag_oper_config_data_cfg->data.ds_mode = p_src_me_ext_vlan_tag_oper_config_data_cfg->data.ds_mode;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_RX_FRAME_VLAN_TAG_OPER_TABLE)) != 0)
    {
        /* doing struct copy */
        p_dst_me_ext_vlan_tag_oper_config_data_cfg->data.rx_frame_vlan_tag_oper_table = p_src_me_ext_vlan_tag_oper_config_data_cfg->data.rx_frame_vlan_tag_oper_table;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_ASSOC_ME_PTR)) != 0)
    {
        p_dst_me_ext_vlan_tag_oper_config_data_cfg->data.assoc_me_ptr = p_src_me_ext_vlan_tag_oper_config_data_cfg->data.assoc_me_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_DSCP_TO_PBIT_MAPPING)) != 0)
    {
        memcpy(p_dst_me_ext_vlan_tag_oper_config_data_cfg->data.dscp_to_pbit_mapping, p_src_me_ext_vlan_tag_oper_config_data_cfg->data.dscp_to_pbit_mapping, 24);
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_ext_vlan_tag_oper_config_data_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_ext_vlan_tag_oper_config_data_cfg *p_me_ext_vlan_tag_oper_config_data_cfg = (const bcm_omci_ext_vlan_tag_oper_config_data_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_ext_vlan_tag_oper_config_data_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_ext_vlan_tag_oper_config_data_cfg);

    if (BCMOS_TRUE != bcm_omci_ext_vlan_tag_oper_config_data_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_ext_vlan_tag_oper_config_data_cfg_data_bounds_check(&p_me_ext_vlan_tag_oper_config_data_cfg->data, p_me_ext_vlan_tag_oper_config_data_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_ext_vlan_tag_oper_config_data_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_ext_vlan_tag_oper_config_data_cfg_encode(p_me_ext_vlan_tag_oper_config_data_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_ext_vlan_tag_oper_config_data_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_ext_vlan_tag_oper_config_data_cfg *p_me_ext_vlan_tag_oper_config_data_cfg = (bcm_omci_ext_vlan_tag_oper_config_data_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_ext_vlan_tag_oper_config_data_cfg_data_decode(&p_me_ext_vlan_tag_oper_config_data_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */
static bcmos_bool bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table_log(const bcm_omci_me_key *key, const bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table *this, dev_log_id log_id, bcm_dev_log_level log_level)
{
    BCM_LOG_LEVEL(log_level, log_id, "\t\tfilter_outer_priority: %u\n", this->outer_filter_word.filter_outer_priority);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tfilter_outer_vid: %u\n", this->outer_filter_word.filter_outer_vid);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tfilter_outer_tpid: %u\n", this->outer_filter_word.filter_outer_tpid);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tfilter_inner_priority: %u\n", this->inner_filter_word.filter_inner_priority);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tfilter_inner_vid: %u\n", this->inner_filter_word.filter_inner_vid);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tfilter_inner_tpid: %u\n", this->inner_filter_word.filter_inner_tpid);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tfilter_ether_type: %u\n", this->inner_filter_word.filter_ether_type);
    BCM_LOG_LEVEL(log_level, log_id, "\t\ttreatment: %u\n", this->outer_treatment_word.treatment);
    BCM_LOG_LEVEL(log_level, log_id, "\t\ttreatment_outer_priority: %u\n", this->outer_treatment_word.treatment_outer_priority);
    BCM_LOG_LEVEL(log_level, log_id, "\t\ttreatment_outer_vid: %u\n", this->outer_treatment_word.treatment_outer_vid);
    BCM_LOG_LEVEL(log_level, log_id, "\t\ttreatment_outer_tpid: %u\n", this->outer_treatment_word.treatment_outer_tpid);
    BCM_LOG_LEVEL(log_level, log_id, "\t\ttreatment_inner_priority: %u\n", this->inner_treatment_word.treatment_inner_priority);
    BCM_LOG_LEVEL(log_level, log_id, "\t\ttreatment_inner_vid: %u\n", this->inner_treatment_word.treatment_inner_vid);
    BCM_LOG_LEVEL(log_level, log_id, "\t\ttreatment_inner_tpid: %u\n", this->inner_treatment_word.treatment_inner_tpid);

    return BCM_ERR_OK;
}

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_ext_vlan_tag_oper_config_data_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_ext_vlan_tag_oper_config_data_cfg *p_me_ext_vlan_tag_oper_config_data_cfg = (const bcm_omci_ext_vlan_tag_oper_config_data_cfg *)me_hdr;
    const bcm_omci_ext_vlan_tag_oper_config_data_cfg_data *p_me_cfg_data = &p_me_ext_vlan_tag_oper_config_data_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_ext_vlan_tag_oper_config_data_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_ext_vlan_tag_oper_config_data_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_ASSOC_TYPE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tassoc_type:\t%u\n", p_me_cfg_data->assoc_type);
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_RX_FRAME_VLAN_TAG_OPER_TABLE_MAX_SIZE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\trx_frame_vlan_tag_oper_table_max_size:\t%u\n", p_me_cfg_data->rx_frame_vlan_tag_oper_table_max_size);
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_INPUT_TPID)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tinput_tpid:\t0x%x\n", p_me_cfg_data->input_tpid);
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_OUTPUT_TPID)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\toutput_tpid:\t0x%x\n", p_me_cfg_data->output_tpid);
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_DS_MODE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tds_mode:\t%u\n", p_me_cfg_data->ds_mode);
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_RX_FRAME_VLAN_TAG_OPER_TABLE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\trx_frame_vlan_tag_oper_table:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->rx_frame_vlan_tag_oper_table)[0], ((const uint8_t *)&p_me_cfg_data->rx_frame_vlan_tag_oper_table)[1], ((const uint8_t *)&p_me_cfg_data->rx_frame_vlan_tag_oper_table)[2], ((const uint8_t *)&p_me_cfg_data->rx_frame_vlan_tag_oper_table)[3], ((const uint8_t *)&p_me_cfg_data->rx_frame_vlan_tag_oper_table)[4], ((const uint8_t *)&p_me_cfg_data->rx_frame_vlan_tag_oper_table)[5], ((const uint8_t *)&p_me_cfg_data->rx_frame_vlan_tag_oper_table)[6], ((const uint8_t *)&p_me_cfg_data->rx_frame_vlan_tag_oper_table)[7], ((const uint8_t *)&p_me_cfg_data->rx_frame_vlan_tag_oper_table)[8], ((const uint8_t *)&p_me_cfg_data->rx_frame_vlan_tag_oper_table)[9], ((const uint8_t *)&p_me_cfg_data->rx_frame_vlan_tag_oper_table)[10], ((const uint8_t *)&p_me_cfg_data->rx_frame_vlan_tag_oper_table)[11], ((const uint8_t *)&p_me_cfg_data->rx_frame_vlan_tag_oper_table)[12], ((const uint8_t *)&p_me_cfg_data->rx_frame_vlan_tag_oper_table)[13], ((const uint8_t *)&p_me_cfg_data->rx_frame_vlan_tag_oper_table)[14], ((const uint8_t *)&p_me_cfg_data->rx_frame_vlan_tag_oper_table)[15]);
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_ASSOC_ME_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tassoc_me_ptr:\t%u\n", p_me_cfg_data->assoc_me_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_DSCP_TO_PBIT_MAPPING)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdscp_to_pbit_mapping:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[0], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[1], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[2], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[3], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[4], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[5], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[6], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[7], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[8], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[9], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[10], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[11], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[12], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[13], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[14], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[15], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[16], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[17], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[18], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[19], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[20], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[21], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[22], ((const uint8_t *)&p_me_cfg_data->dscp_to_pbit_mapping)[23]);

    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_RX_FRAME_VLAN_TAG_OPER_TABLE)) != 0)
        bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table_log(&me_hdr->key, &p_me_cfg_data->rx_frame_vlan_tag_oper_table, log_id, log_level);

    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */
static bcmos_bool bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table_cfg_data_encode(bcm_omci_buf *p_bcm_buf, const bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table *this)
{
    if (!bcm_omci_buf_write_u32(p_bcm_buf, *((const uint32_t *)&this->outer_filter_word)))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u32(p_bcm_buf, *((const uint32_t *)&this->inner_filter_word)))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u32(p_bcm_buf, *((const uint32_t *)&this->outer_treatment_word)))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u32(p_bcm_buf, *((const uint32_t *)&this->inner_treatment_word)))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

static bcmos_bool bcm_omci_ext_vlan_tag_oper_config_data_cfg_data_encode(const bcm_omci_ext_vlan_tag_oper_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_ext_vlan_tag_oper_config_data_cfg_data_encode(const bcm_omci_ext_vlan_tag_oper_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_ASSOC_TYPE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->assoc_type))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_RX_FRAME_VLAN_TAG_OPER_TABLE_MAX_SIZE)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->rx_frame_vlan_tag_oper_table_max_size))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_INPUT_TPID)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->input_tpid))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_OUTPUT_TPID)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->output_tpid))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_DS_MODE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->ds_mode))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_RX_FRAME_VLAN_TAG_OPER_TABLE)) != 0)
    {
        if (!bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table_cfg_data_encode(p_bcm_buf, &p_me_cfg_data->rx_frame_vlan_tag_oper_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_ASSOC_ME_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->assoc_me_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_DSCP_TO_PBIT_MAPPING)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->dscp_to_pbit_mapping, 24))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_ext_vlan_tag_oper_config_data_cfg_encode(const bcm_omci_ext_vlan_tag_oper_config_data_cfg *p_me_ext_vlan_tag_oper_config_data_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_ext_vlan_tag_oper_config_data_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_ext_vlan_tag_oper_config_data_cfg_data_encode(&p_me_ext_vlan_tag_oper_config_data_cfg->data, p_bcm_buf, p_me_ext_vlan_tag_oper_config_data_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */
static bcmos_bool bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table_cfg_data_decode(bcm_omci_buf *p_bcm_buf, bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table *this)
{
     if (!bcm_omci_buf_read_u32(p_bcm_buf, (uint32_t *)&this->outer_filter_word))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u32(p_bcm_buf, (uint32_t *)&this->inner_filter_word))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u32(p_bcm_buf, (uint32_t *)&this->outer_treatment_word))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u32(p_bcm_buf, (uint32_t *)&this->inner_treatment_word))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_ext_vlan_tag_oper_config_data_cfg_data_decode(bcm_omci_ext_vlan_tag_oper_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_ASSOC_TYPE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->assoc_type))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_RX_FRAME_VLAN_TAG_OPER_TABLE_MAX_SIZE)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->rx_frame_vlan_tag_oper_table_max_size))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_INPUT_TPID)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->input_tpid))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_OUTPUT_TPID)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->output_tpid))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_DS_MODE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->ds_mode))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_RX_FRAME_VLAN_TAG_OPER_TABLE)) != 0)
    {
        if (!bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table_cfg_data_decode(p_bcm_buf, &p_me_cfg_data->rx_frame_vlan_tag_oper_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_ASSOC_ME_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->assoc_me_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_CFG_ID_DSCP_TO_PBIT_MAPPING)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->dscp_to_pbit_mapping, 24))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* priority queue-G */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_priority_queue_g_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_priority_queue_g_cfg *p_src_me_priority_queue_g_cfg = (const bcm_omci_priority_queue_g_cfg *)src_me_cfg;
    bcm_omci_priority_queue_g_cfg *p_dst_me_priority_queue_g_cfg = (bcm_omci_priority_queue_g_cfg *)dst_me_cfg;

    p_dst_me_priority_queue_g_cfg->hdr.presence_mask |= p_src_me_priority_queue_g_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_priority_queue_g_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_QUEUE_CONFIG_OPT)) != 0)
    {
        p_dst_me_priority_queue_g_cfg->data.queue_config_opt = p_src_me_priority_queue_g_cfg->data.queue_config_opt;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_MAX_QUEUE_SIZE)) != 0)
    {
        p_dst_me_priority_queue_g_cfg->data.max_queue_size = p_src_me_priority_queue_g_cfg->data.max_queue_size;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_ALLOCATED_QUEUE_SIZE)) != 0)
    {
        p_dst_me_priority_queue_g_cfg->data.allocated_queue_size = p_src_me_priority_queue_g_cfg->data.allocated_queue_size;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DISCARD_COUNTER_RESET_INTERVAL)) != 0)
    {
        p_dst_me_priority_queue_g_cfg->data.discard_counter_reset_interval = p_src_me_priority_queue_g_cfg->data.discard_counter_reset_interval;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DISCARD_THRESHOLD)) != 0)
    {
        p_dst_me_priority_queue_g_cfg->data.discard_threshold = p_src_me_priority_queue_g_cfg->data.discard_threshold;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_RELATED_PORT)) != 0)
    {
        memcpy(p_dst_me_priority_queue_g_cfg->data.related_port, p_src_me_priority_queue_g_cfg->data.related_port, 4);
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_TRAFFIC_SCHEDULER_PTR)) != 0)
    {
        p_dst_me_priority_queue_g_cfg->data.traffic_scheduler_ptr = p_src_me_priority_queue_g_cfg->data.traffic_scheduler_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_WEIGHT)) != 0)
    {
        p_dst_me_priority_queue_g_cfg->data.weight = p_src_me_priority_queue_g_cfg->data.weight;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_OPER)) != 0)
    {
        p_dst_me_priority_queue_g_cfg->data.back_pressure_oper = p_src_me_priority_queue_g_cfg->data.back_pressure_oper;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_TIME)) != 0)
    {
        p_dst_me_priority_queue_g_cfg->data.back_pressure_time = p_src_me_priority_queue_g_cfg->data.back_pressure_time;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_OCCUR_QUEUE_THR)) != 0)
    {
        p_dst_me_priority_queue_g_cfg->data.back_pressure_occur_queue_thr = p_src_me_priority_queue_g_cfg->data.back_pressure_occur_queue_thr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_CLEAR_QUEUE_THR)) != 0)
    {
        p_dst_me_priority_queue_g_cfg->data.back_pressure_clear_queue_thr = p_src_me_priority_queue_g_cfg->data.back_pressure_clear_queue_thr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_PACKET_DROP_QUEUE_THR)) != 0)
    {
        memcpy(p_dst_me_priority_queue_g_cfg->data.packet_drop_queue_thr, p_src_me_priority_queue_g_cfg->data.packet_drop_queue_thr, 8);
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_PACKET_DROP_MAX_P)) != 0)
    {
        p_dst_me_priority_queue_g_cfg->data.packet_drop_max_p = p_src_me_priority_queue_g_cfg->data.packet_drop_max_p;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_QUEUE_DROP_W_Q)) != 0)
    {
        p_dst_me_priority_queue_g_cfg->data.queue_drop_w_q = p_src_me_priority_queue_g_cfg->data.queue_drop_w_q;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DROP_PRECEDENCE_COLOUR_MARKING)) != 0)
    {
        p_dst_me_priority_queue_g_cfg->data.drop_precedence_colour_marking = p_src_me_priority_queue_g_cfg->data.drop_precedence_colour_marking;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_priority_queue_g_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_priority_queue_g_cfg *p_me_priority_queue_g_cfg = (const bcm_omci_priority_queue_g_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_priority_queue_g_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_priority_queue_g_cfg);

    if (BCMOS_TRUE != bcm_omci_priority_queue_g_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_priority_queue_g_cfg_data_bounds_check(&p_me_priority_queue_g_cfg->data, p_me_priority_queue_g_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_priority_queue_g_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_priority_queue_g_cfg_encode(p_me_priority_queue_g_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_priority_queue_g_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_priority_queue_g_cfg *p_me_priority_queue_g_cfg = (bcm_omci_priority_queue_g_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_priority_queue_g_cfg_data_decode(&p_me_priority_queue_g_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_priority_queue_g_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_priority_queue_g_cfg *p_me_priority_queue_g_cfg = (const bcm_omci_priority_queue_g_cfg *)me_hdr;
    const bcm_omci_priority_queue_g_cfg_data *p_me_cfg_data = &p_me_priority_queue_g_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_priority_queue_g_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_priority_queue_g_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_QUEUE_CONFIG_OPT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tqueue_config_opt:\t%u\n", p_me_cfg_data->queue_config_opt);
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_MAX_QUEUE_SIZE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tmax_queue_size:\t%u\n", p_me_cfg_data->max_queue_size);
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_ALLOCATED_QUEUE_SIZE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tallocated_queue_size:\t%u\n", p_me_cfg_data->allocated_queue_size);
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DISCARD_COUNTER_RESET_INTERVAL)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdiscard_counter_reset_interval:\t%u\n", p_me_cfg_data->discard_counter_reset_interval);
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DISCARD_THRESHOLD)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdiscard_threshold:\t%u\n", p_me_cfg_data->discard_threshold);
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_RELATED_PORT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\trelated_port:\t%02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->related_port)[0], ((const uint8_t *)&p_me_cfg_data->related_port)[1], ((const uint8_t *)&p_me_cfg_data->related_port)[2], ((const uint8_t *)&p_me_cfg_data->related_port)[3]);
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_TRAFFIC_SCHEDULER_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttraffic_scheduler_ptr:\t%u\n", p_me_cfg_data->traffic_scheduler_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_WEIGHT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tweight:\t%u\n", p_me_cfg_data->weight);
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_OPER)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tback_pressure_oper:\t%u\n", p_me_cfg_data->back_pressure_oper);
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_TIME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tback_pressure_time:\t%u\n", p_me_cfg_data->back_pressure_time);
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_OCCUR_QUEUE_THR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tback_pressure_occur_queue_thr:\t%u\n", p_me_cfg_data->back_pressure_occur_queue_thr);
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_CLEAR_QUEUE_THR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tback_pressure_clear_queue_thr:\t%u\n", p_me_cfg_data->back_pressure_clear_queue_thr);
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_PACKET_DROP_QUEUE_THR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpacket_drop_queue_thr:\t%02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->packet_drop_queue_thr)[0], ((const uint8_t *)&p_me_cfg_data->packet_drop_queue_thr)[1], ((const uint8_t *)&p_me_cfg_data->packet_drop_queue_thr)[2], ((const uint8_t *)&p_me_cfg_data->packet_drop_queue_thr)[3], ((const uint8_t *)&p_me_cfg_data->packet_drop_queue_thr)[4], ((const uint8_t *)&p_me_cfg_data->packet_drop_queue_thr)[5], ((const uint8_t *)&p_me_cfg_data->packet_drop_queue_thr)[6], ((const uint8_t *)&p_me_cfg_data->packet_drop_queue_thr)[7]);
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_PACKET_DROP_MAX_P)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpacket_drop_max_p:\t%u\n", p_me_cfg_data->packet_drop_max_p);
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_QUEUE_DROP_W_Q)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tqueue_drop_w_q:\t%u\n", p_me_cfg_data->queue_drop_w_q);
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DROP_PRECEDENCE_COLOUR_MARKING)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdrop_precedence_colour_marking:\t%u\n", p_me_cfg_data->drop_precedence_colour_marking);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_priority_queue_g_cfg_data_encode(const bcm_omci_priority_queue_g_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_priority_queue_g_cfg_data_encode(const bcm_omci_priority_queue_g_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_QUEUE_CONFIG_OPT)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->queue_config_opt))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_MAX_QUEUE_SIZE)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->max_queue_size))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_ALLOCATED_QUEUE_SIZE)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->allocated_queue_size))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DISCARD_COUNTER_RESET_INTERVAL)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->discard_counter_reset_interval))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DISCARD_THRESHOLD)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->discard_threshold))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_RELATED_PORT)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->related_port, 4))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_TRAFFIC_SCHEDULER_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->traffic_scheduler_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_WEIGHT)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->weight))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_OPER)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->back_pressure_oper))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_TIME)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->back_pressure_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_OCCUR_QUEUE_THR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->back_pressure_occur_queue_thr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_CLEAR_QUEUE_THR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->back_pressure_clear_queue_thr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_PACKET_DROP_QUEUE_THR)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->packet_drop_queue_thr, 8))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_PACKET_DROP_MAX_P)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->packet_drop_max_p))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_QUEUE_DROP_W_Q)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->queue_drop_w_q))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DROP_PRECEDENCE_COLOUR_MARKING)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->drop_precedence_colour_marking))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_priority_queue_g_cfg_encode(const bcm_omci_priority_queue_g_cfg *p_me_priority_queue_g_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_priority_queue_g_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_priority_queue_g_cfg_data_encode(&p_me_priority_queue_g_cfg->data, p_bcm_buf, p_me_priority_queue_g_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_priority_queue_g_cfg_data_decode(bcm_omci_priority_queue_g_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_QUEUE_CONFIG_OPT)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->queue_config_opt))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_MAX_QUEUE_SIZE)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->max_queue_size))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_ALLOCATED_QUEUE_SIZE)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->allocated_queue_size))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DISCARD_COUNTER_RESET_INTERVAL)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->discard_counter_reset_interval))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DISCARD_THRESHOLD)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->discard_threshold))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_RELATED_PORT)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->related_port, 4))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_TRAFFIC_SCHEDULER_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->traffic_scheduler_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_WEIGHT)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->weight))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_OPER)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->back_pressure_oper))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_TIME)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->back_pressure_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_OCCUR_QUEUE_THR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->back_pressure_occur_queue_thr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_BACK_PRESSURE_CLEAR_QUEUE_THR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->back_pressure_clear_queue_thr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_PACKET_DROP_QUEUE_THR)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->packet_drop_queue_thr, 8))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_PACKET_DROP_MAX_P)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->packet_drop_max_p))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_QUEUE_DROP_W_Q)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->queue_drop_w_q))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PRIORITY_QUEUE_G_CFG_ID_DROP_PRECEDENCE_COLOUR_MARKING)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->drop_precedence_colour_marking))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* Multicast GEM interworking termination point */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_mcast_gem_iw_tp_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_mcast_gem_iw_tp_cfg *p_src_me_mcast_gem_iw_tp_cfg = (const bcm_omci_mcast_gem_iw_tp_cfg *)src_me_cfg;
    bcm_omci_mcast_gem_iw_tp_cfg *p_dst_me_mcast_gem_iw_tp_cfg = (bcm_omci_mcast_gem_iw_tp_cfg *)dst_me_cfg;

    p_dst_me_mcast_gem_iw_tp_cfg->hdr.presence_mask |= p_src_me_mcast_gem_iw_tp_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_mcast_gem_iw_tp_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_GEM_PORT_NET_CTP_CONN_PTR)) != 0)
    {
        p_dst_me_mcast_gem_iw_tp_cfg->data.gem_port_net_ctp_conn_ptr = p_src_me_mcast_gem_iw_tp_cfg->data.gem_port_net_ctp_conn_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IW_OPT)) != 0)
    {
        p_dst_me_mcast_gem_iw_tp_cfg->data.iw_opt = p_src_me_mcast_gem_iw_tp_cfg->data.iw_opt;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_SVC_PROF_PTR)) != 0)
    {
        p_dst_me_mcast_gem_iw_tp_cfg->data.svc_prof_ptr = p_src_me_mcast_gem_iw_tp_cfg->data.svc_prof_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_NOT_USED_1)) != 0)
    {
        p_dst_me_mcast_gem_iw_tp_cfg->data.not_used_1 = p_src_me_mcast_gem_iw_tp_cfg->data.not_used_1;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_PPTP_COUNTER)) != 0)
    {
        p_dst_me_mcast_gem_iw_tp_cfg->data.pptp_counter = p_src_me_mcast_gem_iw_tp_cfg->data.pptp_counter;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_OPER_STATE)) != 0)
    {
        p_dst_me_mcast_gem_iw_tp_cfg->data.oper_state = p_src_me_mcast_gem_iw_tp_cfg->data.oper_state;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_GAL_PROF_PTR)) != 0)
    {
        p_dst_me_mcast_gem_iw_tp_cfg->data.gal_prof_ptr = p_src_me_mcast_gem_iw_tp_cfg->data.gal_prof_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_NOT_USED_2)) != 0)
    {
        p_dst_me_mcast_gem_iw_tp_cfg->data.not_used_2 = p_src_me_mcast_gem_iw_tp_cfg->data.not_used_2;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IPV_4_MCAST_ADDR_TABLE)) != 0)
    {
        /* doing struct copy */
        p_dst_me_mcast_gem_iw_tp_cfg->data.ipv_4_mcast_addr_table = p_src_me_mcast_gem_iw_tp_cfg->data.ipv_4_mcast_addr_table;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IPV_6_MCAST_ADDR_TABLE)) != 0)
    {
        /* doing struct copy */
        p_dst_me_mcast_gem_iw_tp_cfg->data.ipv_6_mcast_addr_table = p_src_me_mcast_gem_iw_tp_cfg->data.ipv_6_mcast_addr_table;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_mcast_gem_iw_tp_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_mcast_gem_iw_tp_cfg *p_me_mcast_gem_iw_tp_cfg = (const bcm_omci_mcast_gem_iw_tp_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_mcast_gem_iw_tp_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_mcast_gem_iw_tp_cfg);

    if (BCMOS_TRUE != bcm_omci_mcast_gem_iw_tp_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_mcast_gem_iw_tp_cfg_data_bounds_check(&p_me_mcast_gem_iw_tp_cfg->data, p_me_mcast_gem_iw_tp_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_mcast_gem_iw_tp_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_mcast_gem_iw_tp_cfg_encode(p_me_mcast_gem_iw_tp_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_mcast_gem_iw_tp_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_mcast_gem_iw_tp_cfg *p_me_mcast_gem_iw_tp_cfg = (bcm_omci_mcast_gem_iw_tp_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_mcast_gem_iw_tp_cfg_data_decode(&p_me_mcast_gem_iw_tp_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */
static bcmos_bool bcm_omci_mcast_gem_iw_tp_ipv_4_mcast_addr_table_log(const bcm_omci_me_key *key, const bcm_omci_mcast_gem_iw_tp_ipv_4_mcast_addr_table *this, dev_log_id log_id, bcm_dev_log_level log_level)
{
    BCM_LOG_LEVEL(log_level, log_id, "\t\tgem_port_id: %u\n", this->gem_port_id);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tsecondary_key: %u\n", this->secondary_key);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tmcast_addr_range_start: 0x%x\n", this->mcast_addr_range_start);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tmcast_addr_range_stop: 0x%x\n", this->mcast_addr_range_stop);

    return BCM_ERR_OK;
}
static bcmos_bool bcm_omci_mcast_gem_iw_tp_ipv_6_mcast_addr_table_log(const bcm_omci_me_key *key, const bcm_omci_mcast_gem_iw_tp_ipv_6_mcast_addr_table *this, dev_log_id log_id, bcm_dev_log_level log_level)
{
    BCM_LOG_LEVEL(log_level, log_id, "\t\tgem_port_id: %u\n", this->gem_port_id);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tsecondary_key: %u\n", this->secondary_key);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tmcast_addr_range_start_lsb: 0x%x\n", this->mcast_addr_range_start_lsb);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tmcast_addr_range_stop_lsb: 0x%x\n", this->mcast_addr_range_stop_lsb);
    bcm_omci_stack_util_dump_raw_buf(key, this->mcast_addr_range_msb, 12, log_id_bcm_omci_stack_me_layer);

    return BCM_ERR_OK;
}

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_mcast_gem_iw_tp_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_mcast_gem_iw_tp_cfg *p_me_mcast_gem_iw_tp_cfg = (const bcm_omci_mcast_gem_iw_tp_cfg *)me_hdr;
    const bcm_omci_mcast_gem_iw_tp_cfg_data *p_me_cfg_data = &p_me_mcast_gem_iw_tp_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_mcast_gem_iw_tp_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_mcast_gem_iw_tp_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_GEM_PORT_NET_CTP_CONN_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tgem_port_net_ctp_conn_ptr:\t%u\n", p_me_cfg_data->gem_port_net_ctp_conn_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IW_OPT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tiw_opt:\t%u\n", p_me_cfg_data->iw_opt);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_SVC_PROF_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsvc_prof_ptr:\t%u\n", p_me_cfg_data->svc_prof_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_NOT_USED_1)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tnot_used_1:\t%u\n", p_me_cfg_data->not_used_1);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_PPTP_COUNTER)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpptp_counter:\t%u\n", p_me_cfg_data->pptp_counter);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_OPER_STATE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\toper_state:\t%u\n", p_me_cfg_data->oper_state);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_GAL_PROF_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tgal_prof_ptr:\t%u\n", p_me_cfg_data->gal_prof_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_NOT_USED_2)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tnot_used_2:\t%u\n", p_me_cfg_data->not_used_2);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IPV_4_MCAST_ADDR_TABLE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tipv_4_mcast_addr_table:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->ipv_4_mcast_addr_table)[0], ((const uint8_t *)&p_me_cfg_data->ipv_4_mcast_addr_table)[1], ((const uint8_t *)&p_me_cfg_data->ipv_4_mcast_addr_table)[2], ((const uint8_t *)&p_me_cfg_data->ipv_4_mcast_addr_table)[3], ((const uint8_t *)&p_me_cfg_data->ipv_4_mcast_addr_table)[4], ((const uint8_t *)&p_me_cfg_data->ipv_4_mcast_addr_table)[5], ((const uint8_t *)&p_me_cfg_data->ipv_4_mcast_addr_table)[6], ((const uint8_t *)&p_me_cfg_data->ipv_4_mcast_addr_table)[7], ((const uint8_t *)&p_me_cfg_data->ipv_4_mcast_addr_table)[8], ((const uint8_t *)&p_me_cfg_data->ipv_4_mcast_addr_table)[9], ((const uint8_t *)&p_me_cfg_data->ipv_4_mcast_addr_table)[10], ((const uint8_t *)&p_me_cfg_data->ipv_4_mcast_addr_table)[11]);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IPV_6_MCAST_ADDR_TABLE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tipv_6_mcast_addr_table:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[0], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[1], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[2], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[3], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[4], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[5], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[6], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[7], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[8], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[9], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[10], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[11], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[12], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[13], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[14], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[15], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[16], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[17], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[18], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[19], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[20], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[21], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[22], ((const uint8_t *)&p_me_cfg_data->ipv_6_mcast_addr_table)[23]);

    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IPV_4_MCAST_ADDR_TABLE)) != 0)
        bcm_omci_mcast_gem_iw_tp_ipv_4_mcast_addr_table_log(&me_hdr->key, &p_me_cfg_data->ipv_4_mcast_addr_table, log_id, log_level);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IPV_6_MCAST_ADDR_TABLE)) != 0)
        bcm_omci_mcast_gem_iw_tp_ipv_6_mcast_addr_table_log(&me_hdr->key, &p_me_cfg_data->ipv_6_mcast_addr_table, log_id, log_level);

    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */
static bcmos_bool bcm_omci_mcast_gem_iw_tp_ipv_4_mcast_addr_table_cfg_data_encode(bcm_omci_buf *p_bcm_buf, const bcm_omci_mcast_gem_iw_tp_ipv_4_mcast_addr_table *this)
{
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->gem_port_id))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->secondary_key))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u32(p_bcm_buf, this->mcast_addr_range_start))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u32(p_bcm_buf, this->mcast_addr_range_stop))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}
static bcmos_bool bcm_omci_mcast_gem_iw_tp_ipv_6_mcast_addr_table_cfg_data_encode(bcm_omci_buf *p_bcm_buf, const bcm_omci_mcast_gem_iw_tp_ipv_6_mcast_addr_table *this)
{
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->gem_port_id))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->secondary_key))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u32(p_bcm_buf, this->mcast_addr_range_start_lsb))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u32(p_bcm_buf, this->mcast_addr_range_stop_lsb))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_write(p_bcm_buf, this->mcast_addr_range_msb, 12))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

static bcmos_bool bcm_omci_mcast_gem_iw_tp_cfg_data_encode(const bcm_omci_mcast_gem_iw_tp_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_mcast_gem_iw_tp_cfg_data_encode(const bcm_omci_mcast_gem_iw_tp_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_GEM_PORT_NET_CTP_CONN_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->gem_port_net_ctp_conn_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IW_OPT)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->iw_opt))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_SVC_PROF_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->svc_prof_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_NOT_USED_1)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->not_used_1))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_PPTP_COUNTER)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->pptp_counter))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_OPER_STATE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->oper_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_GAL_PROF_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->gal_prof_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_NOT_USED_2)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->not_used_2))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IPV_4_MCAST_ADDR_TABLE)) != 0)
    {
        if (!bcm_omci_mcast_gem_iw_tp_ipv_4_mcast_addr_table_cfg_data_encode(p_bcm_buf, &p_me_cfg_data->ipv_4_mcast_addr_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IPV_6_MCAST_ADDR_TABLE)) != 0)
    {
        if (!bcm_omci_mcast_gem_iw_tp_ipv_6_mcast_addr_table_cfg_data_encode(p_bcm_buf, &p_me_cfg_data->ipv_6_mcast_addr_table))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_mcast_gem_iw_tp_cfg_encode(const bcm_omci_mcast_gem_iw_tp_cfg *p_me_mcast_gem_iw_tp_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_mcast_gem_iw_tp_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_mcast_gem_iw_tp_cfg_data_encode(&p_me_mcast_gem_iw_tp_cfg->data, p_bcm_buf, p_me_mcast_gem_iw_tp_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */
static bcmos_bool bcm_omci_mcast_gem_iw_tp_ipv_4_mcast_addr_table_cfg_data_decode(bcm_omci_buf *p_bcm_buf, bcm_omci_mcast_gem_iw_tp_ipv_4_mcast_addr_table *this)
{
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->gem_port_id))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->secondary_key))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u32(p_bcm_buf, &this->mcast_addr_range_start))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u32(p_bcm_buf, &this->mcast_addr_range_stop))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}
static bcmos_bool bcm_omci_mcast_gem_iw_tp_ipv_6_mcast_addr_table_cfg_data_decode(bcm_omci_buf *p_bcm_buf, bcm_omci_mcast_gem_iw_tp_ipv_6_mcast_addr_table *this)
{
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->gem_port_id))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->secondary_key))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u32(p_bcm_buf, &this->mcast_addr_range_start_lsb))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u32(p_bcm_buf, &this->mcast_addr_range_stop_lsb))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read(p_bcm_buf, this->mcast_addr_range_msb, 12))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_mcast_gem_iw_tp_cfg_data_decode(bcm_omci_mcast_gem_iw_tp_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_GEM_PORT_NET_CTP_CONN_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->gem_port_net_ctp_conn_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IW_OPT)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->iw_opt))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_SVC_PROF_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->svc_prof_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_NOT_USED_1)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->not_used_1))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_PPTP_COUNTER)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->pptp_counter))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_OPER_STATE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->oper_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_GAL_PROF_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->gal_prof_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_NOT_USED_2)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->not_used_2))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IPV_4_MCAST_ADDR_TABLE)) != 0)
    {
        if (!bcm_omci_mcast_gem_iw_tp_ipv_4_mcast_addr_table_cfg_data_decode(p_bcm_buf, &p_me_cfg_data->ipv_4_mcast_addr_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_GEM_IW_TP_CFG_ID_IPV_6_MCAST_ADDR_TABLE)) != 0)
    {
        if (!bcm_omci_mcast_gem_iw_tp_ipv_6_mcast_addr_table_cfg_data_decode(p_bcm_buf, &p_me_cfg_data->ipv_6_mcast_addr_table))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* Multicast Operations Profile */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_mcast_operations_profile_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_mcast_operations_profile_cfg *p_src_me_mcast_operations_profile_cfg = (const bcm_omci_mcast_operations_profile_cfg *)src_me_cfg;
    bcm_omci_mcast_operations_profile_cfg *p_dst_me_mcast_operations_profile_cfg = (bcm_omci_mcast_operations_profile_cfg *)dst_me_cfg;

    p_dst_me_mcast_operations_profile_cfg->hdr.presence_mask |= p_src_me_mcast_operations_profile_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_mcast_operations_profile_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IGMP_VERSION)) != 0)
    {
        p_dst_me_mcast_operations_profile_cfg->data.igmp_version = p_src_me_mcast_operations_profile_cfg->data.igmp_version;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IGMP_FUNCTION)) != 0)
    {
        p_dst_me_mcast_operations_profile_cfg->data.igmp_function = p_src_me_mcast_operations_profile_cfg->data.igmp_function;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IMMEDIATE_LEAVE)) != 0)
    {
        p_dst_me_mcast_operations_profile_cfg->data.immediate_leave = p_src_me_mcast_operations_profile_cfg->data.immediate_leave;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_TCI)) != 0)
    {
        p_dst_me_mcast_operations_profile_cfg->data.upstream_igmp_tci = p_src_me_mcast_operations_profile_cfg->data.upstream_igmp_tci;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_TAG_CONTROL)) != 0)
    {
        p_dst_me_mcast_operations_profile_cfg->data.upstream_igmp_tag_control = p_src_me_mcast_operations_profile_cfg->data.upstream_igmp_tag_control;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_RATE)) != 0)
    {
        p_dst_me_mcast_operations_profile_cfg->data.upstream_igmp_rate = p_src_me_mcast_operations_profile_cfg->data.upstream_igmp_rate;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_DYNAMIC_ACCESS_CONTROL_LIST_TABLE)) != 0)
    {
        /* doing struct copy */
        p_dst_me_mcast_operations_profile_cfg->data.dynamic_access_control_list_table = p_src_me_mcast_operations_profile_cfg->data.dynamic_access_control_list_table;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_STATIC_ACCESS_CONTROL_LIST_TABLE)) != 0)
    {
        /* doing struct copy */
        p_dst_me_mcast_operations_profile_cfg->data.static_access_control_list_table = p_src_me_mcast_operations_profile_cfg->data.static_access_control_list_table;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_LOST_GROUPS_LIST_TABLE)) != 0)
    {
        memcpy(p_dst_me_mcast_operations_profile_cfg->data.lost_groups_list_table, p_src_me_mcast_operations_profile_cfg->data.lost_groups_list_table, 10);
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_ROBUSTNESS)) != 0)
    {
        p_dst_me_mcast_operations_profile_cfg->data.robustness = p_src_me_mcast_operations_profile_cfg->data.robustness;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERIER_IP_ADDRESS)) != 0)
    {
        p_dst_me_mcast_operations_profile_cfg->data.querier_ip_address = p_src_me_mcast_operations_profile_cfg->data.querier_ip_address;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERY_INTERVAL)) != 0)
    {
        p_dst_me_mcast_operations_profile_cfg->data.query_interval = p_src_me_mcast_operations_profile_cfg->data.query_interval;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERY_MAX_RESPONSE_TIME)) != 0)
    {
        p_dst_me_mcast_operations_profile_cfg->data.query_max_response_time = p_src_me_mcast_operations_profile_cfg->data.query_max_response_time;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_LAST_MEMBER_QUERY_INTERVAL)) != 0)
    {
        p_dst_me_mcast_operations_profile_cfg->data.last_member_query_interval = p_src_me_mcast_operations_profile_cfg->data.last_member_query_interval;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UNAUTH_JOIN_REQUEST_BEHAVIOUR)) != 0)
    {
        p_dst_me_mcast_operations_profile_cfg->data.unauth_join_request_behaviour = p_src_me_mcast_operations_profile_cfg->data.unauth_join_request_behaviour;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_DS_IGMP_AND_MULTICAST_TCI)) != 0)
    {
        /* doing struct copy */
        p_dst_me_mcast_operations_profile_cfg->data.ds_igmp_and_multicast_tci = p_src_me_mcast_operations_profile_cfg->data.ds_igmp_and_multicast_tci;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_mcast_operations_profile_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_mcast_operations_profile_cfg *p_me_mcast_operations_profile_cfg = (const bcm_omci_mcast_operations_profile_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_mcast_operations_profile_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_mcast_operations_profile_cfg);

    if (BCMOS_TRUE != bcm_omci_mcast_operations_profile_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_mcast_operations_profile_cfg_data_bounds_check(&p_me_mcast_operations_profile_cfg->data, p_me_mcast_operations_profile_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_mcast_operations_profile_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_mcast_operations_profile_cfg_encode(p_me_mcast_operations_profile_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_mcast_operations_profile_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_mcast_operations_profile_cfg *p_me_mcast_operations_profile_cfg = (bcm_omci_mcast_operations_profile_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_mcast_operations_profile_cfg_data_decode(&p_me_mcast_operations_profile_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */
static bcmos_bool bcm_omci_mcast_operations_profile_dynamic_access_control_list_table_log(const bcm_omci_me_key *key, const bcm_omci_mcast_operations_profile_dynamic_access_control_list_table *this, dev_log_id log_id, bcm_dev_log_level log_level)
{
    BCM_LOG_LEVEL(log_level, log_id, "\t\ttable_control: %u\n", this->table_control);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tgem_port_id: %u\n", this->gem_port_id);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tvlan_id: %u\n", this->vlan_id);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tsrc_ip: 0x%x\n", this->src_ip);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tip_mcast_addr_start: 0x%x\n", this->ip_mcast_addr_start);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tip_mcast_addr_end: 0x%x\n", this->ip_mcast_addr_end);
    BCM_LOG_LEVEL(log_level, log_id, "\t\timputed_grp_bw: %u\n", this->imputed_grp_bw);
    BCM_LOG_LEVEL(log_level, log_id, "\t\treserved: %u\n", this->reserved);

    return BCM_ERR_OK;
}
static bcmos_bool bcm_omci_mcast_operations_profile_static_access_control_list_table_log(const bcm_omci_me_key *key, const bcm_omci_mcast_operations_profile_static_access_control_list_table *this, dev_log_id log_id, bcm_dev_log_level log_level)
{
    BCM_LOG_LEVEL(log_level, log_id, "\t\ttable_control: %u\n", this->table_control);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tgem_port_id: %u\n", this->gem_port_id);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tvlan_id: %u\n", this->vlan_id);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tsrc_ip: 0x%x\n", this->src_ip);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tip_mcast_addr_start: 0x%x\n", this->ip_mcast_addr_start);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tip_mcast_addr_end: 0x%x\n", this->ip_mcast_addr_end);
    BCM_LOG_LEVEL(log_level, log_id, "\t\timputed_grp_bw: %u\n", this->imputed_grp_bw);
    BCM_LOG_LEVEL(log_level, log_id, "\t\treserved: %u\n", this->reserved);

    return BCM_ERR_OK;
}
static bcmos_bool bcm_omci_mcast_operations_profile_ds_igmp_and_multicast_tci_log(const bcm_omci_me_key *key, const bcm_omci_mcast_operations_profile_ds_igmp_and_multicast_tci *this, dev_log_id log_id, bcm_dev_log_level log_level)
{
    BCM_LOG_LEVEL(log_level, log_id, "\t\tcontrol_type: %u\n", this->control_type);
    BCM_LOG_LEVEL(log_level, log_id, "\t\ttci: %u\n", this->tci);

    return BCM_ERR_OK;
}

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_mcast_operations_profile_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_mcast_operations_profile_cfg *p_me_mcast_operations_profile_cfg = (const bcm_omci_mcast_operations_profile_cfg *)me_hdr;
    const bcm_omci_mcast_operations_profile_cfg_data *p_me_cfg_data = &p_me_mcast_operations_profile_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_mcast_operations_profile_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_mcast_operations_profile_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IGMP_VERSION)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tigmp_version:\t%u\n", p_me_cfg_data->igmp_version);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IGMP_FUNCTION)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tigmp_function:\t%u\n", p_me_cfg_data->igmp_function);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IMMEDIATE_LEAVE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\timmediate_leave:\t%u\n", p_me_cfg_data->immediate_leave);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_TCI)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tupstream_igmp_tci:\t%u\n", p_me_cfg_data->upstream_igmp_tci);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_TAG_CONTROL)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tupstream_igmp_tag_control:\t%u\n", p_me_cfg_data->upstream_igmp_tag_control);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_RATE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tupstream_igmp_rate:\t%u\n", p_me_cfg_data->upstream_igmp_rate);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_DYNAMIC_ACCESS_CONTROL_LIST_TABLE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdynamic_access_control_list_table:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[0], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[1], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[2], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[3], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[4], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[5], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[6], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[7], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[8], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[9], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[10], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[11], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[12], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[13], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[14], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[15], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[16], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[17], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[18], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[19], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[20], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[21], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[22], ((const uint8_t *)&p_me_cfg_data->dynamic_access_control_list_table)[23]);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_STATIC_ACCESS_CONTROL_LIST_TABLE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tstatic_access_control_list_table:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[0], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[1], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[2], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[3], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[4], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[5], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[6], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[7], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[8], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[9], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[10], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[11], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[12], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[13], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[14], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[15], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[16], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[17], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[18], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[19], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[20], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[21], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[22], ((const uint8_t *)&p_me_cfg_data->static_access_control_list_table)[23]);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_LOST_GROUPS_LIST_TABLE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tlost_groups_list_table:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->lost_groups_list_table)[0], ((const uint8_t *)&p_me_cfg_data->lost_groups_list_table)[1], ((const uint8_t *)&p_me_cfg_data->lost_groups_list_table)[2], ((const uint8_t *)&p_me_cfg_data->lost_groups_list_table)[3], ((const uint8_t *)&p_me_cfg_data->lost_groups_list_table)[4], ((const uint8_t *)&p_me_cfg_data->lost_groups_list_table)[5], ((const uint8_t *)&p_me_cfg_data->lost_groups_list_table)[6], ((const uint8_t *)&p_me_cfg_data->lost_groups_list_table)[7], ((const uint8_t *)&p_me_cfg_data->lost_groups_list_table)[8], ((const uint8_t *)&p_me_cfg_data->lost_groups_list_table)[9]);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_ROBUSTNESS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\trobustness:\t%u\n", p_me_cfg_data->robustness);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERIER_IP_ADDRESS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tquerier_ip_address:\t0x%x\n", p_me_cfg_data->querier_ip_address);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERY_INTERVAL)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tquery_interval:\t%u\n", p_me_cfg_data->query_interval);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERY_MAX_RESPONSE_TIME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tquery_max_response_time:\t%u\n", p_me_cfg_data->query_max_response_time);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_LAST_MEMBER_QUERY_INTERVAL)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tlast_member_query_interval:\t%u\n", p_me_cfg_data->last_member_query_interval);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UNAUTH_JOIN_REQUEST_BEHAVIOUR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tunauth_join_request_behaviour:\t%u\n", p_me_cfg_data->unauth_join_request_behaviour);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_DS_IGMP_AND_MULTICAST_TCI)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tds_igmp_and_multicast_tci:\t%02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->ds_igmp_and_multicast_tci)[0], ((const uint8_t *)&p_me_cfg_data->ds_igmp_and_multicast_tci)[1], ((const uint8_t *)&p_me_cfg_data->ds_igmp_and_multicast_tci)[2]);

    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_DYNAMIC_ACCESS_CONTROL_LIST_TABLE)) != 0)
        bcm_omci_mcast_operations_profile_dynamic_access_control_list_table_log(&me_hdr->key, &p_me_cfg_data->dynamic_access_control_list_table, log_id, log_level);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_STATIC_ACCESS_CONTROL_LIST_TABLE)) != 0)
        bcm_omci_mcast_operations_profile_static_access_control_list_table_log(&me_hdr->key, &p_me_cfg_data->static_access_control_list_table, log_id, log_level);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_DS_IGMP_AND_MULTICAST_TCI)) != 0)
        bcm_omci_mcast_operations_profile_ds_igmp_and_multicast_tci_log(&me_hdr->key, &p_me_cfg_data->ds_igmp_and_multicast_tci, log_id, log_level);

    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */
static bcmos_bool bcm_omci_mcast_operations_profile_dynamic_access_control_list_table_cfg_data_encode(bcm_omci_buf *p_bcm_buf, const bcm_omci_mcast_operations_profile_dynamic_access_control_list_table *this)
{
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->table_control))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->gem_port_id))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->vlan_id))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u32(p_bcm_buf, this->src_ip))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u32(p_bcm_buf, this->ip_mcast_addr_start))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u32(p_bcm_buf, this->ip_mcast_addr_end))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u32(p_bcm_buf, this->imputed_grp_bw))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->reserved))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}
static bcmos_bool bcm_omci_mcast_operations_profile_static_access_control_list_table_cfg_data_encode(bcm_omci_buf *p_bcm_buf, const bcm_omci_mcast_operations_profile_static_access_control_list_table *this)
{
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->table_control))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->gem_port_id))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->vlan_id))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u32(p_bcm_buf, this->src_ip))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u32(p_bcm_buf, this->ip_mcast_addr_start))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u32(p_bcm_buf, this->ip_mcast_addr_end))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u32(p_bcm_buf, this->imputed_grp_bw))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->reserved))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}
static bcmos_bool bcm_omci_mcast_operations_profile_ds_igmp_and_multicast_tci_cfg_data_encode(bcm_omci_buf *p_bcm_buf, const bcm_omci_mcast_operations_profile_ds_igmp_and_multicast_tci *this)
{
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->control_type))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->tci))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

static bcmos_bool bcm_omci_mcast_operations_profile_cfg_data_encode(const bcm_omci_mcast_operations_profile_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_mcast_operations_profile_cfg_data_encode(const bcm_omci_mcast_operations_profile_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IGMP_VERSION)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->igmp_version))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IGMP_FUNCTION)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->igmp_function))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IMMEDIATE_LEAVE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->immediate_leave))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_TCI)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->upstream_igmp_tci))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_TAG_CONTROL)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->upstream_igmp_tag_control))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_RATE)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->upstream_igmp_rate))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_DYNAMIC_ACCESS_CONTROL_LIST_TABLE)) != 0)
    {
        if (!bcm_omci_mcast_operations_profile_dynamic_access_control_list_table_cfg_data_encode(p_bcm_buf, &p_me_cfg_data->dynamic_access_control_list_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_STATIC_ACCESS_CONTROL_LIST_TABLE)) != 0)
    {
        if (!bcm_omci_mcast_operations_profile_static_access_control_list_table_cfg_data_encode(p_bcm_buf, &p_me_cfg_data->static_access_control_list_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_LOST_GROUPS_LIST_TABLE)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->lost_groups_list_table, 10))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_ROBUSTNESS)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->robustness))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERIER_IP_ADDRESS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->querier_ip_address))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERY_INTERVAL)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->query_interval))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERY_MAX_RESPONSE_TIME)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->query_max_response_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_LAST_MEMBER_QUERY_INTERVAL)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->last_member_query_interval))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UNAUTH_JOIN_REQUEST_BEHAVIOUR)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->unauth_join_request_behaviour))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_DS_IGMP_AND_MULTICAST_TCI)) != 0)
    {
        if (!bcm_omci_mcast_operations_profile_ds_igmp_and_multicast_tci_cfg_data_encode(p_bcm_buf, &p_me_cfg_data->ds_igmp_and_multicast_tci))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_mcast_operations_profile_cfg_encode(const bcm_omci_mcast_operations_profile_cfg *p_me_mcast_operations_profile_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_mcast_operations_profile_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_mcast_operations_profile_cfg_data_encode(&p_me_mcast_operations_profile_cfg->data, p_bcm_buf, p_me_mcast_operations_profile_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */
static bcmos_bool bcm_omci_mcast_operations_profile_dynamic_access_control_list_table_cfg_data_decode(bcm_omci_buf *p_bcm_buf, bcm_omci_mcast_operations_profile_dynamic_access_control_list_table *this)
{
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->table_control))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->gem_port_id))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->vlan_id))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u32(p_bcm_buf, &this->src_ip))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u32(p_bcm_buf, &this->ip_mcast_addr_start))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u32(p_bcm_buf, &this->ip_mcast_addr_end))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u32(p_bcm_buf, &this->imputed_grp_bw))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->reserved))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}
static bcmos_bool bcm_omci_mcast_operations_profile_static_access_control_list_table_cfg_data_decode(bcm_omci_buf *p_bcm_buf, bcm_omci_mcast_operations_profile_static_access_control_list_table *this)
{
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->table_control))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->gem_port_id))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->vlan_id))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u32(p_bcm_buf, &this->src_ip))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u32(p_bcm_buf, &this->ip_mcast_addr_start))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u32(p_bcm_buf, &this->ip_mcast_addr_end))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u32(p_bcm_buf, &this->imputed_grp_bw))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->reserved))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}
static bcmos_bool bcm_omci_mcast_operations_profile_ds_igmp_and_multicast_tci_cfg_data_decode(bcm_omci_buf *p_bcm_buf, bcm_omci_mcast_operations_profile_ds_igmp_and_multicast_tci *this)
{
     if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&this->control_type))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->tci))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_mcast_operations_profile_cfg_data_decode(bcm_omci_mcast_operations_profile_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IGMP_VERSION)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->igmp_version))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IGMP_FUNCTION)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->igmp_function))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_IMMEDIATE_LEAVE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->immediate_leave))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_TCI)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->upstream_igmp_tci))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_TAG_CONTROL)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->upstream_igmp_tag_control))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UPSTREAM_IGMP_RATE)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->upstream_igmp_rate))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_DYNAMIC_ACCESS_CONTROL_LIST_TABLE)) != 0)
    {
        if (!bcm_omci_mcast_operations_profile_dynamic_access_control_list_table_cfg_data_decode(p_bcm_buf, &p_me_cfg_data->dynamic_access_control_list_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_STATIC_ACCESS_CONTROL_LIST_TABLE)) != 0)
    {
        if (!bcm_omci_mcast_operations_profile_static_access_control_list_table_cfg_data_decode(p_bcm_buf, &p_me_cfg_data->static_access_control_list_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_LOST_GROUPS_LIST_TABLE)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->lost_groups_list_table, 10))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_ROBUSTNESS)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->robustness))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERIER_IP_ADDRESS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->querier_ip_address))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERY_INTERVAL)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->query_interval))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_QUERY_MAX_RESPONSE_TIME)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->query_max_response_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_LAST_MEMBER_QUERY_INTERVAL)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->last_member_query_interval))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_UNAUTH_JOIN_REQUEST_BEHAVIOUR)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->unauth_join_request_behaviour))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_OPERATIONS_PROFILE_CFG_ID_DS_IGMP_AND_MULTICAST_TCI)) != 0)
    {
        if (!bcm_omci_mcast_operations_profile_ds_igmp_and_multicast_tci_cfg_data_decode(p_bcm_buf, &p_me_cfg_data->ds_igmp_and_multicast_tci))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* Multicast subscriber config info */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_mcast_subscriber_config_info_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_mcast_subscriber_config_info_cfg *p_src_me_mcast_subscriber_config_info_cfg = (const bcm_omci_mcast_subscriber_config_info_cfg *)src_me_cfg;
    bcm_omci_mcast_subscriber_config_info_cfg *p_dst_me_mcast_subscriber_config_info_cfg = (bcm_omci_mcast_subscriber_config_info_cfg *)dst_me_cfg;

    p_dst_me_mcast_subscriber_config_info_cfg->hdr.presence_mask |= p_src_me_mcast_subscriber_config_info_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_mcast_subscriber_config_info_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_ME_TYPE)) != 0)
    {
        p_dst_me_mcast_subscriber_config_info_cfg->data.me_type = p_src_me_mcast_subscriber_config_info_cfg->data.me_type;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MCAST_OPERATIONS_PROF_PTR)) != 0)
    {
        p_dst_me_mcast_subscriber_config_info_cfg->data.mcast_operations_prof_ptr = p_src_me_mcast_subscriber_config_info_cfg->data.mcast_operations_prof_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MAX_SIMULTANEOUS_GROUPS)) != 0)
    {
        p_dst_me_mcast_subscriber_config_info_cfg->data.max_simultaneous_groups = p_src_me_mcast_subscriber_config_info_cfg->data.max_simultaneous_groups;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MAX_MULTICAST_BW)) != 0)
    {
        p_dst_me_mcast_subscriber_config_info_cfg->data.max_multicast_bw = p_src_me_mcast_subscriber_config_info_cfg->data.max_multicast_bw;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_BW_ENFORCEMENT)) != 0)
    {
        p_dst_me_mcast_subscriber_config_info_cfg->data.bw_enforcement = p_src_me_mcast_subscriber_config_info_cfg->data.bw_enforcement;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MCAST_SVC_PKG_TABLE)) != 0)
    {
        memcpy(p_dst_me_mcast_subscriber_config_info_cfg->data.mcast_svc_pkg_table, p_src_me_mcast_subscriber_config_info_cfg->data.mcast_svc_pkg_table, 20);
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_ALLOWED_PREVIEW_GROUPS_TABLE)) != 0)
    {
        memcpy(p_dst_me_mcast_subscriber_config_info_cfg->data.allowed_preview_groups_table, p_src_me_mcast_subscriber_config_info_cfg->data.allowed_preview_groups_table, 24);
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_mcast_subscriber_config_info_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_mcast_subscriber_config_info_cfg *p_me_mcast_subscriber_config_info_cfg = (const bcm_omci_mcast_subscriber_config_info_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_mcast_subscriber_config_info_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_mcast_subscriber_config_info_cfg);

    if (BCMOS_TRUE != bcm_omci_mcast_subscriber_config_info_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_mcast_subscriber_config_info_cfg_data_bounds_check(&p_me_mcast_subscriber_config_info_cfg->data, p_me_mcast_subscriber_config_info_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_mcast_subscriber_config_info_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_mcast_subscriber_config_info_cfg_encode(p_me_mcast_subscriber_config_info_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_mcast_subscriber_config_info_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_mcast_subscriber_config_info_cfg *p_me_mcast_subscriber_config_info_cfg = (bcm_omci_mcast_subscriber_config_info_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_mcast_subscriber_config_info_cfg_data_decode(&p_me_mcast_subscriber_config_info_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_mcast_subscriber_config_info_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_mcast_subscriber_config_info_cfg *p_me_mcast_subscriber_config_info_cfg = (const bcm_omci_mcast_subscriber_config_info_cfg *)me_hdr;
    const bcm_omci_mcast_subscriber_config_info_cfg_data *p_me_cfg_data = &p_me_mcast_subscriber_config_info_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_mcast_subscriber_config_info_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_mcast_subscriber_config_info_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_ME_TYPE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tme_type:\t%u\n", p_me_cfg_data->me_type);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MCAST_OPERATIONS_PROF_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tmcast_operations_prof_ptr:\t%u\n", p_me_cfg_data->mcast_operations_prof_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MAX_SIMULTANEOUS_GROUPS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tmax_simultaneous_groups:\t%u\n", p_me_cfg_data->max_simultaneous_groups);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MAX_MULTICAST_BW)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tmax_multicast_bw:\t%u\n", p_me_cfg_data->max_multicast_bw);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_BW_ENFORCEMENT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tbw_enforcement:\t%u\n", p_me_cfg_data->bw_enforcement);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MCAST_SVC_PKG_TABLE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tmcast_svc_pkg_table:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->mcast_svc_pkg_table)[0], ((const uint8_t *)&p_me_cfg_data->mcast_svc_pkg_table)[1], ((const uint8_t *)&p_me_cfg_data->mcast_svc_pkg_table)[2], ((const uint8_t *)&p_me_cfg_data->mcast_svc_pkg_table)[3], ((const uint8_t *)&p_me_cfg_data->mcast_svc_pkg_table)[4], ((const uint8_t *)&p_me_cfg_data->mcast_svc_pkg_table)[5], ((const uint8_t *)&p_me_cfg_data->mcast_svc_pkg_table)[6], ((const uint8_t *)&p_me_cfg_data->mcast_svc_pkg_table)[7], ((const uint8_t *)&p_me_cfg_data->mcast_svc_pkg_table)[8], ((const uint8_t *)&p_me_cfg_data->mcast_svc_pkg_table)[9], ((const uint8_t *)&p_me_cfg_data->mcast_svc_pkg_table)[10], ((const uint8_t *)&p_me_cfg_data->mcast_svc_pkg_table)[11], ((const uint8_t *)&p_me_cfg_data->mcast_svc_pkg_table)[12], ((const uint8_t *)&p_me_cfg_data->mcast_svc_pkg_table)[13], ((const uint8_t *)&p_me_cfg_data->mcast_svc_pkg_table)[14], ((const uint8_t *)&p_me_cfg_data->mcast_svc_pkg_table)[15], ((const uint8_t *)&p_me_cfg_data->mcast_svc_pkg_table)[16], ((const uint8_t *)&p_me_cfg_data->mcast_svc_pkg_table)[17], ((const uint8_t *)&p_me_cfg_data->mcast_svc_pkg_table)[18], ((const uint8_t *)&p_me_cfg_data->mcast_svc_pkg_table)[19]);
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_ALLOWED_PREVIEW_GROUPS_TABLE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tallowed_preview_groups_table:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[0], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[1], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[2], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[3], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[4], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[5], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[6], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[7], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[8], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[9], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[10], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[11], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[12], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[13], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[14], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[15], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[16], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[17], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[18], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[19], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[20], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[21], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[22], ((const uint8_t *)&p_me_cfg_data->allowed_preview_groups_table)[23]);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_mcast_subscriber_config_info_cfg_data_encode(const bcm_omci_mcast_subscriber_config_info_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_mcast_subscriber_config_info_cfg_data_encode(const bcm_omci_mcast_subscriber_config_info_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_ME_TYPE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->me_type))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MCAST_OPERATIONS_PROF_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->mcast_operations_prof_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MAX_SIMULTANEOUS_GROUPS)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->max_simultaneous_groups))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MAX_MULTICAST_BW)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->max_multicast_bw))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_BW_ENFORCEMENT)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->bw_enforcement))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MCAST_SVC_PKG_TABLE)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->mcast_svc_pkg_table, 20))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_ALLOWED_PREVIEW_GROUPS_TABLE)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->allowed_preview_groups_table, 24))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_mcast_subscriber_config_info_cfg_encode(const bcm_omci_mcast_subscriber_config_info_cfg *p_me_mcast_subscriber_config_info_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_mcast_subscriber_config_info_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_mcast_subscriber_config_info_cfg_data_encode(&p_me_mcast_subscriber_config_info_cfg->data, p_bcm_buf, p_me_mcast_subscriber_config_info_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_mcast_subscriber_config_info_cfg_data_decode(bcm_omci_mcast_subscriber_config_info_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_ME_TYPE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->me_type))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MCAST_OPERATIONS_PROF_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->mcast_operations_prof_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MAX_SIMULTANEOUS_GROUPS)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->max_simultaneous_groups))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MAX_MULTICAST_BW)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->max_multicast_bw))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_BW_ENFORCEMENT)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->bw_enforcement))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_MCAST_SVC_PKG_TABLE)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->mcast_svc_pkg_table, 20))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_CFG_ID_ALLOWED_PREVIEW_GROUPS_TABLE)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->allowed_preview_groups_table, 24))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* PPTP Ethernet UNI */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_pptp_eth_uni_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_pptp_eth_uni_cfg *p_src_me_pptp_eth_uni_cfg = (const bcm_omci_pptp_eth_uni_cfg *)src_me_cfg;
    bcm_omci_pptp_eth_uni_cfg *p_dst_me_pptp_eth_uni_cfg = (bcm_omci_pptp_eth_uni_cfg *)dst_me_cfg;

    p_dst_me_pptp_eth_uni_cfg->hdr.presence_mask |= p_src_me_pptp_eth_uni_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_pptp_eth_uni_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_EXPECTED_TYPE)) != 0)
    {
        p_dst_me_pptp_eth_uni_cfg->data.expected_type = p_src_me_pptp_eth_uni_cfg->data.expected_type;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_SENSED_TYPE)) != 0)
    {
        p_dst_me_pptp_eth_uni_cfg->data.sensed_type = p_src_me_pptp_eth_uni_cfg->data.sensed_type;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_AUTO_DETECTION_CONFIG)) != 0)
    {
        p_dst_me_pptp_eth_uni_cfg->data.auto_detection_config = p_src_me_pptp_eth_uni_cfg->data.auto_detection_config;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ETHERNET_LOOPBACK_CONFIG)) != 0)
    {
        p_dst_me_pptp_eth_uni_cfg->data.ethernet_loopback_config = p_src_me_pptp_eth_uni_cfg->data.ethernet_loopback_config;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ADMIN_STATE)) != 0)
    {
        p_dst_me_pptp_eth_uni_cfg->data.admin_state = p_src_me_pptp_eth_uni_cfg->data.admin_state;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_OPER_STATE)) != 0)
    {
        p_dst_me_pptp_eth_uni_cfg->data.oper_state = p_src_me_pptp_eth_uni_cfg->data.oper_state;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_CONFIG_IND)) != 0)
    {
        p_dst_me_pptp_eth_uni_cfg->data.config_ind = p_src_me_pptp_eth_uni_cfg->data.config_ind;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_MAX_FRAME_SIZE)) != 0)
    {
        p_dst_me_pptp_eth_uni_cfg->data.max_frame_size = p_src_me_pptp_eth_uni_cfg->data.max_frame_size;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_DTE_OR_DCE_IND)) != 0)
    {
        p_dst_me_pptp_eth_uni_cfg->data.dte_or_dce_ind = p_src_me_pptp_eth_uni_cfg->data.dte_or_dce_ind;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_PAUSE_TIME)) != 0)
    {
        p_dst_me_pptp_eth_uni_cfg->data.pause_time = p_src_me_pptp_eth_uni_cfg->data.pause_time;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_BRIDGED_OR_IP_IND)) != 0)
    {
        p_dst_me_pptp_eth_uni_cfg->data.bridged_or_ip_ind = p_src_me_pptp_eth_uni_cfg->data.bridged_or_ip_ind;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ARC)) != 0)
    {
        p_dst_me_pptp_eth_uni_cfg->data.arc = p_src_me_pptp_eth_uni_cfg->data.arc;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ARC_INTERVAL)) != 0)
    {
        p_dst_me_pptp_eth_uni_cfg->data.arc_interval = p_src_me_pptp_eth_uni_cfg->data.arc_interval;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_PPPOE_FILTER)) != 0)
    {
        p_dst_me_pptp_eth_uni_cfg->data.pppoe_filter = p_src_me_pptp_eth_uni_cfg->data.pppoe_filter;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_POWER_CONTROL)) != 0)
    {
        p_dst_me_pptp_eth_uni_cfg->data.power_control = p_src_me_pptp_eth_uni_cfg->data.power_control;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_pptp_eth_uni_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_pptp_eth_uni_cfg *p_me_pptp_eth_uni_cfg = (const bcm_omci_pptp_eth_uni_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_pptp_eth_uni_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_PPTP_ETH_UNI_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_pptp_eth_uni_cfg);

    if (BCMOS_TRUE != bcm_omci_pptp_eth_uni_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_pptp_eth_uni_cfg_data_bounds_check(&p_me_pptp_eth_uni_cfg->data, p_me_pptp_eth_uni_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_pptp_eth_uni_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_pptp_eth_uni_cfg_encode(p_me_pptp_eth_uni_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_pptp_eth_uni_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_pptp_eth_uni_cfg *p_me_pptp_eth_uni_cfg = (bcm_omci_pptp_eth_uni_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_pptp_eth_uni_cfg_data_decode(&p_me_pptp_eth_uni_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_pptp_eth_uni_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_pptp_eth_uni_cfg *p_me_pptp_eth_uni_cfg = (const bcm_omci_pptp_eth_uni_cfg *)me_hdr;
    const bcm_omci_pptp_eth_uni_cfg_data *p_me_cfg_data = &p_me_pptp_eth_uni_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_pptp_eth_uni_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_pptp_eth_uni_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_EXPECTED_TYPE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\texpected_type:\t%u\n", p_me_cfg_data->expected_type);
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_SENSED_TYPE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsensed_type:\t%u\n", p_me_cfg_data->sensed_type);
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_AUTO_DETECTION_CONFIG)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tauto_detection_config:\t%u\n", p_me_cfg_data->auto_detection_config);
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ETHERNET_LOOPBACK_CONFIG)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tethernet_loopback_config:\t%u\n", p_me_cfg_data->ethernet_loopback_config);
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ADMIN_STATE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tadmin_state:\t%u\n", p_me_cfg_data->admin_state);
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_OPER_STATE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\toper_state:\t%u\n", p_me_cfg_data->oper_state);
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_CONFIG_IND)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tconfig_ind:\t%u\n", p_me_cfg_data->config_ind);
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_MAX_FRAME_SIZE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tmax_frame_size:\t%u\n", p_me_cfg_data->max_frame_size);
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_DTE_OR_DCE_IND)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdte_or_dce_ind:\t%u\n", p_me_cfg_data->dte_or_dce_ind);
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_PAUSE_TIME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpause_time:\t%u\n", p_me_cfg_data->pause_time);
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_BRIDGED_OR_IP_IND)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tbridged_or_ip_ind:\t%u\n", p_me_cfg_data->bridged_or_ip_ind);
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ARC)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tarc:\t%u\n", p_me_cfg_data->arc);
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ARC_INTERVAL)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tarc_interval:\t%u\n", p_me_cfg_data->arc_interval);
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_PPPOE_FILTER)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpppoe_filter:\t%u\n", p_me_cfg_data->pppoe_filter);
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_POWER_CONTROL)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpower_control:\t%u\n", p_me_cfg_data->power_control);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_pptp_eth_uni_cfg_data_encode(const bcm_omci_pptp_eth_uni_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_pptp_eth_uni_cfg_data_encode(const bcm_omci_pptp_eth_uni_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_EXPECTED_TYPE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->expected_type))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_SENSED_TYPE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->sensed_type))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_AUTO_DETECTION_CONFIG)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->auto_detection_config))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ETHERNET_LOOPBACK_CONFIG)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->ethernet_loopback_config))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ADMIN_STATE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->admin_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_OPER_STATE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->oper_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_CONFIG_IND)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->config_ind))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_MAX_FRAME_SIZE)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->max_frame_size))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_DTE_OR_DCE_IND)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->dte_or_dce_ind))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_PAUSE_TIME)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->pause_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_BRIDGED_OR_IP_IND)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->bridged_or_ip_ind))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ARC)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->arc))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ARC_INTERVAL)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->arc_interval))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_PPPOE_FILTER)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->pppoe_filter))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_POWER_CONTROL)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->power_control))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_pptp_eth_uni_cfg_encode(const bcm_omci_pptp_eth_uni_cfg *p_me_pptp_eth_uni_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_pptp_eth_uni_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_pptp_eth_uni_cfg_data_encode(&p_me_pptp_eth_uni_cfg->data, p_bcm_buf, p_me_pptp_eth_uni_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_pptp_eth_uni_cfg_data_decode(bcm_omci_pptp_eth_uni_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_EXPECTED_TYPE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->expected_type))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_SENSED_TYPE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->sensed_type))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_AUTO_DETECTION_CONFIG)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->auto_detection_config))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ETHERNET_LOOPBACK_CONFIG)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->ethernet_loopback_config))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ADMIN_STATE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->admin_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_OPER_STATE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->oper_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_CONFIG_IND)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->config_ind))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_MAX_FRAME_SIZE)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->max_frame_size))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_DTE_OR_DCE_IND)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->dte_or_dce_ind))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_PAUSE_TIME)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->pause_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_BRIDGED_OR_IP_IND)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->bridged_or_ip_ind))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ARC)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->arc))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_ARC_INTERVAL)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->arc_interval))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_PPPOE_FILTER)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->pppoe_filter))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_PPTP_ETH_UNI_CFG_ID_POWER_CONTROL)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->power_control))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* Virtual Ethernet Interface Point */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_virtual_eth_intf_point_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_virtual_eth_intf_point_cfg *p_src_me_virtual_eth_intf_point_cfg = (const bcm_omci_virtual_eth_intf_point_cfg *)src_me_cfg;
    bcm_omci_virtual_eth_intf_point_cfg *p_dst_me_virtual_eth_intf_point_cfg = (bcm_omci_virtual_eth_intf_point_cfg *)dst_me_cfg;

    p_dst_me_virtual_eth_intf_point_cfg->hdr.presence_mask |= p_src_me_virtual_eth_intf_point_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_virtual_eth_intf_point_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_ADMIN_STATE)) != 0)
    {
        p_dst_me_virtual_eth_intf_point_cfg->data.admin_state = p_src_me_virtual_eth_intf_point_cfg->data.admin_state;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_OPER_STATE)) != 0)
    {
        p_dst_me_virtual_eth_intf_point_cfg->data.oper_state = p_src_me_virtual_eth_intf_point_cfg->data.oper_state;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_INTERDOMAIN_NAME)) != 0)
    {
        memcpy(p_dst_me_virtual_eth_intf_point_cfg->data.interdomain_name, p_src_me_virtual_eth_intf_point_cfg->data.interdomain_name, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_TCP_UDP_PTR)) != 0)
    {
        p_dst_me_virtual_eth_intf_point_cfg->data.tcp_udp_ptr = p_src_me_virtual_eth_intf_point_cfg->data.tcp_udp_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_IANA_ASSIGNED_PORT)) != 0)
    {
        p_dst_me_virtual_eth_intf_point_cfg->data.iana_assigned_port = p_src_me_virtual_eth_intf_point_cfg->data.iana_assigned_port;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_virtual_eth_intf_point_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_virtual_eth_intf_point_cfg *p_me_virtual_eth_intf_point_cfg = (const bcm_omci_virtual_eth_intf_point_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_virtual_eth_intf_point_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_virtual_eth_intf_point_cfg);

    if (BCMOS_TRUE != bcm_omci_virtual_eth_intf_point_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_virtual_eth_intf_point_cfg_data_bounds_check(&p_me_virtual_eth_intf_point_cfg->data, p_me_virtual_eth_intf_point_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_virtual_eth_intf_point_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_virtual_eth_intf_point_cfg_encode(p_me_virtual_eth_intf_point_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_virtual_eth_intf_point_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_virtual_eth_intf_point_cfg *p_me_virtual_eth_intf_point_cfg = (bcm_omci_virtual_eth_intf_point_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_virtual_eth_intf_point_cfg_data_decode(&p_me_virtual_eth_intf_point_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_virtual_eth_intf_point_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_virtual_eth_intf_point_cfg *p_me_virtual_eth_intf_point_cfg = (const bcm_omci_virtual_eth_intf_point_cfg *)me_hdr;
    const bcm_omci_virtual_eth_intf_point_cfg_data *p_me_cfg_data = &p_me_virtual_eth_intf_point_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_virtual_eth_intf_point_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_virtual_eth_intf_point_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_ADMIN_STATE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tadmin_state:\t%u\n", p_me_cfg_data->admin_state);
    if ((fields_present & (1ULL << BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_OPER_STATE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\toper_state:\t%u\n", p_me_cfg_data->oper_state);
    if ((fields_present & (1ULL << BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_INTERDOMAIN_NAME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tinterdomain_name:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->interdomain_name)[0], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[1], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[2], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[3], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[4], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[5], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[6], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[7], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[8], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[9], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[10], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[11], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[12], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[13], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[14], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[15], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[16], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[17], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[18], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[19], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[20], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[21], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[22], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[23], ((const uint8_t *)&p_me_cfg_data->interdomain_name)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_TCP_UDP_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttcp_udp_ptr:\t%u\n", p_me_cfg_data->tcp_udp_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_IANA_ASSIGNED_PORT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tiana_assigned_port:\t%u\n", p_me_cfg_data->iana_assigned_port);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_virtual_eth_intf_point_cfg_data_encode(const bcm_omci_virtual_eth_intf_point_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_virtual_eth_intf_point_cfg_data_encode(const bcm_omci_virtual_eth_intf_point_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_ADMIN_STATE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->admin_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_OPER_STATE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->oper_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_INTERDOMAIN_NAME)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->interdomain_name, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_TCP_UDP_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->tcp_udp_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_IANA_ASSIGNED_PORT)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->iana_assigned_port))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_virtual_eth_intf_point_cfg_encode(const bcm_omci_virtual_eth_intf_point_cfg *p_me_virtual_eth_intf_point_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_virtual_eth_intf_point_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_virtual_eth_intf_point_cfg_data_encode(&p_me_virtual_eth_intf_point_cfg->data, p_bcm_buf, p_me_virtual_eth_intf_point_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_virtual_eth_intf_point_cfg_data_decode(bcm_omci_virtual_eth_intf_point_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_ADMIN_STATE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->admin_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_OPER_STATE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->oper_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_INTERDOMAIN_NAME)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->interdomain_name, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_TCP_UDP_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->tcp_udp_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VIRTUAL_ETH_INTF_POINT_CFG_ID_IANA_ASSIGNED_PORT)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->iana_assigned_port))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* ONU data */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_onu_data_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_onu_data_cfg *p_src_me_onu_data_cfg = (const bcm_omci_onu_data_cfg *)src_me_cfg;
    bcm_omci_onu_data_cfg *p_dst_me_onu_data_cfg = (bcm_omci_onu_data_cfg *)dst_me_cfg;

    p_dst_me_onu_data_cfg->hdr.presence_mask |= p_src_me_onu_data_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_onu_data_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_ONU_DATA_CFG_ID_MIB_DATA_SYNC)) != 0)
    {
        p_dst_me_onu_data_cfg->data.mib_data_sync = p_src_me_onu_data_cfg->data.mib_data_sync;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_onu_data_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_onu_data_cfg *p_me_onu_data_cfg = (const bcm_omci_onu_data_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_onu_data_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_ONU_DATA_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_onu_data_cfg);

    if (BCMOS_TRUE != bcm_omci_onu_data_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_onu_data_cfg_data_bounds_check(&p_me_onu_data_cfg->data, p_me_onu_data_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_onu_data_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_onu_data_cfg_encode(p_me_onu_data_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_onu_data_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_onu_data_cfg *p_me_onu_data_cfg = (bcm_omci_onu_data_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_onu_data_cfg_data_decode(&p_me_onu_data_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_onu_data_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_onu_data_cfg *p_me_onu_data_cfg = (const bcm_omci_onu_data_cfg *)me_hdr;
    const bcm_omci_onu_data_cfg_data *p_me_cfg_data = &p_me_onu_data_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_onu_data_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_onu_data_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_ONU_DATA_CFG_ID_MIB_DATA_SYNC)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tmib_data_sync:\t%u\n", p_me_cfg_data->mib_data_sync);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_onu_data_cfg_data_encode(const bcm_omci_onu_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_onu_data_cfg_data_encode(const bcm_omci_onu_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_ONU_DATA_CFG_ID_MIB_DATA_SYNC)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->mib_data_sync))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_onu_data_cfg_encode(const bcm_omci_onu_data_cfg *p_me_onu_data_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_onu_data_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_onu_data_cfg_data_encode(&p_me_onu_data_cfg->data, p_bcm_buf, p_me_onu_data_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_onu_data_cfg_data_decode(bcm_omci_onu_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_ONU_DATA_CFG_ID_MIB_DATA_SYNC)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->mib_data_sync))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* ONU-G (9.1.1) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_onu_g_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_onu_g_cfg *p_src_me_onu_g_cfg = (const bcm_omci_onu_g_cfg *)src_me_cfg;
    bcm_omci_onu_g_cfg *p_dst_me_onu_g_cfg = (bcm_omci_onu_g_cfg *)dst_me_cfg;

    p_dst_me_onu_g_cfg->hdr.presence_mask |= p_src_me_onu_g_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_onu_g_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_VENDOR_ID)) != 0)
    {
        p_dst_me_onu_g_cfg->data.vendor_id = p_src_me_onu_g_cfg->data.vendor_id;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_VERSION)) != 0)
    {
        memcpy(p_dst_me_onu_g_cfg->data.version, p_src_me_onu_g_cfg->data.version, 14);
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_SERIAL_NUMBER)) != 0)
    {
        memcpy(p_dst_me_onu_g_cfg->data.serial_number, p_src_me_onu_g_cfg->data.serial_number, 8);
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_TRAFFIC_MANAGEMENT)) != 0)
    {
        p_dst_me_onu_g_cfg->data.traffic_management = p_src_me_onu_g_cfg->data.traffic_management;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_DEPRECATED0)) != 0)
    {
        p_dst_me_onu_g_cfg->data.deprecated0 = p_src_me_onu_g_cfg->data.deprecated0;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_BATTERY_BACKUP)) != 0)
    {
        p_dst_me_onu_g_cfg->data.battery_backup = p_src_me_onu_g_cfg->data.battery_backup;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_ADMIN_STATE)) != 0)
    {
        p_dst_me_onu_g_cfg->data.admin_state = p_src_me_onu_g_cfg->data.admin_state;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_OPER_STATE)) != 0)
    {
        p_dst_me_onu_g_cfg->data.oper_state = p_src_me_onu_g_cfg->data.oper_state;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_SURVIVAL_TIME)) != 0)
    {
        p_dst_me_onu_g_cfg->data.survival_time = p_src_me_onu_g_cfg->data.survival_time;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_LOGICAL_ONU_ID)) != 0)
    {
        memcpy(p_dst_me_onu_g_cfg->data.logical_onu_id, p_src_me_onu_g_cfg->data.logical_onu_id, 24);
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_LOGICAL_PASSWORD)) != 0)
    {
        memcpy(p_dst_me_onu_g_cfg->data.logical_password, p_src_me_onu_g_cfg->data.logical_password, 12);
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_CREDENTIALS_STATUS)) != 0)
    {
        p_dst_me_onu_g_cfg->data.credentials_status = p_src_me_onu_g_cfg->data.credentials_status;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_EXTENDED_TC_OPTIONS)) != 0)
    {
        p_dst_me_onu_g_cfg->data.extended_tc_options = p_src_me_onu_g_cfg->data.extended_tc_options;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_onu_g_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_onu_g_cfg *p_me_onu_g_cfg = (const bcm_omci_onu_g_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_onu_g_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_ONU_G_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_onu_g_cfg);

    if (BCMOS_TRUE != bcm_omci_onu_g_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_onu_g_cfg_data_bounds_check(&p_me_onu_g_cfg->data, p_me_onu_g_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_onu_g_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_onu_g_cfg_encode(p_me_onu_g_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_onu_g_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_onu_g_cfg *p_me_onu_g_cfg = (bcm_omci_onu_g_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_onu_g_cfg_data_decode(&p_me_onu_g_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_onu_g_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_onu_g_cfg *p_me_onu_g_cfg = (const bcm_omci_onu_g_cfg *)me_hdr;
    const bcm_omci_onu_g_cfg_data *p_me_cfg_data = &p_me_onu_g_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_onu_g_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_onu_g_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_VENDOR_ID)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tvendor_id:\t%u\n", p_me_cfg_data->vendor_id);
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_VERSION)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tversion:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->version)[0], ((const uint8_t *)&p_me_cfg_data->version)[1], ((const uint8_t *)&p_me_cfg_data->version)[2], ((const uint8_t *)&p_me_cfg_data->version)[3], ((const uint8_t *)&p_me_cfg_data->version)[4], ((const uint8_t *)&p_me_cfg_data->version)[5], ((const uint8_t *)&p_me_cfg_data->version)[6], ((const uint8_t *)&p_me_cfg_data->version)[7], ((const uint8_t *)&p_me_cfg_data->version)[8], ((const uint8_t *)&p_me_cfg_data->version)[9], ((const uint8_t *)&p_me_cfg_data->version)[10], ((const uint8_t *)&p_me_cfg_data->version)[11], ((const uint8_t *)&p_me_cfg_data->version)[12], ((const uint8_t *)&p_me_cfg_data->version)[13]);
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_SERIAL_NUMBER)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tserial_number:\t%02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->serial_number)[0], ((const uint8_t *)&p_me_cfg_data->serial_number)[1], ((const uint8_t *)&p_me_cfg_data->serial_number)[2], ((const uint8_t *)&p_me_cfg_data->serial_number)[3], ((const uint8_t *)&p_me_cfg_data->serial_number)[4], ((const uint8_t *)&p_me_cfg_data->serial_number)[5], ((const uint8_t *)&p_me_cfg_data->serial_number)[6], ((const uint8_t *)&p_me_cfg_data->serial_number)[7]);
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_TRAFFIC_MANAGEMENT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttraffic_management:\t%u\n", p_me_cfg_data->traffic_management);
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_DEPRECATED0)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdeprecated0:\t%u\n", p_me_cfg_data->deprecated0);
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_BATTERY_BACKUP)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tbattery_backup:\t%u\n", p_me_cfg_data->battery_backup);
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_ADMIN_STATE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tadmin_state:\t%u\n", p_me_cfg_data->admin_state);
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_OPER_STATE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\toper_state:\t%u\n", p_me_cfg_data->oper_state);
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_SURVIVAL_TIME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsurvival_time:\t%u\n", p_me_cfg_data->survival_time);
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_LOGICAL_ONU_ID)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tlogical_onu_id:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[0], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[1], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[2], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[3], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[4], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[5], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[6], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[7], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[8], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[9], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[10], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[11], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[12], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[13], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[14], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[15], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[16], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[17], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[18], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[19], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[20], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[21], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[22], ((const uint8_t *)&p_me_cfg_data->logical_onu_id)[23]);
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_LOGICAL_PASSWORD)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tlogical_password:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->logical_password)[0], ((const uint8_t *)&p_me_cfg_data->logical_password)[1], ((const uint8_t *)&p_me_cfg_data->logical_password)[2], ((const uint8_t *)&p_me_cfg_data->logical_password)[3], ((const uint8_t *)&p_me_cfg_data->logical_password)[4], ((const uint8_t *)&p_me_cfg_data->logical_password)[5], ((const uint8_t *)&p_me_cfg_data->logical_password)[6], ((const uint8_t *)&p_me_cfg_data->logical_password)[7], ((const uint8_t *)&p_me_cfg_data->logical_password)[8], ((const uint8_t *)&p_me_cfg_data->logical_password)[9], ((const uint8_t *)&p_me_cfg_data->logical_password)[10], ((const uint8_t *)&p_me_cfg_data->logical_password)[11]);
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_CREDENTIALS_STATUS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcredentials_status:\t%u\n", p_me_cfg_data->credentials_status);
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_EXTENDED_TC_OPTIONS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\textended_tc_options:\t0x%x\n", p_me_cfg_data->extended_tc_options);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_onu_g_cfg_data_encode(const bcm_omci_onu_g_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_onu_g_cfg_data_encode(const bcm_omci_onu_g_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_VENDOR_ID)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->vendor_id))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_VERSION)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->version, 14))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_SERIAL_NUMBER)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->serial_number, 8))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_TRAFFIC_MANAGEMENT)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->traffic_management))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_DEPRECATED0)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->deprecated0))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_BATTERY_BACKUP)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->battery_backup))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_ADMIN_STATE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->admin_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_OPER_STATE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->oper_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_SURVIVAL_TIME)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->survival_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_LOGICAL_ONU_ID)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->logical_onu_id, 24))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_LOGICAL_PASSWORD)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->logical_password, 12))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_CREDENTIALS_STATUS)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->credentials_status))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_EXTENDED_TC_OPTIONS)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->extended_tc_options))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_onu_g_cfg_encode(const bcm_omci_onu_g_cfg *p_me_onu_g_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_onu_g_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_onu_g_cfg_data_encode(&p_me_onu_g_cfg->data, p_bcm_buf, p_me_onu_g_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_onu_g_cfg_data_decode(bcm_omci_onu_g_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_VENDOR_ID)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->vendor_id))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_VERSION)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->version, 14))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_SERIAL_NUMBER)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->serial_number, 8))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_TRAFFIC_MANAGEMENT)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->traffic_management))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_DEPRECATED0)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->deprecated0))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_BATTERY_BACKUP)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->battery_backup))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_ADMIN_STATE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->admin_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_OPER_STATE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->oper_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_SURVIVAL_TIME)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->survival_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_LOGICAL_ONU_ID)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->logical_onu_id, 24))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_LOGICAL_PASSWORD)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->logical_password, 12))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_CREDENTIALS_STATUS)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->credentials_status))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU_G_CFG_ID_EXTENDED_TC_OPTIONS)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->extended_tc_options))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* ONU2-G (9.1.2) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_onu2_g_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_onu2_g_cfg *p_src_me_onu2_g_cfg = (const bcm_omci_onu2_g_cfg *)src_me_cfg;
    bcm_omci_onu2_g_cfg *p_dst_me_onu2_g_cfg = (bcm_omci_onu2_g_cfg *)dst_me_cfg;

    p_dst_me_onu2_g_cfg->hdr.presence_mask |= p_src_me_onu2_g_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_onu2_g_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_EQUIPMENT_ID)) != 0)
    {
        memcpy(p_dst_me_onu2_g_cfg->data.equipment_id, p_src_me_onu2_g_cfg->data.equipment_id, 20);
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_OMCC_VERSION)) != 0)
    {
        p_dst_me_onu2_g_cfg->data.omcc_version = p_src_me_onu2_g_cfg->data.omcc_version;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_VENDOR_PRODUCT_CODE)) != 0)
    {
        p_dst_me_onu2_g_cfg->data.vendor_product_code = p_src_me_onu2_g_cfg->data.vendor_product_code;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_SECURITY_CAPABILITY)) != 0)
    {
        p_dst_me_onu2_g_cfg->data.security_capability = p_src_me_onu2_g_cfg->data.security_capability;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_SECURITY_MODE)) != 0)
    {
        p_dst_me_onu2_g_cfg->data.security_mode = p_src_me_onu2_g_cfg->data.security_mode;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_TOTAL_PRIORITY_QUEUE_NUMBER)) != 0)
    {
        p_dst_me_onu2_g_cfg->data.total_priority_queue_number = p_src_me_onu2_g_cfg->data.total_priority_queue_number;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_TOTAL_TRAF_SCHED_NUMBER)) != 0)
    {
        p_dst_me_onu2_g_cfg->data.total_traf_sched_number = p_src_me_onu2_g_cfg->data.total_traf_sched_number;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_DEPRECATED0)) != 0)
    {
        p_dst_me_onu2_g_cfg->data.deprecated0 = p_src_me_onu2_g_cfg->data.deprecated0;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_TOTAL_GEM_PORT_NUMBER)) != 0)
    {
        p_dst_me_onu2_g_cfg->data.total_gem_port_number = p_src_me_onu2_g_cfg->data.total_gem_port_number;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_SYS_UP_TIME)) != 0)
    {
        p_dst_me_onu2_g_cfg->data.sys_up_time = p_src_me_onu2_g_cfg->data.sys_up_time;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_CONNECTIVITY_CAPABILITY)) != 0)
    {
        p_dst_me_onu2_g_cfg->data.connectivity_capability = p_src_me_onu2_g_cfg->data.connectivity_capability;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_CONNECTIVITY_MODE)) != 0)
    {
        p_dst_me_onu2_g_cfg->data.connectivity_mode = p_src_me_onu2_g_cfg->data.connectivity_mode;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_QOS_CONFIG_FLEXIBILITY)) != 0)
    {
        p_dst_me_onu2_g_cfg->data.qos_config_flexibility = p_src_me_onu2_g_cfg->data.qos_config_flexibility;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_PRIORITY_QUEUE_SCALE_FACTOR)) != 0)
    {
        p_dst_me_onu2_g_cfg->data.priority_queue_scale_factor = p_src_me_onu2_g_cfg->data.priority_queue_scale_factor;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_onu2_g_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_onu2_g_cfg *p_me_onu2_g_cfg = (const bcm_omci_onu2_g_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_onu2_g_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_ONU2_G_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_onu2_g_cfg);

    if (BCMOS_TRUE != bcm_omci_onu2_g_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_onu2_g_cfg_data_bounds_check(&p_me_onu2_g_cfg->data, p_me_onu2_g_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_onu2_g_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_onu2_g_cfg_encode(p_me_onu2_g_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_onu2_g_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_onu2_g_cfg *p_me_onu2_g_cfg = (bcm_omci_onu2_g_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_onu2_g_cfg_data_decode(&p_me_onu2_g_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_onu2_g_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_onu2_g_cfg *p_me_onu2_g_cfg = (const bcm_omci_onu2_g_cfg *)me_hdr;
    const bcm_omci_onu2_g_cfg_data *p_me_cfg_data = &p_me_onu2_g_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_onu2_g_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_onu2_g_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_EQUIPMENT_ID)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tequipment_id:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->equipment_id)[0], ((const uint8_t *)&p_me_cfg_data->equipment_id)[1], ((const uint8_t *)&p_me_cfg_data->equipment_id)[2], ((const uint8_t *)&p_me_cfg_data->equipment_id)[3], ((const uint8_t *)&p_me_cfg_data->equipment_id)[4], ((const uint8_t *)&p_me_cfg_data->equipment_id)[5], ((const uint8_t *)&p_me_cfg_data->equipment_id)[6], ((const uint8_t *)&p_me_cfg_data->equipment_id)[7], ((const uint8_t *)&p_me_cfg_data->equipment_id)[8], ((const uint8_t *)&p_me_cfg_data->equipment_id)[9], ((const uint8_t *)&p_me_cfg_data->equipment_id)[10], ((const uint8_t *)&p_me_cfg_data->equipment_id)[11], ((const uint8_t *)&p_me_cfg_data->equipment_id)[12], ((const uint8_t *)&p_me_cfg_data->equipment_id)[13], ((const uint8_t *)&p_me_cfg_data->equipment_id)[14], ((const uint8_t *)&p_me_cfg_data->equipment_id)[15], ((const uint8_t *)&p_me_cfg_data->equipment_id)[16], ((const uint8_t *)&p_me_cfg_data->equipment_id)[17], ((const uint8_t *)&p_me_cfg_data->equipment_id)[18], ((const uint8_t *)&p_me_cfg_data->equipment_id)[19]);
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_OMCC_VERSION)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tomcc_version:\t%u\n", p_me_cfg_data->omcc_version);
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_VENDOR_PRODUCT_CODE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tvendor_product_code:\t0x%x\n", p_me_cfg_data->vendor_product_code);
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_SECURITY_CAPABILITY)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsecurity_capability:\t%u\n", p_me_cfg_data->security_capability);
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_SECURITY_MODE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsecurity_mode:\t%u\n", p_me_cfg_data->security_mode);
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_TOTAL_PRIORITY_QUEUE_NUMBER)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttotal_priority_queue_number:\t%u\n", p_me_cfg_data->total_priority_queue_number);
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_TOTAL_TRAF_SCHED_NUMBER)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttotal_traf_sched_number:\t%u\n", p_me_cfg_data->total_traf_sched_number);
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_DEPRECATED0)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdeprecated0:\t%u\n", p_me_cfg_data->deprecated0);
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_TOTAL_GEM_PORT_NUMBER)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttotal_gem_port_number:\t%u\n", p_me_cfg_data->total_gem_port_number);
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_SYS_UP_TIME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsys_up_time:\t%u\n", p_me_cfg_data->sys_up_time);
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_CONNECTIVITY_CAPABILITY)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tconnectivity_capability:\t0x%x\n", p_me_cfg_data->connectivity_capability);
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_CONNECTIVITY_MODE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tconnectivity_mode:\t%u\n", p_me_cfg_data->connectivity_mode);
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_QOS_CONFIG_FLEXIBILITY)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tqos_config_flexibility:\t%u\n", p_me_cfg_data->qos_config_flexibility);
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_PRIORITY_QUEUE_SCALE_FACTOR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpriority_queue_scale_factor:\t%u\n", p_me_cfg_data->priority_queue_scale_factor);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_onu2_g_cfg_data_encode(const bcm_omci_onu2_g_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_onu2_g_cfg_data_encode(const bcm_omci_onu2_g_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_EQUIPMENT_ID)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->equipment_id, 20))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_OMCC_VERSION)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->omcc_version))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_VENDOR_PRODUCT_CODE)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->vendor_product_code))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_SECURITY_CAPABILITY)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->security_capability))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_SECURITY_MODE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->security_mode))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_TOTAL_PRIORITY_QUEUE_NUMBER)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->total_priority_queue_number))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_TOTAL_TRAF_SCHED_NUMBER)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->total_traf_sched_number))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_DEPRECATED0)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->deprecated0))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_TOTAL_GEM_PORT_NUMBER)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->total_gem_port_number))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_SYS_UP_TIME)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->sys_up_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_CONNECTIVITY_CAPABILITY)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->connectivity_capability))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_CONNECTIVITY_MODE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->connectivity_mode))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_QOS_CONFIG_FLEXIBILITY)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->qos_config_flexibility))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_PRIORITY_QUEUE_SCALE_FACTOR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->priority_queue_scale_factor))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_onu2_g_cfg_encode(const bcm_omci_onu2_g_cfg *p_me_onu2_g_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_onu2_g_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_onu2_g_cfg_data_encode(&p_me_onu2_g_cfg->data, p_bcm_buf, p_me_onu2_g_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_onu2_g_cfg_data_decode(bcm_omci_onu2_g_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_EQUIPMENT_ID)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->equipment_id, 20))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_OMCC_VERSION)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->omcc_version))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_VENDOR_PRODUCT_CODE)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->vendor_product_code))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_SECURITY_CAPABILITY)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->security_capability))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_SECURITY_MODE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->security_mode))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_TOTAL_PRIORITY_QUEUE_NUMBER)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->total_priority_queue_number))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_TOTAL_TRAF_SCHED_NUMBER)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->total_traf_sched_number))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_DEPRECATED0)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->deprecated0))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_TOTAL_GEM_PORT_NUMBER)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->total_gem_port_number))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_SYS_UP_TIME)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->sys_up_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_CONNECTIVITY_CAPABILITY)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->connectivity_capability))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_CONNECTIVITY_MODE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->connectivity_mode))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_QOS_CONFIG_FLEXIBILITY)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->qos_config_flexibility))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ONU2_G_CFG_ID_PRIORITY_QUEUE_SCALE_FACTOR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->priority_queue_scale_factor))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* Software image (9.1.4) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_sw_image_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_sw_image_cfg *p_src_me_sw_image_cfg = (const bcm_omci_sw_image_cfg *)src_me_cfg;
    bcm_omci_sw_image_cfg *p_dst_me_sw_image_cfg = (bcm_omci_sw_image_cfg *)dst_me_cfg;

    p_dst_me_sw_image_cfg->hdr.presence_mask |= p_src_me_sw_image_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_sw_image_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_VERSION)) != 0)
    {
        memcpy(p_dst_me_sw_image_cfg->data.version, p_src_me_sw_image_cfg->data.version, 14);
    }
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_IS_COMMITTED)) != 0)
    {
        p_dst_me_sw_image_cfg->data.is_committed = p_src_me_sw_image_cfg->data.is_committed;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_IS_ACTIVE)) != 0)
    {
        p_dst_me_sw_image_cfg->data.is_active = p_src_me_sw_image_cfg->data.is_active;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_IS_VALID)) != 0)
    {
        p_dst_me_sw_image_cfg->data.is_valid = p_src_me_sw_image_cfg->data.is_valid;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_PRODUCT_CODE)) != 0)
    {
        memcpy(p_dst_me_sw_image_cfg->data.product_code, p_src_me_sw_image_cfg->data.product_code, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_IMAGE_HASH)) != 0)
    {
        memcpy(p_dst_me_sw_image_cfg->data.image_hash, p_src_me_sw_image_cfg->data.image_hash, 16);
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_sw_image_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_sw_image_cfg *p_me_sw_image_cfg = (const bcm_omci_sw_image_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_sw_image_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_SW_IMAGE_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_sw_image_cfg);

    if (BCMOS_TRUE != bcm_omci_sw_image_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_sw_image_cfg_data_bounds_check(&p_me_sw_image_cfg->data, p_me_sw_image_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_sw_image_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_sw_image_cfg_encode(p_me_sw_image_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_sw_image_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_sw_image_cfg *p_me_sw_image_cfg = (bcm_omci_sw_image_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_sw_image_cfg_data_decode(&p_me_sw_image_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_sw_image_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_sw_image_cfg *p_me_sw_image_cfg = (const bcm_omci_sw_image_cfg *)me_hdr;
    const bcm_omci_sw_image_cfg_data *p_me_cfg_data = &p_me_sw_image_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_sw_image_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_sw_image_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_VERSION)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tversion:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->version)[0], ((const uint8_t *)&p_me_cfg_data->version)[1], ((const uint8_t *)&p_me_cfg_data->version)[2], ((const uint8_t *)&p_me_cfg_data->version)[3], ((const uint8_t *)&p_me_cfg_data->version)[4], ((const uint8_t *)&p_me_cfg_data->version)[5], ((const uint8_t *)&p_me_cfg_data->version)[6], ((const uint8_t *)&p_me_cfg_data->version)[7], ((const uint8_t *)&p_me_cfg_data->version)[8], ((const uint8_t *)&p_me_cfg_data->version)[9], ((const uint8_t *)&p_me_cfg_data->version)[10], ((const uint8_t *)&p_me_cfg_data->version)[11], ((const uint8_t *)&p_me_cfg_data->version)[12], ((const uint8_t *)&p_me_cfg_data->version)[13]);
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_IS_COMMITTED)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tis_committed:\t%u\n", p_me_cfg_data->is_committed);
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_IS_ACTIVE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tis_active:\t%u\n", p_me_cfg_data->is_active);
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_IS_VALID)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tis_valid:\t%u\n", p_me_cfg_data->is_valid);
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_PRODUCT_CODE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tproduct_code:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->product_code)[0], ((const uint8_t *)&p_me_cfg_data->product_code)[1], ((const uint8_t *)&p_me_cfg_data->product_code)[2], ((const uint8_t *)&p_me_cfg_data->product_code)[3], ((const uint8_t *)&p_me_cfg_data->product_code)[4], ((const uint8_t *)&p_me_cfg_data->product_code)[5], ((const uint8_t *)&p_me_cfg_data->product_code)[6], ((const uint8_t *)&p_me_cfg_data->product_code)[7], ((const uint8_t *)&p_me_cfg_data->product_code)[8], ((const uint8_t *)&p_me_cfg_data->product_code)[9], ((const uint8_t *)&p_me_cfg_data->product_code)[10], ((const uint8_t *)&p_me_cfg_data->product_code)[11], ((const uint8_t *)&p_me_cfg_data->product_code)[12], ((const uint8_t *)&p_me_cfg_data->product_code)[13], ((const uint8_t *)&p_me_cfg_data->product_code)[14], ((const uint8_t *)&p_me_cfg_data->product_code)[15], ((const uint8_t *)&p_me_cfg_data->product_code)[16], ((const uint8_t *)&p_me_cfg_data->product_code)[17], ((const uint8_t *)&p_me_cfg_data->product_code)[18], ((const uint8_t *)&p_me_cfg_data->product_code)[19], ((const uint8_t *)&p_me_cfg_data->product_code)[20], ((const uint8_t *)&p_me_cfg_data->product_code)[21], ((const uint8_t *)&p_me_cfg_data->product_code)[22], ((const uint8_t *)&p_me_cfg_data->product_code)[23], ((const uint8_t *)&p_me_cfg_data->product_code)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_IMAGE_HASH)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\timage_hash:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->image_hash)[0], ((const uint8_t *)&p_me_cfg_data->image_hash)[1], ((const uint8_t *)&p_me_cfg_data->image_hash)[2], ((const uint8_t *)&p_me_cfg_data->image_hash)[3], ((const uint8_t *)&p_me_cfg_data->image_hash)[4], ((const uint8_t *)&p_me_cfg_data->image_hash)[5], ((const uint8_t *)&p_me_cfg_data->image_hash)[6], ((const uint8_t *)&p_me_cfg_data->image_hash)[7], ((const uint8_t *)&p_me_cfg_data->image_hash)[8], ((const uint8_t *)&p_me_cfg_data->image_hash)[9], ((const uint8_t *)&p_me_cfg_data->image_hash)[10], ((const uint8_t *)&p_me_cfg_data->image_hash)[11], ((const uint8_t *)&p_me_cfg_data->image_hash)[12], ((const uint8_t *)&p_me_cfg_data->image_hash)[13], ((const uint8_t *)&p_me_cfg_data->image_hash)[14], ((const uint8_t *)&p_me_cfg_data->image_hash)[15]);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_sw_image_cfg_data_encode(const bcm_omci_sw_image_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_sw_image_cfg_data_encode(const bcm_omci_sw_image_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_VERSION)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->version, 14))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_IS_COMMITTED)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->is_committed))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_IS_ACTIVE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->is_active))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_IS_VALID)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->is_valid))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_PRODUCT_CODE)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->product_code, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_IMAGE_HASH)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->image_hash, 16))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_sw_image_cfg_encode(const bcm_omci_sw_image_cfg *p_me_sw_image_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_sw_image_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_sw_image_cfg_data_encode(&p_me_sw_image_cfg->data, p_bcm_buf, p_me_sw_image_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_sw_image_cfg_data_decode(bcm_omci_sw_image_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_VERSION)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->version, 14))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_IS_COMMITTED)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->is_committed))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_IS_ACTIVE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->is_active))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_IS_VALID)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->is_valid))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_PRODUCT_CODE)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->product_code, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SW_IMAGE_CFG_ID_IMAGE_HASH)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->image_hash, 16))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* ANI-G (9.2.1) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_ani_g_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_ani_g_cfg *p_src_me_ani_g_cfg = (const bcm_omci_ani_g_cfg *)src_me_cfg;
    bcm_omci_ani_g_cfg *p_dst_me_ani_g_cfg = (bcm_omci_ani_g_cfg *)dst_me_cfg;

    p_dst_me_ani_g_cfg->hdr.presence_mask |= p_src_me_ani_g_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_ani_g_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_SR_INDICATION)) != 0)
    {
        p_dst_me_ani_g_cfg->data.sr_indication = p_src_me_ani_g_cfg->data.sr_indication;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_TOTAL_TCONT_NUMBER)) != 0)
    {
        p_dst_me_ani_g_cfg->data.total_tcont_number = p_src_me_ani_g_cfg->data.total_tcont_number;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_GEM_BLOCK_LENGTH)) != 0)
    {
        p_dst_me_ani_g_cfg->data.gem_block_length = p_src_me_ani_g_cfg->data.gem_block_length;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_PIGGY_BACK_DBA_REPORTING)) != 0)
    {
        p_dst_me_ani_g_cfg->data.piggy_back_dba_reporting = p_src_me_ani_g_cfg->data.piggy_back_dba_reporting;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_DEPRECATED)) != 0)
    {
        p_dst_me_ani_g_cfg->data.deprecated = p_src_me_ani_g_cfg->data.deprecated;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_SF_THRESHOLD)) != 0)
    {
        p_dst_me_ani_g_cfg->data.sf_threshold = p_src_me_ani_g_cfg->data.sf_threshold;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_SD_THRESHOLD)) != 0)
    {
        p_dst_me_ani_g_cfg->data.sd_threshold = p_src_me_ani_g_cfg->data.sd_threshold;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_ARC)) != 0)
    {
        p_dst_me_ani_g_cfg->data.arc = p_src_me_ani_g_cfg->data.arc;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_ARC_INTERVAL)) != 0)
    {
        p_dst_me_ani_g_cfg->data.arc_interval = p_src_me_ani_g_cfg->data.arc_interval;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_OPTICAL_SIGNAL_LEVEL)) != 0)
    {
        p_dst_me_ani_g_cfg->data.optical_signal_level = p_src_me_ani_g_cfg->data.optical_signal_level;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_LOWER_OPTICAL_THRESHOLD)) != 0)
    {
        p_dst_me_ani_g_cfg->data.lower_optical_threshold = p_src_me_ani_g_cfg->data.lower_optical_threshold;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_UPPER_OPTICAL_THRESHOLD)) != 0)
    {
        p_dst_me_ani_g_cfg->data.upper_optical_threshold = p_src_me_ani_g_cfg->data.upper_optical_threshold;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_ONU_RESPONSE_TIME)) != 0)
    {
        p_dst_me_ani_g_cfg->data.onu_response_time = p_src_me_ani_g_cfg->data.onu_response_time;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_TRANSMIT_OPTICAL_LEVEL)) != 0)
    {
        p_dst_me_ani_g_cfg->data.transmit_optical_level = p_src_me_ani_g_cfg->data.transmit_optical_level;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_LOWER_TRANSMIT_POWER_THRESHOLD)) != 0)
    {
        p_dst_me_ani_g_cfg->data.lower_transmit_power_threshold = p_src_me_ani_g_cfg->data.lower_transmit_power_threshold;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_UPPER_TRANSMIT_POWER_THRESHOLD)) != 0)
    {
        p_dst_me_ani_g_cfg->data.upper_transmit_power_threshold = p_src_me_ani_g_cfg->data.upper_transmit_power_threshold;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_ani_g_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_ani_g_cfg *p_me_ani_g_cfg = (const bcm_omci_ani_g_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_ani_g_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_ANI_G_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_ani_g_cfg);

    if (BCMOS_TRUE != bcm_omci_ani_g_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_ani_g_cfg_data_bounds_check(&p_me_ani_g_cfg->data, p_me_ani_g_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_ani_g_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_ani_g_cfg_encode(p_me_ani_g_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_ani_g_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_ani_g_cfg *p_me_ani_g_cfg = (bcm_omci_ani_g_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_ani_g_cfg_data_decode(&p_me_ani_g_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_ani_g_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_ani_g_cfg *p_me_ani_g_cfg = (const bcm_omci_ani_g_cfg *)me_hdr;
    const bcm_omci_ani_g_cfg_data *p_me_cfg_data = &p_me_ani_g_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_ani_g_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_ani_g_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_SR_INDICATION)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsr_indication:\t%u\n", p_me_cfg_data->sr_indication);
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_TOTAL_TCONT_NUMBER)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttotal_tcont_number:\t%u\n", p_me_cfg_data->total_tcont_number);
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_GEM_BLOCK_LENGTH)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tgem_block_length:\t%u\n", p_me_cfg_data->gem_block_length);
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_PIGGY_BACK_DBA_REPORTING)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpiggy_back_dba_reporting:\t%u\n", p_me_cfg_data->piggy_back_dba_reporting);
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_DEPRECATED)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdeprecated:\t%u\n", p_me_cfg_data->deprecated);
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_SF_THRESHOLD)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsf_threshold:\t%u\n", p_me_cfg_data->sf_threshold);
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_SD_THRESHOLD)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsd_threshold:\t%u\n", p_me_cfg_data->sd_threshold);
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_ARC)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tarc:\t%u\n", p_me_cfg_data->arc);
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_ARC_INTERVAL)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tarc_interval:\t%u\n", p_me_cfg_data->arc_interval);
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_OPTICAL_SIGNAL_LEVEL)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\toptical_signal_level:\t%u\n", p_me_cfg_data->optical_signal_level);
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_LOWER_OPTICAL_THRESHOLD)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tlower_optical_threshold:\t%u\n", p_me_cfg_data->lower_optical_threshold);
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_UPPER_OPTICAL_THRESHOLD)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tupper_optical_threshold:\t%u\n", p_me_cfg_data->upper_optical_threshold);
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_ONU_RESPONSE_TIME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tonu_response_time:\t%u\n", p_me_cfg_data->onu_response_time);
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_TRANSMIT_OPTICAL_LEVEL)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttransmit_optical_level:\t%u\n", p_me_cfg_data->transmit_optical_level);
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_LOWER_TRANSMIT_POWER_THRESHOLD)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tlower_transmit_power_threshold:\t%u\n", p_me_cfg_data->lower_transmit_power_threshold);
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_UPPER_TRANSMIT_POWER_THRESHOLD)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tupper_transmit_power_threshold:\t%u\n", p_me_cfg_data->upper_transmit_power_threshold);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_ani_g_cfg_data_encode(const bcm_omci_ani_g_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_ani_g_cfg_data_encode(const bcm_omci_ani_g_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_SR_INDICATION)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->sr_indication))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_TOTAL_TCONT_NUMBER)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->total_tcont_number))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_GEM_BLOCK_LENGTH)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->gem_block_length))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_PIGGY_BACK_DBA_REPORTING)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->piggy_back_dba_reporting))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_DEPRECATED)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->deprecated))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_SF_THRESHOLD)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->sf_threshold))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_SD_THRESHOLD)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->sd_threshold))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_ARC)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->arc))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_ARC_INTERVAL)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->arc_interval))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_OPTICAL_SIGNAL_LEVEL)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->optical_signal_level))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_LOWER_OPTICAL_THRESHOLD)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->lower_optical_threshold))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_UPPER_OPTICAL_THRESHOLD)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->upper_optical_threshold))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_ONU_RESPONSE_TIME)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->onu_response_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_TRANSMIT_OPTICAL_LEVEL)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->transmit_optical_level))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_LOWER_TRANSMIT_POWER_THRESHOLD)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->lower_transmit_power_threshold))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_UPPER_TRANSMIT_POWER_THRESHOLD)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->upper_transmit_power_threshold))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_ani_g_cfg_encode(const bcm_omci_ani_g_cfg *p_me_ani_g_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_ani_g_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_ani_g_cfg_data_encode(&p_me_ani_g_cfg->data, p_bcm_buf, p_me_ani_g_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_ani_g_cfg_data_decode(bcm_omci_ani_g_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_SR_INDICATION)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->sr_indication))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_TOTAL_TCONT_NUMBER)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->total_tcont_number))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_GEM_BLOCK_LENGTH)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->gem_block_length))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_PIGGY_BACK_DBA_REPORTING)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->piggy_back_dba_reporting))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_DEPRECATED)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->deprecated))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_SF_THRESHOLD)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->sf_threshold))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_SD_THRESHOLD)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->sd_threshold))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_ARC)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->arc))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_ARC_INTERVAL)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->arc_interval))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_OPTICAL_SIGNAL_LEVEL)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->optical_signal_level))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_LOWER_OPTICAL_THRESHOLD)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->lower_optical_threshold))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_UPPER_OPTICAL_THRESHOLD)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->upper_optical_threshold))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_ONU_RESPONSE_TIME)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->onu_response_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_TRANSMIT_OPTICAL_LEVEL)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->transmit_optical_level))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_LOWER_TRANSMIT_POWER_THRESHOLD)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->lower_transmit_power_threshold))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ANI_G_CFG_ID_UPPER_TRANSMIT_POWER_THRESHOLD)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->upper_transmit_power_threshold))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* GEM Port Network CTP PM(9.2.13) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_gem_port_net_ctp_pm_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_gem_port_net_ctp_pm_cfg *p_src_me_gem_port_net_ctp_pm_cfg = (const bcm_omci_gem_port_net_ctp_pm_cfg *)src_me_cfg;
    bcm_omci_gem_port_net_ctp_pm_cfg *p_dst_me_gem_port_net_ctp_pm_cfg = (bcm_omci_gem_port_net_ctp_pm_cfg *)dst_me_cfg;

    p_dst_me_gem_port_net_ctp_pm_cfg->hdr.presence_mask |= p_src_me_gem_port_net_ctp_pm_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_gem_port_net_ctp_pm_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_INTERVAL_END_TIME)) != 0)
    {
        p_dst_me_gem_port_net_ctp_pm_cfg->data.interval_end_time = p_src_me_gem_port_net_ctp_pm_cfg->data.interval_end_time;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_THRESHOLD_DATA)) != 0)
    {
        p_dst_me_gem_port_net_ctp_pm_cfg->data.threshold_data = p_src_me_gem_port_net_ctp_pm_cfg->data.threshold_data;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_TX_GEM_FRAMES)) != 0)
    {
        p_dst_me_gem_port_net_ctp_pm_cfg->data.tx_gem_frames = p_src_me_gem_port_net_ctp_pm_cfg->data.tx_gem_frames;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_RX_GEM_FRAMES)) != 0)
    {
        p_dst_me_gem_port_net_ctp_pm_cfg->data.rx_gem_frames = p_src_me_gem_port_net_ctp_pm_cfg->data.rx_gem_frames;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_RX_PAYLOAD_BYTES)) != 0)
    {
        memcpy(p_dst_me_gem_port_net_ctp_pm_cfg->data.rx_payload_bytes, p_src_me_gem_port_net_ctp_pm_cfg->data.rx_payload_bytes, 8);
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_TX_PAYLOAD_BYTES)) != 0)
    {
        memcpy(p_dst_me_gem_port_net_ctp_pm_cfg->data.tx_payload_bytes, p_src_me_gem_port_net_ctp_pm_cfg->data.tx_payload_bytes, 8);
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_ENCRY_KEY_ERRORS)) != 0)
    {
        p_dst_me_gem_port_net_ctp_pm_cfg->data.encry_key_errors = p_src_me_gem_port_net_ctp_pm_cfg->data.encry_key_errors;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_gem_port_net_ctp_pm_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_gem_port_net_ctp_pm_cfg *p_me_gem_port_net_ctp_pm_cfg = (const bcm_omci_gem_port_net_ctp_pm_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_gem_port_net_ctp_pm_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_gem_port_net_ctp_pm_cfg);

    if (BCMOS_TRUE != bcm_omci_gem_port_net_ctp_pm_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_gem_port_net_ctp_pm_cfg_data_bounds_check(&p_me_gem_port_net_ctp_pm_cfg->data, p_me_gem_port_net_ctp_pm_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_gem_port_net_ctp_pm_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_gem_port_net_ctp_pm_cfg_encode(p_me_gem_port_net_ctp_pm_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_gem_port_net_ctp_pm_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_gem_port_net_ctp_pm_cfg *p_me_gem_port_net_ctp_pm_cfg = (bcm_omci_gem_port_net_ctp_pm_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_gem_port_net_ctp_pm_cfg_data_decode(&p_me_gem_port_net_ctp_pm_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_gem_port_net_ctp_pm_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_gem_port_net_ctp_pm_cfg *p_me_gem_port_net_ctp_pm_cfg = (const bcm_omci_gem_port_net_ctp_pm_cfg *)me_hdr;
    const bcm_omci_gem_port_net_ctp_pm_cfg_data *p_me_cfg_data = &p_me_gem_port_net_ctp_pm_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_gem_port_net_ctp_pm_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_gem_port_net_ctp_pm_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_INTERVAL_END_TIME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tinterval_end_time:\t%u\n", p_me_cfg_data->interval_end_time);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_THRESHOLD_DATA)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tthreshold_data:\t%u\n", p_me_cfg_data->threshold_data);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_TX_GEM_FRAMES)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttx_gem_frames:\t%u\n", p_me_cfg_data->tx_gem_frames);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_RX_GEM_FRAMES)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\trx_gem_frames:\t%u\n", p_me_cfg_data->rx_gem_frames);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_RX_PAYLOAD_BYTES)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\trx_payload_bytes:\t%02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->rx_payload_bytes)[0], ((const uint8_t *)&p_me_cfg_data->rx_payload_bytes)[1], ((const uint8_t *)&p_me_cfg_data->rx_payload_bytes)[2], ((const uint8_t *)&p_me_cfg_data->rx_payload_bytes)[3], ((const uint8_t *)&p_me_cfg_data->rx_payload_bytes)[4], ((const uint8_t *)&p_me_cfg_data->rx_payload_bytes)[5], ((const uint8_t *)&p_me_cfg_data->rx_payload_bytes)[6], ((const uint8_t *)&p_me_cfg_data->rx_payload_bytes)[7]);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_TX_PAYLOAD_BYTES)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttx_payload_bytes:\t%02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->tx_payload_bytes)[0], ((const uint8_t *)&p_me_cfg_data->tx_payload_bytes)[1], ((const uint8_t *)&p_me_cfg_data->tx_payload_bytes)[2], ((const uint8_t *)&p_me_cfg_data->tx_payload_bytes)[3], ((const uint8_t *)&p_me_cfg_data->tx_payload_bytes)[4], ((const uint8_t *)&p_me_cfg_data->tx_payload_bytes)[5], ((const uint8_t *)&p_me_cfg_data->tx_payload_bytes)[6], ((const uint8_t *)&p_me_cfg_data->tx_payload_bytes)[7]);
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_ENCRY_KEY_ERRORS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tencry_key_errors:\t%u\n", p_me_cfg_data->encry_key_errors);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_gem_port_net_ctp_pm_cfg_data_encode(const bcm_omci_gem_port_net_ctp_pm_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_gem_port_net_ctp_pm_cfg_data_encode(const bcm_omci_gem_port_net_ctp_pm_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_INTERVAL_END_TIME)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->interval_end_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_THRESHOLD_DATA)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->threshold_data))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_TX_GEM_FRAMES)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->tx_gem_frames))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_RX_GEM_FRAMES)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->rx_gem_frames))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_RX_PAYLOAD_BYTES)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->rx_payload_bytes, 8))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_TX_PAYLOAD_BYTES)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->tx_payload_bytes, 8))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_ENCRY_KEY_ERRORS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->encry_key_errors))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_gem_port_net_ctp_pm_cfg_encode(const bcm_omci_gem_port_net_ctp_pm_cfg *p_me_gem_port_net_ctp_pm_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_gem_port_net_ctp_pm_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_gem_port_net_ctp_pm_cfg_data_encode(&p_me_gem_port_net_ctp_pm_cfg->data, p_bcm_buf, p_me_gem_port_net_ctp_pm_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_gem_port_net_ctp_pm_cfg_data_decode(bcm_omci_gem_port_net_ctp_pm_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_INTERVAL_END_TIME)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->interval_end_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_THRESHOLD_DATA)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->threshold_data))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_TX_GEM_FRAMES)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->tx_gem_frames))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_RX_GEM_FRAMES)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->rx_gem_frames))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_RX_PAYLOAD_BYTES)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->rx_payload_bytes, 8))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_TX_PAYLOAD_BYTES)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->tx_payload_bytes, 8))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_GEM_PORT_NET_CTP_PM_CFG_ID_ENCRY_KEY_ERRORS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->encry_key_errors))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* ETH FRAME UPSTREAM PM(9.3.30) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_eth_frame_upstream_pm_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_eth_frame_upstream_pm_cfg *p_src_me_eth_frame_upstream_pm_cfg = (const bcm_omci_eth_frame_upstream_pm_cfg *)src_me_cfg;
    bcm_omci_eth_frame_upstream_pm_cfg *p_dst_me_eth_frame_upstream_pm_cfg = (bcm_omci_eth_frame_upstream_pm_cfg *)dst_me_cfg;

    p_dst_me_eth_frame_upstream_pm_cfg->hdr.presence_mask |= p_src_me_eth_frame_upstream_pm_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_eth_frame_upstream_pm_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_INTERVAL_END_TIME)) != 0)
    {
        p_dst_me_eth_frame_upstream_pm_cfg->data.interval_end_time = p_src_me_eth_frame_upstream_pm_cfg->data.interval_end_time;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_THRESHOLD_DATA)) != 0)
    {
        p_dst_me_eth_frame_upstream_pm_cfg->data.threshold_data = p_src_me_eth_frame_upstream_pm_cfg->data.threshold_data;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_DROP_EVENTS)) != 0)
    {
        p_dst_me_eth_frame_upstream_pm_cfg->data.up_drop_events = p_src_me_eth_frame_upstream_pm_cfg->data.up_drop_events;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_OCTETS)) != 0)
    {
        p_dst_me_eth_frame_upstream_pm_cfg->data.up_octets = p_src_me_eth_frame_upstream_pm_cfg->data.up_octets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS)) != 0)
    {
        p_dst_me_eth_frame_upstream_pm_cfg->data.up_packets = p_src_me_eth_frame_upstream_pm_cfg->data.up_packets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_BROADCAST_PACKETS)) != 0)
    {
        p_dst_me_eth_frame_upstream_pm_cfg->data.up_broadcast_packets = p_src_me_eth_frame_upstream_pm_cfg->data.up_broadcast_packets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_MULTICAST_PACKETS)) != 0)
    {
        p_dst_me_eth_frame_upstream_pm_cfg->data.up_multicast_packets = p_src_me_eth_frame_upstream_pm_cfg->data.up_multicast_packets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_CRC_ERRORED_PACKETS)) != 0)
    {
        p_dst_me_eth_frame_upstream_pm_cfg->data.up_crc_errored_packets = p_src_me_eth_frame_upstream_pm_cfg->data.up_crc_errored_packets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_UNDERSIZE_PACKETS)) != 0)
    {
        p_dst_me_eth_frame_upstream_pm_cfg->data.up_undersize_packets = p_src_me_eth_frame_upstream_pm_cfg->data.up_undersize_packets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_OVERSIZE_PACKETS)) != 0)
    {
        p_dst_me_eth_frame_upstream_pm_cfg->data.up_oversize_packets = p_src_me_eth_frame_upstream_pm_cfg->data.up_oversize_packets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_64_OCTETS)) != 0)
    {
        p_dst_me_eth_frame_upstream_pm_cfg->data.up_packets_64_octets = p_src_me_eth_frame_upstream_pm_cfg->data.up_packets_64_octets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_65_127_OCTETS)) != 0)
    {
        p_dst_me_eth_frame_upstream_pm_cfg->data.up_packets_65_127_octets = p_src_me_eth_frame_upstream_pm_cfg->data.up_packets_65_127_octets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_128_255_OCTETS)) != 0)
    {
        p_dst_me_eth_frame_upstream_pm_cfg->data.up_packets_128_255_octets = p_src_me_eth_frame_upstream_pm_cfg->data.up_packets_128_255_octets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_256_511_OCTETS)) != 0)
    {
        p_dst_me_eth_frame_upstream_pm_cfg->data.up_packets_256_511_octets = p_src_me_eth_frame_upstream_pm_cfg->data.up_packets_256_511_octets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_512_1023_OCTETS)) != 0)
    {
        p_dst_me_eth_frame_upstream_pm_cfg->data.up_packets_512_1023_octets = p_src_me_eth_frame_upstream_pm_cfg->data.up_packets_512_1023_octets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_1024_1518_OCTETS)) != 0)
    {
        p_dst_me_eth_frame_upstream_pm_cfg->data.up_packets_1024_1518_octets = p_src_me_eth_frame_upstream_pm_cfg->data.up_packets_1024_1518_octets;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_eth_frame_upstream_pm_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_eth_frame_upstream_pm_cfg *p_me_eth_frame_upstream_pm_cfg = (const bcm_omci_eth_frame_upstream_pm_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_eth_frame_upstream_pm_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_eth_frame_upstream_pm_cfg);

    if (BCMOS_TRUE != bcm_omci_eth_frame_upstream_pm_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_eth_frame_upstream_pm_cfg_data_bounds_check(&p_me_eth_frame_upstream_pm_cfg->data, p_me_eth_frame_upstream_pm_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_eth_frame_upstream_pm_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_eth_frame_upstream_pm_cfg_encode(p_me_eth_frame_upstream_pm_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_eth_frame_upstream_pm_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_eth_frame_upstream_pm_cfg *p_me_eth_frame_upstream_pm_cfg = (bcm_omci_eth_frame_upstream_pm_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_eth_frame_upstream_pm_cfg_data_decode(&p_me_eth_frame_upstream_pm_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_eth_frame_upstream_pm_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_eth_frame_upstream_pm_cfg *p_me_eth_frame_upstream_pm_cfg = (const bcm_omci_eth_frame_upstream_pm_cfg *)me_hdr;
    const bcm_omci_eth_frame_upstream_pm_cfg_data *p_me_cfg_data = &p_me_eth_frame_upstream_pm_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_eth_frame_upstream_pm_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_eth_frame_upstream_pm_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_INTERVAL_END_TIME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tinterval_end_time:\t%u\n", p_me_cfg_data->interval_end_time);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_THRESHOLD_DATA)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tthreshold_data:\t%u\n", p_me_cfg_data->threshold_data);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_DROP_EVENTS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tup_drop_events:\t%u\n", p_me_cfg_data->up_drop_events);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_OCTETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tup_octets:\t%u\n", p_me_cfg_data->up_octets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tup_packets:\t%u\n", p_me_cfg_data->up_packets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_BROADCAST_PACKETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tup_broadcast_packets:\t%u\n", p_me_cfg_data->up_broadcast_packets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_MULTICAST_PACKETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tup_multicast_packets:\t%u\n", p_me_cfg_data->up_multicast_packets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_CRC_ERRORED_PACKETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tup_crc_errored_packets:\t%u\n", p_me_cfg_data->up_crc_errored_packets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_UNDERSIZE_PACKETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tup_undersize_packets:\t%u\n", p_me_cfg_data->up_undersize_packets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_OVERSIZE_PACKETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tup_oversize_packets:\t%u\n", p_me_cfg_data->up_oversize_packets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_64_OCTETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tup_packets_64_octets:\t%u\n", p_me_cfg_data->up_packets_64_octets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_65_127_OCTETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tup_packets_65_127_octets:\t%u\n", p_me_cfg_data->up_packets_65_127_octets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_128_255_OCTETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tup_packets_128_255_octets:\t%u\n", p_me_cfg_data->up_packets_128_255_octets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_256_511_OCTETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tup_packets_256_511_octets:\t%u\n", p_me_cfg_data->up_packets_256_511_octets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_512_1023_OCTETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tup_packets_512_1023_octets:\t%u\n", p_me_cfg_data->up_packets_512_1023_octets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_1024_1518_OCTETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tup_packets_1024_1518_octets:\t%u\n", p_me_cfg_data->up_packets_1024_1518_octets);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_eth_frame_upstream_pm_cfg_data_encode(const bcm_omci_eth_frame_upstream_pm_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_eth_frame_upstream_pm_cfg_data_encode(const bcm_omci_eth_frame_upstream_pm_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_INTERVAL_END_TIME)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->interval_end_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_THRESHOLD_DATA)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->threshold_data))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_DROP_EVENTS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->up_drop_events))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->up_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->up_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_BROADCAST_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->up_broadcast_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_MULTICAST_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->up_multicast_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_CRC_ERRORED_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->up_crc_errored_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_UNDERSIZE_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->up_undersize_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_OVERSIZE_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->up_oversize_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_64_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->up_packets_64_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_65_127_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->up_packets_65_127_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_128_255_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->up_packets_128_255_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_256_511_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->up_packets_256_511_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_512_1023_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->up_packets_512_1023_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_1024_1518_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->up_packets_1024_1518_octets))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_eth_frame_upstream_pm_cfg_encode(const bcm_omci_eth_frame_upstream_pm_cfg *p_me_eth_frame_upstream_pm_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_eth_frame_upstream_pm_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_eth_frame_upstream_pm_cfg_data_encode(&p_me_eth_frame_upstream_pm_cfg->data, p_bcm_buf, p_me_eth_frame_upstream_pm_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_eth_frame_upstream_pm_cfg_data_decode(bcm_omci_eth_frame_upstream_pm_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_INTERVAL_END_TIME)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->interval_end_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_THRESHOLD_DATA)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->threshold_data))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_DROP_EVENTS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->up_drop_events))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->up_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->up_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_BROADCAST_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->up_broadcast_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_MULTICAST_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->up_multicast_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_CRC_ERRORED_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->up_crc_errored_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_UNDERSIZE_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->up_undersize_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_OVERSIZE_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->up_oversize_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_64_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->up_packets_64_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_65_127_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->up_packets_65_127_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_128_255_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->up_packets_128_255_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_256_511_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->up_packets_256_511_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_512_1023_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->up_packets_512_1023_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_UPSTREAM_PM_CFG_ID_UP_PACKETS_1024_1518_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->up_packets_1024_1518_octets))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* ETH FRAME DOWNSTREAM PM(9.3.31) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_eth_frame_downstream_pm_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_eth_frame_downstream_pm_cfg *p_src_me_eth_frame_downstream_pm_cfg = (const bcm_omci_eth_frame_downstream_pm_cfg *)src_me_cfg;
    bcm_omci_eth_frame_downstream_pm_cfg *p_dst_me_eth_frame_downstream_pm_cfg = (bcm_omci_eth_frame_downstream_pm_cfg *)dst_me_cfg;

    p_dst_me_eth_frame_downstream_pm_cfg->hdr.presence_mask |= p_src_me_eth_frame_downstream_pm_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_eth_frame_downstream_pm_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_INTERVAL_END_TIME)) != 0)
    {
        p_dst_me_eth_frame_downstream_pm_cfg->data.interval_end_time = p_src_me_eth_frame_downstream_pm_cfg->data.interval_end_time;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_THRESHOLD_DATA)) != 0)
    {
        p_dst_me_eth_frame_downstream_pm_cfg->data.threshold_data = p_src_me_eth_frame_downstream_pm_cfg->data.threshold_data;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_DROP_EVENTS)) != 0)
    {
        p_dst_me_eth_frame_downstream_pm_cfg->data.dn_drop_events = p_src_me_eth_frame_downstream_pm_cfg->data.dn_drop_events;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_OCTETS)) != 0)
    {
        p_dst_me_eth_frame_downstream_pm_cfg->data.dn_octets = p_src_me_eth_frame_downstream_pm_cfg->data.dn_octets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS)) != 0)
    {
        p_dst_me_eth_frame_downstream_pm_cfg->data.dn_packets = p_src_me_eth_frame_downstream_pm_cfg->data.dn_packets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_BROADCAST_PACKETS)) != 0)
    {
        p_dst_me_eth_frame_downstream_pm_cfg->data.dn_broadcast_packets = p_src_me_eth_frame_downstream_pm_cfg->data.dn_broadcast_packets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_MULTICAST_PACKETS)) != 0)
    {
        p_dst_me_eth_frame_downstream_pm_cfg->data.dn_multicast_packets = p_src_me_eth_frame_downstream_pm_cfg->data.dn_multicast_packets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_CRC_ERRORED_PACKETS)) != 0)
    {
        p_dst_me_eth_frame_downstream_pm_cfg->data.dn_crc_errored_packets = p_src_me_eth_frame_downstream_pm_cfg->data.dn_crc_errored_packets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_UNDERSIZE_PACKETS)) != 0)
    {
        p_dst_me_eth_frame_downstream_pm_cfg->data.dn_undersize_packets = p_src_me_eth_frame_downstream_pm_cfg->data.dn_undersize_packets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_OVERSIZE_PACKETS)) != 0)
    {
        p_dst_me_eth_frame_downstream_pm_cfg->data.dn_oversize_packets = p_src_me_eth_frame_downstream_pm_cfg->data.dn_oversize_packets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_64_OCTETS)) != 0)
    {
        p_dst_me_eth_frame_downstream_pm_cfg->data.dn_packets_64_octets = p_src_me_eth_frame_downstream_pm_cfg->data.dn_packets_64_octets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_65_127_OCTETS)) != 0)
    {
        p_dst_me_eth_frame_downstream_pm_cfg->data.dn_packets_65_127_octets = p_src_me_eth_frame_downstream_pm_cfg->data.dn_packets_65_127_octets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_128_255_OCTETS)) != 0)
    {
        p_dst_me_eth_frame_downstream_pm_cfg->data.dn_packets_128_255_octets = p_src_me_eth_frame_downstream_pm_cfg->data.dn_packets_128_255_octets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_256_511_OCTETS)) != 0)
    {
        p_dst_me_eth_frame_downstream_pm_cfg->data.dn_packets_256_511_octets = p_src_me_eth_frame_downstream_pm_cfg->data.dn_packets_256_511_octets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_512_1023_OCTETS)) != 0)
    {
        p_dst_me_eth_frame_downstream_pm_cfg->data.dn_packets_512_1023_octets = p_src_me_eth_frame_downstream_pm_cfg->data.dn_packets_512_1023_octets;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_1024_1518_OCTETS)) != 0)
    {
        p_dst_me_eth_frame_downstream_pm_cfg->data.dn_packets_1024_1518_octets = p_src_me_eth_frame_downstream_pm_cfg->data.dn_packets_1024_1518_octets;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_eth_frame_downstream_pm_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_eth_frame_downstream_pm_cfg *p_me_eth_frame_downstream_pm_cfg = (const bcm_omci_eth_frame_downstream_pm_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_eth_frame_downstream_pm_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_eth_frame_downstream_pm_cfg);

    if (BCMOS_TRUE != bcm_omci_eth_frame_downstream_pm_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_eth_frame_downstream_pm_cfg_data_bounds_check(&p_me_eth_frame_downstream_pm_cfg->data, p_me_eth_frame_downstream_pm_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_eth_frame_downstream_pm_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_eth_frame_downstream_pm_cfg_encode(p_me_eth_frame_downstream_pm_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_eth_frame_downstream_pm_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_eth_frame_downstream_pm_cfg *p_me_eth_frame_downstream_pm_cfg = (bcm_omci_eth_frame_downstream_pm_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_eth_frame_downstream_pm_cfg_data_decode(&p_me_eth_frame_downstream_pm_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_eth_frame_downstream_pm_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_eth_frame_downstream_pm_cfg *p_me_eth_frame_downstream_pm_cfg = (const bcm_omci_eth_frame_downstream_pm_cfg *)me_hdr;
    const bcm_omci_eth_frame_downstream_pm_cfg_data *p_me_cfg_data = &p_me_eth_frame_downstream_pm_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_eth_frame_downstream_pm_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_eth_frame_downstream_pm_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_INTERVAL_END_TIME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tinterval_end_time:\t%u\n", p_me_cfg_data->interval_end_time);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_THRESHOLD_DATA)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tthreshold_data:\t%u\n", p_me_cfg_data->threshold_data);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_DROP_EVENTS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdn_drop_events:\t%u\n", p_me_cfg_data->dn_drop_events);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_OCTETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdn_octets:\t%u\n", p_me_cfg_data->dn_octets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdn_packets:\t%u\n", p_me_cfg_data->dn_packets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_BROADCAST_PACKETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdn_broadcast_packets:\t%u\n", p_me_cfg_data->dn_broadcast_packets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_MULTICAST_PACKETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdn_multicast_packets:\t%u\n", p_me_cfg_data->dn_multicast_packets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_CRC_ERRORED_PACKETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdn_crc_errored_packets:\t%u\n", p_me_cfg_data->dn_crc_errored_packets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_UNDERSIZE_PACKETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdn_undersize_packets:\t%u\n", p_me_cfg_data->dn_undersize_packets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_OVERSIZE_PACKETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdn_oversize_packets:\t%u\n", p_me_cfg_data->dn_oversize_packets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_64_OCTETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdn_packets_64_octets:\t%u\n", p_me_cfg_data->dn_packets_64_octets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_65_127_OCTETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdn_packets_65_127_octets:\t%u\n", p_me_cfg_data->dn_packets_65_127_octets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_128_255_OCTETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdn_packets_128_255_octets:\t%u\n", p_me_cfg_data->dn_packets_128_255_octets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_256_511_OCTETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdn_packets_256_511_octets:\t%u\n", p_me_cfg_data->dn_packets_256_511_octets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_512_1023_OCTETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdn_packets_512_1023_octets:\t%u\n", p_me_cfg_data->dn_packets_512_1023_octets);
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_1024_1518_OCTETS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdn_packets_1024_1518_octets:\t%u\n", p_me_cfg_data->dn_packets_1024_1518_octets);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_eth_frame_downstream_pm_cfg_data_encode(const bcm_omci_eth_frame_downstream_pm_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_eth_frame_downstream_pm_cfg_data_encode(const bcm_omci_eth_frame_downstream_pm_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_INTERVAL_END_TIME)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->interval_end_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_THRESHOLD_DATA)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->threshold_data))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_DROP_EVENTS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->dn_drop_events))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->dn_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->dn_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_BROADCAST_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->dn_broadcast_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_MULTICAST_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->dn_multicast_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_CRC_ERRORED_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->dn_crc_errored_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_UNDERSIZE_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->dn_undersize_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_OVERSIZE_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->dn_oversize_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_64_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->dn_packets_64_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_65_127_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->dn_packets_65_127_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_128_255_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->dn_packets_128_255_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_256_511_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->dn_packets_256_511_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_512_1023_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->dn_packets_512_1023_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_1024_1518_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->dn_packets_1024_1518_octets))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_eth_frame_downstream_pm_cfg_encode(const bcm_omci_eth_frame_downstream_pm_cfg *p_me_eth_frame_downstream_pm_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_eth_frame_downstream_pm_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_eth_frame_downstream_pm_cfg_data_encode(&p_me_eth_frame_downstream_pm_cfg->data, p_bcm_buf, p_me_eth_frame_downstream_pm_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_eth_frame_downstream_pm_cfg_data_decode(bcm_omci_eth_frame_downstream_pm_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_INTERVAL_END_TIME)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->interval_end_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_THRESHOLD_DATA)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->threshold_data))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_DROP_EVENTS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->dn_drop_events))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->dn_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->dn_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_BROADCAST_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->dn_broadcast_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_MULTICAST_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->dn_multicast_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_CRC_ERRORED_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->dn_crc_errored_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_UNDERSIZE_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->dn_undersize_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_OVERSIZE_PACKETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->dn_oversize_packets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_64_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->dn_packets_64_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_65_127_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->dn_packets_65_127_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_128_255_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->dn_packets_128_255_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_256_511_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->dn_packets_256_511_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_512_1023_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->dn_packets_512_1023_octets))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_CFG_ID_DN_PACKETS_1024_1518_OCTETS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->dn_packets_1024_1518_octets))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* FEC PERFORMANCE PM DATA(9.2.9) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_fec_pm_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_fec_pm_cfg *p_src_me_fec_pm_cfg = (const bcm_omci_fec_pm_cfg *)src_me_cfg;
    bcm_omci_fec_pm_cfg *p_dst_me_fec_pm_cfg = (bcm_omci_fec_pm_cfg *)dst_me_cfg;

    p_dst_me_fec_pm_cfg->hdr.presence_mask |= p_src_me_fec_pm_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_fec_pm_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_INTERVAL_END_TIME)) != 0)
    {
        p_dst_me_fec_pm_cfg->data.interval_end_time = p_src_me_fec_pm_cfg->data.interval_end_time;
    }
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_THRESHOLD_DATA)) != 0)
    {
        p_dst_me_fec_pm_cfg->data.threshold_data = p_src_me_fec_pm_cfg->data.threshold_data;
    }
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_CORRECTED_BYTES)) != 0)
    {
        p_dst_me_fec_pm_cfg->data.corrected_bytes = p_src_me_fec_pm_cfg->data.corrected_bytes;
    }
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_CORRECTED_CODE_WORDS)) != 0)
    {
        p_dst_me_fec_pm_cfg->data.corrected_code_words = p_src_me_fec_pm_cfg->data.corrected_code_words;
    }
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_UNCORRECTABLE_CODE_WORDS)) != 0)
    {
        p_dst_me_fec_pm_cfg->data.uncorrectable_code_words = p_src_me_fec_pm_cfg->data.uncorrectable_code_words;
    }
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_TOTAL_CODE_WORDS)) != 0)
    {
        p_dst_me_fec_pm_cfg->data.total_code_words = p_src_me_fec_pm_cfg->data.total_code_words;
    }
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_FEC_SECONDS)) != 0)
    {
        p_dst_me_fec_pm_cfg->data.fec_seconds = p_src_me_fec_pm_cfg->data.fec_seconds;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_fec_pm_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_fec_pm_cfg *p_me_fec_pm_cfg = (const bcm_omci_fec_pm_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_fec_pm_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_FEC_PM_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_fec_pm_cfg);

    if (BCMOS_TRUE != bcm_omci_fec_pm_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_fec_pm_cfg_data_bounds_check(&p_me_fec_pm_cfg->data, p_me_fec_pm_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_fec_pm_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_fec_pm_cfg_encode(p_me_fec_pm_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_fec_pm_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_fec_pm_cfg *p_me_fec_pm_cfg = (bcm_omci_fec_pm_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_fec_pm_cfg_data_decode(&p_me_fec_pm_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_fec_pm_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_fec_pm_cfg *p_me_fec_pm_cfg = (const bcm_omci_fec_pm_cfg *)me_hdr;
    const bcm_omci_fec_pm_cfg_data *p_me_cfg_data = &p_me_fec_pm_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_fec_pm_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_fec_pm_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_INTERVAL_END_TIME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tinterval_end_time:\t%u\n", p_me_cfg_data->interval_end_time);
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_THRESHOLD_DATA)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tthreshold_data:\t%u\n", p_me_cfg_data->threshold_data);
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_CORRECTED_BYTES)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcorrected_bytes:\t%u\n", p_me_cfg_data->corrected_bytes);
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_CORRECTED_CODE_WORDS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcorrected_code_words:\t%u\n", p_me_cfg_data->corrected_code_words);
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_UNCORRECTABLE_CODE_WORDS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tuncorrectable_code_words:\t%u\n", p_me_cfg_data->uncorrectable_code_words);
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_TOTAL_CODE_WORDS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttotal_code_words:\t%u\n", p_me_cfg_data->total_code_words);
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_FEC_SECONDS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tfec_seconds:\t%u\n", p_me_cfg_data->fec_seconds);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_fec_pm_cfg_data_encode(const bcm_omci_fec_pm_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_fec_pm_cfg_data_encode(const bcm_omci_fec_pm_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_INTERVAL_END_TIME)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->interval_end_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_THRESHOLD_DATA)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->threshold_data))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_CORRECTED_BYTES)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->corrected_bytes))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_CORRECTED_CODE_WORDS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->corrected_code_words))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_UNCORRECTABLE_CODE_WORDS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->uncorrectable_code_words))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_TOTAL_CODE_WORDS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->total_code_words))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_FEC_SECONDS)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->fec_seconds))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_fec_pm_cfg_encode(const bcm_omci_fec_pm_cfg *p_me_fec_pm_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_fec_pm_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_fec_pm_cfg_data_encode(&p_me_fec_pm_cfg->data, p_bcm_buf, p_me_fec_pm_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_fec_pm_cfg_data_decode(bcm_omci_fec_pm_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_INTERVAL_END_TIME)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->interval_end_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_THRESHOLD_DATA)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->threshold_data))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_CORRECTED_BYTES)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->corrected_bytes))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_CORRECTED_CODE_WORDS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->corrected_code_words))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_UNCORRECTABLE_CODE_WORDS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->uncorrectable_code_words))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_TOTAL_CODE_WORDS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->total_code_words))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_FEC_PM_CFG_ID_FEC_SECONDS)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->fec_seconds))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* XG-PON TC PERFORMANCE PM DATA(9.2.15) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_xgpon_tc_pm_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_xgpon_tc_pm_cfg *p_src_me_xgpon_tc_pm_cfg = (const bcm_omci_xgpon_tc_pm_cfg *)src_me_cfg;
    bcm_omci_xgpon_tc_pm_cfg *p_dst_me_xgpon_tc_pm_cfg = (bcm_omci_xgpon_tc_pm_cfg *)dst_me_cfg;

    p_dst_me_xgpon_tc_pm_cfg->hdr.presence_mask |= p_src_me_xgpon_tc_pm_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_xgpon_tc_pm_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_INTERVAL_END_TIME)) != 0)
    {
        p_dst_me_xgpon_tc_pm_cfg->data.interval_end_time = p_src_me_xgpon_tc_pm_cfg->data.interval_end_time;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_THRESHOLD_DATA)) != 0)
    {
        p_dst_me_xgpon_tc_pm_cfg->data.threshold_data = p_src_me_xgpon_tc_pm_cfg->data.threshold_data;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_PSBD_HEC_ERROR_COUNT)) != 0)
    {
        p_dst_me_xgpon_tc_pm_cfg->data.psbd_hec_error_count = p_src_me_xgpon_tc_pm_cfg->data.psbd_hec_error_count;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_XGTC_HEC_ERROR_COUNT)) != 0)
    {
        p_dst_me_xgpon_tc_pm_cfg->data.xgtc_hec_error_count = p_src_me_xgpon_tc_pm_cfg->data.xgtc_hec_error_count;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_UNKNOWN_PROFILE_COUNT)) != 0)
    {
        p_dst_me_xgpon_tc_pm_cfg->data.unknown_profile_count = p_src_me_xgpon_tc_pm_cfg->data.unknown_profile_count;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_TRANSMITTED_XGEM_FRAMES)) != 0)
    {
        p_dst_me_xgpon_tc_pm_cfg->data.transmitted_xgem_frames = p_src_me_xgpon_tc_pm_cfg->data.transmitted_xgem_frames;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_FRAGMENT_XGEM_FRAMES)) != 0)
    {
        p_dst_me_xgpon_tc_pm_cfg->data.fragment_xgem_frames = p_src_me_xgpon_tc_pm_cfg->data.fragment_xgem_frames;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_HEC_LOST_WORDS_COUNT)) != 0)
    {
        p_dst_me_xgpon_tc_pm_cfg->data.xgem_hec_lost_words_count = p_src_me_xgpon_tc_pm_cfg->data.xgem_hec_lost_words_count;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_KEY_ERRORS)) != 0)
    {
        p_dst_me_xgpon_tc_pm_cfg->data.xgem_key_errors = p_src_me_xgpon_tc_pm_cfg->data.xgem_key_errors;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_HEC_ERROR_COUNT)) != 0)
    {
        p_dst_me_xgpon_tc_pm_cfg->data.xgem_hec_error_count = p_src_me_xgpon_tc_pm_cfg->data.xgem_hec_error_count;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_TX_BYTES_IN_NON_IDLE_XGEM_FRAMES)) != 0)
    {
        memcpy(p_dst_me_xgpon_tc_pm_cfg->data.tx_bytes_in_non_idle_xgem_frames, p_src_me_xgpon_tc_pm_cfg->data.tx_bytes_in_non_idle_xgem_frames, 8);
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_RX_BYTES_IN_NON_IDLE_XGEM_FRAMES)) != 0)
    {
        memcpy(p_dst_me_xgpon_tc_pm_cfg->data.rx_bytes_in_non_idle_xgem_frames, p_src_me_xgpon_tc_pm_cfg->data.rx_bytes_in_non_idle_xgem_frames, 8);
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_LODS_EVENT_COUNT)) != 0)
    {
        p_dst_me_xgpon_tc_pm_cfg->data.lods_event_count = p_src_me_xgpon_tc_pm_cfg->data.lods_event_count;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_LODS_EVENT_RESTORED_COUNT)) != 0)
    {
        p_dst_me_xgpon_tc_pm_cfg->data.lods_event_restored_count = p_src_me_xgpon_tc_pm_cfg->data.lods_event_restored_count;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_ONU_REACTIVATION_BY_LODS_EVENTS)) != 0)
    {
        p_dst_me_xgpon_tc_pm_cfg->data.onu_reactivation_by_lods_events = p_src_me_xgpon_tc_pm_cfg->data.onu_reactivation_by_lods_events;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_xgpon_tc_pm_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_xgpon_tc_pm_cfg *p_me_xgpon_tc_pm_cfg = (const bcm_omci_xgpon_tc_pm_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_xgpon_tc_pm_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_XGPON_TC_PM_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_xgpon_tc_pm_cfg);

    if (BCMOS_TRUE != bcm_omci_xgpon_tc_pm_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_xgpon_tc_pm_cfg_data_bounds_check(&p_me_xgpon_tc_pm_cfg->data, p_me_xgpon_tc_pm_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_xgpon_tc_pm_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_xgpon_tc_pm_cfg_encode(p_me_xgpon_tc_pm_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_xgpon_tc_pm_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_xgpon_tc_pm_cfg *p_me_xgpon_tc_pm_cfg = (bcm_omci_xgpon_tc_pm_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_xgpon_tc_pm_cfg_data_decode(&p_me_xgpon_tc_pm_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_xgpon_tc_pm_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_xgpon_tc_pm_cfg *p_me_xgpon_tc_pm_cfg = (const bcm_omci_xgpon_tc_pm_cfg *)me_hdr;
    const bcm_omci_xgpon_tc_pm_cfg_data *p_me_cfg_data = &p_me_xgpon_tc_pm_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_xgpon_tc_pm_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_xgpon_tc_pm_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_INTERVAL_END_TIME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tinterval_end_time:\t%u\n", p_me_cfg_data->interval_end_time);
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_THRESHOLD_DATA)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tthreshold_data:\t%u\n", p_me_cfg_data->threshold_data);
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_PSBD_HEC_ERROR_COUNT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpsbd_hec_error_count:\t%u\n", p_me_cfg_data->psbd_hec_error_count);
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_XGTC_HEC_ERROR_COUNT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\txgtc_hec_error_count:\t%u\n", p_me_cfg_data->xgtc_hec_error_count);
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_UNKNOWN_PROFILE_COUNT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tunknown_profile_count:\t%u\n", p_me_cfg_data->unknown_profile_count);
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_TRANSMITTED_XGEM_FRAMES)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttransmitted_xgem_frames:\t%u\n", p_me_cfg_data->transmitted_xgem_frames);
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_FRAGMENT_XGEM_FRAMES)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tfragment_xgem_frames:\t%u\n", p_me_cfg_data->fragment_xgem_frames);
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_HEC_LOST_WORDS_COUNT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\txgem_hec_lost_words_count:\t%u\n", p_me_cfg_data->xgem_hec_lost_words_count);
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_KEY_ERRORS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\txgem_key_errors:\t%u\n", p_me_cfg_data->xgem_key_errors);
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_HEC_ERROR_COUNT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\txgem_hec_error_count:\t%u\n", p_me_cfg_data->xgem_hec_error_count);
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_TX_BYTES_IN_NON_IDLE_XGEM_FRAMES)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttx_bytes_in_non_idle_xgem_frames:\t%02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->tx_bytes_in_non_idle_xgem_frames)[0], ((const uint8_t *)&p_me_cfg_data->tx_bytes_in_non_idle_xgem_frames)[1], ((const uint8_t *)&p_me_cfg_data->tx_bytes_in_non_idle_xgem_frames)[2], ((const uint8_t *)&p_me_cfg_data->tx_bytes_in_non_idle_xgem_frames)[3], ((const uint8_t *)&p_me_cfg_data->tx_bytes_in_non_idle_xgem_frames)[4], ((const uint8_t *)&p_me_cfg_data->tx_bytes_in_non_idle_xgem_frames)[5], ((const uint8_t *)&p_me_cfg_data->tx_bytes_in_non_idle_xgem_frames)[6], ((const uint8_t *)&p_me_cfg_data->tx_bytes_in_non_idle_xgem_frames)[7]);
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_RX_BYTES_IN_NON_IDLE_XGEM_FRAMES)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\trx_bytes_in_non_idle_xgem_frames:\t%02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->rx_bytes_in_non_idle_xgem_frames)[0], ((const uint8_t *)&p_me_cfg_data->rx_bytes_in_non_idle_xgem_frames)[1], ((const uint8_t *)&p_me_cfg_data->rx_bytes_in_non_idle_xgem_frames)[2], ((const uint8_t *)&p_me_cfg_data->rx_bytes_in_non_idle_xgem_frames)[3], ((const uint8_t *)&p_me_cfg_data->rx_bytes_in_non_idle_xgem_frames)[4], ((const uint8_t *)&p_me_cfg_data->rx_bytes_in_non_idle_xgem_frames)[5], ((const uint8_t *)&p_me_cfg_data->rx_bytes_in_non_idle_xgem_frames)[6], ((const uint8_t *)&p_me_cfg_data->rx_bytes_in_non_idle_xgem_frames)[7]);
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_LODS_EVENT_COUNT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tlods_event_count:\t%u\n", p_me_cfg_data->lods_event_count);
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_LODS_EVENT_RESTORED_COUNT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tlods_event_restored_count:\t%u\n", p_me_cfg_data->lods_event_restored_count);
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_ONU_REACTIVATION_BY_LODS_EVENTS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tonu_reactivation_by_lods_events:\t%u\n", p_me_cfg_data->onu_reactivation_by_lods_events);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_xgpon_tc_pm_cfg_data_encode(const bcm_omci_xgpon_tc_pm_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_xgpon_tc_pm_cfg_data_encode(const bcm_omci_xgpon_tc_pm_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_INTERVAL_END_TIME)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->interval_end_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_THRESHOLD_DATA)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->threshold_data))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_PSBD_HEC_ERROR_COUNT)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->psbd_hec_error_count))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_XGTC_HEC_ERROR_COUNT)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->xgtc_hec_error_count))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_UNKNOWN_PROFILE_COUNT)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->unknown_profile_count))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_TRANSMITTED_XGEM_FRAMES)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->transmitted_xgem_frames))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_FRAGMENT_XGEM_FRAMES)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->fragment_xgem_frames))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_HEC_LOST_WORDS_COUNT)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->xgem_hec_lost_words_count))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_KEY_ERRORS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->xgem_key_errors))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_HEC_ERROR_COUNT)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->xgem_hec_error_count))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_TX_BYTES_IN_NON_IDLE_XGEM_FRAMES)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->tx_bytes_in_non_idle_xgem_frames, 8))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_RX_BYTES_IN_NON_IDLE_XGEM_FRAMES)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->rx_bytes_in_non_idle_xgem_frames, 8))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_LODS_EVENT_COUNT)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->lods_event_count))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_LODS_EVENT_RESTORED_COUNT)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->lods_event_restored_count))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_ONU_REACTIVATION_BY_LODS_EVENTS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->onu_reactivation_by_lods_events))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_xgpon_tc_pm_cfg_encode(const bcm_omci_xgpon_tc_pm_cfg *p_me_xgpon_tc_pm_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_xgpon_tc_pm_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_xgpon_tc_pm_cfg_data_encode(&p_me_xgpon_tc_pm_cfg->data, p_bcm_buf, p_me_xgpon_tc_pm_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_xgpon_tc_pm_cfg_data_decode(bcm_omci_xgpon_tc_pm_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_INTERVAL_END_TIME)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->interval_end_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_THRESHOLD_DATA)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->threshold_data))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_PSBD_HEC_ERROR_COUNT)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->psbd_hec_error_count))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_XGTC_HEC_ERROR_COUNT)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->xgtc_hec_error_count))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_UNKNOWN_PROFILE_COUNT)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->unknown_profile_count))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_TRANSMITTED_XGEM_FRAMES)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->transmitted_xgem_frames))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_FRAGMENT_XGEM_FRAMES)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->fragment_xgem_frames))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_HEC_LOST_WORDS_COUNT)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->xgem_hec_lost_words_count))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_KEY_ERRORS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->xgem_key_errors))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_XGEM_HEC_ERROR_COUNT)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->xgem_hec_error_count))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_TX_BYTES_IN_NON_IDLE_XGEM_FRAMES)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->tx_bytes_in_non_idle_xgem_frames, 8))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_RX_BYTES_IN_NON_IDLE_XGEM_FRAMES)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->rx_bytes_in_non_idle_xgem_frames, 8))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_LODS_EVENT_COUNT)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->lods_event_count))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_LODS_EVENT_RESTORED_COUNT)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->lods_event_restored_count))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_XGPON_TC_PM_CFG_ID_ONU_REACTIVATION_BY_LODS_EVENTS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->onu_reactivation_by_lods_events))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* IP Host Config Data (9.4.1) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_ip_host_config_data_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_ip_host_config_data_cfg *p_src_me_ip_host_config_data_cfg = (const bcm_omci_ip_host_config_data_cfg *)src_me_cfg;
    bcm_omci_ip_host_config_data_cfg *p_dst_me_ip_host_config_data_cfg = (bcm_omci_ip_host_config_data_cfg *)dst_me_cfg;

    p_dst_me_ip_host_config_data_cfg->hdr.presence_mask |= p_src_me_ip_host_config_data_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_ip_host_config_data_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_IP_OPTIONS)) != 0)
    {
        p_dst_me_ip_host_config_data_cfg->data.ip_options = p_src_me_ip_host_config_data_cfg->data.ip_options;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_MAC_ADDR)) != 0)
    {
        memcpy(p_dst_me_ip_host_config_data_cfg->data.mac_addr, p_src_me_ip_host_config_data_cfg->data.mac_addr, 6);
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_ONU_ID)) != 0)
    {
        memcpy(p_dst_me_ip_host_config_data_cfg->data.onu_id, p_src_me_ip_host_config_data_cfg->data.onu_id, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_IP_ADDRESS)) != 0)
    {
        p_dst_me_ip_host_config_data_cfg->data.ip_address = p_src_me_ip_host_config_data_cfg->data.ip_address;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_MASK)) != 0)
    {
        p_dst_me_ip_host_config_data_cfg->data.mask = p_src_me_ip_host_config_data_cfg->data.mask;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_GATEWAY)) != 0)
    {
        p_dst_me_ip_host_config_data_cfg->data.gateway = p_src_me_ip_host_config_data_cfg->data.gateway;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_PRIMARY_DNS)) != 0)
    {
        p_dst_me_ip_host_config_data_cfg->data.primary_dns = p_src_me_ip_host_config_data_cfg->data.primary_dns;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_SECONDARY_DNS)) != 0)
    {
        p_dst_me_ip_host_config_data_cfg->data.secondary_dns = p_src_me_ip_host_config_data_cfg->data.secondary_dns;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_ADDRESS)) != 0)
    {
        p_dst_me_ip_host_config_data_cfg->data.current_address = p_src_me_ip_host_config_data_cfg->data.current_address;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_MASK)) != 0)
    {
        p_dst_me_ip_host_config_data_cfg->data.current_mask = p_src_me_ip_host_config_data_cfg->data.current_mask;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_GATEWAY)) != 0)
    {
        p_dst_me_ip_host_config_data_cfg->data.current_gateway = p_src_me_ip_host_config_data_cfg->data.current_gateway;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_PRIMARY_DNS)) != 0)
    {
        p_dst_me_ip_host_config_data_cfg->data.current_primary_dns = p_src_me_ip_host_config_data_cfg->data.current_primary_dns;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_SECONDARY_DNS)) != 0)
    {
        p_dst_me_ip_host_config_data_cfg->data.current_secondary_dns = p_src_me_ip_host_config_data_cfg->data.current_secondary_dns;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_DOMAIN_NAME)) != 0)
    {
        memcpy(p_dst_me_ip_host_config_data_cfg->data.domain_name, p_src_me_ip_host_config_data_cfg->data.domain_name, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_HOST_NAME)) != 0)
    {
        memcpy(p_dst_me_ip_host_config_data_cfg->data.host_name, p_src_me_ip_host_config_data_cfg->data.host_name, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_RELAY_AGENT_OPTIONS)) != 0)
    {
        memcpy(p_dst_me_ip_host_config_data_cfg->data.relay_agent_options, p_src_me_ip_host_config_data_cfg->data.relay_agent_options, 2);
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_ip_host_config_data_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_ip_host_config_data_cfg *p_me_ip_host_config_data_cfg = (const bcm_omci_ip_host_config_data_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_ip_host_config_data_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_ip_host_config_data_cfg);

    if (BCMOS_TRUE != bcm_omci_ip_host_config_data_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_ip_host_config_data_cfg_data_bounds_check(&p_me_ip_host_config_data_cfg->data, p_me_ip_host_config_data_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_ip_host_config_data_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_ip_host_config_data_cfg_encode(p_me_ip_host_config_data_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_ip_host_config_data_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_ip_host_config_data_cfg *p_me_ip_host_config_data_cfg = (bcm_omci_ip_host_config_data_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_ip_host_config_data_cfg_data_decode(&p_me_ip_host_config_data_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_ip_host_config_data_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_ip_host_config_data_cfg *p_me_ip_host_config_data_cfg = (const bcm_omci_ip_host_config_data_cfg *)me_hdr;
    const bcm_omci_ip_host_config_data_cfg_data *p_me_cfg_data = &p_me_ip_host_config_data_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_ip_host_config_data_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_ip_host_config_data_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_IP_OPTIONS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tip_options:\t0x%x\n", p_me_cfg_data->ip_options);
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_MAC_ADDR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tmac_addr:\t%02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->mac_addr)[0], ((const uint8_t *)&p_me_cfg_data->mac_addr)[1], ((const uint8_t *)&p_me_cfg_data->mac_addr)[2], ((const uint8_t *)&p_me_cfg_data->mac_addr)[3], ((const uint8_t *)&p_me_cfg_data->mac_addr)[4], ((const uint8_t *)&p_me_cfg_data->mac_addr)[5]);
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_ONU_ID)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tonu_id:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->onu_id)[0], ((const uint8_t *)&p_me_cfg_data->onu_id)[1], ((const uint8_t *)&p_me_cfg_data->onu_id)[2], ((const uint8_t *)&p_me_cfg_data->onu_id)[3], ((const uint8_t *)&p_me_cfg_data->onu_id)[4], ((const uint8_t *)&p_me_cfg_data->onu_id)[5], ((const uint8_t *)&p_me_cfg_data->onu_id)[6], ((const uint8_t *)&p_me_cfg_data->onu_id)[7], ((const uint8_t *)&p_me_cfg_data->onu_id)[8], ((const uint8_t *)&p_me_cfg_data->onu_id)[9], ((const uint8_t *)&p_me_cfg_data->onu_id)[10], ((const uint8_t *)&p_me_cfg_data->onu_id)[11], ((const uint8_t *)&p_me_cfg_data->onu_id)[12], ((const uint8_t *)&p_me_cfg_data->onu_id)[13], ((const uint8_t *)&p_me_cfg_data->onu_id)[14], ((const uint8_t *)&p_me_cfg_data->onu_id)[15], ((const uint8_t *)&p_me_cfg_data->onu_id)[16], ((const uint8_t *)&p_me_cfg_data->onu_id)[17], ((const uint8_t *)&p_me_cfg_data->onu_id)[18], ((const uint8_t *)&p_me_cfg_data->onu_id)[19], ((const uint8_t *)&p_me_cfg_data->onu_id)[20], ((const uint8_t *)&p_me_cfg_data->onu_id)[21], ((const uint8_t *)&p_me_cfg_data->onu_id)[22], ((const uint8_t *)&p_me_cfg_data->onu_id)[23], ((const uint8_t *)&p_me_cfg_data->onu_id)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_IP_ADDRESS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tip_address:\t0x%x\n", p_me_cfg_data->ip_address);
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_MASK)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tmask:\t0x%x\n", p_me_cfg_data->mask);
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_GATEWAY)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tgateway:\t0x%x\n", p_me_cfg_data->gateway);
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_PRIMARY_DNS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tprimary_dns:\t0x%x\n", p_me_cfg_data->primary_dns);
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_SECONDARY_DNS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsecondary_dns:\t0x%x\n", p_me_cfg_data->secondary_dns);
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_ADDRESS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcurrent_address:\t0x%x\n", p_me_cfg_data->current_address);
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_MASK)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcurrent_mask:\t0x%x\n", p_me_cfg_data->current_mask);
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_GATEWAY)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcurrent_gateway:\t0x%x\n", p_me_cfg_data->current_gateway);
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_PRIMARY_DNS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcurrent_primary_dns:\t0x%x\n", p_me_cfg_data->current_primary_dns);
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_SECONDARY_DNS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcurrent_secondary_dns:\t0x%x\n", p_me_cfg_data->current_secondary_dns);
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_DOMAIN_NAME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdomain_name:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->domain_name)[0], ((const uint8_t *)&p_me_cfg_data->domain_name)[1], ((const uint8_t *)&p_me_cfg_data->domain_name)[2], ((const uint8_t *)&p_me_cfg_data->domain_name)[3], ((const uint8_t *)&p_me_cfg_data->domain_name)[4], ((const uint8_t *)&p_me_cfg_data->domain_name)[5], ((const uint8_t *)&p_me_cfg_data->domain_name)[6], ((const uint8_t *)&p_me_cfg_data->domain_name)[7], ((const uint8_t *)&p_me_cfg_data->domain_name)[8], ((const uint8_t *)&p_me_cfg_data->domain_name)[9], ((const uint8_t *)&p_me_cfg_data->domain_name)[10], ((const uint8_t *)&p_me_cfg_data->domain_name)[11], ((const uint8_t *)&p_me_cfg_data->domain_name)[12], ((const uint8_t *)&p_me_cfg_data->domain_name)[13], ((const uint8_t *)&p_me_cfg_data->domain_name)[14], ((const uint8_t *)&p_me_cfg_data->domain_name)[15], ((const uint8_t *)&p_me_cfg_data->domain_name)[16], ((const uint8_t *)&p_me_cfg_data->domain_name)[17], ((const uint8_t *)&p_me_cfg_data->domain_name)[18], ((const uint8_t *)&p_me_cfg_data->domain_name)[19], ((const uint8_t *)&p_me_cfg_data->domain_name)[20], ((const uint8_t *)&p_me_cfg_data->domain_name)[21], ((const uint8_t *)&p_me_cfg_data->domain_name)[22], ((const uint8_t *)&p_me_cfg_data->domain_name)[23], ((const uint8_t *)&p_me_cfg_data->domain_name)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_HOST_NAME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\thost_name:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->host_name)[0], ((const uint8_t *)&p_me_cfg_data->host_name)[1], ((const uint8_t *)&p_me_cfg_data->host_name)[2], ((const uint8_t *)&p_me_cfg_data->host_name)[3], ((const uint8_t *)&p_me_cfg_data->host_name)[4], ((const uint8_t *)&p_me_cfg_data->host_name)[5], ((const uint8_t *)&p_me_cfg_data->host_name)[6], ((const uint8_t *)&p_me_cfg_data->host_name)[7], ((const uint8_t *)&p_me_cfg_data->host_name)[8], ((const uint8_t *)&p_me_cfg_data->host_name)[9], ((const uint8_t *)&p_me_cfg_data->host_name)[10], ((const uint8_t *)&p_me_cfg_data->host_name)[11], ((const uint8_t *)&p_me_cfg_data->host_name)[12], ((const uint8_t *)&p_me_cfg_data->host_name)[13], ((const uint8_t *)&p_me_cfg_data->host_name)[14], ((const uint8_t *)&p_me_cfg_data->host_name)[15], ((const uint8_t *)&p_me_cfg_data->host_name)[16], ((const uint8_t *)&p_me_cfg_data->host_name)[17], ((const uint8_t *)&p_me_cfg_data->host_name)[18], ((const uint8_t *)&p_me_cfg_data->host_name)[19], ((const uint8_t *)&p_me_cfg_data->host_name)[20], ((const uint8_t *)&p_me_cfg_data->host_name)[21], ((const uint8_t *)&p_me_cfg_data->host_name)[22], ((const uint8_t *)&p_me_cfg_data->host_name)[23], ((const uint8_t *)&p_me_cfg_data->host_name)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_RELAY_AGENT_OPTIONS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\trelay_agent_options:\t%02x %02x\n", ((const uint8_t *)&p_me_cfg_data->relay_agent_options)[0], ((const uint8_t *)&p_me_cfg_data->relay_agent_options)[1]);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_ip_host_config_data_cfg_data_encode(const bcm_omci_ip_host_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_ip_host_config_data_cfg_data_encode(const bcm_omci_ip_host_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_IP_OPTIONS)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->ip_options))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_MAC_ADDR)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->mac_addr, 6))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_ONU_ID)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->onu_id, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_IP_ADDRESS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->ip_address))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_MASK)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->mask))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_GATEWAY)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->gateway))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_PRIMARY_DNS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->primary_dns))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_SECONDARY_DNS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->secondary_dns))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_ADDRESS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->current_address))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_MASK)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->current_mask))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_GATEWAY)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->current_gateway))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_PRIMARY_DNS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->current_primary_dns))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_SECONDARY_DNS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->current_secondary_dns))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_DOMAIN_NAME)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->domain_name, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_HOST_NAME)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->host_name, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_RELAY_AGENT_OPTIONS)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->relay_agent_options, 2))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_ip_host_config_data_cfg_encode(const bcm_omci_ip_host_config_data_cfg *p_me_ip_host_config_data_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_ip_host_config_data_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_ip_host_config_data_cfg_data_encode(&p_me_ip_host_config_data_cfg->data, p_bcm_buf, p_me_ip_host_config_data_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_ip_host_config_data_cfg_data_decode(bcm_omci_ip_host_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_IP_OPTIONS)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->ip_options))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_MAC_ADDR)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->mac_addr, 6))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_ONU_ID)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->onu_id, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_IP_ADDRESS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->ip_address))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_MASK)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->mask))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_GATEWAY)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->gateway))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_PRIMARY_DNS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->primary_dns))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_SECONDARY_DNS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->secondary_dns))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_ADDRESS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->current_address))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_MASK)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->current_mask))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_GATEWAY)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->current_gateway))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_PRIMARY_DNS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->current_primary_dns))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_CURRENT_SECONDARY_DNS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->current_secondary_dns))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_DOMAIN_NAME)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->domain_name, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_HOST_NAME)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->host_name, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_IP_HOST_CONFIG_DATA_CFG_ID_RELAY_AGENT_OPTIONS)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->relay_agent_options, 2))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* VoIP Line Status (9.9.11) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_voip_line_status_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_voip_line_status_cfg *p_src_me_voip_line_status_cfg = (const bcm_omci_voip_line_status_cfg *)src_me_cfg;
    bcm_omci_voip_line_status_cfg *p_dst_me_voip_line_status_cfg = (bcm_omci_voip_line_status_cfg *)dst_me_cfg;

    p_dst_me_voip_line_status_cfg->hdr.presence_mask |= p_src_me_voip_line_status_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_voip_line_status_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CODEC)) != 0)
    {
        p_dst_me_voip_line_status_cfg->data.codec = p_src_me_voip_line_status_cfg->data.codec;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_VOICE_SERVER_STATUS)) != 0)
    {
        p_dst_me_voip_line_status_cfg->data.voice_server_status = p_src_me_voip_line_status_cfg->data.voice_server_status;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_PORT_SESSION_TYPE)) != 0)
    {
        p_dst_me_voip_line_status_cfg->data.port_session_type = p_src_me_voip_line_status_cfg->data.port_session_type;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL1_PACKET_PERIOD)) != 0)
    {
        p_dst_me_voip_line_status_cfg->data.call1_packet_period = p_src_me_voip_line_status_cfg->data.call1_packet_period;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL2_PACKET_PERIOD)) != 0)
    {
        p_dst_me_voip_line_status_cfg->data.call2_packet_period = p_src_me_voip_line_status_cfg->data.call2_packet_period;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL1_DEST_ADDRESS)) != 0)
    {
        memcpy(p_dst_me_voip_line_status_cfg->data.call1_dest_address, p_src_me_voip_line_status_cfg->data.call1_dest_address, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL2_DEST_ADDRESS)) != 0)
    {
        memcpy(p_dst_me_voip_line_status_cfg->data.call2_dest_address, p_src_me_voip_line_status_cfg->data.call2_dest_address, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_LINE_STATE)) != 0)
    {
        p_dst_me_voip_line_status_cfg->data.line_state = p_src_me_voip_line_status_cfg->data.line_state;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_EMERGENCY_CALL_STATUS)) != 0)
    {
        p_dst_me_voip_line_status_cfg->data.emergency_call_status = p_src_me_voip_line_status_cfg->data.emergency_call_status;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_voip_line_status_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_voip_line_status_cfg *p_me_voip_line_status_cfg = (const bcm_omci_voip_line_status_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_voip_line_status_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_VOIP_LINE_STATUS_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_voip_line_status_cfg);

    if (BCMOS_TRUE != bcm_omci_voip_line_status_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_voip_line_status_cfg_data_bounds_check(&p_me_voip_line_status_cfg->data, p_me_voip_line_status_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_voip_line_status_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_voip_line_status_cfg_encode(p_me_voip_line_status_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_voip_line_status_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_voip_line_status_cfg *p_me_voip_line_status_cfg = (bcm_omci_voip_line_status_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_voip_line_status_cfg_data_decode(&p_me_voip_line_status_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_voip_line_status_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_voip_line_status_cfg *p_me_voip_line_status_cfg = (const bcm_omci_voip_line_status_cfg *)me_hdr;
    const bcm_omci_voip_line_status_cfg_data *p_me_cfg_data = &p_me_voip_line_status_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_voip_line_status_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_voip_line_status_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CODEC)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcodec:\t%u\n", p_me_cfg_data->codec);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_VOICE_SERVER_STATUS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tvoice_server_status:\t%u\n", p_me_cfg_data->voice_server_status);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_PORT_SESSION_TYPE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tport_session_type:\t%u\n", p_me_cfg_data->port_session_type);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL1_PACKET_PERIOD)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcall1_packet_period:\t%u\n", p_me_cfg_data->call1_packet_period);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL2_PACKET_PERIOD)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcall2_packet_period:\t%u\n", p_me_cfg_data->call2_packet_period);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL1_DEST_ADDRESS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcall1_dest_address:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[0], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[1], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[2], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[3], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[4], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[5], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[6], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[7], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[8], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[9], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[10], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[11], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[12], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[13], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[14], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[15], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[16], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[17], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[18], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[19], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[20], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[21], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[22], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[23], ((const uint8_t *)&p_me_cfg_data->call1_dest_address)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL2_DEST_ADDRESS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcall2_dest_address:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[0], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[1], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[2], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[3], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[4], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[5], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[6], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[7], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[8], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[9], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[10], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[11], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[12], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[13], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[14], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[15], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[16], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[17], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[18], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[19], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[20], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[21], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[22], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[23], ((const uint8_t *)&p_me_cfg_data->call2_dest_address)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_LINE_STATE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tline_state:\t%u\n", p_me_cfg_data->line_state);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_EMERGENCY_CALL_STATUS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\temergency_call_status:\t%u\n", p_me_cfg_data->emergency_call_status);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_voip_line_status_cfg_data_encode(const bcm_omci_voip_line_status_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_voip_line_status_cfg_data_encode(const bcm_omci_voip_line_status_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CODEC)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->codec))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_VOICE_SERVER_STATUS)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->voice_server_status))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_PORT_SESSION_TYPE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->port_session_type))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL1_PACKET_PERIOD)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->call1_packet_period))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL2_PACKET_PERIOD)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->call2_packet_period))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL1_DEST_ADDRESS)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->call1_dest_address, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL2_DEST_ADDRESS)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->call2_dest_address, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_LINE_STATE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->line_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_EMERGENCY_CALL_STATUS)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->emergency_call_status))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_voip_line_status_cfg_encode(const bcm_omci_voip_line_status_cfg *p_me_voip_line_status_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_voip_line_status_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_voip_line_status_cfg_data_encode(&p_me_voip_line_status_cfg->data, p_bcm_buf, p_me_voip_line_status_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_voip_line_status_cfg_data_decode(bcm_omci_voip_line_status_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CODEC)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, (uint16_t *)&p_me_cfg_data->codec))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_VOICE_SERVER_STATUS)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->voice_server_status))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_PORT_SESSION_TYPE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->port_session_type))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL1_PACKET_PERIOD)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->call1_packet_period))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL2_PACKET_PERIOD)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->call2_packet_period))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL1_DEST_ADDRESS)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->call1_dest_address, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_CALL2_DEST_ADDRESS)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->call2_dest_address, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_LINE_STATE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->line_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_LINE_STATUS_CFG_ID_EMERGENCY_CALL_STATUS)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->emergency_call_status))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* VoIP Line Status (9.9.11) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_voip_media_profile_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_voip_media_profile_cfg *p_src_me_voip_media_profile_cfg = (const bcm_omci_voip_media_profile_cfg *)src_me_cfg;
    bcm_omci_voip_media_profile_cfg *p_dst_me_voip_media_profile_cfg = (bcm_omci_voip_media_profile_cfg *)dst_me_cfg;

    p_dst_me_voip_media_profile_cfg->hdr.presence_mask |= p_src_me_voip_media_profile_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_voip_media_profile_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_FAX_MODE)) != 0)
    {
        p_dst_me_voip_media_profile_cfg->data.fax_mode = p_src_me_voip_media_profile_cfg->data.fax_mode;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_VOICE_SERVICE_PROF_PTR)) != 0)
    {
        p_dst_me_voip_media_profile_cfg->data.voice_service_prof_ptr = p_src_me_voip_media_profile_cfg->data.voice_service_prof_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION1)) != 0)
    {
        p_dst_me_voip_media_profile_cfg->data.codec_selection1 = p_src_me_voip_media_profile_cfg->data.codec_selection1;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD1)) != 0)
    {
        p_dst_me_voip_media_profile_cfg->data.packet_period1 = p_src_me_voip_media_profile_cfg->data.packet_period1;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION1)) != 0)
    {
        p_dst_me_voip_media_profile_cfg->data.silence_supression1 = p_src_me_voip_media_profile_cfg->data.silence_supression1;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION2)) != 0)
    {
        p_dst_me_voip_media_profile_cfg->data.codec_selection2 = p_src_me_voip_media_profile_cfg->data.codec_selection2;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD2)) != 0)
    {
        p_dst_me_voip_media_profile_cfg->data.packet_period2 = p_src_me_voip_media_profile_cfg->data.packet_period2;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION2)) != 0)
    {
        p_dst_me_voip_media_profile_cfg->data.silence_supression2 = p_src_me_voip_media_profile_cfg->data.silence_supression2;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION3)) != 0)
    {
        p_dst_me_voip_media_profile_cfg->data.codec_selection3 = p_src_me_voip_media_profile_cfg->data.codec_selection3;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD3)) != 0)
    {
        p_dst_me_voip_media_profile_cfg->data.packet_period3 = p_src_me_voip_media_profile_cfg->data.packet_period3;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION3)) != 0)
    {
        p_dst_me_voip_media_profile_cfg->data.silence_supression3 = p_src_me_voip_media_profile_cfg->data.silence_supression3;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION4)) != 0)
    {
        p_dst_me_voip_media_profile_cfg->data.codec_selection4 = p_src_me_voip_media_profile_cfg->data.codec_selection4;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD4)) != 0)
    {
        p_dst_me_voip_media_profile_cfg->data.packet_period4 = p_src_me_voip_media_profile_cfg->data.packet_period4;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION4)) != 0)
    {
        p_dst_me_voip_media_profile_cfg->data.silence_supression4 = p_src_me_voip_media_profile_cfg->data.silence_supression4;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_OOB_DTMF)) != 0)
    {
        p_dst_me_voip_media_profile_cfg->data.oob_dtmf = p_src_me_voip_media_profile_cfg->data.oob_dtmf;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_RTP_PROFILE_PTR)) != 0)
    {
        p_dst_me_voip_media_profile_cfg->data.rtp_profile_ptr = p_src_me_voip_media_profile_cfg->data.rtp_profile_ptr;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_voip_media_profile_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_voip_media_profile_cfg *p_me_voip_media_profile_cfg = (const bcm_omci_voip_media_profile_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_voip_media_profile_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_voip_media_profile_cfg);

    if (BCMOS_TRUE != bcm_omci_voip_media_profile_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_voip_media_profile_cfg_data_bounds_check(&p_me_voip_media_profile_cfg->data, p_me_voip_media_profile_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_voip_media_profile_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_voip_media_profile_cfg_encode(p_me_voip_media_profile_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_voip_media_profile_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_voip_media_profile_cfg *p_me_voip_media_profile_cfg = (bcm_omci_voip_media_profile_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_voip_media_profile_cfg_data_decode(&p_me_voip_media_profile_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_voip_media_profile_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_voip_media_profile_cfg *p_me_voip_media_profile_cfg = (const bcm_omci_voip_media_profile_cfg *)me_hdr;
    const bcm_omci_voip_media_profile_cfg_data *p_me_cfg_data = &p_me_voip_media_profile_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_voip_media_profile_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_voip_media_profile_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_FAX_MODE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tfax_mode:\t%u\n", p_me_cfg_data->fax_mode);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_VOICE_SERVICE_PROF_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tvoice_service_prof_ptr:\t%u\n", p_me_cfg_data->voice_service_prof_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION1)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcodec_selection1:\t%u\n", p_me_cfg_data->codec_selection1);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD1)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpacket_period1:\t%u\n", p_me_cfg_data->packet_period1);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION1)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsilence_supression1:\t%u\n", p_me_cfg_data->silence_supression1);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION2)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcodec_selection2:\t%u\n", p_me_cfg_data->codec_selection2);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD2)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpacket_period2:\t%u\n", p_me_cfg_data->packet_period2);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION2)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsilence_supression2:\t%u\n", p_me_cfg_data->silence_supression2);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION3)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcodec_selection3:\t%u\n", p_me_cfg_data->codec_selection3);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD3)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpacket_period3:\t%u\n", p_me_cfg_data->packet_period3);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION3)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsilence_supression3:\t%u\n", p_me_cfg_data->silence_supression3);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION4)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcodec_selection4:\t%u\n", p_me_cfg_data->codec_selection4);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD4)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpacket_period4:\t%u\n", p_me_cfg_data->packet_period4);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION4)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsilence_supression4:\t%u\n", p_me_cfg_data->silence_supression4);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_OOB_DTMF)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\toob_dtmf:\t%u\n", p_me_cfg_data->oob_dtmf);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_RTP_PROFILE_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\trtp_profile_ptr:\t%u\n", p_me_cfg_data->rtp_profile_ptr);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_voip_media_profile_cfg_data_encode(const bcm_omci_voip_media_profile_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_voip_media_profile_cfg_data_encode(const bcm_omci_voip_media_profile_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_FAX_MODE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->fax_mode))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_VOICE_SERVICE_PROF_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->voice_service_prof_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION1)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->codec_selection1))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD1)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->packet_period1))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION1)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->silence_supression1))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION2)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->codec_selection2))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD2)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->packet_period2))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION2)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->silence_supression2))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION3)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->codec_selection3))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD3)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->packet_period3))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION3)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->silence_supression3))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION4)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->codec_selection4))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD4)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->packet_period4))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION4)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->silence_supression4))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_OOB_DTMF)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->oob_dtmf))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_RTP_PROFILE_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->rtp_profile_ptr))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_voip_media_profile_cfg_encode(const bcm_omci_voip_media_profile_cfg *p_me_voip_media_profile_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_voip_media_profile_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_voip_media_profile_cfg_data_encode(&p_me_voip_media_profile_cfg->data, p_bcm_buf, p_me_voip_media_profile_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_voip_media_profile_cfg_data_decode(bcm_omci_voip_media_profile_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_FAX_MODE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->fax_mode))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_VOICE_SERVICE_PROF_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->voice_service_prof_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION1)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->codec_selection1))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD1)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->packet_period1))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION1)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->silence_supression1))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION2)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->codec_selection2))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD2)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->packet_period2))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION2)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->silence_supression2))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION3)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->codec_selection3))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD3)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->packet_period3))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION3)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->silence_supression3))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_CODEC_SELECTION4)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->codec_selection4))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_PACKET_PERIOD4)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->packet_period4))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_SILENCE_SUPRESSION4)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->silence_supression4))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_OOB_DTMF)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->oob_dtmf))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_MEDIA_PROFILE_CFG_ID_RTP_PROFILE_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->rtp_profile_ptr))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* SIP User Data (9.9.2) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_sip_user_data_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_sip_user_data_cfg *p_src_me_sip_user_data_cfg = (const bcm_omci_sip_user_data_cfg *)src_me_cfg;
    bcm_omci_sip_user_data_cfg *p_dst_me_sip_user_data_cfg = (bcm_omci_sip_user_data_cfg *)dst_me_cfg;

    p_dst_me_sip_user_data_cfg->hdr.presence_mask |= p_src_me_sip_user_data_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_sip_user_data_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_SIP_AGENT_PTR)) != 0)
    {
        p_dst_me_sip_user_data_cfg->data.sip_agent_ptr = p_src_me_sip_user_data_cfg->data.sip_agent_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_USER_PART_AOR)) != 0)
    {
        p_dst_me_sip_user_data_cfg->data.user_part_aor = p_src_me_sip_user_data_cfg->data.user_part_aor;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_SIP_DISPLAY_NAME)) != 0)
    {
        memcpy(p_dst_me_sip_user_data_cfg->data.sip_display_name, p_src_me_sip_user_data_cfg->data.sip_display_name, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_USERNAME_PASSWORD)) != 0)
    {
        p_dst_me_sip_user_data_cfg->data.username_password = p_src_me_sip_user_data_cfg->data.username_password;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_VOICEMAIL_SERVER_URI)) != 0)
    {
        p_dst_me_sip_user_data_cfg->data.voicemail_server_uri = p_src_me_sip_user_data_cfg->data.voicemail_server_uri;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_VOICEMAIL_SUBSCRIPTION_EXP_TIME)) != 0)
    {
        p_dst_me_sip_user_data_cfg->data.voicemail_subscription_exp_time = p_src_me_sip_user_data_cfg->data.voicemail_subscription_exp_time;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_NETWORK_DIAL_PLAN_PTR)) != 0)
    {
        p_dst_me_sip_user_data_cfg->data.network_dial_plan_ptr = p_src_me_sip_user_data_cfg->data.network_dial_plan_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_APP_SERVICE_PROF_PTR)) != 0)
    {
        p_dst_me_sip_user_data_cfg->data.app_service_prof_ptr = p_src_me_sip_user_data_cfg->data.app_service_prof_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_FEATURE_CODE_PTR)) != 0)
    {
        p_dst_me_sip_user_data_cfg->data.feature_code_ptr = p_src_me_sip_user_data_cfg->data.feature_code_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_PPTP_PTR)) != 0)
    {
        p_dst_me_sip_user_data_cfg->data.pptp_ptr = p_src_me_sip_user_data_cfg->data.pptp_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_RELEASE_TIMER)) != 0)
    {
        p_dst_me_sip_user_data_cfg->data.release_timer = p_src_me_sip_user_data_cfg->data.release_timer;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_ROH_TIMER)) != 0)
    {
        p_dst_me_sip_user_data_cfg->data.roh_timer = p_src_me_sip_user_data_cfg->data.roh_timer;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_sip_user_data_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_sip_user_data_cfg *p_me_sip_user_data_cfg = (const bcm_omci_sip_user_data_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_sip_user_data_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_SIP_USER_DATA_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_sip_user_data_cfg);

    if (BCMOS_TRUE != bcm_omci_sip_user_data_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_sip_user_data_cfg_data_bounds_check(&p_me_sip_user_data_cfg->data, p_me_sip_user_data_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_sip_user_data_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_sip_user_data_cfg_encode(p_me_sip_user_data_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_sip_user_data_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_sip_user_data_cfg *p_me_sip_user_data_cfg = (bcm_omci_sip_user_data_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_sip_user_data_cfg_data_decode(&p_me_sip_user_data_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_sip_user_data_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_sip_user_data_cfg *p_me_sip_user_data_cfg = (const bcm_omci_sip_user_data_cfg *)me_hdr;
    const bcm_omci_sip_user_data_cfg_data *p_me_cfg_data = &p_me_sip_user_data_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_sip_user_data_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_sip_user_data_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_SIP_AGENT_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsip_agent_ptr:\t%u\n", p_me_cfg_data->sip_agent_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_USER_PART_AOR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tuser_part_aor:\t%u\n", p_me_cfg_data->user_part_aor);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_SIP_DISPLAY_NAME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsip_display_name:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->sip_display_name)[0], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[1], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[2], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[3], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[4], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[5], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[6], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[7], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[8], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[9], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[10], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[11], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[12], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[13], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[14], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[15], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[16], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[17], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[18], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[19], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[20], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[21], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[22], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[23], ((const uint8_t *)&p_me_cfg_data->sip_display_name)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_USERNAME_PASSWORD)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tusername_password:\t%u\n", p_me_cfg_data->username_password);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_VOICEMAIL_SERVER_URI)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tvoicemail_server_uri:\t%u\n", p_me_cfg_data->voicemail_server_uri);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_VOICEMAIL_SUBSCRIPTION_EXP_TIME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tvoicemail_subscription_exp_time:\t%u\n", p_me_cfg_data->voicemail_subscription_exp_time);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_NETWORK_DIAL_PLAN_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tnetwork_dial_plan_ptr:\t%u\n", p_me_cfg_data->network_dial_plan_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_APP_SERVICE_PROF_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tapp_service_prof_ptr:\t%u\n", p_me_cfg_data->app_service_prof_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_FEATURE_CODE_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tfeature_code_ptr:\t%u\n", p_me_cfg_data->feature_code_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_PPTP_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpptp_ptr:\t%u\n", p_me_cfg_data->pptp_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_RELEASE_TIMER)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\trelease_timer:\t%u\n", p_me_cfg_data->release_timer);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_ROH_TIMER)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\troh_timer:\t%u\n", p_me_cfg_data->roh_timer);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_sip_user_data_cfg_data_encode(const bcm_omci_sip_user_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_sip_user_data_cfg_data_encode(const bcm_omci_sip_user_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_SIP_AGENT_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->sip_agent_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_USER_PART_AOR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->user_part_aor))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_SIP_DISPLAY_NAME)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->sip_display_name, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_USERNAME_PASSWORD)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->username_password))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_VOICEMAIL_SERVER_URI)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->voicemail_server_uri))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_VOICEMAIL_SUBSCRIPTION_EXP_TIME)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->voicemail_subscription_exp_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_NETWORK_DIAL_PLAN_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->network_dial_plan_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_APP_SERVICE_PROF_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->app_service_prof_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_FEATURE_CODE_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->feature_code_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_PPTP_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->pptp_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_RELEASE_TIMER)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->release_timer))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_ROH_TIMER)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->roh_timer))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_sip_user_data_cfg_encode(const bcm_omci_sip_user_data_cfg *p_me_sip_user_data_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_sip_user_data_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_sip_user_data_cfg_data_encode(&p_me_sip_user_data_cfg->data, p_bcm_buf, p_me_sip_user_data_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_sip_user_data_cfg_data_decode(bcm_omci_sip_user_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_SIP_AGENT_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->sip_agent_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_USER_PART_AOR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->user_part_aor))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_SIP_DISPLAY_NAME)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->sip_display_name, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_USERNAME_PASSWORD)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->username_password))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_VOICEMAIL_SERVER_URI)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->voicemail_server_uri))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_VOICEMAIL_SUBSCRIPTION_EXP_TIME)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->voicemail_subscription_exp_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_NETWORK_DIAL_PLAN_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->network_dial_plan_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_APP_SERVICE_PROF_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->app_service_prof_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_FEATURE_CODE_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->feature_code_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_PPTP_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->pptp_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_RELEASE_TIMER)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->release_timer))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_USER_DATA_CFG_ID_ROH_TIMER)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->roh_timer))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* SIP Agent Config Data (9.9.3) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_sip_agent_config_data_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_sip_agent_config_data_cfg *p_src_me_sip_agent_config_data_cfg = (const bcm_omci_sip_agent_config_data_cfg *)src_me_cfg;
    bcm_omci_sip_agent_config_data_cfg *p_dst_me_sip_agent_config_data_cfg = (bcm_omci_sip_agent_config_data_cfg *)dst_me_cfg;

    p_dst_me_sip_agent_config_data_cfg->hdr.presence_mask |= p_src_me_sip_agent_config_data_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_sip_agent_config_data_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_PROXY_SERVER_ADDR_PTR)) != 0)
    {
        p_dst_me_sip_agent_config_data_cfg->data.proxy_server_addr_ptr = p_src_me_sip_agent_config_data_cfg->data.proxy_server_addr_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_OUTBOUND_PROXY_ADDR_PTR)) != 0)
    {
        p_dst_me_sip_agent_config_data_cfg->data.outbound_proxy_addr_ptr = p_src_me_sip_agent_config_data_cfg->data.outbound_proxy_addr_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_PRIMARY_SIP_DNS)) != 0)
    {
        p_dst_me_sip_agent_config_data_cfg->data.primary_sip_dns = p_src_me_sip_agent_config_data_cfg->data.primary_sip_dns;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SECONDARY_SIP_DNS)) != 0)
    {
        p_dst_me_sip_agent_config_data_cfg->data.secondary_sip_dns = p_src_me_sip_agent_config_data_cfg->data.secondary_sip_dns;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_TCP_UDP_PTR)) != 0)
    {
        p_dst_me_sip_agent_config_data_cfg->data.tcp_udp_ptr = p_src_me_sip_agent_config_data_cfg->data.tcp_udp_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REG_EXP_TIME)) != 0)
    {
        p_dst_me_sip_agent_config_data_cfg->data.sip_reg_exp_time = p_src_me_sip_agent_config_data_cfg->data.sip_reg_exp_time;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REREG_HEAD_START_TIME)) != 0)
    {
        p_dst_me_sip_agent_config_data_cfg->data.sip_rereg_head_start_time = p_src_me_sip_agent_config_data_cfg->data.sip_rereg_head_start_time;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_HOST_PART_URI)) != 0)
    {
        p_dst_me_sip_agent_config_data_cfg->data.host_part_uri = p_src_me_sip_agent_config_data_cfg->data.host_part_uri;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_STATUS)) != 0)
    {
        p_dst_me_sip_agent_config_data_cfg->data.sip_status = p_src_me_sip_agent_config_data_cfg->data.sip_status;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REGISTRAR)) != 0)
    {
        p_dst_me_sip_agent_config_data_cfg->data.sip_registrar = p_src_me_sip_agent_config_data_cfg->data.sip_registrar;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SOFTSWITCH)) != 0)
    {
        p_dst_me_sip_agent_config_data_cfg->data.softswitch = p_src_me_sip_agent_config_data_cfg->data.softswitch;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_RESPONSE_TABLE)) != 0)
    {
        /* doing struct copy */
        p_dst_me_sip_agent_config_data_cfg->data.sip_response_table = p_src_me_sip_agent_config_data_cfg->data.sip_response_table;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_TRANSMIT_CONTROL)) != 0)
    {
        p_dst_me_sip_agent_config_data_cfg->data.sip_transmit_control = p_src_me_sip_agent_config_data_cfg->data.sip_transmit_control;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_URI_FORMAT)) != 0)
    {
        p_dst_me_sip_agent_config_data_cfg->data.sip_uri_format = p_src_me_sip_agent_config_data_cfg->data.sip_uri_format;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_REDUNDANT_SIP_AGENT_PTR)) != 0)
    {
        p_dst_me_sip_agent_config_data_cfg->data.redundant_sip_agent_ptr = p_src_me_sip_agent_config_data_cfg->data.redundant_sip_agent_ptr;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_sip_agent_config_data_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_sip_agent_config_data_cfg *p_me_sip_agent_config_data_cfg = (const bcm_omci_sip_agent_config_data_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_sip_agent_config_data_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_sip_agent_config_data_cfg);

    if (BCMOS_TRUE != bcm_omci_sip_agent_config_data_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_sip_agent_config_data_cfg_data_bounds_check(&p_me_sip_agent_config_data_cfg->data, p_me_sip_agent_config_data_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_sip_agent_config_data_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_sip_agent_config_data_cfg_encode(p_me_sip_agent_config_data_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_sip_agent_config_data_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_sip_agent_config_data_cfg *p_me_sip_agent_config_data_cfg = (bcm_omci_sip_agent_config_data_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_sip_agent_config_data_cfg_data_decode(&p_me_sip_agent_config_data_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */
static bcmos_bool bcm_omci_sip_agent_config_data_sip_response_table_log(const bcm_omci_me_key *key, const bcm_omci_sip_agent_config_data_sip_response_table *this, dev_log_id log_id, bcm_dev_log_level log_level)
{
    BCM_LOG_LEVEL(log_level, log_id, "\t\tresponse_code: %u\n", this->response_code);
    BCM_LOG_LEVEL(log_level, log_id, "\t\ttone: %u\n", this->tone);
    BCM_LOG_LEVEL(log_level, log_id, "\t\ttext_message: %u\n", this->text_message);

    return BCM_ERR_OK;
}

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_sip_agent_config_data_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_sip_agent_config_data_cfg *p_me_sip_agent_config_data_cfg = (const bcm_omci_sip_agent_config_data_cfg *)me_hdr;
    const bcm_omci_sip_agent_config_data_cfg_data *p_me_cfg_data = &p_me_sip_agent_config_data_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_sip_agent_config_data_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_sip_agent_config_data_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_PROXY_SERVER_ADDR_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tproxy_server_addr_ptr:\t%u\n", p_me_cfg_data->proxy_server_addr_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_OUTBOUND_PROXY_ADDR_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\toutbound_proxy_addr_ptr:\t%u\n", p_me_cfg_data->outbound_proxy_addr_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_PRIMARY_SIP_DNS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tprimary_sip_dns:\t0x%x\n", p_me_cfg_data->primary_sip_dns);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SECONDARY_SIP_DNS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsecondary_sip_dns:\t0x%x\n", p_me_cfg_data->secondary_sip_dns);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_TCP_UDP_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttcp_udp_ptr:\t%u\n", p_me_cfg_data->tcp_udp_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REG_EXP_TIME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsip_reg_exp_time:\t%u\n", p_me_cfg_data->sip_reg_exp_time);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REREG_HEAD_START_TIME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsip_rereg_head_start_time:\t%u\n", p_me_cfg_data->sip_rereg_head_start_time);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_HOST_PART_URI)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\thost_part_uri:\t%u\n", p_me_cfg_data->host_part_uri);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_STATUS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsip_status:\t%u\n", p_me_cfg_data->sip_status);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REGISTRAR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsip_registrar:\t%u\n", p_me_cfg_data->sip_registrar);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SOFTSWITCH)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsoftswitch:\t%u\n", p_me_cfg_data->softswitch);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_RESPONSE_TABLE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsip_response_table:\t%02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->sip_response_table)[0], ((const uint8_t *)&p_me_cfg_data->sip_response_table)[1], ((const uint8_t *)&p_me_cfg_data->sip_response_table)[2], ((const uint8_t *)&p_me_cfg_data->sip_response_table)[3], ((const uint8_t *)&p_me_cfg_data->sip_response_table)[4]);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_TRANSMIT_CONTROL)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsip_transmit_control:\t%u\n", p_me_cfg_data->sip_transmit_control);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_URI_FORMAT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsip_uri_format:\t%u\n", p_me_cfg_data->sip_uri_format);
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_REDUNDANT_SIP_AGENT_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tredundant_sip_agent_ptr:\t%u\n", p_me_cfg_data->redundant_sip_agent_ptr);

    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_RESPONSE_TABLE)) != 0)
        bcm_omci_sip_agent_config_data_sip_response_table_log(&me_hdr->key, &p_me_cfg_data->sip_response_table, log_id, log_level);

    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */
static bcmos_bool bcm_omci_sip_agent_config_data_sip_response_table_cfg_data_encode(bcm_omci_buf *p_bcm_buf, const bcm_omci_sip_agent_config_data_sip_response_table *this)
{
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->response_code))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->tone))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->text_message))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

static bcmos_bool bcm_omci_sip_agent_config_data_cfg_data_encode(const bcm_omci_sip_agent_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_sip_agent_config_data_cfg_data_encode(const bcm_omci_sip_agent_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_PROXY_SERVER_ADDR_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->proxy_server_addr_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_OUTBOUND_PROXY_ADDR_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->outbound_proxy_addr_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_PRIMARY_SIP_DNS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->primary_sip_dns))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SECONDARY_SIP_DNS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->secondary_sip_dns))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_TCP_UDP_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->tcp_udp_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REG_EXP_TIME)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->sip_reg_exp_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REREG_HEAD_START_TIME)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->sip_rereg_head_start_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_HOST_PART_URI)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->host_part_uri))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_STATUS)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->sip_status))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REGISTRAR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->sip_registrar))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SOFTSWITCH)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->softswitch))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_RESPONSE_TABLE)) != 0)
    {
        if (!bcm_omci_sip_agent_config_data_sip_response_table_cfg_data_encode(p_bcm_buf, &p_me_cfg_data->sip_response_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_TRANSMIT_CONTROL)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->sip_transmit_control))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_URI_FORMAT)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->sip_uri_format))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_REDUNDANT_SIP_AGENT_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->redundant_sip_agent_ptr))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_sip_agent_config_data_cfg_encode(const bcm_omci_sip_agent_config_data_cfg *p_me_sip_agent_config_data_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_sip_agent_config_data_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_sip_agent_config_data_cfg_data_encode(&p_me_sip_agent_config_data_cfg->data, p_bcm_buf, p_me_sip_agent_config_data_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */
static bcmos_bool bcm_omci_sip_agent_config_data_sip_response_table_cfg_data_decode(bcm_omci_buf *p_bcm_buf, bcm_omci_sip_agent_config_data_sip_response_table *this)
{
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->response_code))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->tone))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->text_message))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_sip_agent_config_data_cfg_data_decode(bcm_omci_sip_agent_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_PROXY_SERVER_ADDR_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->proxy_server_addr_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_OUTBOUND_PROXY_ADDR_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->outbound_proxy_addr_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_PRIMARY_SIP_DNS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->primary_sip_dns))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SECONDARY_SIP_DNS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->secondary_sip_dns))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_TCP_UDP_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->tcp_udp_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REG_EXP_TIME)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->sip_reg_exp_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REREG_HEAD_START_TIME)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->sip_rereg_head_start_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_HOST_PART_URI)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->host_part_uri))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_STATUS)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->sip_status))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_REGISTRAR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->sip_registrar))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SOFTSWITCH)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->softswitch))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_RESPONSE_TABLE)) != 0)
    {
        if (!bcm_omci_sip_agent_config_data_sip_response_table_cfg_data_decode(p_bcm_buf, &p_me_cfg_data->sip_response_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_TRANSMIT_CONTROL)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->sip_transmit_control))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_SIP_URI_FORMAT)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->sip_uri_format))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_SIP_AGENT_CONFIG_DATA_CFG_ID_REDUNDANT_SIP_AGENT_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->redundant_sip_agent_ptr))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* Network Address (9.12.3) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_network_address_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_network_address_cfg *p_src_me_network_address_cfg = (const bcm_omci_network_address_cfg *)src_me_cfg;
    bcm_omci_network_address_cfg *p_dst_me_network_address_cfg = (bcm_omci_network_address_cfg *)dst_me_cfg;

    p_dst_me_network_address_cfg->hdr.presence_mask |= p_src_me_network_address_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_network_address_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_ADDRESS_CFG_ID_SECURITY_PTR)) != 0)
    {
        p_dst_me_network_address_cfg->data.security_ptr = p_src_me_network_address_cfg->data.security_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_ADDRESS_CFG_ID_ADDRESS_PTR)) != 0)
    {
        p_dst_me_network_address_cfg->data.address_ptr = p_src_me_network_address_cfg->data.address_ptr;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_network_address_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_network_address_cfg *p_me_network_address_cfg = (const bcm_omci_network_address_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_network_address_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_NETWORK_ADDRESS_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_network_address_cfg);

    if (BCMOS_TRUE != bcm_omci_network_address_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_network_address_cfg_data_bounds_check(&p_me_network_address_cfg->data, p_me_network_address_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_network_address_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_network_address_cfg_encode(p_me_network_address_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_network_address_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_network_address_cfg *p_me_network_address_cfg = (bcm_omci_network_address_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_network_address_cfg_data_decode(&p_me_network_address_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_network_address_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_network_address_cfg *p_me_network_address_cfg = (const bcm_omci_network_address_cfg *)me_hdr;
    const bcm_omci_network_address_cfg_data *p_me_cfg_data = &p_me_network_address_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_network_address_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_network_address_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_ADDRESS_CFG_ID_SECURITY_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsecurity_ptr:\t%u\n", p_me_cfg_data->security_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_ADDRESS_CFG_ID_ADDRESS_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\taddress_ptr:\t%u\n", p_me_cfg_data->address_ptr);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_network_address_cfg_data_encode(const bcm_omci_network_address_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_network_address_cfg_data_encode(const bcm_omci_network_address_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_ADDRESS_CFG_ID_SECURITY_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->security_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_ADDRESS_CFG_ID_ADDRESS_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->address_ptr))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_network_address_cfg_encode(const bcm_omci_network_address_cfg *p_me_network_address_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_network_address_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_network_address_cfg_data_encode(&p_me_network_address_cfg->data, p_bcm_buf, p_me_network_address_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_network_address_cfg_data_decode(bcm_omci_network_address_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_ADDRESS_CFG_ID_SECURITY_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->security_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_ADDRESS_CFG_ID_ADDRESS_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->address_ptr))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* Large String (9.12.5) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_large_string_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_large_string_cfg *p_src_me_large_string_cfg = (const bcm_omci_large_string_cfg *)src_me_cfg;
    bcm_omci_large_string_cfg *p_dst_me_large_string_cfg = (bcm_omci_large_string_cfg *)dst_me_cfg;

    p_dst_me_large_string_cfg->hdr.presence_mask |= p_src_me_large_string_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_large_string_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_NUMBER_OF_PARTS)) != 0)
    {
        p_dst_me_large_string_cfg->data.number_of_parts = p_src_me_large_string_cfg->data.number_of_parts;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART1)) != 0)
    {
        memcpy(p_dst_me_large_string_cfg->data.part1, p_src_me_large_string_cfg->data.part1, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART2)) != 0)
    {
        memcpy(p_dst_me_large_string_cfg->data.part2, p_src_me_large_string_cfg->data.part2, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART3)) != 0)
    {
        memcpy(p_dst_me_large_string_cfg->data.part3, p_src_me_large_string_cfg->data.part3, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART4)) != 0)
    {
        memcpy(p_dst_me_large_string_cfg->data.part4, p_src_me_large_string_cfg->data.part4, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART5)) != 0)
    {
        memcpy(p_dst_me_large_string_cfg->data.part5, p_src_me_large_string_cfg->data.part5, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART6)) != 0)
    {
        memcpy(p_dst_me_large_string_cfg->data.part6, p_src_me_large_string_cfg->data.part6, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART7)) != 0)
    {
        memcpy(p_dst_me_large_string_cfg->data.part7, p_src_me_large_string_cfg->data.part7, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART8)) != 0)
    {
        memcpy(p_dst_me_large_string_cfg->data.part8, p_src_me_large_string_cfg->data.part8, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART9)) != 0)
    {
        memcpy(p_dst_me_large_string_cfg->data.part9, p_src_me_large_string_cfg->data.part9, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART10)) != 0)
    {
        memcpy(p_dst_me_large_string_cfg->data.part10, p_src_me_large_string_cfg->data.part10, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART11)) != 0)
    {
        memcpy(p_dst_me_large_string_cfg->data.part11, p_src_me_large_string_cfg->data.part11, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART12)) != 0)
    {
        memcpy(p_dst_me_large_string_cfg->data.part12, p_src_me_large_string_cfg->data.part12, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART13)) != 0)
    {
        memcpy(p_dst_me_large_string_cfg->data.part13, p_src_me_large_string_cfg->data.part13, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART14)) != 0)
    {
        memcpy(p_dst_me_large_string_cfg->data.part14, p_src_me_large_string_cfg->data.part14, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART15)) != 0)
    {
        memcpy(p_dst_me_large_string_cfg->data.part15, p_src_me_large_string_cfg->data.part15, 25);
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_large_string_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_large_string_cfg *p_me_large_string_cfg = (const bcm_omci_large_string_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_large_string_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_LARGE_STRING_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_large_string_cfg);

    if (BCMOS_TRUE != bcm_omci_large_string_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_large_string_cfg_data_bounds_check(&p_me_large_string_cfg->data, p_me_large_string_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_large_string_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_large_string_cfg_encode(p_me_large_string_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_large_string_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_large_string_cfg *p_me_large_string_cfg = (bcm_omci_large_string_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_large_string_cfg_data_decode(&p_me_large_string_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_large_string_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_large_string_cfg *p_me_large_string_cfg = (const bcm_omci_large_string_cfg *)me_hdr;
    const bcm_omci_large_string_cfg_data *p_me_cfg_data = &p_me_large_string_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_large_string_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_large_string_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_NUMBER_OF_PARTS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tnumber_of_parts:\t%u\n", p_me_cfg_data->number_of_parts);
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART1)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpart1:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->part1)[0], ((const uint8_t *)&p_me_cfg_data->part1)[1], ((const uint8_t *)&p_me_cfg_data->part1)[2], ((const uint8_t *)&p_me_cfg_data->part1)[3], ((const uint8_t *)&p_me_cfg_data->part1)[4], ((const uint8_t *)&p_me_cfg_data->part1)[5], ((const uint8_t *)&p_me_cfg_data->part1)[6], ((const uint8_t *)&p_me_cfg_data->part1)[7], ((const uint8_t *)&p_me_cfg_data->part1)[8], ((const uint8_t *)&p_me_cfg_data->part1)[9], ((const uint8_t *)&p_me_cfg_data->part1)[10], ((const uint8_t *)&p_me_cfg_data->part1)[11], ((const uint8_t *)&p_me_cfg_data->part1)[12], ((const uint8_t *)&p_me_cfg_data->part1)[13], ((const uint8_t *)&p_me_cfg_data->part1)[14], ((const uint8_t *)&p_me_cfg_data->part1)[15], ((const uint8_t *)&p_me_cfg_data->part1)[16], ((const uint8_t *)&p_me_cfg_data->part1)[17], ((const uint8_t *)&p_me_cfg_data->part1)[18], ((const uint8_t *)&p_me_cfg_data->part1)[19], ((const uint8_t *)&p_me_cfg_data->part1)[20], ((const uint8_t *)&p_me_cfg_data->part1)[21], ((const uint8_t *)&p_me_cfg_data->part1)[22], ((const uint8_t *)&p_me_cfg_data->part1)[23], ((const uint8_t *)&p_me_cfg_data->part1)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART2)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpart2:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->part2)[0], ((const uint8_t *)&p_me_cfg_data->part2)[1], ((const uint8_t *)&p_me_cfg_data->part2)[2], ((const uint8_t *)&p_me_cfg_data->part2)[3], ((const uint8_t *)&p_me_cfg_data->part2)[4], ((const uint8_t *)&p_me_cfg_data->part2)[5], ((const uint8_t *)&p_me_cfg_data->part2)[6], ((const uint8_t *)&p_me_cfg_data->part2)[7], ((const uint8_t *)&p_me_cfg_data->part2)[8], ((const uint8_t *)&p_me_cfg_data->part2)[9], ((const uint8_t *)&p_me_cfg_data->part2)[10], ((const uint8_t *)&p_me_cfg_data->part2)[11], ((const uint8_t *)&p_me_cfg_data->part2)[12], ((const uint8_t *)&p_me_cfg_data->part2)[13], ((const uint8_t *)&p_me_cfg_data->part2)[14], ((const uint8_t *)&p_me_cfg_data->part2)[15], ((const uint8_t *)&p_me_cfg_data->part2)[16], ((const uint8_t *)&p_me_cfg_data->part2)[17], ((const uint8_t *)&p_me_cfg_data->part2)[18], ((const uint8_t *)&p_me_cfg_data->part2)[19], ((const uint8_t *)&p_me_cfg_data->part2)[20], ((const uint8_t *)&p_me_cfg_data->part2)[21], ((const uint8_t *)&p_me_cfg_data->part2)[22], ((const uint8_t *)&p_me_cfg_data->part2)[23], ((const uint8_t *)&p_me_cfg_data->part2)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART3)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpart3:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->part3)[0], ((const uint8_t *)&p_me_cfg_data->part3)[1], ((const uint8_t *)&p_me_cfg_data->part3)[2], ((const uint8_t *)&p_me_cfg_data->part3)[3], ((const uint8_t *)&p_me_cfg_data->part3)[4], ((const uint8_t *)&p_me_cfg_data->part3)[5], ((const uint8_t *)&p_me_cfg_data->part3)[6], ((const uint8_t *)&p_me_cfg_data->part3)[7], ((const uint8_t *)&p_me_cfg_data->part3)[8], ((const uint8_t *)&p_me_cfg_data->part3)[9], ((const uint8_t *)&p_me_cfg_data->part3)[10], ((const uint8_t *)&p_me_cfg_data->part3)[11], ((const uint8_t *)&p_me_cfg_data->part3)[12], ((const uint8_t *)&p_me_cfg_data->part3)[13], ((const uint8_t *)&p_me_cfg_data->part3)[14], ((const uint8_t *)&p_me_cfg_data->part3)[15], ((const uint8_t *)&p_me_cfg_data->part3)[16], ((const uint8_t *)&p_me_cfg_data->part3)[17], ((const uint8_t *)&p_me_cfg_data->part3)[18], ((const uint8_t *)&p_me_cfg_data->part3)[19], ((const uint8_t *)&p_me_cfg_data->part3)[20], ((const uint8_t *)&p_me_cfg_data->part3)[21], ((const uint8_t *)&p_me_cfg_data->part3)[22], ((const uint8_t *)&p_me_cfg_data->part3)[23], ((const uint8_t *)&p_me_cfg_data->part3)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART4)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpart4:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->part4)[0], ((const uint8_t *)&p_me_cfg_data->part4)[1], ((const uint8_t *)&p_me_cfg_data->part4)[2], ((const uint8_t *)&p_me_cfg_data->part4)[3], ((const uint8_t *)&p_me_cfg_data->part4)[4], ((const uint8_t *)&p_me_cfg_data->part4)[5], ((const uint8_t *)&p_me_cfg_data->part4)[6], ((const uint8_t *)&p_me_cfg_data->part4)[7], ((const uint8_t *)&p_me_cfg_data->part4)[8], ((const uint8_t *)&p_me_cfg_data->part4)[9], ((const uint8_t *)&p_me_cfg_data->part4)[10], ((const uint8_t *)&p_me_cfg_data->part4)[11], ((const uint8_t *)&p_me_cfg_data->part4)[12], ((const uint8_t *)&p_me_cfg_data->part4)[13], ((const uint8_t *)&p_me_cfg_data->part4)[14], ((const uint8_t *)&p_me_cfg_data->part4)[15], ((const uint8_t *)&p_me_cfg_data->part4)[16], ((const uint8_t *)&p_me_cfg_data->part4)[17], ((const uint8_t *)&p_me_cfg_data->part4)[18], ((const uint8_t *)&p_me_cfg_data->part4)[19], ((const uint8_t *)&p_me_cfg_data->part4)[20], ((const uint8_t *)&p_me_cfg_data->part4)[21], ((const uint8_t *)&p_me_cfg_data->part4)[22], ((const uint8_t *)&p_me_cfg_data->part4)[23], ((const uint8_t *)&p_me_cfg_data->part4)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART5)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpart5:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->part5)[0], ((const uint8_t *)&p_me_cfg_data->part5)[1], ((const uint8_t *)&p_me_cfg_data->part5)[2], ((const uint8_t *)&p_me_cfg_data->part5)[3], ((const uint8_t *)&p_me_cfg_data->part5)[4], ((const uint8_t *)&p_me_cfg_data->part5)[5], ((const uint8_t *)&p_me_cfg_data->part5)[6], ((const uint8_t *)&p_me_cfg_data->part5)[7], ((const uint8_t *)&p_me_cfg_data->part5)[8], ((const uint8_t *)&p_me_cfg_data->part5)[9], ((const uint8_t *)&p_me_cfg_data->part5)[10], ((const uint8_t *)&p_me_cfg_data->part5)[11], ((const uint8_t *)&p_me_cfg_data->part5)[12], ((const uint8_t *)&p_me_cfg_data->part5)[13], ((const uint8_t *)&p_me_cfg_data->part5)[14], ((const uint8_t *)&p_me_cfg_data->part5)[15], ((const uint8_t *)&p_me_cfg_data->part5)[16], ((const uint8_t *)&p_me_cfg_data->part5)[17], ((const uint8_t *)&p_me_cfg_data->part5)[18], ((const uint8_t *)&p_me_cfg_data->part5)[19], ((const uint8_t *)&p_me_cfg_data->part5)[20], ((const uint8_t *)&p_me_cfg_data->part5)[21], ((const uint8_t *)&p_me_cfg_data->part5)[22], ((const uint8_t *)&p_me_cfg_data->part5)[23], ((const uint8_t *)&p_me_cfg_data->part5)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART6)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpart6:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->part6)[0], ((const uint8_t *)&p_me_cfg_data->part6)[1], ((const uint8_t *)&p_me_cfg_data->part6)[2], ((const uint8_t *)&p_me_cfg_data->part6)[3], ((const uint8_t *)&p_me_cfg_data->part6)[4], ((const uint8_t *)&p_me_cfg_data->part6)[5], ((const uint8_t *)&p_me_cfg_data->part6)[6], ((const uint8_t *)&p_me_cfg_data->part6)[7], ((const uint8_t *)&p_me_cfg_data->part6)[8], ((const uint8_t *)&p_me_cfg_data->part6)[9], ((const uint8_t *)&p_me_cfg_data->part6)[10], ((const uint8_t *)&p_me_cfg_data->part6)[11], ((const uint8_t *)&p_me_cfg_data->part6)[12], ((const uint8_t *)&p_me_cfg_data->part6)[13], ((const uint8_t *)&p_me_cfg_data->part6)[14], ((const uint8_t *)&p_me_cfg_data->part6)[15], ((const uint8_t *)&p_me_cfg_data->part6)[16], ((const uint8_t *)&p_me_cfg_data->part6)[17], ((const uint8_t *)&p_me_cfg_data->part6)[18], ((const uint8_t *)&p_me_cfg_data->part6)[19], ((const uint8_t *)&p_me_cfg_data->part6)[20], ((const uint8_t *)&p_me_cfg_data->part6)[21], ((const uint8_t *)&p_me_cfg_data->part6)[22], ((const uint8_t *)&p_me_cfg_data->part6)[23], ((const uint8_t *)&p_me_cfg_data->part6)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART7)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpart7:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->part7)[0], ((const uint8_t *)&p_me_cfg_data->part7)[1], ((const uint8_t *)&p_me_cfg_data->part7)[2], ((const uint8_t *)&p_me_cfg_data->part7)[3], ((const uint8_t *)&p_me_cfg_data->part7)[4], ((const uint8_t *)&p_me_cfg_data->part7)[5], ((const uint8_t *)&p_me_cfg_data->part7)[6], ((const uint8_t *)&p_me_cfg_data->part7)[7], ((const uint8_t *)&p_me_cfg_data->part7)[8], ((const uint8_t *)&p_me_cfg_data->part7)[9], ((const uint8_t *)&p_me_cfg_data->part7)[10], ((const uint8_t *)&p_me_cfg_data->part7)[11], ((const uint8_t *)&p_me_cfg_data->part7)[12], ((const uint8_t *)&p_me_cfg_data->part7)[13], ((const uint8_t *)&p_me_cfg_data->part7)[14], ((const uint8_t *)&p_me_cfg_data->part7)[15], ((const uint8_t *)&p_me_cfg_data->part7)[16], ((const uint8_t *)&p_me_cfg_data->part7)[17], ((const uint8_t *)&p_me_cfg_data->part7)[18], ((const uint8_t *)&p_me_cfg_data->part7)[19], ((const uint8_t *)&p_me_cfg_data->part7)[20], ((const uint8_t *)&p_me_cfg_data->part7)[21], ((const uint8_t *)&p_me_cfg_data->part7)[22], ((const uint8_t *)&p_me_cfg_data->part7)[23], ((const uint8_t *)&p_me_cfg_data->part7)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART8)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpart8:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->part8)[0], ((const uint8_t *)&p_me_cfg_data->part8)[1], ((const uint8_t *)&p_me_cfg_data->part8)[2], ((const uint8_t *)&p_me_cfg_data->part8)[3], ((const uint8_t *)&p_me_cfg_data->part8)[4], ((const uint8_t *)&p_me_cfg_data->part8)[5], ((const uint8_t *)&p_me_cfg_data->part8)[6], ((const uint8_t *)&p_me_cfg_data->part8)[7], ((const uint8_t *)&p_me_cfg_data->part8)[8], ((const uint8_t *)&p_me_cfg_data->part8)[9], ((const uint8_t *)&p_me_cfg_data->part8)[10], ((const uint8_t *)&p_me_cfg_data->part8)[11], ((const uint8_t *)&p_me_cfg_data->part8)[12], ((const uint8_t *)&p_me_cfg_data->part8)[13], ((const uint8_t *)&p_me_cfg_data->part8)[14], ((const uint8_t *)&p_me_cfg_data->part8)[15], ((const uint8_t *)&p_me_cfg_data->part8)[16], ((const uint8_t *)&p_me_cfg_data->part8)[17], ((const uint8_t *)&p_me_cfg_data->part8)[18], ((const uint8_t *)&p_me_cfg_data->part8)[19], ((const uint8_t *)&p_me_cfg_data->part8)[20], ((const uint8_t *)&p_me_cfg_data->part8)[21], ((const uint8_t *)&p_me_cfg_data->part8)[22], ((const uint8_t *)&p_me_cfg_data->part8)[23], ((const uint8_t *)&p_me_cfg_data->part8)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART9)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpart9:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->part9)[0], ((const uint8_t *)&p_me_cfg_data->part9)[1], ((const uint8_t *)&p_me_cfg_data->part9)[2], ((const uint8_t *)&p_me_cfg_data->part9)[3], ((const uint8_t *)&p_me_cfg_data->part9)[4], ((const uint8_t *)&p_me_cfg_data->part9)[5], ((const uint8_t *)&p_me_cfg_data->part9)[6], ((const uint8_t *)&p_me_cfg_data->part9)[7], ((const uint8_t *)&p_me_cfg_data->part9)[8], ((const uint8_t *)&p_me_cfg_data->part9)[9], ((const uint8_t *)&p_me_cfg_data->part9)[10], ((const uint8_t *)&p_me_cfg_data->part9)[11], ((const uint8_t *)&p_me_cfg_data->part9)[12], ((const uint8_t *)&p_me_cfg_data->part9)[13], ((const uint8_t *)&p_me_cfg_data->part9)[14], ((const uint8_t *)&p_me_cfg_data->part9)[15], ((const uint8_t *)&p_me_cfg_data->part9)[16], ((const uint8_t *)&p_me_cfg_data->part9)[17], ((const uint8_t *)&p_me_cfg_data->part9)[18], ((const uint8_t *)&p_me_cfg_data->part9)[19], ((const uint8_t *)&p_me_cfg_data->part9)[20], ((const uint8_t *)&p_me_cfg_data->part9)[21], ((const uint8_t *)&p_me_cfg_data->part9)[22], ((const uint8_t *)&p_me_cfg_data->part9)[23], ((const uint8_t *)&p_me_cfg_data->part9)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART10)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpart10:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->part10)[0], ((const uint8_t *)&p_me_cfg_data->part10)[1], ((const uint8_t *)&p_me_cfg_data->part10)[2], ((const uint8_t *)&p_me_cfg_data->part10)[3], ((const uint8_t *)&p_me_cfg_data->part10)[4], ((const uint8_t *)&p_me_cfg_data->part10)[5], ((const uint8_t *)&p_me_cfg_data->part10)[6], ((const uint8_t *)&p_me_cfg_data->part10)[7], ((const uint8_t *)&p_me_cfg_data->part10)[8], ((const uint8_t *)&p_me_cfg_data->part10)[9], ((const uint8_t *)&p_me_cfg_data->part10)[10], ((const uint8_t *)&p_me_cfg_data->part10)[11], ((const uint8_t *)&p_me_cfg_data->part10)[12], ((const uint8_t *)&p_me_cfg_data->part10)[13], ((const uint8_t *)&p_me_cfg_data->part10)[14], ((const uint8_t *)&p_me_cfg_data->part10)[15], ((const uint8_t *)&p_me_cfg_data->part10)[16], ((const uint8_t *)&p_me_cfg_data->part10)[17], ((const uint8_t *)&p_me_cfg_data->part10)[18], ((const uint8_t *)&p_me_cfg_data->part10)[19], ((const uint8_t *)&p_me_cfg_data->part10)[20], ((const uint8_t *)&p_me_cfg_data->part10)[21], ((const uint8_t *)&p_me_cfg_data->part10)[22], ((const uint8_t *)&p_me_cfg_data->part10)[23], ((const uint8_t *)&p_me_cfg_data->part10)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART11)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpart11:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->part11)[0], ((const uint8_t *)&p_me_cfg_data->part11)[1], ((const uint8_t *)&p_me_cfg_data->part11)[2], ((const uint8_t *)&p_me_cfg_data->part11)[3], ((const uint8_t *)&p_me_cfg_data->part11)[4], ((const uint8_t *)&p_me_cfg_data->part11)[5], ((const uint8_t *)&p_me_cfg_data->part11)[6], ((const uint8_t *)&p_me_cfg_data->part11)[7], ((const uint8_t *)&p_me_cfg_data->part11)[8], ((const uint8_t *)&p_me_cfg_data->part11)[9], ((const uint8_t *)&p_me_cfg_data->part11)[10], ((const uint8_t *)&p_me_cfg_data->part11)[11], ((const uint8_t *)&p_me_cfg_data->part11)[12], ((const uint8_t *)&p_me_cfg_data->part11)[13], ((const uint8_t *)&p_me_cfg_data->part11)[14], ((const uint8_t *)&p_me_cfg_data->part11)[15], ((const uint8_t *)&p_me_cfg_data->part11)[16], ((const uint8_t *)&p_me_cfg_data->part11)[17], ((const uint8_t *)&p_me_cfg_data->part11)[18], ((const uint8_t *)&p_me_cfg_data->part11)[19], ((const uint8_t *)&p_me_cfg_data->part11)[20], ((const uint8_t *)&p_me_cfg_data->part11)[21], ((const uint8_t *)&p_me_cfg_data->part11)[22], ((const uint8_t *)&p_me_cfg_data->part11)[23], ((const uint8_t *)&p_me_cfg_data->part11)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART12)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpart12:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->part12)[0], ((const uint8_t *)&p_me_cfg_data->part12)[1], ((const uint8_t *)&p_me_cfg_data->part12)[2], ((const uint8_t *)&p_me_cfg_data->part12)[3], ((const uint8_t *)&p_me_cfg_data->part12)[4], ((const uint8_t *)&p_me_cfg_data->part12)[5], ((const uint8_t *)&p_me_cfg_data->part12)[6], ((const uint8_t *)&p_me_cfg_data->part12)[7], ((const uint8_t *)&p_me_cfg_data->part12)[8], ((const uint8_t *)&p_me_cfg_data->part12)[9], ((const uint8_t *)&p_me_cfg_data->part12)[10], ((const uint8_t *)&p_me_cfg_data->part12)[11], ((const uint8_t *)&p_me_cfg_data->part12)[12], ((const uint8_t *)&p_me_cfg_data->part12)[13], ((const uint8_t *)&p_me_cfg_data->part12)[14], ((const uint8_t *)&p_me_cfg_data->part12)[15], ((const uint8_t *)&p_me_cfg_data->part12)[16], ((const uint8_t *)&p_me_cfg_data->part12)[17], ((const uint8_t *)&p_me_cfg_data->part12)[18], ((const uint8_t *)&p_me_cfg_data->part12)[19], ((const uint8_t *)&p_me_cfg_data->part12)[20], ((const uint8_t *)&p_me_cfg_data->part12)[21], ((const uint8_t *)&p_me_cfg_data->part12)[22], ((const uint8_t *)&p_me_cfg_data->part12)[23], ((const uint8_t *)&p_me_cfg_data->part12)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART13)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpart13:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->part13)[0], ((const uint8_t *)&p_me_cfg_data->part13)[1], ((const uint8_t *)&p_me_cfg_data->part13)[2], ((const uint8_t *)&p_me_cfg_data->part13)[3], ((const uint8_t *)&p_me_cfg_data->part13)[4], ((const uint8_t *)&p_me_cfg_data->part13)[5], ((const uint8_t *)&p_me_cfg_data->part13)[6], ((const uint8_t *)&p_me_cfg_data->part13)[7], ((const uint8_t *)&p_me_cfg_data->part13)[8], ((const uint8_t *)&p_me_cfg_data->part13)[9], ((const uint8_t *)&p_me_cfg_data->part13)[10], ((const uint8_t *)&p_me_cfg_data->part13)[11], ((const uint8_t *)&p_me_cfg_data->part13)[12], ((const uint8_t *)&p_me_cfg_data->part13)[13], ((const uint8_t *)&p_me_cfg_data->part13)[14], ((const uint8_t *)&p_me_cfg_data->part13)[15], ((const uint8_t *)&p_me_cfg_data->part13)[16], ((const uint8_t *)&p_me_cfg_data->part13)[17], ((const uint8_t *)&p_me_cfg_data->part13)[18], ((const uint8_t *)&p_me_cfg_data->part13)[19], ((const uint8_t *)&p_me_cfg_data->part13)[20], ((const uint8_t *)&p_me_cfg_data->part13)[21], ((const uint8_t *)&p_me_cfg_data->part13)[22], ((const uint8_t *)&p_me_cfg_data->part13)[23], ((const uint8_t *)&p_me_cfg_data->part13)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART14)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpart14:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->part14)[0], ((const uint8_t *)&p_me_cfg_data->part14)[1], ((const uint8_t *)&p_me_cfg_data->part14)[2], ((const uint8_t *)&p_me_cfg_data->part14)[3], ((const uint8_t *)&p_me_cfg_data->part14)[4], ((const uint8_t *)&p_me_cfg_data->part14)[5], ((const uint8_t *)&p_me_cfg_data->part14)[6], ((const uint8_t *)&p_me_cfg_data->part14)[7], ((const uint8_t *)&p_me_cfg_data->part14)[8], ((const uint8_t *)&p_me_cfg_data->part14)[9], ((const uint8_t *)&p_me_cfg_data->part14)[10], ((const uint8_t *)&p_me_cfg_data->part14)[11], ((const uint8_t *)&p_me_cfg_data->part14)[12], ((const uint8_t *)&p_me_cfg_data->part14)[13], ((const uint8_t *)&p_me_cfg_data->part14)[14], ((const uint8_t *)&p_me_cfg_data->part14)[15], ((const uint8_t *)&p_me_cfg_data->part14)[16], ((const uint8_t *)&p_me_cfg_data->part14)[17], ((const uint8_t *)&p_me_cfg_data->part14)[18], ((const uint8_t *)&p_me_cfg_data->part14)[19], ((const uint8_t *)&p_me_cfg_data->part14)[20], ((const uint8_t *)&p_me_cfg_data->part14)[21], ((const uint8_t *)&p_me_cfg_data->part14)[22], ((const uint8_t *)&p_me_cfg_data->part14)[23], ((const uint8_t *)&p_me_cfg_data->part14)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART15)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpart15:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->part15)[0], ((const uint8_t *)&p_me_cfg_data->part15)[1], ((const uint8_t *)&p_me_cfg_data->part15)[2], ((const uint8_t *)&p_me_cfg_data->part15)[3], ((const uint8_t *)&p_me_cfg_data->part15)[4], ((const uint8_t *)&p_me_cfg_data->part15)[5], ((const uint8_t *)&p_me_cfg_data->part15)[6], ((const uint8_t *)&p_me_cfg_data->part15)[7], ((const uint8_t *)&p_me_cfg_data->part15)[8], ((const uint8_t *)&p_me_cfg_data->part15)[9], ((const uint8_t *)&p_me_cfg_data->part15)[10], ((const uint8_t *)&p_me_cfg_data->part15)[11], ((const uint8_t *)&p_me_cfg_data->part15)[12], ((const uint8_t *)&p_me_cfg_data->part15)[13], ((const uint8_t *)&p_me_cfg_data->part15)[14], ((const uint8_t *)&p_me_cfg_data->part15)[15], ((const uint8_t *)&p_me_cfg_data->part15)[16], ((const uint8_t *)&p_me_cfg_data->part15)[17], ((const uint8_t *)&p_me_cfg_data->part15)[18], ((const uint8_t *)&p_me_cfg_data->part15)[19], ((const uint8_t *)&p_me_cfg_data->part15)[20], ((const uint8_t *)&p_me_cfg_data->part15)[21], ((const uint8_t *)&p_me_cfg_data->part15)[22], ((const uint8_t *)&p_me_cfg_data->part15)[23], ((const uint8_t *)&p_me_cfg_data->part15)[24]);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_large_string_cfg_data_encode(const bcm_omci_large_string_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_large_string_cfg_data_encode(const bcm_omci_large_string_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_NUMBER_OF_PARTS)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->number_of_parts))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART1)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->part1, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART2)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->part2, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART3)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->part3, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART4)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->part4, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART5)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->part5, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART6)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->part6, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART7)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->part7, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART8)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->part8, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART9)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->part9, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART10)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->part10, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART11)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->part11, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART12)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->part12, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART13)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->part13, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART14)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->part14, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART15)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->part15, 25))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_large_string_cfg_encode(const bcm_omci_large_string_cfg *p_me_large_string_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_large_string_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_large_string_cfg_data_encode(&p_me_large_string_cfg->data, p_bcm_buf, p_me_large_string_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_large_string_cfg_data_decode(bcm_omci_large_string_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_NUMBER_OF_PARTS)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->number_of_parts))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART1)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->part1, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART2)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->part2, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART3)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->part3, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART4)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->part4, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART5)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->part5, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART6)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->part6, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART7)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->part7, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART8)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->part8, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART9)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->part9, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART10)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->part10, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART11)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->part11, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART12)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->part12, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART13)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->part13, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART14)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->part14, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_LARGE_STRING_CFG_ID_PART15)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->part15, 25))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* Authentication Security Method (9.12.4) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_authentication_security_method_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_authentication_security_method_cfg *p_src_me_authentication_security_method_cfg = (const bcm_omci_authentication_security_method_cfg *)src_me_cfg;
    bcm_omci_authentication_security_method_cfg *p_dst_me_authentication_security_method_cfg = (bcm_omci_authentication_security_method_cfg *)dst_me_cfg;

    p_dst_me_authentication_security_method_cfg->hdr.presence_mask |= p_src_me_authentication_security_method_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_authentication_security_method_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_VALIDATION_SCHEME)) != 0)
    {
        p_dst_me_authentication_security_method_cfg->data.validation_scheme = p_src_me_authentication_security_method_cfg->data.validation_scheme;
    }
    if ((fields_present & (1ULL << BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_USERNAME1)) != 0)
    {
        memcpy(p_dst_me_authentication_security_method_cfg->data.username1, p_src_me_authentication_security_method_cfg->data.username1, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_PASSWORD)) != 0)
    {
        memcpy(p_dst_me_authentication_security_method_cfg->data.password, p_src_me_authentication_security_method_cfg->data.password, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_REALM)) != 0)
    {
        memcpy(p_dst_me_authentication_security_method_cfg->data.realm, p_src_me_authentication_security_method_cfg->data.realm, 25);
    }
    if ((fields_present & (1ULL << BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_USERNAME2)) != 0)
    {
        memcpy(p_dst_me_authentication_security_method_cfg->data.username2, p_src_me_authentication_security_method_cfg->data.username2, 25);
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_authentication_security_method_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_authentication_security_method_cfg *p_me_authentication_security_method_cfg = (const bcm_omci_authentication_security_method_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_authentication_security_method_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_authentication_security_method_cfg);

    if (BCMOS_TRUE != bcm_omci_authentication_security_method_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_authentication_security_method_cfg_data_bounds_check(&p_me_authentication_security_method_cfg->data, p_me_authentication_security_method_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_authentication_security_method_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_authentication_security_method_cfg_encode(p_me_authentication_security_method_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_authentication_security_method_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_authentication_security_method_cfg *p_me_authentication_security_method_cfg = (bcm_omci_authentication_security_method_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_authentication_security_method_cfg_data_decode(&p_me_authentication_security_method_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_authentication_security_method_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_authentication_security_method_cfg *p_me_authentication_security_method_cfg = (const bcm_omci_authentication_security_method_cfg *)me_hdr;
    const bcm_omci_authentication_security_method_cfg_data *p_me_cfg_data = &p_me_authentication_security_method_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_authentication_security_method_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_authentication_security_method_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_VALIDATION_SCHEME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tvalidation_scheme:\t%u\n", p_me_cfg_data->validation_scheme);
    if ((fields_present & (1ULL << BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_USERNAME1)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tusername1:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->username1)[0], ((const uint8_t *)&p_me_cfg_data->username1)[1], ((const uint8_t *)&p_me_cfg_data->username1)[2], ((const uint8_t *)&p_me_cfg_data->username1)[3], ((const uint8_t *)&p_me_cfg_data->username1)[4], ((const uint8_t *)&p_me_cfg_data->username1)[5], ((const uint8_t *)&p_me_cfg_data->username1)[6], ((const uint8_t *)&p_me_cfg_data->username1)[7], ((const uint8_t *)&p_me_cfg_data->username1)[8], ((const uint8_t *)&p_me_cfg_data->username1)[9], ((const uint8_t *)&p_me_cfg_data->username1)[10], ((const uint8_t *)&p_me_cfg_data->username1)[11], ((const uint8_t *)&p_me_cfg_data->username1)[12], ((const uint8_t *)&p_me_cfg_data->username1)[13], ((const uint8_t *)&p_me_cfg_data->username1)[14], ((const uint8_t *)&p_me_cfg_data->username1)[15], ((const uint8_t *)&p_me_cfg_data->username1)[16], ((const uint8_t *)&p_me_cfg_data->username1)[17], ((const uint8_t *)&p_me_cfg_data->username1)[18], ((const uint8_t *)&p_me_cfg_data->username1)[19], ((const uint8_t *)&p_me_cfg_data->username1)[20], ((const uint8_t *)&p_me_cfg_data->username1)[21], ((const uint8_t *)&p_me_cfg_data->username1)[22], ((const uint8_t *)&p_me_cfg_data->username1)[23], ((const uint8_t *)&p_me_cfg_data->username1)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_PASSWORD)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpassword:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->password)[0], ((const uint8_t *)&p_me_cfg_data->password)[1], ((const uint8_t *)&p_me_cfg_data->password)[2], ((const uint8_t *)&p_me_cfg_data->password)[3], ((const uint8_t *)&p_me_cfg_data->password)[4], ((const uint8_t *)&p_me_cfg_data->password)[5], ((const uint8_t *)&p_me_cfg_data->password)[6], ((const uint8_t *)&p_me_cfg_data->password)[7], ((const uint8_t *)&p_me_cfg_data->password)[8], ((const uint8_t *)&p_me_cfg_data->password)[9], ((const uint8_t *)&p_me_cfg_data->password)[10], ((const uint8_t *)&p_me_cfg_data->password)[11], ((const uint8_t *)&p_me_cfg_data->password)[12], ((const uint8_t *)&p_me_cfg_data->password)[13], ((const uint8_t *)&p_me_cfg_data->password)[14], ((const uint8_t *)&p_me_cfg_data->password)[15], ((const uint8_t *)&p_me_cfg_data->password)[16], ((const uint8_t *)&p_me_cfg_data->password)[17], ((const uint8_t *)&p_me_cfg_data->password)[18], ((const uint8_t *)&p_me_cfg_data->password)[19], ((const uint8_t *)&p_me_cfg_data->password)[20], ((const uint8_t *)&p_me_cfg_data->password)[21], ((const uint8_t *)&p_me_cfg_data->password)[22], ((const uint8_t *)&p_me_cfg_data->password)[23], ((const uint8_t *)&p_me_cfg_data->password)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_REALM)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\trealm:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->realm)[0], ((const uint8_t *)&p_me_cfg_data->realm)[1], ((const uint8_t *)&p_me_cfg_data->realm)[2], ((const uint8_t *)&p_me_cfg_data->realm)[3], ((const uint8_t *)&p_me_cfg_data->realm)[4], ((const uint8_t *)&p_me_cfg_data->realm)[5], ((const uint8_t *)&p_me_cfg_data->realm)[6], ((const uint8_t *)&p_me_cfg_data->realm)[7], ((const uint8_t *)&p_me_cfg_data->realm)[8], ((const uint8_t *)&p_me_cfg_data->realm)[9], ((const uint8_t *)&p_me_cfg_data->realm)[10], ((const uint8_t *)&p_me_cfg_data->realm)[11], ((const uint8_t *)&p_me_cfg_data->realm)[12], ((const uint8_t *)&p_me_cfg_data->realm)[13], ((const uint8_t *)&p_me_cfg_data->realm)[14], ((const uint8_t *)&p_me_cfg_data->realm)[15], ((const uint8_t *)&p_me_cfg_data->realm)[16], ((const uint8_t *)&p_me_cfg_data->realm)[17], ((const uint8_t *)&p_me_cfg_data->realm)[18], ((const uint8_t *)&p_me_cfg_data->realm)[19], ((const uint8_t *)&p_me_cfg_data->realm)[20], ((const uint8_t *)&p_me_cfg_data->realm)[21], ((const uint8_t *)&p_me_cfg_data->realm)[22], ((const uint8_t *)&p_me_cfg_data->realm)[23], ((const uint8_t *)&p_me_cfg_data->realm)[24]);
    if ((fields_present & (1ULL << BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_USERNAME2)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tusername2:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->username2)[0], ((const uint8_t *)&p_me_cfg_data->username2)[1], ((const uint8_t *)&p_me_cfg_data->username2)[2], ((const uint8_t *)&p_me_cfg_data->username2)[3], ((const uint8_t *)&p_me_cfg_data->username2)[4], ((const uint8_t *)&p_me_cfg_data->username2)[5], ((const uint8_t *)&p_me_cfg_data->username2)[6], ((const uint8_t *)&p_me_cfg_data->username2)[7], ((const uint8_t *)&p_me_cfg_data->username2)[8], ((const uint8_t *)&p_me_cfg_data->username2)[9], ((const uint8_t *)&p_me_cfg_data->username2)[10], ((const uint8_t *)&p_me_cfg_data->username2)[11], ((const uint8_t *)&p_me_cfg_data->username2)[12], ((const uint8_t *)&p_me_cfg_data->username2)[13], ((const uint8_t *)&p_me_cfg_data->username2)[14], ((const uint8_t *)&p_me_cfg_data->username2)[15], ((const uint8_t *)&p_me_cfg_data->username2)[16], ((const uint8_t *)&p_me_cfg_data->username2)[17], ((const uint8_t *)&p_me_cfg_data->username2)[18], ((const uint8_t *)&p_me_cfg_data->username2)[19], ((const uint8_t *)&p_me_cfg_data->username2)[20], ((const uint8_t *)&p_me_cfg_data->username2)[21], ((const uint8_t *)&p_me_cfg_data->username2)[22], ((const uint8_t *)&p_me_cfg_data->username2)[23], ((const uint8_t *)&p_me_cfg_data->username2)[24]);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_authentication_security_method_cfg_data_encode(const bcm_omci_authentication_security_method_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_authentication_security_method_cfg_data_encode(const bcm_omci_authentication_security_method_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_VALIDATION_SCHEME)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->validation_scheme))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_USERNAME1)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->username1, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_PASSWORD)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->password, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_REALM)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->realm, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_USERNAME2)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->username2, 25))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_authentication_security_method_cfg_encode(const bcm_omci_authentication_security_method_cfg *p_me_authentication_security_method_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_authentication_security_method_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_authentication_security_method_cfg_data_encode(&p_me_authentication_security_method_cfg->data, p_bcm_buf, p_me_authentication_security_method_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_authentication_security_method_cfg_data_decode(bcm_omci_authentication_security_method_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_VALIDATION_SCHEME)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->validation_scheme))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_USERNAME1)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->username1, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_PASSWORD)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->password, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_REALM)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->realm, 25))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_CFG_ID_USERNAME2)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->username2, 25))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* Voice Service Profile (9.9.6) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_voice_service_profile_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_voice_service_profile_cfg *p_src_me_voice_service_profile_cfg = (const bcm_omci_voice_service_profile_cfg *)src_me_cfg;
    bcm_omci_voice_service_profile_cfg *p_dst_me_voice_service_profile_cfg = (bcm_omci_voice_service_profile_cfg *)dst_me_cfg;

    p_dst_me_voice_service_profile_cfg->hdr.presence_mask |= p_src_me_voice_service_profile_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_voice_service_profile_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_ANNOUNCEMENT_TYPE)) != 0)
    {
        p_dst_me_voice_service_profile_cfg->data.announcement_type = p_src_me_voice_service_profile_cfg->data.announcement_type;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_JITTER_TARGET)) != 0)
    {
        p_dst_me_voice_service_profile_cfg->data.jitter_target = p_src_me_voice_service_profile_cfg->data.jitter_target;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_JITTER_BUFFER_MAX)) != 0)
    {
        p_dst_me_voice_service_profile_cfg->data.jitter_buffer_max = p_src_me_voice_service_profile_cfg->data.jitter_buffer_max;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_ECHO_CANCEL)) != 0)
    {
        p_dst_me_voice_service_profile_cfg->data.echo_cancel = p_src_me_voice_service_profile_cfg->data.echo_cancel;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_PSTN_PROTOCOL_VARIANT)) != 0)
    {
        p_dst_me_voice_service_profile_cfg->data.pstn_protocol_variant = p_src_me_voice_service_profile_cfg->data.pstn_protocol_variant;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_DTMF_DIGIT_LEVELS)) != 0)
    {
        p_dst_me_voice_service_profile_cfg->data.dtmf_digit_levels = p_src_me_voice_service_profile_cfg->data.dtmf_digit_levels;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_DTMF_DIGIT_DURATION)) != 0)
    {
        p_dst_me_voice_service_profile_cfg->data.dtmf_digit_duration = p_src_me_voice_service_profile_cfg->data.dtmf_digit_duration;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_HOOK_FLASH_MIN_TIME)) != 0)
    {
        p_dst_me_voice_service_profile_cfg->data.hook_flash_min_time = p_src_me_voice_service_profile_cfg->data.hook_flash_min_time;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_HOOK_FLASH_MAX_TIME)) != 0)
    {
        p_dst_me_voice_service_profile_cfg->data.hook_flash_max_time = p_src_me_voice_service_profile_cfg->data.hook_flash_max_time;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_TONE_PATTERN_TABLE)) != 0)
    {
        /* doing struct copy */
        p_dst_me_voice_service_profile_cfg->data.tone_pattern_table = p_src_me_voice_service_profile_cfg->data.tone_pattern_table;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_TONE_EVENT_TABLE)) != 0)
    {
        /* doing struct copy */
        p_dst_me_voice_service_profile_cfg->data.tone_event_table = p_src_me_voice_service_profile_cfg->data.tone_event_table;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_RINGING_PATTERN_TABLE)) != 0)
    {
        /* doing struct copy */
        p_dst_me_voice_service_profile_cfg->data.ringing_pattern_table = p_src_me_voice_service_profile_cfg->data.ringing_pattern_table;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_RINGING_EVENT_TABLE)) != 0)
    {
        /* doing struct copy */
        p_dst_me_voice_service_profile_cfg->data.ringing_event_table = p_src_me_voice_service_profile_cfg->data.ringing_event_table;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_NETWORK_SPECIFIC_EXT_PTR)) != 0)
    {
        p_dst_me_voice_service_profile_cfg->data.network_specific_ext_ptr = p_src_me_voice_service_profile_cfg->data.network_specific_ext_ptr;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_voice_service_profile_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_voice_service_profile_cfg *p_me_voice_service_profile_cfg = (const bcm_omci_voice_service_profile_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_voice_service_profile_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_voice_service_profile_cfg);

    if (BCMOS_TRUE != bcm_omci_voice_service_profile_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_voice_service_profile_cfg_data_bounds_check(&p_me_voice_service_profile_cfg->data, p_me_voice_service_profile_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_voice_service_profile_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_voice_service_profile_cfg_encode(p_me_voice_service_profile_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_voice_service_profile_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_voice_service_profile_cfg *p_me_voice_service_profile_cfg = (bcm_omci_voice_service_profile_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_voice_service_profile_cfg_data_decode(&p_me_voice_service_profile_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */
static bcmos_bool bcm_omci_voice_service_profile_tone_pattern_table_log(const bcm_omci_me_key *key, const bcm_omci_voice_service_profile_tone_pattern_table *this, dev_log_id log_id, bcm_dev_log_level log_level)
{
    BCM_LOG_LEVEL(log_level, log_id, "\t\tindex: %u\n", this->index);
    BCM_LOG_LEVEL(log_level, log_id, "\t\ttone_on: %u\n", this->tone_on);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tfrequency1: %u\n", this->frequency1);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tpower1: %u\n", this->power1);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tfrequency2: %u\n", this->frequency2);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tpower2: %u\n", this->power2);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tfrequency3: %u\n", this->frequency3);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tpower3: %u\n", this->power3);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tfrequency4: %u\n", this->frequency4);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tpower4: %u\n", this->power4);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tmodulation_frequency: %u\n", this->modulation_frequency);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tmodulation_power: %u\n", this->modulation_power);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tduration: %u\n", this->duration);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tnext_entry: %u\n", this->next_entry);

    return BCM_ERR_OK;
}
static bcmos_bool bcm_omci_voice_service_profile_tone_event_table_log(const bcm_omci_me_key *key, const bcm_omci_voice_service_profile_tone_event_table *this, dev_log_id log_id, bcm_dev_log_level log_level)
{
    BCM_LOG_LEVEL(log_level, log_id, "\t\tevent: %u\n", this->event);
    BCM_LOG_LEVEL(log_level, log_id, "\t\ttone_pattern: %u\n", this->tone_pattern);
    BCM_LOG_LEVEL(log_level, log_id, "\t\ttone_file: %u\n", this->tone_file);
    BCM_LOG_LEVEL(log_level, log_id, "\t\ttone_file_repetitions: %u\n", this->tone_file_repetitions);
    BCM_LOG_LEVEL(log_level, log_id, "\t\treserved: %u\n", this->reserved);

    return BCM_ERR_OK;
}
static bcmos_bool bcm_omci_voice_service_profile_ringing_pattern_table_log(const bcm_omci_me_key *key, const bcm_omci_voice_service_profile_ringing_pattern_table *this, dev_log_id log_id, bcm_dev_log_level log_level)
{
    BCM_LOG_LEVEL(log_level, log_id, "\t\tindex: %u\n", this->index);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tringing_on: %u\n", this->ringing_on);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tduration: %u\n", this->duration);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tnext_entry: %u\n", this->next_entry);

    return BCM_ERR_OK;
}
static bcmos_bool bcm_omci_voice_service_profile_ringing_event_table_log(const bcm_omci_me_key *key, const bcm_omci_voice_service_profile_ringing_event_table *this, dev_log_id log_id, bcm_dev_log_level log_level)
{
    BCM_LOG_LEVEL(log_level, log_id, "\t\tevent: %u\n", this->event);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tringing_pattern: %u\n", this->ringing_pattern);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tringing_file: %u\n", this->ringing_file);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tringing_file_repetitions: %u\n", this->ringing_file_repetitions);
    BCM_LOG_LEVEL(log_level, log_id, "\t\tringing_text: %u\n", this->ringing_text);

    return BCM_ERR_OK;
}

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_voice_service_profile_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_voice_service_profile_cfg *p_me_voice_service_profile_cfg = (const bcm_omci_voice_service_profile_cfg *)me_hdr;
    const bcm_omci_voice_service_profile_cfg_data *p_me_cfg_data = &p_me_voice_service_profile_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_voice_service_profile_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_voice_service_profile_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_ANNOUNCEMENT_TYPE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tannouncement_type:\t%u\n", p_me_cfg_data->announcement_type);
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_JITTER_TARGET)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tjitter_target:\t%u\n", p_me_cfg_data->jitter_target);
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_JITTER_BUFFER_MAX)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tjitter_buffer_max:\t%u\n", p_me_cfg_data->jitter_buffer_max);
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_ECHO_CANCEL)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\techo_cancel:\t%u\n", p_me_cfg_data->echo_cancel);
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_PSTN_PROTOCOL_VARIANT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpstn_protocol_variant:\t%u\n", p_me_cfg_data->pstn_protocol_variant);
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_DTMF_DIGIT_LEVELS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdtmf_digit_levels:\t%u\n", p_me_cfg_data->dtmf_digit_levels);
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_DTMF_DIGIT_DURATION)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdtmf_digit_duration:\t%u\n", p_me_cfg_data->dtmf_digit_duration);
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_HOOK_FLASH_MIN_TIME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\thook_flash_min_time:\t%u\n", p_me_cfg_data->hook_flash_min_time);
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_HOOK_FLASH_MAX_TIME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\thook_flash_max_time:\t%u\n", p_me_cfg_data->hook_flash_max_time);
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_TONE_PATTERN_TABLE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttone_pattern_table:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->tone_pattern_table)[0], ((const uint8_t *)&p_me_cfg_data->tone_pattern_table)[1], ((const uint8_t *)&p_me_cfg_data->tone_pattern_table)[2], ((const uint8_t *)&p_me_cfg_data->tone_pattern_table)[3], ((const uint8_t *)&p_me_cfg_data->tone_pattern_table)[4], ((const uint8_t *)&p_me_cfg_data->tone_pattern_table)[5], ((const uint8_t *)&p_me_cfg_data->tone_pattern_table)[6], ((const uint8_t *)&p_me_cfg_data->tone_pattern_table)[7], ((const uint8_t *)&p_me_cfg_data->tone_pattern_table)[8], ((const uint8_t *)&p_me_cfg_data->tone_pattern_table)[9], ((const uint8_t *)&p_me_cfg_data->tone_pattern_table)[10], ((const uint8_t *)&p_me_cfg_data->tone_pattern_table)[11], ((const uint8_t *)&p_me_cfg_data->tone_pattern_table)[12], ((const uint8_t *)&p_me_cfg_data->tone_pattern_table)[13], ((const uint8_t *)&p_me_cfg_data->tone_pattern_table)[14], ((const uint8_t *)&p_me_cfg_data->tone_pattern_table)[15], ((const uint8_t *)&p_me_cfg_data->tone_pattern_table)[16], ((const uint8_t *)&p_me_cfg_data->tone_pattern_table)[17], ((const uint8_t *)&p_me_cfg_data->tone_pattern_table)[18], ((const uint8_t *)&p_me_cfg_data->tone_pattern_table)[19]);
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_TONE_EVENT_TABLE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttone_event_table:\t%02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->tone_event_table)[0], ((const uint8_t *)&p_me_cfg_data->tone_event_table)[1], ((const uint8_t *)&p_me_cfg_data->tone_event_table)[2], ((const uint8_t *)&p_me_cfg_data->tone_event_table)[3], ((const uint8_t *)&p_me_cfg_data->tone_event_table)[4], ((const uint8_t *)&p_me_cfg_data->tone_event_table)[5], ((const uint8_t *)&p_me_cfg_data->tone_event_table)[6]);
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_RINGING_PATTERN_TABLE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tringing_pattern_table:\t%02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->ringing_pattern_table)[0], ((const uint8_t *)&p_me_cfg_data->ringing_pattern_table)[1], ((const uint8_t *)&p_me_cfg_data->ringing_pattern_table)[2], ((const uint8_t *)&p_me_cfg_data->ringing_pattern_table)[3], ((const uint8_t *)&p_me_cfg_data->ringing_pattern_table)[4]);
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_RINGING_EVENT_TABLE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tringing_event_table:\t%02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->ringing_event_table)[0], ((const uint8_t *)&p_me_cfg_data->ringing_event_table)[1], ((const uint8_t *)&p_me_cfg_data->ringing_event_table)[2], ((const uint8_t *)&p_me_cfg_data->ringing_event_table)[3], ((const uint8_t *)&p_me_cfg_data->ringing_event_table)[4], ((const uint8_t *)&p_me_cfg_data->ringing_event_table)[5], ((const uint8_t *)&p_me_cfg_data->ringing_event_table)[6]);
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_NETWORK_SPECIFIC_EXT_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tnetwork_specific_ext_ptr:\t%u\n", p_me_cfg_data->network_specific_ext_ptr);

    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_TONE_PATTERN_TABLE)) != 0)
        bcm_omci_voice_service_profile_tone_pattern_table_log(&me_hdr->key, &p_me_cfg_data->tone_pattern_table, log_id, log_level);
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_TONE_EVENT_TABLE)) != 0)
        bcm_omci_voice_service_profile_tone_event_table_log(&me_hdr->key, &p_me_cfg_data->tone_event_table, log_id, log_level);
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_RINGING_PATTERN_TABLE)) != 0)
        bcm_omci_voice_service_profile_ringing_pattern_table_log(&me_hdr->key, &p_me_cfg_data->ringing_pattern_table, log_id, log_level);
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_RINGING_EVENT_TABLE)) != 0)
        bcm_omci_voice_service_profile_ringing_event_table_log(&me_hdr->key, &p_me_cfg_data->ringing_event_table, log_id, log_level);

    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */
static bcmos_bool bcm_omci_voice_service_profile_tone_pattern_table_cfg_data_encode(bcm_omci_buf *p_bcm_buf, const bcm_omci_voice_service_profile_tone_pattern_table *this)
{
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->index))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->tone_on))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->frequency1))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->power1))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->frequency2))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->power2))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->frequency3))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->power3))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->frequency4))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->power4))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->modulation_frequency))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->modulation_power))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->duration))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->next_entry))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}
static bcmos_bool bcm_omci_voice_service_profile_tone_event_table_cfg_data_encode(bcm_omci_buf *p_bcm_buf, const bcm_omci_voice_service_profile_tone_event_table *this)
{
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->event))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->tone_pattern))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->tone_file))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->tone_file_repetitions))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->reserved))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}
static bcmos_bool bcm_omci_voice_service_profile_ringing_pattern_table_cfg_data_encode(bcm_omci_buf *p_bcm_buf, const bcm_omci_voice_service_profile_ringing_pattern_table *this)
{
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->index))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->ringing_on))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->duration))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->next_entry))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}
static bcmos_bool bcm_omci_voice_service_profile_ringing_event_table_cfg_data_encode(bcm_omci_buf *p_bcm_buf, const bcm_omci_voice_service_profile_ringing_event_table *this)
{
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->event))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->ringing_pattern))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->ringing_file))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->ringing_file_repetitions))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u16(p_bcm_buf, this->ringing_text))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

static bcmos_bool bcm_omci_voice_service_profile_cfg_data_encode(const bcm_omci_voice_service_profile_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_voice_service_profile_cfg_data_encode(const bcm_omci_voice_service_profile_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_ANNOUNCEMENT_TYPE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->announcement_type))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_JITTER_TARGET)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->jitter_target))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_JITTER_BUFFER_MAX)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->jitter_buffer_max))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_ECHO_CANCEL)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->echo_cancel))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_PSTN_PROTOCOL_VARIANT)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->pstn_protocol_variant))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_DTMF_DIGIT_LEVELS)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->dtmf_digit_levels))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_DTMF_DIGIT_DURATION)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->dtmf_digit_duration))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_HOOK_FLASH_MIN_TIME)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->hook_flash_min_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_HOOK_FLASH_MAX_TIME)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->hook_flash_max_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_TONE_PATTERN_TABLE)) != 0)
    {
        if (!bcm_omci_voice_service_profile_tone_pattern_table_cfg_data_encode(p_bcm_buf, &p_me_cfg_data->tone_pattern_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_TONE_EVENT_TABLE)) != 0)
    {
        if (!bcm_omci_voice_service_profile_tone_event_table_cfg_data_encode(p_bcm_buf, &p_me_cfg_data->tone_event_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_RINGING_PATTERN_TABLE)) != 0)
    {
        if (!bcm_omci_voice_service_profile_ringing_pattern_table_cfg_data_encode(p_bcm_buf, &p_me_cfg_data->ringing_pattern_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_RINGING_EVENT_TABLE)) != 0)
    {
        if (!bcm_omci_voice_service_profile_ringing_event_table_cfg_data_encode(p_bcm_buf, &p_me_cfg_data->ringing_event_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_NETWORK_SPECIFIC_EXT_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->network_specific_ext_ptr))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_voice_service_profile_cfg_encode(const bcm_omci_voice_service_profile_cfg *p_me_voice_service_profile_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_voice_service_profile_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_voice_service_profile_cfg_data_encode(&p_me_voice_service_profile_cfg->data, p_bcm_buf, p_me_voice_service_profile_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */
static bcmos_bool bcm_omci_voice_service_profile_tone_pattern_table_cfg_data_decode(bcm_omci_buf *p_bcm_buf, bcm_omci_voice_service_profile_tone_pattern_table *this)
{
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->index))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->tone_on))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->frequency1))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->power1))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->frequency2))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->power2))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->frequency3))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->power3))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->frequency4))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->power4))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->modulation_frequency))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->modulation_power))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->duration))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->next_entry))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}
static bcmos_bool bcm_omci_voice_service_profile_tone_event_table_cfg_data_decode(bcm_omci_buf *p_bcm_buf, bcm_omci_voice_service_profile_tone_event_table *this)
{
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->event))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->tone_pattern))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->tone_file))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->tone_file_repetitions))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->reserved))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}
static bcmos_bool bcm_omci_voice_service_profile_ringing_pattern_table_cfg_data_decode(bcm_omci_buf *p_bcm_buf, bcm_omci_voice_service_profile_ringing_pattern_table *this)
{
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->index))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->ringing_on))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->duration))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->next_entry))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}
static bcmos_bool bcm_omci_voice_service_profile_ringing_event_table_cfg_data_decode(bcm_omci_buf *p_bcm_buf, bcm_omci_voice_service_profile_ringing_event_table *this)
{
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->event))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->ringing_pattern))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->ringing_file))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->ringing_file_repetitions))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u16(p_bcm_buf, &this->ringing_text))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_voice_service_profile_cfg_data_decode(bcm_omci_voice_service_profile_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_ANNOUNCEMENT_TYPE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->announcement_type))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_JITTER_TARGET)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->jitter_target))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_JITTER_BUFFER_MAX)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->jitter_buffer_max))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_ECHO_CANCEL)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->echo_cancel))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_PSTN_PROTOCOL_VARIANT)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->pstn_protocol_variant))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_DTMF_DIGIT_LEVELS)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->dtmf_digit_levels))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_DTMF_DIGIT_DURATION)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->dtmf_digit_duration))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_HOOK_FLASH_MIN_TIME)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->hook_flash_min_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_HOOK_FLASH_MAX_TIME)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->hook_flash_max_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_TONE_PATTERN_TABLE)) != 0)
    {
        if (!bcm_omci_voice_service_profile_tone_pattern_table_cfg_data_decode(p_bcm_buf, &p_me_cfg_data->tone_pattern_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_TONE_EVENT_TABLE)) != 0)
    {
        if (!bcm_omci_voice_service_profile_tone_event_table_cfg_data_decode(p_bcm_buf, &p_me_cfg_data->tone_event_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_RINGING_PATTERN_TABLE)) != 0)
    {
        if (!bcm_omci_voice_service_profile_ringing_pattern_table_cfg_data_decode(p_bcm_buf, &p_me_cfg_data->ringing_pattern_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_RINGING_EVENT_TABLE)) != 0)
    {
        if (!bcm_omci_voice_service_profile_ringing_event_table_cfg_data_decode(p_bcm_buf, &p_me_cfg_data->ringing_event_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOICE_SERVICE_PROFILE_CFG_ID_NETWORK_SPECIFIC_EXT_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->network_specific_ext_ptr))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* VoIP config data (9.9.18) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_voip_config_data_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_voip_config_data_cfg *p_src_me_voip_config_data_cfg = (const bcm_omci_voip_config_data_cfg *)src_me_cfg;
    bcm_omci_voip_config_data_cfg *p_dst_me_voip_config_data_cfg = (bcm_omci_voip_config_data_cfg *)dst_me_cfg;

    p_dst_me_voip_config_data_cfg->hdr.presence_mask |= p_src_me_voip_config_data_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_voip_config_data_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_AVAILABLE_SIGNALLING_PROTOCOLS)) != 0)
    {
        p_dst_me_voip_config_data_cfg->data.available_signalling_protocols = p_src_me_voip_config_data_cfg->data.available_signalling_protocols;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_SIGNALLING_PROTOCOL_USED)) != 0)
    {
        p_dst_me_voip_config_data_cfg->data.signalling_protocol_used = p_src_me_voip_config_data_cfg->data.signalling_protocol_used;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_AVAILABLE_VOIP_CONFIG_METHODS)) != 0)
    {
        p_dst_me_voip_config_data_cfg->data.available_voip_config_methods = p_src_me_voip_config_data_cfg->data.available_voip_config_methods;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOIP_CONFIG_METHOD_USED)) != 0)
    {
        p_dst_me_voip_config_data_cfg->data.voip_config_method_used = p_src_me_voip_config_data_cfg->data.voip_config_method_used;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOICE_CONFIG_PTR)) != 0)
    {
        p_dst_me_voip_config_data_cfg->data.voice_config_ptr = p_src_me_voip_config_data_cfg->data.voice_config_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOIP_CONFIG_STATE)) != 0)
    {
        p_dst_me_voip_config_data_cfg->data.voip_config_state = p_src_me_voip_config_data_cfg->data.voip_config_state;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_RETRIEVE_PROFILE)) != 0)
    {
        p_dst_me_voip_config_data_cfg->data.retrieve_profile = p_src_me_voip_config_data_cfg->data.retrieve_profile;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_PROFILE_VERSION)) != 0)
    {
        memcpy(p_dst_me_voip_config_data_cfg->data.profile_version, p_src_me_voip_config_data_cfg->data.profile_version, 25);
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_voip_config_data_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_voip_config_data_cfg *p_me_voip_config_data_cfg = (const bcm_omci_voip_config_data_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_voip_config_data_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_voip_config_data_cfg);

    if (BCMOS_TRUE != bcm_omci_voip_config_data_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_voip_config_data_cfg_data_bounds_check(&p_me_voip_config_data_cfg->data, p_me_voip_config_data_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_voip_config_data_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_voip_config_data_cfg_encode(p_me_voip_config_data_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_voip_config_data_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_voip_config_data_cfg *p_me_voip_config_data_cfg = (bcm_omci_voip_config_data_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_voip_config_data_cfg_data_decode(&p_me_voip_config_data_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_voip_config_data_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_voip_config_data_cfg *p_me_voip_config_data_cfg = (const bcm_omci_voip_config_data_cfg *)me_hdr;
    const bcm_omci_voip_config_data_cfg_data *p_me_cfg_data = &p_me_voip_config_data_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_voip_config_data_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_voip_config_data_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_AVAILABLE_SIGNALLING_PROTOCOLS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tavailable_signalling_protocols:\t%u\n", p_me_cfg_data->available_signalling_protocols);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_SIGNALLING_PROTOCOL_USED)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsignalling_protocol_used:\t%u\n", p_me_cfg_data->signalling_protocol_used);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_AVAILABLE_VOIP_CONFIG_METHODS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tavailable_voip_config_methods:\t%u\n", p_me_cfg_data->available_voip_config_methods);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOIP_CONFIG_METHOD_USED)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tvoip_config_method_used:\t%u\n", p_me_cfg_data->voip_config_method_used);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOICE_CONFIG_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tvoice_config_ptr:\t%u\n", p_me_cfg_data->voice_config_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOIP_CONFIG_STATE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tvoip_config_state:\t%u\n", p_me_cfg_data->voip_config_state);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_RETRIEVE_PROFILE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tretrieve_profile:\t%u\n", p_me_cfg_data->retrieve_profile);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_PROFILE_VERSION)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tprofile_version:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->profile_version)[0], ((const uint8_t *)&p_me_cfg_data->profile_version)[1], ((const uint8_t *)&p_me_cfg_data->profile_version)[2], ((const uint8_t *)&p_me_cfg_data->profile_version)[3], ((const uint8_t *)&p_me_cfg_data->profile_version)[4], ((const uint8_t *)&p_me_cfg_data->profile_version)[5], ((const uint8_t *)&p_me_cfg_data->profile_version)[6], ((const uint8_t *)&p_me_cfg_data->profile_version)[7], ((const uint8_t *)&p_me_cfg_data->profile_version)[8], ((const uint8_t *)&p_me_cfg_data->profile_version)[9], ((const uint8_t *)&p_me_cfg_data->profile_version)[10], ((const uint8_t *)&p_me_cfg_data->profile_version)[11], ((const uint8_t *)&p_me_cfg_data->profile_version)[12], ((const uint8_t *)&p_me_cfg_data->profile_version)[13], ((const uint8_t *)&p_me_cfg_data->profile_version)[14], ((const uint8_t *)&p_me_cfg_data->profile_version)[15], ((const uint8_t *)&p_me_cfg_data->profile_version)[16], ((const uint8_t *)&p_me_cfg_data->profile_version)[17], ((const uint8_t *)&p_me_cfg_data->profile_version)[18], ((const uint8_t *)&p_me_cfg_data->profile_version)[19], ((const uint8_t *)&p_me_cfg_data->profile_version)[20], ((const uint8_t *)&p_me_cfg_data->profile_version)[21], ((const uint8_t *)&p_me_cfg_data->profile_version)[22], ((const uint8_t *)&p_me_cfg_data->profile_version)[23], ((const uint8_t *)&p_me_cfg_data->profile_version)[24]);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_voip_config_data_cfg_data_encode(const bcm_omci_voip_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_voip_config_data_cfg_data_encode(const bcm_omci_voip_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_AVAILABLE_SIGNALLING_PROTOCOLS)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->available_signalling_protocols))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_SIGNALLING_PROTOCOL_USED)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->signalling_protocol_used))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_AVAILABLE_VOIP_CONFIG_METHODS)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->available_voip_config_methods))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOIP_CONFIG_METHOD_USED)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->voip_config_method_used))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOICE_CONFIG_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->voice_config_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOIP_CONFIG_STATE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->voip_config_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_RETRIEVE_PROFILE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->retrieve_profile))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_PROFILE_VERSION)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->profile_version, 25))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_voip_config_data_cfg_encode(const bcm_omci_voip_config_data_cfg *p_me_voip_config_data_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_voip_config_data_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_voip_config_data_cfg_data_encode(&p_me_voip_config_data_cfg->data, p_bcm_buf, p_me_voip_config_data_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_voip_config_data_cfg_data_decode(bcm_omci_voip_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_AVAILABLE_SIGNALLING_PROTOCOLS)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->available_signalling_protocols))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_SIGNALLING_PROTOCOL_USED)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->signalling_protocol_used))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_AVAILABLE_VOIP_CONFIG_METHODS)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, (uint32_t *)&p_me_cfg_data->available_voip_config_methods))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOIP_CONFIG_METHOD_USED)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->voip_config_method_used))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOICE_CONFIG_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->voice_config_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_VOIP_CONFIG_STATE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->voip_config_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_RETRIEVE_PROFILE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->retrieve_profile))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_CONFIG_DATA_CFG_ID_PROFILE_VERSION)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->profile_version, 25))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* VoIP voice CTP (9.9.4) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_voip_voice_ctp_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_voip_voice_ctp_cfg *p_src_me_voip_voice_ctp_cfg = (const bcm_omci_voip_voice_ctp_cfg *)src_me_cfg;
    bcm_omci_voip_voice_ctp_cfg *p_dst_me_voip_voice_ctp_cfg = (bcm_omci_voip_voice_ctp_cfg *)dst_me_cfg;

    p_dst_me_voip_voice_ctp_cfg->hdr.presence_mask |= p_src_me_voip_voice_ctp_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_voip_voice_ctp_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_USER_PROTOCOL_PTR)) != 0)
    {
        p_dst_me_voip_voice_ctp_cfg->data.user_protocol_ptr = p_src_me_voip_voice_ctp_cfg->data.user_protocol_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_PPTP_PTR)) != 0)
    {
        p_dst_me_voip_voice_ctp_cfg->data.pptp_ptr = p_src_me_voip_voice_ctp_cfg->data.pptp_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_VOICE_MEDIA_PROFILE_PTR)) != 0)
    {
        p_dst_me_voip_voice_ctp_cfg->data.voice_media_profile_ptr = p_src_me_voip_voice_ctp_cfg->data.voice_media_profile_ptr;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_SIGNALLING_CODE)) != 0)
    {
        p_dst_me_voip_voice_ctp_cfg->data.signalling_code = p_src_me_voip_voice_ctp_cfg->data.signalling_code;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_voip_voice_ctp_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_voip_voice_ctp_cfg *p_me_voip_voice_ctp_cfg = (const bcm_omci_voip_voice_ctp_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_voip_voice_ctp_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_VOIP_VOICE_CTP_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_voip_voice_ctp_cfg);

    if (BCMOS_TRUE != bcm_omci_voip_voice_ctp_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_voip_voice_ctp_cfg_data_bounds_check(&p_me_voip_voice_ctp_cfg->data, p_me_voip_voice_ctp_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_voip_voice_ctp_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_voip_voice_ctp_cfg_encode(p_me_voip_voice_ctp_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_voip_voice_ctp_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_voip_voice_ctp_cfg *p_me_voip_voice_ctp_cfg = (bcm_omci_voip_voice_ctp_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_voip_voice_ctp_cfg_data_decode(&p_me_voip_voice_ctp_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_voip_voice_ctp_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_voip_voice_ctp_cfg *p_me_voip_voice_ctp_cfg = (const bcm_omci_voip_voice_ctp_cfg *)me_hdr;
    const bcm_omci_voip_voice_ctp_cfg_data *p_me_cfg_data = &p_me_voip_voice_ctp_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_voip_voice_ctp_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_voip_voice_ctp_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_USER_PROTOCOL_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tuser_protocol_ptr:\t%u\n", p_me_cfg_data->user_protocol_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_PPTP_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpptp_ptr:\t%u\n", p_me_cfg_data->pptp_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_VOICE_MEDIA_PROFILE_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tvoice_media_profile_ptr:\t%u\n", p_me_cfg_data->voice_media_profile_ptr);
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_SIGNALLING_CODE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tsignalling_code:\t%u\n", p_me_cfg_data->signalling_code);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_voip_voice_ctp_cfg_data_encode(const bcm_omci_voip_voice_ctp_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_voip_voice_ctp_cfg_data_encode(const bcm_omci_voip_voice_ctp_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_USER_PROTOCOL_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->user_protocol_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_PPTP_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->pptp_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_VOICE_MEDIA_PROFILE_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->voice_media_profile_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_SIGNALLING_CODE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->signalling_code))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_voip_voice_ctp_cfg_encode(const bcm_omci_voip_voice_ctp_cfg *p_me_voip_voice_ctp_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_voip_voice_ctp_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_voip_voice_ctp_cfg_data_encode(&p_me_voip_voice_ctp_cfg->data, p_bcm_buf, p_me_voip_voice_ctp_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_voip_voice_ctp_cfg_data_decode(bcm_omci_voip_voice_ctp_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_USER_PROTOCOL_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->user_protocol_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_PPTP_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->pptp_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_VOICE_MEDIA_PROFILE_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->voice_media_profile_ptr))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_VOIP_VOICE_CTP_CFG_ID_SIGNALLING_CODE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->signalling_code))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* TCP/UDP config data (9.4.3) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_tcp_udp_config_data_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_tcp_udp_config_data_cfg *p_src_me_tcp_udp_config_data_cfg = (const bcm_omci_tcp_udp_config_data_cfg *)src_me_cfg;
    bcm_omci_tcp_udp_config_data_cfg *p_dst_me_tcp_udp_config_data_cfg = (bcm_omci_tcp_udp_config_data_cfg *)dst_me_cfg;

    p_dst_me_tcp_udp_config_data_cfg->hdr.presence_mask |= p_src_me_tcp_udp_config_data_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_tcp_udp_config_data_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_PORT_ID)) != 0)
    {
        p_dst_me_tcp_udp_config_data_cfg->data.port_id = p_src_me_tcp_udp_config_data_cfg->data.port_id;
    }
    if ((fields_present & (1ULL << BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_PROTOCOL)) != 0)
    {
        p_dst_me_tcp_udp_config_data_cfg->data.protocol = p_src_me_tcp_udp_config_data_cfg->data.protocol;
    }
    if ((fields_present & (1ULL << BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_TOS)) != 0)
    {
        p_dst_me_tcp_udp_config_data_cfg->data.tos = p_src_me_tcp_udp_config_data_cfg->data.tos;
    }
    if ((fields_present & (1ULL << BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_IP_HOST_PTR)) != 0)
    {
        p_dst_me_tcp_udp_config_data_cfg->data.ip_host_ptr = p_src_me_tcp_udp_config_data_cfg->data.ip_host_ptr;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_tcp_udp_config_data_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_tcp_udp_config_data_cfg *p_me_tcp_udp_config_data_cfg = (const bcm_omci_tcp_udp_config_data_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_tcp_udp_config_data_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_tcp_udp_config_data_cfg);

    if (BCMOS_TRUE != bcm_omci_tcp_udp_config_data_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_tcp_udp_config_data_cfg_data_bounds_check(&p_me_tcp_udp_config_data_cfg->data, p_me_tcp_udp_config_data_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_tcp_udp_config_data_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_tcp_udp_config_data_cfg_encode(p_me_tcp_udp_config_data_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_tcp_udp_config_data_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_tcp_udp_config_data_cfg *p_me_tcp_udp_config_data_cfg = (bcm_omci_tcp_udp_config_data_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_tcp_udp_config_data_cfg_data_decode(&p_me_tcp_udp_config_data_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_tcp_udp_config_data_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_tcp_udp_config_data_cfg *p_me_tcp_udp_config_data_cfg = (const bcm_omci_tcp_udp_config_data_cfg *)me_hdr;
    const bcm_omci_tcp_udp_config_data_cfg_data *p_me_cfg_data = &p_me_tcp_udp_config_data_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_tcp_udp_config_data_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_tcp_udp_config_data_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_PORT_ID)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tport_id:\t%u\n", p_me_cfg_data->port_id);
    if ((fields_present & (1ULL << BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_PROTOCOL)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tprotocol:\t%u\n", p_me_cfg_data->protocol);
    if ((fields_present & (1ULL << BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_TOS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttos:\t%u\n", p_me_cfg_data->tos);
    if ((fields_present & (1ULL << BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_IP_HOST_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tip_host_ptr:\t%u\n", p_me_cfg_data->ip_host_ptr);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_tcp_udp_config_data_cfg_data_encode(const bcm_omci_tcp_udp_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_tcp_udp_config_data_cfg_data_encode(const bcm_omci_tcp_udp_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_PORT_ID)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->port_id))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_PROTOCOL)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->protocol))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_TOS)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->tos))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_IP_HOST_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->ip_host_ptr))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_tcp_udp_config_data_cfg_encode(const bcm_omci_tcp_udp_config_data_cfg *p_me_tcp_udp_config_data_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_tcp_udp_config_data_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_tcp_udp_config_data_cfg_data_encode(&p_me_tcp_udp_config_data_cfg->data, p_bcm_buf, p_me_tcp_udp_config_data_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_tcp_udp_config_data_cfg_data_decode(bcm_omci_tcp_udp_config_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_PORT_ID)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->port_id))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_PROTOCOL)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->protocol))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_TOS)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->tos))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_TCP_UDP_CONFIG_DATA_CFG_ID_IP_HOST_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->ip_host_ptr))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* Network dial plan table (9.9.10) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_network_dial_plan_table_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_network_dial_plan_table_cfg *p_src_me_network_dial_plan_table_cfg = (const bcm_omci_network_dial_plan_table_cfg *)src_me_cfg;
    bcm_omci_network_dial_plan_table_cfg *p_dst_me_network_dial_plan_table_cfg = (bcm_omci_network_dial_plan_table_cfg *)dst_me_cfg;

    p_dst_me_network_dial_plan_table_cfg->hdr.presence_mask |= p_src_me_network_dial_plan_table_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_network_dial_plan_table_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_NUMBER)) != 0)
    {
        p_dst_me_network_dial_plan_table_cfg->data.dial_plan_number = p_src_me_network_dial_plan_table_cfg->data.dial_plan_number;
    }
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_TABLE_MAX_SIZE)) != 0)
    {
        p_dst_me_network_dial_plan_table_cfg->data.dial_plan_table_max_size = p_src_me_network_dial_plan_table_cfg->data.dial_plan_table_max_size;
    }
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_CRITICAL_DIAL_TIMEOUT)) != 0)
    {
        p_dst_me_network_dial_plan_table_cfg->data.critical_dial_timeout = p_src_me_network_dial_plan_table_cfg->data.critical_dial_timeout;
    }
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_PARTIAL_DIAL_TIMEOUT)) != 0)
    {
        p_dst_me_network_dial_plan_table_cfg->data.partial_dial_timeout = p_src_me_network_dial_plan_table_cfg->data.partial_dial_timeout;
    }
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_FORMAT)) != 0)
    {
        p_dst_me_network_dial_plan_table_cfg->data.dial_plan_format = p_src_me_network_dial_plan_table_cfg->data.dial_plan_format;
    }
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_TABLE)) != 0)
    {
        /* doing struct copy */
        p_dst_me_network_dial_plan_table_cfg->data.dial_plan_table = p_src_me_network_dial_plan_table_cfg->data.dial_plan_table;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_network_dial_plan_table_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_network_dial_plan_table_cfg *p_me_network_dial_plan_table_cfg = (const bcm_omci_network_dial_plan_table_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_network_dial_plan_table_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_network_dial_plan_table_cfg);

    if (BCMOS_TRUE != bcm_omci_network_dial_plan_table_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_network_dial_plan_table_cfg_data_bounds_check(&p_me_network_dial_plan_table_cfg->data, p_me_network_dial_plan_table_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_network_dial_plan_table_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_network_dial_plan_table_cfg_encode(p_me_network_dial_plan_table_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_network_dial_plan_table_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_network_dial_plan_table_cfg *p_me_network_dial_plan_table_cfg = (bcm_omci_network_dial_plan_table_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_network_dial_plan_table_cfg_data_decode(&p_me_network_dial_plan_table_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */
static bcmos_bool bcm_omci_network_dial_plan_table_dial_plan_table_log(const bcm_omci_me_key *key, const bcm_omci_network_dial_plan_table_dial_plan_table *this, dev_log_id log_id, bcm_dev_log_level log_level)
{
    BCM_LOG_LEVEL(log_level, log_id, "\t\tdial_plan_id: %u\n", this->dial_plan_id);
    BCM_LOG_LEVEL(log_level, log_id, "\t\taction: %u\n", this->action);
    bcm_omci_stack_util_dump_raw_buf(key, this->dial_plan_token, 28, log_id_bcm_omci_stack_me_layer);

    return BCM_ERR_OK;
}

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_network_dial_plan_table_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_network_dial_plan_table_cfg *p_me_network_dial_plan_table_cfg = (const bcm_omci_network_dial_plan_table_cfg *)me_hdr;
    const bcm_omci_network_dial_plan_table_cfg_data *p_me_cfg_data = &p_me_network_dial_plan_table_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_network_dial_plan_table_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_network_dial_plan_table_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_NUMBER)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdial_plan_number:\t%u\n", p_me_cfg_data->dial_plan_number);
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_TABLE_MAX_SIZE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdial_plan_table_max_size:\t%u\n", p_me_cfg_data->dial_plan_table_max_size);
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_CRITICAL_DIAL_TIMEOUT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcritical_dial_timeout:\t%u\n", p_me_cfg_data->critical_dial_timeout);
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_PARTIAL_DIAL_TIMEOUT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpartial_dial_timeout:\t%u\n", p_me_cfg_data->partial_dial_timeout);
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_FORMAT)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdial_plan_format:\t%u\n", p_me_cfg_data->dial_plan_format);
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_TABLE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdial_plan_table:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[0], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[1], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[2], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[3], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[4], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[5], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[6], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[7], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[8], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[9], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[10], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[11], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[12], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[13], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[14], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[15], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[16], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[17], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[18], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[19], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[20], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[21], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[22], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[23], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[24], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[25], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[26], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[27], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[28], ((const uint8_t *)&p_me_cfg_data->dial_plan_table)[29]);

    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_TABLE)) != 0)
        bcm_omci_network_dial_plan_table_dial_plan_table_log(&me_hdr->key, &p_me_cfg_data->dial_plan_table, log_id, log_level);

    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */
static bcmos_bool bcm_omci_network_dial_plan_table_dial_plan_table_cfg_data_encode(bcm_omci_buf *p_bcm_buf, const bcm_omci_network_dial_plan_table_dial_plan_table *this)
{
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->dial_plan_id))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->action))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_write(p_bcm_buf, this->dial_plan_token, 28))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

static bcmos_bool bcm_omci_network_dial_plan_table_cfg_data_encode(const bcm_omci_network_dial_plan_table_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_network_dial_plan_table_cfg_data_encode(const bcm_omci_network_dial_plan_table_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_NUMBER)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->dial_plan_number))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_TABLE_MAX_SIZE)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->dial_plan_table_max_size))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_CRITICAL_DIAL_TIMEOUT)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->critical_dial_timeout))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_PARTIAL_DIAL_TIMEOUT)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->partial_dial_timeout))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_FORMAT)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->dial_plan_format))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_TABLE)) != 0)
    {
        if (!bcm_omci_network_dial_plan_table_dial_plan_table_cfg_data_encode(p_bcm_buf, &p_me_cfg_data->dial_plan_table))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_network_dial_plan_table_cfg_encode(const bcm_omci_network_dial_plan_table_cfg *p_me_network_dial_plan_table_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_network_dial_plan_table_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_network_dial_plan_table_cfg_data_encode(&p_me_network_dial_plan_table_cfg->data, p_bcm_buf, p_me_network_dial_plan_table_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */
static bcmos_bool bcm_omci_network_dial_plan_table_dial_plan_table_cfg_data_decode(bcm_omci_buf *p_bcm_buf, bcm_omci_network_dial_plan_table_dial_plan_table *this)
{
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->dial_plan_id))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->action))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read(p_bcm_buf, this->dial_plan_token, 28))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_network_dial_plan_table_cfg_data_decode(bcm_omci_network_dial_plan_table_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_NUMBER)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->dial_plan_number))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_TABLE_MAX_SIZE)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->dial_plan_table_max_size))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_CRITICAL_DIAL_TIMEOUT)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->critical_dial_timeout))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_PARTIAL_DIAL_TIMEOUT)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->partial_dial_timeout))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_FORMAT)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->dial_plan_format))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_CFG_ID_DIAL_PLAN_TABLE)) != 0)
    {
        if (!bcm_omci_network_dial_plan_table_dial_plan_table_cfg_data_decode(p_bcm_buf, &p_me_cfg_data->dial_plan_table))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* RTP profile data (9.9.7) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_rtp_profile_data_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_rtp_profile_data_cfg *p_src_me_rtp_profile_data_cfg = (const bcm_omci_rtp_profile_data_cfg *)src_me_cfg;
    bcm_omci_rtp_profile_data_cfg *p_dst_me_rtp_profile_data_cfg = (bcm_omci_rtp_profile_data_cfg *)dst_me_cfg;

    p_dst_me_rtp_profile_data_cfg->hdr.presence_mask |= p_src_me_rtp_profile_data_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_rtp_profile_data_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_LOCAL_PORT_MIN)) != 0)
    {
        p_dst_me_rtp_profile_data_cfg->data.local_port_min = p_src_me_rtp_profile_data_cfg->data.local_port_min;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_LOCAL_PORT_MAX)) != 0)
    {
        p_dst_me_rtp_profile_data_cfg->data.local_port_max = p_src_me_rtp_profile_data_cfg->data.local_port_max;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_DSCP_MARK)) != 0)
    {
        p_dst_me_rtp_profile_data_cfg->data.dscp_mark = p_src_me_rtp_profile_data_cfg->data.dscp_mark;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_PIGGYBACK_EVENTS)) != 0)
    {
        p_dst_me_rtp_profile_data_cfg->data.piggyback_events = p_src_me_rtp_profile_data_cfg->data.piggyback_events;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_TONE_EVENTS)) != 0)
    {
        p_dst_me_rtp_profile_data_cfg->data.tone_events = p_src_me_rtp_profile_data_cfg->data.tone_events;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_DTMF_EVENTS)) != 0)
    {
        p_dst_me_rtp_profile_data_cfg->data.dtmf_events = p_src_me_rtp_profile_data_cfg->data.dtmf_events;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_CAS_EVENTS)) != 0)
    {
        p_dst_me_rtp_profile_data_cfg->data.cas_events = p_src_me_rtp_profile_data_cfg->data.cas_events;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_IP_HOST_CONFIG_PTR)) != 0)
    {
        p_dst_me_rtp_profile_data_cfg->data.ip_host_config_ptr = p_src_me_rtp_profile_data_cfg->data.ip_host_config_ptr;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_rtp_profile_data_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_rtp_profile_data_cfg *p_me_rtp_profile_data_cfg = (const bcm_omci_rtp_profile_data_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_rtp_profile_data_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_RTP_PROFILE_DATA_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_rtp_profile_data_cfg);

    if (BCMOS_TRUE != bcm_omci_rtp_profile_data_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_rtp_profile_data_cfg_data_bounds_check(&p_me_rtp_profile_data_cfg->data, p_me_rtp_profile_data_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_rtp_profile_data_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_rtp_profile_data_cfg_encode(p_me_rtp_profile_data_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_rtp_profile_data_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_rtp_profile_data_cfg *p_me_rtp_profile_data_cfg = (bcm_omci_rtp_profile_data_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_rtp_profile_data_cfg_data_decode(&p_me_rtp_profile_data_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_rtp_profile_data_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_rtp_profile_data_cfg *p_me_rtp_profile_data_cfg = (const bcm_omci_rtp_profile_data_cfg *)me_hdr;
    const bcm_omci_rtp_profile_data_cfg_data *p_me_cfg_data = &p_me_rtp_profile_data_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_rtp_profile_data_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_rtp_profile_data_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_LOCAL_PORT_MIN)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tlocal_port_min:\t%u\n", p_me_cfg_data->local_port_min);
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_LOCAL_PORT_MAX)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tlocal_port_max:\t%u\n", p_me_cfg_data->local_port_max);
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_DSCP_MARK)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdscp_mark:\t%u\n", p_me_cfg_data->dscp_mark);
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_PIGGYBACK_EVENTS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpiggyback_events:\t%u\n", p_me_cfg_data->piggyback_events);
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_TONE_EVENTS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttone_events:\t%u\n", p_me_cfg_data->tone_events);
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_DTMF_EVENTS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdtmf_events:\t%u\n", p_me_cfg_data->dtmf_events);
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_CAS_EVENTS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcas_events:\t%u\n", p_me_cfg_data->cas_events);
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_IP_HOST_CONFIG_PTR)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tip_host_config_ptr:\t%u\n", p_me_cfg_data->ip_host_config_ptr);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_rtp_profile_data_cfg_data_encode(const bcm_omci_rtp_profile_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_rtp_profile_data_cfg_data_encode(const bcm_omci_rtp_profile_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_LOCAL_PORT_MIN)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->local_port_min))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_LOCAL_PORT_MAX)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->local_port_max))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_DSCP_MARK)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->dscp_mark))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_PIGGYBACK_EVENTS)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->piggyback_events))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_TONE_EVENTS)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->tone_events))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_DTMF_EVENTS)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->dtmf_events))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_CAS_EVENTS)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->cas_events))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_IP_HOST_CONFIG_PTR)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->ip_host_config_ptr))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_rtp_profile_data_cfg_encode(const bcm_omci_rtp_profile_data_cfg *p_me_rtp_profile_data_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_rtp_profile_data_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_rtp_profile_data_cfg_data_encode(&p_me_rtp_profile_data_cfg->data, p_bcm_buf, p_me_rtp_profile_data_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_rtp_profile_data_cfg_data_decode(bcm_omci_rtp_profile_data_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_LOCAL_PORT_MIN)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->local_port_min))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_LOCAL_PORT_MAX)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->local_port_max))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_DSCP_MARK)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->dscp_mark))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_PIGGYBACK_EVENTS)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->piggyback_events))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_TONE_EVENTS)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->tone_events))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_DTMF_EVENTS)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->dtmf_events))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_CAS_EVENTS)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->cas_events))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_RTP_PROFILE_DATA_CFG_ID_IP_HOST_CONFIG_PTR)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->ip_host_config_ptr))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* Physical path termination point POTS UNI (9.9.1) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_pots_uni_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_pots_uni_cfg *p_src_me_pots_uni_cfg = (const bcm_omci_pots_uni_cfg *)src_me_cfg;
    bcm_omci_pots_uni_cfg *p_dst_me_pots_uni_cfg = (bcm_omci_pots_uni_cfg *)dst_me_cfg;

    p_dst_me_pots_uni_cfg->hdr.presence_mask |= p_src_me_pots_uni_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_pots_uni_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_ADMIN_STATE)) != 0)
    {
        p_dst_me_pots_uni_cfg->data.admin_state = p_src_me_pots_uni_cfg->data.admin_state;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_DEPRECATED1)) != 0)
    {
        p_dst_me_pots_uni_cfg->data.deprecated1 = p_src_me_pots_uni_cfg->data.deprecated1;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_ARC)) != 0)
    {
        p_dst_me_pots_uni_cfg->data.arc = p_src_me_pots_uni_cfg->data.arc;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_ARC_INTERVAL)) != 0)
    {
        p_dst_me_pots_uni_cfg->data.arc_interval = p_src_me_pots_uni_cfg->data.arc_interval;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_IMPEDANCE)) != 0)
    {
        p_dst_me_pots_uni_cfg->data.impedance = p_src_me_pots_uni_cfg->data.impedance;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_TRANSMISSION_PATH)) != 0)
    {
        p_dst_me_pots_uni_cfg->data.transmission_path = p_src_me_pots_uni_cfg->data.transmission_path;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_RX_GAIN)) != 0)
    {
        p_dst_me_pots_uni_cfg->data.rx_gain = p_src_me_pots_uni_cfg->data.rx_gain;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_TX_GAIN)) != 0)
    {
        p_dst_me_pots_uni_cfg->data.tx_gain = p_src_me_pots_uni_cfg->data.tx_gain;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_OPER_STATE)) != 0)
    {
        p_dst_me_pots_uni_cfg->data.oper_state = p_src_me_pots_uni_cfg->data.oper_state;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_HOOK_STATE)) != 0)
    {
        p_dst_me_pots_uni_cfg->data.hook_state = p_src_me_pots_uni_cfg->data.hook_state;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_HOLDOVER_TIME)) != 0)
    {
        p_dst_me_pots_uni_cfg->data.holdover_time = p_src_me_pots_uni_cfg->data.holdover_time;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_NOMINAL_FEED_VOLTAGE)) != 0)
    {
        p_dst_me_pots_uni_cfg->data.nominal_feed_voltage = p_src_me_pots_uni_cfg->data.nominal_feed_voltage;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_pots_uni_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_pots_uni_cfg *p_me_pots_uni_cfg = (const bcm_omci_pots_uni_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_pots_uni_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_POTS_UNI_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_pots_uni_cfg);

    if (BCMOS_TRUE != bcm_omci_pots_uni_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_pots_uni_cfg_data_bounds_check(&p_me_pots_uni_cfg->data, p_me_pots_uni_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_pots_uni_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_pots_uni_cfg_encode(p_me_pots_uni_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_pots_uni_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_pots_uni_cfg *p_me_pots_uni_cfg = (bcm_omci_pots_uni_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_pots_uni_cfg_data_decode(&p_me_pots_uni_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_pots_uni_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_pots_uni_cfg *p_me_pots_uni_cfg = (const bcm_omci_pots_uni_cfg *)me_hdr;
    const bcm_omci_pots_uni_cfg_data *p_me_cfg_data = &p_me_pots_uni_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_pots_uni_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_pots_uni_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_ADMIN_STATE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tadmin_state:\t%u\n", p_me_cfg_data->admin_state);
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_DEPRECATED1)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tdeprecated1:\t%u\n", p_me_cfg_data->deprecated1);
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_ARC)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tarc:\t%u\n", p_me_cfg_data->arc);
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_ARC_INTERVAL)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tarc_interval:\t%u\n", p_me_cfg_data->arc_interval);
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_IMPEDANCE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\timpedance:\t%u\n", p_me_cfg_data->impedance);
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_TRANSMISSION_PATH)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttransmission_path:\t%u\n", p_me_cfg_data->transmission_path);
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_RX_GAIN)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\trx_gain:\t%u\n", p_me_cfg_data->rx_gain);
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_TX_GAIN)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttx_gain:\t%u\n", p_me_cfg_data->tx_gain);
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_OPER_STATE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\toper_state:\t%u\n", p_me_cfg_data->oper_state);
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_HOOK_STATE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\thook_state:\t%u\n", p_me_cfg_data->hook_state);
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_HOLDOVER_TIME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tholdover_time:\t%u\n", p_me_cfg_data->holdover_time);
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_NOMINAL_FEED_VOLTAGE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tnominal_feed_voltage:\t%u\n", p_me_cfg_data->nominal_feed_voltage);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_pots_uni_cfg_data_encode(const bcm_omci_pots_uni_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_pots_uni_cfg_data_encode(const bcm_omci_pots_uni_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_ADMIN_STATE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->admin_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_DEPRECATED1)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->deprecated1))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_ARC)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->arc))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_ARC_INTERVAL)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->arc_interval))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_IMPEDANCE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->impedance))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_TRANSMISSION_PATH)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->transmission_path))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_RX_GAIN)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->rx_gain))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_TX_GAIN)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->tx_gain))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_OPER_STATE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->oper_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_HOOK_STATE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->hook_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_HOLDOVER_TIME)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->holdover_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_NOMINAL_FEED_VOLTAGE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->nominal_feed_voltage))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_pots_uni_cfg_encode(const bcm_omci_pots_uni_cfg *p_me_pots_uni_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_pots_uni_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_pots_uni_cfg_data_encode(&p_me_pots_uni_cfg->data, p_bcm_buf, p_me_pots_uni_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_pots_uni_cfg_data_decode(bcm_omci_pots_uni_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_ADMIN_STATE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->admin_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_DEPRECATED1)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->deprecated1))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_ARC)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->arc))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_ARC_INTERVAL)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->arc_interval))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_IMPEDANCE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->impedance))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_TRANSMISSION_PATH)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->transmission_path))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_RX_GAIN)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->rx_gain))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_TX_GAIN)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->tx_gain))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_OPER_STATE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->oper_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_HOOK_STATE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->hook_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_HOLDOVER_TIME)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->holdover_time))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_POTS_UNI_CFG_ID_NOMINAL_FEED_VOLTAGE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->nominal_feed_voltage))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* Circuit pack (9.1.6) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_circuit_pack_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_circuit_pack_cfg *p_src_me_circuit_pack_cfg = (const bcm_omci_circuit_pack_cfg *)src_me_cfg;
    bcm_omci_circuit_pack_cfg *p_dst_me_circuit_pack_cfg = (bcm_omci_circuit_pack_cfg *)dst_me_cfg;

    p_dst_me_circuit_pack_cfg->hdr.presence_mask |= p_src_me_circuit_pack_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_circuit_pack_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_TYPE)) != 0)
    {
        p_dst_me_circuit_pack_cfg->data.type = p_src_me_circuit_pack_cfg->data.type;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_NUMBER_OF_PORTS)) != 0)
    {
        p_dst_me_circuit_pack_cfg->data.number_of_ports = p_src_me_circuit_pack_cfg->data.number_of_ports;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_SERIAL_NUMBER)) != 0)
    {
        memcpy(p_dst_me_circuit_pack_cfg->data.serial_number, p_src_me_circuit_pack_cfg->data.serial_number, 8);
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_VERSION)) != 0)
    {
        memcpy(p_dst_me_circuit_pack_cfg->data.version, p_src_me_circuit_pack_cfg->data.version, 14);
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_VENDOR_ID)) != 0)
    {
        memcpy(p_dst_me_circuit_pack_cfg->data.vendor_id, p_src_me_circuit_pack_cfg->data.vendor_id, 4);
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_ADMIN_STATE)) != 0)
    {
        p_dst_me_circuit_pack_cfg->data.admin_state = p_src_me_circuit_pack_cfg->data.admin_state;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_OPER_STATE)) != 0)
    {
        p_dst_me_circuit_pack_cfg->data.oper_state = p_src_me_circuit_pack_cfg->data.oper_state;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_BRIDGED_OR_IP)) != 0)
    {
        p_dst_me_circuit_pack_cfg->data.bridged_or_ip = p_src_me_circuit_pack_cfg->data.bridged_or_ip;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_EQUIP_ID)) != 0)
    {
        memcpy(p_dst_me_circuit_pack_cfg->data.equip_id, p_src_me_circuit_pack_cfg->data.equip_id, 20);
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_CARD_CONFIG)) != 0)
    {
        p_dst_me_circuit_pack_cfg->data.card_config = p_src_me_circuit_pack_cfg->data.card_config;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_TCONT_BUFFER_NUMBER)) != 0)
    {
        p_dst_me_circuit_pack_cfg->data.tcont_buffer_number = p_src_me_circuit_pack_cfg->data.tcont_buffer_number;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_PRIORITY_QUEUE_NUMBER)) != 0)
    {
        p_dst_me_circuit_pack_cfg->data.priority_queue_number = p_src_me_circuit_pack_cfg->data.priority_queue_number;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_TRAFFIC_SCHED_NUMBER)) != 0)
    {
        p_dst_me_circuit_pack_cfg->data.traffic_sched_number = p_src_me_circuit_pack_cfg->data.traffic_sched_number;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_POWER_SHED_OVERRIDE)) != 0)
    {
        p_dst_me_circuit_pack_cfg->data.power_shed_override = p_src_me_circuit_pack_cfg->data.power_shed_override;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_circuit_pack_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_circuit_pack_cfg *p_me_circuit_pack_cfg = (const bcm_omci_circuit_pack_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_circuit_pack_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_CIRCUIT_PACK_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_circuit_pack_cfg);

    if (BCMOS_TRUE != bcm_omci_circuit_pack_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_circuit_pack_cfg_data_bounds_check(&p_me_circuit_pack_cfg->data, p_me_circuit_pack_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_circuit_pack_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_circuit_pack_cfg_encode(p_me_circuit_pack_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_circuit_pack_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_circuit_pack_cfg *p_me_circuit_pack_cfg = (bcm_omci_circuit_pack_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_circuit_pack_cfg_data_decode(&p_me_circuit_pack_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_circuit_pack_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_circuit_pack_cfg *p_me_circuit_pack_cfg = (const bcm_omci_circuit_pack_cfg *)me_hdr;
    const bcm_omci_circuit_pack_cfg_data *p_me_cfg_data = &p_me_circuit_pack_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_circuit_pack_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_circuit_pack_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_TYPE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttype:\t%u\n", p_me_cfg_data->type);
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_NUMBER_OF_PORTS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tnumber_of_ports:\t%u\n", p_me_cfg_data->number_of_ports);
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_SERIAL_NUMBER)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tserial_number:\t%02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->serial_number)[0], ((const uint8_t *)&p_me_cfg_data->serial_number)[1], ((const uint8_t *)&p_me_cfg_data->serial_number)[2], ((const uint8_t *)&p_me_cfg_data->serial_number)[3], ((const uint8_t *)&p_me_cfg_data->serial_number)[4], ((const uint8_t *)&p_me_cfg_data->serial_number)[5], ((const uint8_t *)&p_me_cfg_data->serial_number)[6], ((const uint8_t *)&p_me_cfg_data->serial_number)[7]);
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_VERSION)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tversion:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->version)[0], ((const uint8_t *)&p_me_cfg_data->version)[1], ((const uint8_t *)&p_me_cfg_data->version)[2], ((const uint8_t *)&p_me_cfg_data->version)[3], ((const uint8_t *)&p_me_cfg_data->version)[4], ((const uint8_t *)&p_me_cfg_data->version)[5], ((const uint8_t *)&p_me_cfg_data->version)[6], ((const uint8_t *)&p_me_cfg_data->version)[7], ((const uint8_t *)&p_me_cfg_data->version)[8], ((const uint8_t *)&p_me_cfg_data->version)[9], ((const uint8_t *)&p_me_cfg_data->version)[10], ((const uint8_t *)&p_me_cfg_data->version)[11], ((const uint8_t *)&p_me_cfg_data->version)[12], ((const uint8_t *)&p_me_cfg_data->version)[13]);
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_VENDOR_ID)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tvendor_id:\t%02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->vendor_id)[0], ((const uint8_t *)&p_me_cfg_data->vendor_id)[1], ((const uint8_t *)&p_me_cfg_data->vendor_id)[2], ((const uint8_t *)&p_me_cfg_data->vendor_id)[3]);
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_ADMIN_STATE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tadmin_state:\t%u\n", p_me_cfg_data->admin_state);
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_OPER_STATE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\toper_state:\t%u\n", p_me_cfg_data->oper_state);
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_BRIDGED_OR_IP)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tbridged_or_ip:\t%u\n", p_me_cfg_data->bridged_or_ip);
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_EQUIP_ID)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tequip_id:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->equip_id)[0], ((const uint8_t *)&p_me_cfg_data->equip_id)[1], ((const uint8_t *)&p_me_cfg_data->equip_id)[2], ((const uint8_t *)&p_me_cfg_data->equip_id)[3], ((const uint8_t *)&p_me_cfg_data->equip_id)[4], ((const uint8_t *)&p_me_cfg_data->equip_id)[5], ((const uint8_t *)&p_me_cfg_data->equip_id)[6], ((const uint8_t *)&p_me_cfg_data->equip_id)[7], ((const uint8_t *)&p_me_cfg_data->equip_id)[8], ((const uint8_t *)&p_me_cfg_data->equip_id)[9], ((const uint8_t *)&p_me_cfg_data->equip_id)[10], ((const uint8_t *)&p_me_cfg_data->equip_id)[11], ((const uint8_t *)&p_me_cfg_data->equip_id)[12], ((const uint8_t *)&p_me_cfg_data->equip_id)[13], ((const uint8_t *)&p_me_cfg_data->equip_id)[14], ((const uint8_t *)&p_me_cfg_data->equip_id)[15], ((const uint8_t *)&p_me_cfg_data->equip_id)[16], ((const uint8_t *)&p_me_cfg_data->equip_id)[17], ((const uint8_t *)&p_me_cfg_data->equip_id)[18], ((const uint8_t *)&p_me_cfg_data->equip_id)[19]);
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_CARD_CONFIG)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcard_config:\t%u\n", p_me_cfg_data->card_config);
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_TCONT_BUFFER_NUMBER)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttcont_buffer_number:\t%u\n", p_me_cfg_data->tcont_buffer_number);
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_PRIORITY_QUEUE_NUMBER)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpriority_queue_number:\t%u\n", p_me_cfg_data->priority_queue_number);
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_TRAFFIC_SCHED_NUMBER)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\ttraffic_sched_number:\t%u\n", p_me_cfg_data->traffic_sched_number);
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_POWER_SHED_OVERRIDE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tpower_shed_override:\t%u\n", p_me_cfg_data->power_shed_override);


    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */

static bcmos_bool bcm_omci_circuit_pack_cfg_data_encode(const bcm_omci_circuit_pack_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_circuit_pack_cfg_data_encode(const bcm_omci_circuit_pack_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_TYPE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->type))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_NUMBER_OF_PORTS)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->number_of_ports))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_SERIAL_NUMBER)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->serial_number, 8))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_VERSION)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->version, 14))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_VENDOR_ID)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->vendor_id, 4))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_ADMIN_STATE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->admin_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_OPER_STATE)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->oper_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_BRIDGED_OR_IP)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->bridged_or_ip))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_EQUIP_ID)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->equip_id, 20))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_CARD_CONFIG)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->card_config))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_TCONT_BUFFER_NUMBER)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->tcont_buffer_number))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_PRIORITY_QUEUE_NUMBER)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->priority_queue_number))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_TRAFFIC_SCHED_NUMBER)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->traffic_sched_number))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_POWER_SHED_OVERRIDE)) != 0)
    {
        if (!bcm_omci_buf_write_u32(p_bcm_buf, p_me_cfg_data->power_shed_override))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_circuit_pack_cfg_encode(const bcm_omci_circuit_pack_cfg *p_me_circuit_pack_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_circuit_pack_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_circuit_pack_cfg_data_encode(&p_me_circuit_pack_cfg->data, p_bcm_buf, p_me_circuit_pack_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_circuit_pack_cfg_data_decode(bcm_omci_circuit_pack_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_TYPE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->type))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_NUMBER_OF_PORTS)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->number_of_ports))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_SERIAL_NUMBER)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->serial_number, 8))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_VERSION)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->version, 14))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_VENDOR_ID)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->vendor_id, 4))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_ADMIN_STATE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->admin_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_OPER_STATE)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->oper_state))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_BRIDGED_OR_IP)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->bridged_or_ip))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_EQUIP_ID)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->equip_id, 20))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_CARD_CONFIG)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&p_me_cfg_data->card_config))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_TCONT_BUFFER_NUMBER)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->tcont_buffer_number))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_PRIORITY_QUEUE_NUMBER)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->priority_queue_number))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_TRAFFIC_SCHED_NUMBER)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->traffic_sched_number))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_CIRCUIT_PACK_CFG_ID_POWER_SHED_OVERRIDE)) != 0)
    {
        if (!bcm_omci_buf_read_u32(p_bcm_buf, &p_me_cfg_data->power_shed_override))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

/* Enhanced Security Control (9.13.11) */

/* copy ME segment from src to destination */
static bcmos_errno bcm_omci_me_enhanced_security_control_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg)
{
    BUG_ON(NULL == src_me_cfg);
    BUG_ON(NULL == dst_me_cfg);

    const bcm_omci_enhanced_security_control_cfg *p_src_me_enhanced_security_control_cfg = (const bcm_omci_enhanced_security_control_cfg *)src_me_cfg;
    bcm_omci_enhanced_security_control_cfg *p_dst_me_enhanced_security_control_cfg = (bcm_omci_enhanced_security_control_cfg *)dst_me_cfg;

    p_dst_me_enhanced_security_control_cfg->hdr.presence_mask |= p_src_me_enhanced_security_control_cfg->hdr.presence_mask;
    bcm_omci_presence_mask  fields_present = p_src_me_enhanced_security_control_cfg->hdr.presence_mask;

    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_CRYPTO_CAPABILITIES)) != 0)
    {
        memcpy(p_dst_me_enhanced_security_control_cfg->data.crypto_capabilities, p_src_me_enhanced_security_control_cfg->data.crypto_capabilities, 16);
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_RANDOM_CHALLENGE_TABLE)) != 0)
    {
        /* doing struct copy */
        p_dst_me_enhanced_security_control_cfg->data.olt_random_challenge_table = p_src_me_enhanced_security_control_cfg->data.olt_random_challenge_table;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_CHALLENGE_STATUS)) != 0)
    {
        p_dst_me_enhanced_security_control_cfg->data.olt_challenge_status = p_src_me_enhanced_security_control_cfg->data.olt_challenge_status;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_SELECTED_CRYPTO_CAPABILITIES)) != 0)
    {
        p_dst_me_enhanced_security_control_cfg->data.onu_selected_crypto_capabilities = p_src_me_enhanced_security_control_cfg->data.onu_selected_crypto_capabilities;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_RANDOM_CHALLENGE_TABLE)) != 0)
    {
        /* doing struct copy */
        p_dst_me_enhanced_security_control_cfg->data.onu_random_challenge_table = p_src_me_enhanced_security_control_cfg->data.onu_random_challenge_table;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_AUTH_RESULT_TABLE)) != 0)
    {
        /* doing struct copy */
        p_dst_me_enhanced_security_control_cfg->data.onu_auth_result_table = p_src_me_enhanced_security_control_cfg->data.onu_auth_result_table;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_AUTH_RESULT_TABLE)) != 0)
    {
        /* doing struct copy */
        p_dst_me_enhanced_security_control_cfg->data.olt_auth_result_table = p_src_me_enhanced_security_control_cfg->data.olt_auth_result_table;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_RESULT_STATUS)) != 0)
    {
        p_dst_me_enhanced_security_control_cfg->data.olt_result_status = p_src_me_enhanced_security_control_cfg->data.olt_result_status;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_AUTH_STATUS)) != 0)
    {
        p_dst_me_enhanced_security_control_cfg->data.onu_auth_status = p_src_me_enhanced_security_control_cfg->data.onu_auth_status;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_MASTER_SESSION_KEY_NAME)) != 0)
    {
        memcpy(p_dst_me_enhanced_security_control_cfg->data.master_session_key_name, p_src_me_enhanced_security_control_cfg->data.master_session_key_name, 16);
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_BROADCAST_KEY_TABLE)) != 0)
    {
        /* doing struct copy */
        p_dst_me_enhanced_security_control_cfg->data.broadcast_key_table = p_src_me_enhanced_security_control_cfg->data.broadcast_key_table;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_EFFECTIVE_KEY_LENGTH)) != 0)
    {
        p_dst_me_enhanced_security_control_cfg->data.effective_key_length = p_src_me_enhanced_security_control_cfg->data.effective_key_length;
    }

    return BCM_ERR_OK;
}

/* Top level encode function for a me cfg */
static bcmos_errno bcm_omci_me_enhanced_security_control_cfg_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc = BCM_ERR_OK;
    const bcm_omci_enhanced_security_control_cfg *p_me_enhanced_security_control_cfg = (const bcm_omci_enhanced_security_control_cfg *)me_hdr;
    bcm_omci_me_key_id failed_key_prop = 0;
    bcm_omci_enhanced_security_control_cfg_id failed_attr_prop = 0;
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    uint32_t err_attr_id = BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID__NUM_OF;

    *encode_len = 0;
    *encode_buf = NULL;

    BUG_ON(NULL == p_me_enhanced_security_control_cfg);

    if (BCMOS_TRUE != bcm_omci_enhanced_security_control_key_bounds_check(&me_hdr->key, BCM_OMCI_PRESENCE_MASK_ALL, &failed_key_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_enhanced_security_control_cfg_data_bounds_check(&p_me_enhanced_security_control_cfg->data, p_me_enhanced_security_control_cfg->hdr.presence_mask, &failed_attr_prop))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_enhanced_security_control_cfg_actions_check(me_hdr->omci_msg_type))
        return BCM_ERR_PARM;

    if (BCMOS_TRUE != bcm_omci_presence_mask_check(me_hdr, omci_msg_type, &err_attr_id))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error in attr properties check: ME = %s, err attrid = %d\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), err_attr_id);
        return BCM_ERR_PARM;
    }

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_PARM;
    }

    if (BCMOS_TRUE != _bcm_omci_me_enhanced_security_control_cfg_encode(p_me_enhanced_security_control_cfg, &bcm_buf, omci_msg_type))
        return BCM_ERR_PARM;

    /* Bytes 41-48: Skip OMCI Trailer encoding. Transport Layer will fill it in */

    /** Finally set the args out before returning */
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* Top level decode function for a me cfg */
static bcmos_errno bcm_omci_me_enhanced_security_control_cfg_decode(bcm_omci_me_hdr *me_hdr, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    bcm_omci_enhanced_security_control_cfg *p_me_enhanced_security_control_cfg = (bcm_omci_enhanced_security_control_cfg *)me_hdr;

    /** @todo see if other validations need to be done */

    /* Decode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_enhanced_security_control_cfg_data_decode(&p_me_enhanced_security_control_cfg->data, p_bcm_buf, me_hdr->presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCM_ERR_OK;
}

#ifdef ENABLE_LOG
/* Logging function(s) for attribute(s) with fields/ sub-fields */
static bcmos_bool bcm_omci_enhanced_security_control_olt_random_challenge_table_log(const bcm_omci_me_key *key, const bcm_omci_enhanced_security_control_olt_random_challenge_table *this, dev_log_id log_id, bcm_dev_log_level log_level)
{
    BCM_LOG_LEVEL(log_level, log_id, "\t\trow_number: %u\n", this->row_number);
    bcm_omci_stack_util_dump_raw_buf(key, this->content, 16, log_id_bcm_omci_stack_me_layer);

    return BCM_ERR_OK;
}
static bcmos_bool bcm_omci_enhanced_security_control_onu_random_challenge_table_log(const bcm_omci_me_key *key, const bcm_omci_enhanced_security_control_onu_random_challenge_table *this, dev_log_id log_id, bcm_dev_log_level log_level)
{
    bcm_omci_stack_util_dump_raw_buf(key, this->content, 16, log_id_bcm_omci_stack_me_layer);

    return BCM_ERR_OK;
}
static bcmos_bool bcm_omci_enhanced_security_control_onu_auth_result_table_log(const bcm_omci_me_key *key, const bcm_omci_enhanced_security_control_onu_auth_result_table *this, dev_log_id log_id, bcm_dev_log_level log_level)
{
    bcm_omci_stack_util_dump_raw_buf(key, this->content, 16, log_id_bcm_omci_stack_me_layer);

    return BCM_ERR_OK;
}
static bcmos_bool bcm_omci_enhanced_security_control_olt_auth_result_table_log(const bcm_omci_me_key *key, const bcm_omci_enhanced_security_control_olt_auth_result_table *this, dev_log_id log_id, bcm_dev_log_level log_level)
{
    BCM_LOG_LEVEL(log_level, log_id, "\t\trow_number: %u\n", this->row_number);
    bcm_omci_stack_util_dump_raw_buf(key, this->content, 16, log_id_bcm_omci_stack_me_layer);

    return BCM_ERR_OK;
}
static bcmos_bool bcm_omci_enhanced_security_control_broadcast_key_table_log(const bcm_omci_me_key *key, const bcm_omci_enhanced_security_control_broadcast_key_table *this, dev_log_id log_id, bcm_dev_log_level log_level)
{
    BCM_LOG_LEVEL(log_level, log_id, "\t\trow_control: %u\n", this->row_control);
    BCM_LOG_LEVEL(log_level, log_id, "\t\trow_number: %u\n", this->row_number);
    bcm_omci_stack_util_dump_raw_buf(key, this->content, 16, log_id_bcm_omci_stack_me_layer);

    return BCM_ERR_OK;
}

/* Top level log function for a me cfg */
static bcmos_errno bcm_omci_me_enhanced_security_control_cfg_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    const bcm_omci_enhanced_security_control_cfg *p_me_enhanced_security_control_cfg = (const bcm_omci_enhanced_security_control_cfg *)me_hdr;
    const bcm_omci_enhanced_security_control_cfg_data *p_me_cfg_data = &p_me_enhanced_security_control_cfg->data;
    bcm_omci_presence_mask fields_present = p_me_enhanced_security_control_cfg->hdr.presence_mask;

    BCM_LOG_LEVEL(log_level, log_id, "{olt=%u pon_if=%u, onu_id=%u, cookie=%lu}: Dump ME: %s (%d), Entity: %d, Action: %s [\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id, me_hdr->key.cookie,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(p_me_enhanced_security_control_cfg->hdr.omci_msg_type));

    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_CRYPTO_CAPABILITIES)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tcrypto_capabilities:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->crypto_capabilities)[0], ((const uint8_t *)&p_me_cfg_data->crypto_capabilities)[1], ((const uint8_t *)&p_me_cfg_data->crypto_capabilities)[2], ((const uint8_t *)&p_me_cfg_data->crypto_capabilities)[3], ((const uint8_t *)&p_me_cfg_data->crypto_capabilities)[4], ((const uint8_t *)&p_me_cfg_data->crypto_capabilities)[5], ((const uint8_t *)&p_me_cfg_data->crypto_capabilities)[6], ((const uint8_t *)&p_me_cfg_data->crypto_capabilities)[7], ((const uint8_t *)&p_me_cfg_data->crypto_capabilities)[8], ((const uint8_t *)&p_me_cfg_data->crypto_capabilities)[9], ((const uint8_t *)&p_me_cfg_data->crypto_capabilities)[10], ((const uint8_t *)&p_me_cfg_data->crypto_capabilities)[11], ((const uint8_t *)&p_me_cfg_data->crypto_capabilities)[12], ((const uint8_t *)&p_me_cfg_data->crypto_capabilities)[13], ((const uint8_t *)&p_me_cfg_data->crypto_capabilities)[14], ((const uint8_t *)&p_me_cfg_data->crypto_capabilities)[15]);
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_RANDOM_CHALLENGE_TABLE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tolt_random_challenge_table:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->olt_random_challenge_table)[0], ((const uint8_t *)&p_me_cfg_data->olt_random_challenge_table)[1], ((const uint8_t *)&p_me_cfg_data->olt_random_challenge_table)[2], ((const uint8_t *)&p_me_cfg_data->olt_random_challenge_table)[3], ((const uint8_t *)&p_me_cfg_data->olt_random_challenge_table)[4], ((const uint8_t *)&p_me_cfg_data->olt_random_challenge_table)[5], ((const uint8_t *)&p_me_cfg_data->olt_random_challenge_table)[6], ((const uint8_t *)&p_me_cfg_data->olt_random_challenge_table)[7], ((const uint8_t *)&p_me_cfg_data->olt_random_challenge_table)[8], ((const uint8_t *)&p_me_cfg_data->olt_random_challenge_table)[9], ((const uint8_t *)&p_me_cfg_data->olt_random_challenge_table)[10], ((const uint8_t *)&p_me_cfg_data->olt_random_challenge_table)[11], ((const uint8_t *)&p_me_cfg_data->olt_random_challenge_table)[12], ((const uint8_t *)&p_me_cfg_data->olt_random_challenge_table)[13], ((const uint8_t *)&p_me_cfg_data->olt_random_challenge_table)[14], ((const uint8_t *)&p_me_cfg_data->olt_random_challenge_table)[15], ((const uint8_t *)&p_me_cfg_data->olt_random_challenge_table)[16]);
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_CHALLENGE_STATUS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tolt_challenge_status:\t%u\n", p_me_cfg_data->olt_challenge_status);
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_SELECTED_CRYPTO_CAPABILITIES)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tonu_selected_crypto_capabilities:\t%u\n", p_me_cfg_data->onu_selected_crypto_capabilities);
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_RANDOM_CHALLENGE_TABLE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tonu_random_challenge_table:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->onu_random_challenge_table)[0], ((const uint8_t *)&p_me_cfg_data->onu_random_challenge_table)[1], ((const uint8_t *)&p_me_cfg_data->onu_random_challenge_table)[2], ((const uint8_t *)&p_me_cfg_data->onu_random_challenge_table)[3], ((const uint8_t *)&p_me_cfg_data->onu_random_challenge_table)[4], ((const uint8_t *)&p_me_cfg_data->onu_random_challenge_table)[5], ((const uint8_t *)&p_me_cfg_data->onu_random_challenge_table)[6], ((const uint8_t *)&p_me_cfg_data->onu_random_challenge_table)[7], ((const uint8_t *)&p_me_cfg_data->onu_random_challenge_table)[8], ((const uint8_t *)&p_me_cfg_data->onu_random_challenge_table)[9], ((const uint8_t *)&p_me_cfg_data->onu_random_challenge_table)[10], ((const uint8_t *)&p_me_cfg_data->onu_random_challenge_table)[11], ((const uint8_t *)&p_me_cfg_data->onu_random_challenge_table)[12], ((const uint8_t *)&p_me_cfg_data->onu_random_challenge_table)[13], ((const uint8_t *)&p_me_cfg_data->onu_random_challenge_table)[14], ((const uint8_t *)&p_me_cfg_data->onu_random_challenge_table)[15]);
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_AUTH_RESULT_TABLE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tonu_auth_result_table:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->onu_auth_result_table)[0], ((const uint8_t *)&p_me_cfg_data->onu_auth_result_table)[1], ((const uint8_t *)&p_me_cfg_data->onu_auth_result_table)[2], ((const uint8_t *)&p_me_cfg_data->onu_auth_result_table)[3], ((const uint8_t *)&p_me_cfg_data->onu_auth_result_table)[4], ((const uint8_t *)&p_me_cfg_data->onu_auth_result_table)[5], ((const uint8_t *)&p_me_cfg_data->onu_auth_result_table)[6], ((const uint8_t *)&p_me_cfg_data->onu_auth_result_table)[7], ((const uint8_t *)&p_me_cfg_data->onu_auth_result_table)[8], ((const uint8_t *)&p_me_cfg_data->onu_auth_result_table)[9], ((const uint8_t *)&p_me_cfg_data->onu_auth_result_table)[10], ((const uint8_t *)&p_me_cfg_data->onu_auth_result_table)[11], ((const uint8_t *)&p_me_cfg_data->onu_auth_result_table)[12], ((const uint8_t *)&p_me_cfg_data->onu_auth_result_table)[13], ((const uint8_t *)&p_me_cfg_data->onu_auth_result_table)[14], ((const uint8_t *)&p_me_cfg_data->onu_auth_result_table)[15]);
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_AUTH_RESULT_TABLE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tolt_auth_result_table:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->olt_auth_result_table)[0], ((const uint8_t *)&p_me_cfg_data->olt_auth_result_table)[1], ((const uint8_t *)&p_me_cfg_data->olt_auth_result_table)[2], ((const uint8_t *)&p_me_cfg_data->olt_auth_result_table)[3], ((const uint8_t *)&p_me_cfg_data->olt_auth_result_table)[4], ((const uint8_t *)&p_me_cfg_data->olt_auth_result_table)[5], ((const uint8_t *)&p_me_cfg_data->olt_auth_result_table)[6], ((const uint8_t *)&p_me_cfg_data->olt_auth_result_table)[7], ((const uint8_t *)&p_me_cfg_data->olt_auth_result_table)[8], ((const uint8_t *)&p_me_cfg_data->olt_auth_result_table)[9], ((const uint8_t *)&p_me_cfg_data->olt_auth_result_table)[10], ((const uint8_t *)&p_me_cfg_data->olt_auth_result_table)[11], ((const uint8_t *)&p_me_cfg_data->olt_auth_result_table)[12], ((const uint8_t *)&p_me_cfg_data->olt_auth_result_table)[13], ((const uint8_t *)&p_me_cfg_data->olt_auth_result_table)[14], ((const uint8_t *)&p_me_cfg_data->olt_auth_result_table)[15], ((const uint8_t *)&p_me_cfg_data->olt_auth_result_table)[16]);
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_RESULT_STATUS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tolt_result_status:\t%u\n", p_me_cfg_data->olt_result_status);
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_AUTH_STATUS)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tonu_auth_status:\t%u\n", p_me_cfg_data->onu_auth_status);
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_MASTER_SESSION_KEY_NAME)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tmaster_session_key_name:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->master_session_key_name)[0], ((const uint8_t *)&p_me_cfg_data->master_session_key_name)[1], ((const uint8_t *)&p_me_cfg_data->master_session_key_name)[2], ((const uint8_t *)&p_me_cfg_data->master_session_key_name)[3], ((const uint8_t *)&p_me_cfg_data->master_session_key_name)[4], ((const uint8_t *)&p_me_cfg_data->master_session_key_name)[5], ((const uint8_t *)&p_me_cfg_data->master_session_key_name)[6], ((const uint8_t *)&p_me_cfg_data->master_session_key_name)[7], ((const uint8_t *)&p_me_cfg_data->master_session_key_name)[8], ((const uint8_t *)&p_me_cfg_data->master_session_key_name)[9], ((const uint8_t *)&p_me_cfg_data->master_session_key_name)[10], ((const uint8_t *)&p_me_cfg_data->master_session_key_name)[11], ((const uint8_t *)&p_me_cfg_data->master_session_key_name)[12], ((const uint8_t *)&p_me_cfg_data->master_session_key_name)[13], ((const uint8_t *)&p_me_cfg_data->master_session_key_name)[14], ((const uint8_t *)&p_me_cfg_data->master_session_key_name)[15]);
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_BROADCAST_KEY_TABLE)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\tbroadcast_key_table:\t%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ((const uint8_t *)&p_me_cfg_data->broadcast_key_table)[0], ((const uint8_t *)&p_me_cfg_data->broadcast_key_table)[1], ((const uint8_t *)&p_me_cfg_data->broadcast_key_table)[2], ((const uint8_t *)&p_me_cfg_data->broadcast_key_table)[3], ((const uint8_t *)&p_me_cfg_data->broadcast_key_table)[4], ((const uint8_t *)&p_me_cfg_data->broadcast_key_table)[5], ((const uint8_t *)&p_me_cfg_data->broadcast_key_table)[6], ((const uint8_t *)&p_me_cfg_data->broadcast_key_table)[7], ((const uint8_t *)&p_me_cfg_data->broadcast_key_table)[8], ((const uint8_t *)&p_me_cfg_data->broadcast_key_table)[9], ((const uint8_t *)&p_me_cfg_data->broadcast_key_table)[10], ((const uint8_t *)&p_me_cfg_data->broadcast_key_table)[11], ((const uint8_t *)&p_me_cfg_data->broadcast_key_table)[12], ((const uint8_t *)&p_me_cfg_data->broadcast_key_table)[13], ((const uint8_t *)&p_me_cfg_data->broadcast_key_table)[14], ((const uint8_t *)&p_me_cfg_data->broadcast_key_table)[15], ((const uint8_t *)&p_me_cfg_data->broadcast_key_table)[16], ((const uint8_t *)&p_me_cfg_data->broadcast_key_table)[17]);
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_EFFECTIVE_KEY_LENGTH)) != 0)
        BCM_LOG_LEVEL(log_level, log_id, "\teffective_key_length:\t%u\n", p_me_cfg_data->effective_key_length);

    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_RANDOM_CHALLENGE_TABLE)) != 0)
        bcm_omci_enhanced_security_control_olt_random_challenge_table_log(&me_hdr->key, &p_me_cfg_data->olt_random_challenge_table, log_id, log_level);
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_RANDOM_CHALLENGE_TABLE)) != 0)
        bcm_omci_enhanced_security_control_onu_random_challenge_table_log(&me_hdr->key, &p_me_cfg_data->onu_random_challenge_table, log_id, log_level);
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_AUTH_RESULT_TABLE)) != 0)
        bcm_omci_enhanced_security_control_onu_auth_result_table_log(&me_hdr->key, &p_me_cfg_data->onu_auth_result_table, log_id, log_level);
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_AUTH_RESULT_TABLE)) != 0)
        bcm_omci_enhanced_security_control_olt_auth_result_table_log(&me_hdr->key, &p_me_cfg_data->olt_auth_result_table, log_id, log_level);
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_BROADCAST_KEY_TABLE)) != 0)
        bcm_omci_enhanced_security_control_broadcast_key_table_log(&me_hdr->key, &p_me_cfg_data->broadcast_key_table, log_id, log_level);

    BCM_LOG_LEVEL(log_level, log_id, "] \n");

    return BCM_ERR_OK;
}

#endif

/* Encode function(s) for "fields" in attribute(s) of me cfg */
static bcmos_bool bcm_omci_enhanced_security_control_olt_random_challenge_table_cfg_data_encode(bcm_omci_buf *p_bcm_buf, const bcm_omci_enhanced_security_control_olt_random_challenge_table *this)
{
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->row_number))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_write(p_bcm_buf, this->content, 16))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}
static bcmos_bool bcm_omci_enhanced_security_control_onu_random_challenge_table_cfg_data_encode(bcm_omci_buf *p_bcm_buf, const bcm_omci_enhanced_security_control_onu_random_challenge_table *this)
{
     if (!bcm_omci_buf_write(p_bcm_buf, this->content, 16))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}
static bcmos_bool bcm_omci_enhanced_security_control_onu_auth_result_table_cfg_data_encode(bcm_omci_buf *p_bcm_buf, const bcm_omci_enhanced_security_control_onu_auth_result_table *this)
{
     if (!bcm_omci_buf_write(p_bcm_buf, this->content, 16))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}
static bcmos_bool bcm_omci_enhanced_security_control_olt_auth_result_table_cfg_data_encode(bcm_omci_buf *p_bcm_buf, const bcm_omci_enhanced_security_control_olt_auth_result_table *this)
{
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->row_number))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_write(p_bcm_buf, this->content, 16))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}
static bcmos_bool bcm_omci_enhanced_security_control_broadcast_key_table_cfg_data_encode(bcm_omci_buf *p_bcm_buf, const bcm_omci_enhanced_security_control_broadcast_key_table *this)
{
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->row_control))
        return BCMOS_FALSE;
    if (!bcm_omci_buf_write_u8(p_bcm_buf, this->row_number))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_write(p_bcm_buf, this->content, 16))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

static bcmos_bool bcm_omci_enhanced_security_control_cfg_data_encode(const bcm_omci_enhanced_security_control_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);

/* Encode function for data portion of me cfg */
static bcmos_bool bcm_omci_enhanced_security_control_cfg_data_encode(const bcm_omci_enhanced_security_control_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if (!BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type))
        return BCMOS_TRUE;

    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_CRYPTO_CAPABILITIES)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->crypto_capabilities, 16))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_RANDOM_CHALLENGE_TABLE)) != 0)
    {
        if (!bcm_omci_enhanced_security_control_olt_random_challenge_table_cfg_data_encode(p_bcm_buf, &p_me_cfg_data->olt_random_challenge_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_CHALLENGE_STATUS)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->olt_challenge_status))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_SELECTED_CRYPTO_CAPABILITIES)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->onu_selected_crypto_capabilities))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_RANDOM_CHALLENGE_TABLE)) != 0)
    {
        if (!bcm_omci_enhanced_security_control_onu_random_challenge_table_cfg_data_encode(p_bcm_buf, &p_me_cfg_data->onu_random_challenge_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_AUTH_RESULT_TABLE)) != 0)
    {
        if (!bcm_omci_enhanced_security_control_onu_auth_result_table_cfg_data_encode(p_bcm_buf, &p_me_cfg_data->onu_auth_result_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_AUTH_RESULT_TABLE)) != 0)
    {
        if (!bcm_omci_enhanced_security_control_olt_auth_result_table_cfg_data_encode(p_bcm_buf, &p_me_cfg_data->olt_auth_result_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_RESULT_STATUS)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->olt_result_status))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_AUTH_STATUS)) != 0)
    {
        if (!bcm_omci_buf_write_u8(p_bcm_buf, p_me_cfg_data->onu_auth_status))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_MASTER_SESSION_KEY_NAME)) != 0)
    {
        if (!bcm_omci_buf_write(p_bcm_buf, p_me_cfg_data->master_session_key_name, 16))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_BROADCAST_KEY_TABLE)) != 0)
    {
        if (!bcm_omci_enhanced_security_control_broadcast_key_table_cfg_data_encode(p_bcm_buf, &p_me_cfg_data->broadcast_key_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_EFFECTIVE_KEY_LENGTH)) != 0)
    {
        if (!bcm_omci_buf_write_u16(p_bcm_buf, p_me_cfg_data->effective_key_length))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}

static bcmos_bool _bcm_omci_me_enhanced_security_control_cfg_encode(const bcm_omci_enhanced_security_control_cfg *p_me_enhanced_security_control_cfg, bcm_omci_buf *p_bcm_buf, bcm_omci_msg_type omci_msg_type)
{
    /** Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc */
    if (BCMOS_TRUE != _bcm_omci_common_attribute_mask_encode(p_bcm_buf, p_me_enhanced_security_control_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    /* Encode Message Contents - see base msg format in A.3 of G.988 */
    if (BCMOS_TRUE != bcm_omci_enhanced_security_control_cfg_data_encode(&p_me_enhanced_security_control_cfg->data, p_bcm_buf, p_me_enhanced_security_control_cfg->hdr.presence_mask, omci_msg_type))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function(s) for sub-fields in attribute(s) of me cfg */
static bcmos_bool bcm_omci_enhanced_security_control_olt_random_challenge_table_cfg_data_decode(bcm_omci_buf *p_bcm_buf, bcm_omci_enhanced_security_control_olt_random_challenge_table *this)
{
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->row_number))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read(p_bcm_buf, this->content, 16))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}
static bcmos_bool bcm_omci_enhanced_security_control_onu_random_challenge_table_cfg_data_decode(bcm_omci_buf *p_bcm_buf, bcm_omci_enhanced_security_control_onu_random_challenge_table *this)
{
     if (!bcm_omci_buf_read(p_bcm_buf, this->content, 16))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}
static bcmos_bool bcm_omci_enhanced_security_control_onu_auth_result_table_cfg_data_decode(bcm_omci_buf *p_bcm_buf, bcm_omci_enhanced_security_control_onu_auth_result_table *this)
{
     if (!bcm_omci_buf_read(p_bcm_buf, this->content, 16))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}
static bcmos_bool bcm_omci_enhanced_security_control_olt_auth_result_table_cfg_data_decode(bcm_omci_buf *p_bcm_buf, bcm_omci_enhanced_security_control_olt_auth_result_table *this)
{
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->row_number))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read(p_bcm_buf, this->content, 16))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}
static bcmos_bool bcm_omci_enhanced_security_control_broadcast_key_table_cfg_data_decode(bcm_omci_buf *p_bcm_buf, bcm_omci_enhanced_security_control_broadcast_key_table *this)
{
     if (!bcm_omci_buf_read_u8(p_bcm_buf, (uint8_t *)&this->row_control))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read_u8(p_bcm_buf, &this->row_number))
        return BCMOS_FALSE;
     if (!bcm_omci_buf_read(p_bcm_buf, this->content, 16))
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Decode function for data portion of me cfg */
static bcmos_bool bcm_omci_enhanced_security_control_cfg_data_decode(bcm_omci_enhanced_security_control_cfg_data *p_me_cfg_data, bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_CRYPTO_CAPABILITIES)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->crypto_capabilities, 16))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_RANDOM_CHALLENGE_TABLE)) != 0)
    {
        if (!bcm_omci_enhanced_security_control_olt_random_challenge_table_cfg_data_decode(p_bcm_buf, &p_me_cfg_data->olt_random_challenge_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_CHALLENGE_STATUS)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->olt_challenge_status))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_SELECTED_CRYPTO_CAPABILITIES)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->onu_selected_crypto_capabilities))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_RANDOM_CHALLENGE_TABLE)) != 0)
    {
        if (!bcm_omci_enhanced_security_control_onu_random_challenge_table_cfg_data_decode(p_bcm_buf, &p_me_cfg_data->onu_random_challenge_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_AUTH_RESULT_TABLE)) != 0)
    {
        if (!bcm_omci_enhanced_security_control_onu_auth_result_table_cfg_data_decode(p_bcm_buf, &p_me_cfg_data->onu_auth_result_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_AUTH_RESULT_TABLE)) != 0)
    {
        if (!bcm_omci_enhanced_security_control_olt_auth_result_table_cfg_data_decode(p_bcm_buf, &p_me_cfg_data->olt_auth_result_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_OLT_RESULT_STATUS)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->olt_result_status))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_ONU_AUTH_STATUS)) != 0)
    {
        if (!bcm_omci_buf_read_u8(p_bcm_buf, &p_me_cfg_data->onu_auth_status))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_MASTER_SESSION_KEY_NAME)) != 0)
    {
        if (!bcm_omci_buf_read(p_bcm_buf, p_me_cfg_data->master_session_key_name, 16))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_BROADCAST_KEY_TABLE)) != 0)
    {
        if (!bcm_omci_enhanced_security_control_broadcast_key_table_cfg_data_decode(p_bcm_buf, &p_me_cfg_data->broadcast_key_table))
            return BCMOS_FALSE;
    }
    if ((fields_present & (1ULL << BCM_OMCI_ENHANCED_SECURITY_CONTROL_CFG_ID_EFFECTIVE_KEY_LENGTH)) != 0)
    {
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &p_me_cfg_data->effective_key_length))
            return BCMOS_FALSE;
    }

    return BCMOS_TRUE;
}


/* Top level encode function with switch/case per object type */
bcmos_errno bcm_omci_me_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc;
    switch(me_hdr->obj_type)
    {
    case BCM_OMCI_GAL_ETH_PROF_OBJ_ID:
        rc = bcm_omci_me_gal_eth_prof_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_GEM_IW_TP_OBJ_ID:
        rc = bcm_omci_me_gem_iw_tp_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_GEM_PORT_NET_CTP_OBJ_ID:
        rc = bcm_omci_me_gem_port_net_ctp_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_OBJ_ID:
        rc = bcm_omci_me_ieee_8021_p_mapper_svc_prof_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_OBJ_ID:
        rc = bcm_omci_me_mac_bridge_port_config_data_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_MAC_BRIDGE_SVC_PROF_OBJ_ID:
        rc = bcm_omci_me_mac_bridge_svc_prof_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_VLAN_TAG_FILTER_DATA_OBJ_ID:
        rc = bcm_omci_me_vlan_tag_filter_data_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_TCONT_OBJ_ID:
        rc = bcm_omci_me_tcont_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_OBJ_ID:
        rc = bcm_omci_me_ext_vlan_tag_oper_config_data_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_PRIORITY_QUEUE_G_OBJ_ID:
        rc = bcm_omci_me_priority_queue_g_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_MCAST_GEM_IW_TP_OBJ_ID:
        rc = bcm_omci_me_mcast_gem_iw_tp_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_MCAST_OPERATIONS_PROFILE_OBJ_ID:
        rc = bcm_omci_me_mcast_operations_profile_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_OBJ_ID:
        rc = bcm_omci_me_mcast_subscriber_config_info_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_PPTP_ETH_UNI_OBJ_ID:
        rc = bcm_omci_me_pptp_eth_uni_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_VIRTUAL_ETH_INTF_POINT_OBJ_ID:
        rc = bcm_omci_me_virtual_eth_intf_point_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_ONU_DATA_OBJ_ID:
        rc = bcm_omci_me_onu_data_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_ONU_G_OBJ_ID:
        rc = bcm_omci_me_onu_g_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_ONU2_G_OBJ_ID:
        rc = bcm_omci_me_onu2_g_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_SW_IMAGE_OBJ_ID:
        rc = bcm_omci_me_sw_image_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_ANI_G_OBJ_ID:
        rc = bcm_omci_me_ani_g_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_GEM_PORT_NET_CTP_PM_OBJ_ID:
        rc = bcm_omci_me_gem_port_net_ctp_pm_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_ETH_FRAME_UPSTREAM_PM_OBJ_ID:
        rc = bcm_omci_me_eth_frame_upstream_pm_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_OBJ_ID:
        rc = bcm_omci_me_eth_frame_downstream_pm_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_FEC_PM_OBJ_ID:
        rc = bcm_omci_me_fec_pm_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_XGPON_TC_PM_OBJ_ID:
        rc = bcm_omci_me_xgpon_tc_pm_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_IP_HOST_CONFIG_DATA_OBJ_ID:
        rc = bcm_omci_me_ip_host_config_data_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_VOIP_LINE_STATUS_OBJ_ID:
        rc = bcm_omci_me_voip_line_status_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_VOIP_MEDIA_PROFILE_OBJ_ID:
        rc = bcm_omci_me_voip_media_profile_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_SIP_USER_DATA_OBJ_ID:
        rc = bcm_omci_me_sip_user_data_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_SIP_AGENT_CONFIG_DATA_OBJ_ID:
        rc = bcm_omci_me_sip_agent_config_data_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_NETWORK_ADDRESS_OBJ_ID:
        rc = bcm_omci_me_network_address_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_LARGE_STRING_OBJ_ID:
        rc = bcm_omci_me_large_string_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_OBJ_ID:
        rc = bcm_omci_me_authentication_security_method_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_VOICE_SERVICE_PROFILE_OBJ_ID:
        rc = bcm_omci_me_voice_service_profile_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_VOIP_CONFIG_DATA_OBJ_ID:
        rc = bcm_omci_me_voip_config_data_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_VOIP_VOICE_CTP_OBJ_ID:
        rc = bcm_omci_me_voip_voice_ctp_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_TCP_UDP_CONFIG_DATA_OBJ_ID:
        rc = bcm_omci_me_tcp_udp_config_data_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_OBJ_ID:
        rc = bcm_omci_me_network_dial_plan_table_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_RTP_PROFILE_DATA_OBJ_ID:
        rc = bcm_omci_me_rtp_profile_data_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_POTS_UNI_OBJ_ID:
        rc = bcm_omci_me_pots_uni_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_CIRCUIT_PACK_OBJ_ID:
        rc = bcm_omci_me_circuit_pack_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    case BCM_OMCI_ENHANCED_SECURITY_CONTROL_OBJ_ID:
        rc = bcm_omci_me_enhanced_security_control_cfg_encode(me_hdr, encode_buf, encode_len, omci_msg_type);
        break;
    default:
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : unsupported me cfg entity class = %d\n",
            __FUNCTION__, me_hdr->key.entity_class);
        rc = BCM_ERR_NOT_SUPPORTED;
        break;
    }
    return rc;
}

/* Top level decode function with switch/case per object type */
bcmos_errno bcm_omci_me_decode(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len, bcm_omci_msg_type omci_msg_type)
{
    bcmos_errno rc;
    bcm_omci_buf  bcm_buf = {};
    bcmos_bool res;
    bcmos_bool has_data;

    if (!decode_len || (NULL == decode_buf))
    {
        return BCM_ERR_PARM;
    }

    bcm_omci_buf_init (&bcm_buf, decode_len, decode_buf);

    /** Decode the Attribute Mask - decoded for Set, Get etc . Not decoded for Create, Delete etc */
    if (bcm_omci_is_onu_to_olt(me_hdr))
    {
        res = _bcm_omci_common_attribute_recv_mask_decode(&bcm_buf, &me_hdr->presence_mask, omci_msg_type);
        has_data = BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_RECV_MSG(omci_msg_type);
    }
    else
    {
        res = _bcm_omci_common_attribute_send_mask_decode(&bcm_buf, &me_hdr->presence_mask, omci_msg_type);
        has_data = BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(omci_msg_type);
    }
    if (!res)
        return BCM_ERR_PARM;
    if (!has_data)
        return BCM_ERR_OK;

    switch(me_hdr->obj_type)
    {
    case BCM_OMCI_GAL_ETH_PROF_OBJ_ID:
        rc = bcm_omci_me_gal_eth_prof_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_GEM_IW_TP_OBJ_ID:
        rc = bcm_omci_me_gem_iw_tp_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_GEM_PORT_NET_CTP_OBJ_ID:
        rc = bcm_omci_me_gem_port_net_ctp_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_OBJ_ID:
        rc = bcm_omci_me_ieee_8021_p_mapper_svc_prof_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_OBJ_ID:
        rc = bcm_omci_me_mac_bridge_port_config_data_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_MAC_BRIDGE_SVC_PROF_OBJ_ID:
        rc = bcm_omci_me_mac_bridge_svc_prof_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_VLAN_TAG_FILTER_DATA_OBJ_ID:
        rc = bcm_omci_me_vlan_tag_filter_data_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_TCONT_OBJ_ID:
        rc = bcm_omci_me_tcont_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_OBJ_ID:
        rc = bcm_omci_me_ext_vlan_tag_oper_config_data_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_PRIORITY_QUEUE_G_OBJ_ID:
        rc = bcm_omci_me_priority_queue_g_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_MCAST_GEM_IW_TP_OBJ_ID:
        rc = bcm_omci_me_mcast_gem_iw_tp_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_MCAST_OPERATIONS_PROFILE_OBJ_ID:
        rc = bcm_omci_me_mcast_operations_profile_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_OBJ_ID:
        rc = bcm_omci_me_mcast_subscriber_config_info_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_PPTP_ETH_UNI_OBJ_ID:
        rc = bcm_omci_me_pptp_eth_uni_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_VIRTUAL_ETH_INTF_POINT_OBJ_ID:
        rc = bcm_omci_me_virtual_eth_intf_point_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_ONU_DATA_OBJ_ID:
        rc = bcm_omci_me_onu_data_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_ONU_G_OBJ_ID:
        rc = bcm_omci_me_onu_g_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_ONU2_G_OBJ_ID:
        rc = bcm_omci_me_onu2_g_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_SW_IMAGE_OBJ_ID:
        rc = bcm_omci_me_sw_image_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_ANI_G_OBJ_ID:
        rc = bcm_omci_me_ani_g_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_GEM_PORT_NET_CTP_PM_OBJ_ID:
        rc = bcm_omci_me_gem_port_net_ctp_pm_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_ETH_FRAME_UPSTREAM_PM_OBJ_ID:
        rc = bcm_omci_me_eth_frame_upstream_pm_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_OBJ_ID:
        rc = bcm_omci_me_eth_frame_downstream_pm_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_FEC_PM_OBJ_ID:
        rc = bcm_omci_me_fec_pm_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_XGPON_TC_PM_OBJ_ID:
        rc = bcm_omci_me_xgpon_tc_pm_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_IP_HOST_CONFIG_DATA_OBJ_ID:
        rc = bcm_omci_me_ip_host_config_data_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_VOIP_LINE_STATUS_OBJ_ID:
        rc = bcm_omci_me_voip_line_status_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_VOIP_MEDIA_PROFILE_OBJ_ID:
        rc = bcm_omci_me_voip_media_profile_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_SIP_USER_DATA_OBJ_ID:
        rc = bcm_omci_me_sip_user_data_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_SIP_AGENT_CONFIG_DATA_OBJ_ID:
        rc = bcm_omci_me_sip_agent_config_data_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_NETWORK_ADDRESS_OBJ_ID:
        rc = bcm_omci_me_network_address_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_LARGE_STRING_OBJ_ID:
        rc = bcm_omci_me_large_string_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_OBJ_ID:
        rc = bcm_omci_me_authentication_security_method_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_VOICE_SERVICE_PROFILE_OBJ_ID:
        rc = bcm_omci_me_voice_service_profile_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_VOIP_CONFIG_DATA_OBJ_ID:
        rc = bcm_omci_me_voip_config_data_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_VOIP_VOICE_CTP_OBJ_ID:
        rc = bcm_omci_me_voip_voice_ctp_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_TCP_UDP_CONFIG_DATA_OBJ_ID:
        rc = bcm_omci_me_tcp_udp_config_data_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_OBJ_ID:
        rc = bcm_omci_me_network_dial_plan_table_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_RTP_PROFILE_DATA_OBJ_ID:
        rc = bcm_omci_me_rtp_profile_data_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_POTS_UNI_OBJ_ID:
        rc = bcm_omci_me_pots_uni_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_CIRCUIT_PACK_OBJ_ID:
        rc = bcm_omci_me_circuit_pack_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    case BCM_OMCI_ENHANCED_SECURITY_CONTROL_OBJ_ID:
        rc = bcm_omci_me_enhanced_security_control_cfg_decode(me_hdr, &bcm_buf, omci_msg_type);
        break;
    default:
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : unsupported me cfg entity class = %d\n",
            __FUNCTION__, me_hdr->key.entity_class);
        rc = BCM_ERR_NOT_SUPPORTED;
        break;
    }
    return rc;
}

#ifdef ENABLE_LOG
bcmos_errno bcm_omci_me_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level)
{
    bcmos_errno rc;
    switch(me_hdr->obj_type)
    {
    case BCM_OMCI_GAL_ETH_PROF_OBJ_ID:
        rc = bcm_omci_me_gal_eth_prof_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_GEM_IW_TP_OBJ_ID:
        rc = bcm_omci_me_gem_iw_tp_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_GEM_PORT_NET_CTP_OBJ_ID:
        rc = bcm_omci_me_gem_port_net_ctp_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_IEEE_8021_P_MAPPER_SVC_PROF_OBJ_ID:
        rc = bcm_omci_me_ieee_8021_p_mapper_svc_prof_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_MAC_BRIDGE_PORT_CONFIG_DATA_OBJ_ID:
        rc = bcm_omci_me_mac_bridge_port_config_data_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_MAC_BRIDGE_SVC_PROF_OBJ_ID:
        rc = bcm_omci_me_mac_bridge_svc_prof_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_VLAN_TAG_FILTER_DATA_OBJ_ID:
        rc = bcm_omci_me_vlan_tag_filter_data_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_TCONT_OBJ_ID:
        rc = bcm_omci_me_tcont_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_EXT_VLAN_TAG_OPER_CONFIG_DATA_OBJ_ID:
        rc = bcm_omci_me_ext_vlan_tag_oper_config_data_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_PRIORITY_QUEUE_G_OBJ_ID:
        rc = bcm_omci_me_priority_queue_g_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_MCAST_GEM_IW_TP_OBJ_ID:
        rc = bcm_omci_me_mcast_gem_iw_tp_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_MCAST_OPERATIONS_PROFILE_OBJ_ID:
        rc = bcm_omci_me_mcast_operations_profile_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_MCAST_SUBSCRIBER_CONFIG_INFO_OBJ_ID:
        rc = bcm_omci_me_mcast_subscriber_config_info_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_PPTP_ETH_UNI_OBJ_ID:
        rc = bcm_omci_me_pptp_eth_uni_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_VIRTUAL_ETH_INTF_POINT_OBJ_ID:
        rc = bcm_omci_me_virtual_eth_intf_point_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_ONU_DATA_OBJ_ID:
        rc = bcm_omci_me_onu_data_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_ONU_G_OBJ_ID:
        rc = bcm_omci_me_onu_g_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_ONU2_G_OBJ_ID:
        rc = bcm_omci_me_onu2_g_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_SW_IMAGE_OBJ_ID:
        rc = bcm_omci_me_sw_image_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_ANI_G_OBJ_ID:
        rc = bcm_omci_me_ani_g_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_GEM_PORT_NET_CTP_PM_OBJ_ID:
        rc = bcm_omci_me_gem_port_net_ctp_pm_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_ETH_FRAME_UPSTREAM_PM_OBJ_ID:
        rc = bcm_omci_me_eth_frame_upstream_pm_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_ETH_FRAME_DOWNSTREAM_PM_OBJ_ID:
        rc = bcm_omci_me_eth_frame_downstream_pm_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_FEC_PM_OBJ_ID:
        rc = bcm_omci_me_fec_pm_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_XGPON_TC_PM_OBJ_ID:
        rc = bcm_omci_me_xgpon_tc_pm_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_IP_HOST_CONFIG_DATA_OBJ_ID:
        rc = bcm_omci_me_ip_host_config_data_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_VOIP_LINE_STATUS_OBJ_ID:
        rc = bcm_omci_me_voip_line_status_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_VOIP_MEDIA_PROFILE_OBJ_ID:
        rc = bcm_omci_me_voip_media_profile_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_SIP_USER_DATA_OBJ_ID:
        rc = bcm_omci_me_sip_user_data_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_SIP_AGENT_CONFIG_DATA_OBJ_ID:
        rc = bcm_omci_me_sip_agent_config_data_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_NETWORK_ADDRESS_OBJ_ID:
        rc = bcm_omci_me_network_address_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_LARGE_STRING_OBJ_ID:
        rc = bcm_omci_me_large_string_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_AUTHENTICATION_SECURITY_METHOD_OBJ_ID:
        rc = bcm_omci_me_authentication_security_method_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_VOICE_SERVICE_PROFILE_OBJ_ID:
        rc = bcm_omci_me_voice_service_profile_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_VOIP_CONFIG_DATA_OBJ_ID:
        rc = bcm_omci_me_voip_config_data_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_VOIP_VOICE_CTP_OBJ_ID:
        rc = bcm_omci_me_voip_voice_ctp_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_TCP_UDP_CONFIG_DATA_OBJ_ID:
        rc = bcm_omci_me_tcp_udp_config_data_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_NETWORK_DIAL_PLAN_TABLE_OBJ_ID:
        rc = bcm_omci_me_network_dial_plan_table_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_RTP_PROFILE_DATA_OBJ_ID:
        rc = bcm_omci_me_rtp_profile_data_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_POTS_UNI_OBJ_ID:
        rc = bcm_omci_me_pots_uni_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_CIRCUIT_PACK_OBJ_ID:
        rc = bcm_omci_me_circuit_pack_cfg_log(me_hdr, log_id, log_level);
        break;
    case BCM_OMCI_ENHANCED_SECURITY_CONTROL_OBJ_ID:
        rc = bcm_omci_me_enhanced_security_control_cfg_log(me_hdr, log_id, log_level);
        break;
    default:
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : unsupported me cfg entity class = %d\n",
            __FUNCTION__, me_hdr->key.entity_class);
        rc = BCM_ERR_NOT_SUPPORTED;
        break;
    }
    return rc;
}
#endif
