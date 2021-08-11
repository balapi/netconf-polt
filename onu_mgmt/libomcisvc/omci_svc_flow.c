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
#include <bcmolt_conv.h>
#include <bcm_dev_log.h>
#include <onu_mgmt_model_funcs.h>
#include "omci_svc_adapter_common.h"
#include "omci_svc_common.h"
#include "omci_svc_flow.h"

#define OMCI_SVC_NULL_PTR 0xFFFF

#define OMCI_SVC_TCONT_ALLOC_ID_UNASSIGNED 0xFFFF

#define OMCI_SVC_VLAN_TAGGING_OPERATION_BIDIRECTIONAL_POSITIVE_FILTERING_BY_TCI_VID_INVESTIGATION 0x10

/* This value stands for the scenario in which there is no action on the outer VID and also there is no match on the outer VID, and hence, we are dealing with any outer VID.
 * So this value will be the entity ID of MAC Bridge Port Configuration Data ME, VLAN Tagging Filter ME and 802.1p Mapper Service Profile ME. */
#define OMCI_SVC_FLOW_ACTION_O_VID_ANY 4096

#define OMCI_SVC_FLOW_ACTION_I_VID_ANY 4096

#define OMCI_SVC_FLOW_TYPE_STR(flow_type) \
    (flow_type == BCMONU_MGMT_FLOW_TYPE_UNICAST ? "unicast":\
        (flow_type == BCMONU_MGMT_FLOW_TYPE_MULTICAST ? "multicast":\
            (flow_type == BCMONU_MGMT_FLOW_TYPE_BROADCAST ? "broadcast":"invalid")))


#define OMCI_SVC_MULTICAST_OPERATIONS_PROFILE_DYNAMIC_ACL_SET_CTRL_SHIFT 14 /* Bits 15-16 are set control. */
#define OMCI_SVC_MULTICAST_OPERATIONS_PROFILE_DYNAMIC_ACL_ROW_PART_ID_SHIFT 11 /* Bits 12-14 are row part ID. */

/* Extended VLAN Tagging Operation Configuration Data */
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_ETHER_TYPE_FILTER_NONE 0x0
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_ETHER_TYPE_FILTER_IPOE 0x1
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_ETHER_TYPE_FILTER_PPPOE 0x2
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_ETHER_TYPE_FILTER_ARP 0x3
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_ETHER_TYPE_FILTER_IPV6_IPOE 0x4

/** Ext Vlan Tag OUTER: Filter & treatment */
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_OUTER_PRIO_NOT_DOUBLE_TAGGED 0xF
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_OUTER_PRIO_DONT_FILTER 0x8
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_OUTER_VID_DONT_FILTER 0x1000
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_OUTER_TPID_DEI_DONT_FILTER 0x0

#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_OUTER_PRIO_COPY_FROM_OUTER_PRIO 0x9
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_OUTER_PRIO_DONT_TAG 0xF
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_OUTER_VID_DONT_CARE 0x0
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_OUTER_TPID_DEI_DONT_CARE 0x0
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_OUTER_DELETE 0xFFFFFFFF /* The OLT deletes a table entry by setting all of its last eight bytes to 0xFF. */

/** Ext Vlan Tag INNER: Filter & treatment */
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_INNER_PRIO_UNTAGGED 0xF
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_INNER_PRIO_DONT_FILTER 0x8
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_INNER_VID_DONT_FILTER 0x1000
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_INNER_TPID_DEI_DONT_FILTER 0x0


#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_PRIO_COPY_FROM_INNER_PRIO 0x8
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_PRIO_DONT_TAG 0xF
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_VID_DONT_CARE 0x0
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_VID_DONT_CHANGE 0x1000 /* Keep the original VID of the tag. */
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_TPID_DEI_DONT_CARE 0x0
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_TPID_DEI_COPY 0x0
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_TPID_DEI_SET_TPID_OUTPUT_TPID_DEI0 0x6 /* Set TPID = output TPID, DEI = 0 */
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_DELETE 0xFFFFFFFF /* The OLT deletes a table entry by setting all of its last eight bytes to 0xFF. */

#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_UNTAGGED (1 << 0)
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_SINGLE_TAGGED (1 << 1)

#define OMCI_SVC_ETHER_TYPE_IPOE 0x0800
#define OMCI_SVC_ETHER_TYPE_PPPOE0 0x8863
#define OMCI_SVC_ETHER_TYPE_PPPOE1 0x8864
#define OMCI_SVC_ETHER_TYPE_ARP 0x0806
#define OMCI_SVC_ETHER_TYPE_IPV6_IPOE 0x86DD


/** @brief flow cfg DB */
omci_svc_flow_cfg_db_t omci_svc_flow_cfg_db;

static const char *action_type2str[] =
{
    [BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(push)] = "push",
    [BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(pop)] = "pop",
    [BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(translate_pcp)] = "translate_pcp",
    [BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(translate_vid)] = "translate_vid",
    [BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(translate_pcp) | BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(translate_vid)] = "translate_pcp+translate_vid",
};

static const char *igmp_us_action_type2str[] =
{
    [BCMONU_MGMT_IGMP_US_PROP_MASK_GET(action_type, add_vlan_tag)] = "add_vlan_tag",
    [BCMONU_MGMT_IGMP_US_PROP_MASK_GET(action_type, replace_tci)] = "replace_tci",
    [BCMONU_MGMT_IGMP_US_PROP_MASK_GET(action_type, replace_vid)] = "replace_vid",
};

typedef void (*omci_svc_flow_sm_cb)(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow, void *context);
typedef bcmos_errno (*omci_svc_flow_validate_cb)(bcmonu_mgmt_flow_cfg *flow);
static bcmos_errno omci_svc_flow_add_validate_cb(bcmonu_mgmt_flow_cfg *flow);
static bcmos_errno omci_svc_flow_delete_validate_cb(bcmonu_mgmt_flow_cfg *flow);

BCMOLT_TYPE2STR(omci_svc_flow_state_id, static);

static omci_svc_flow_state_id2str_t omci_svc_flow_state_id2str[] =
{
    /* Up direction */
    {OMCI_SVC_FLOW_STATE_ID_INACTIVE, "inactive"},
    {OMCI_SVC_FLOW_STATE_ID_SET_TCONT, "set_tcont"},
    {OMCI_SVC_FLOW_STATE_ID_CREATE_GEM_PORT_NETWORK_CTP, "create_gem_port_network_ctp"},
    {OMCI_SVC_FLOW_STATE_ID_ADD_ENTRY_MULTICAST_GEM_INTERWORKING_TP, "add_entry_multicast_gem_interworking_tp"},
    {OMCI_SVC_FLOW_STATE_ID_CREATE_8021P_MAPPER_SERVICE_PROFILE, "create_8021p_mapper_service_profile"},
    {OMCI_SVC_FLOW_STATE_ID_CREATE_GEM_INTERWORKING_TP, "create_gem_interworking_tp"},
    {OMCI_SVC_FLOW_STATE_ID_SET_8021P_MAPPER_SERVICE_PROFILE, "set_8021p_mapper_service_profile"},
    {OMCI_SVC_FLOW_STATE_ID_CREATE_MAC_BRIDGE_PORT_CFG_DATA, "create_mac_bridge_port_cfg_data"},
    {OMCI_SVC_FLOW_STATE_ID_CREATE_VLAN_TAGGING_FILTER_DATA, "create_vlan_tagging_filter_data"},
    {OMCI_SVC_FLOW_STATE_ID_ADD_ENTRY_EXT_VLAN_TAG_OPER_CFG_DATA, "add_entry_ext_vlan_tag_oper_cfg_data"},
    {OMCI_SVC_FLOW_STATE_ID_SET_MULTICAST_OPERATIONS_PROFILE, "set_multicast_operations_profile"},
    {OMCI_SVC_FLOW_STATE_ID_ADD_ENTRY_MULTICAST_OPERATIONS_PROFILE_DYNAMIC_ACL, "add_entry_multicast_operations_profile_dynamic_acl"},
    {OMCI_SVC_FLOW_STATE_ID_UP_SEQUENCE_END, "up_sequence_end"},

    {OMCI_SVC_FLOW_STATE_ID_ACTIVE, "active"},

    /* Down direction */
    {OMCI_SVC_FLOW_STATE_ID_DELETE_ENTRY_MULTICAST_OPERATIONS_PROFILE_DYNAMIC_ACL, "delete_entry_multicast_operations_profile_dynamic_acl"},
    {OMCI_SVC_FLOW_STATE_ID_DELETE_ENTRY_EXT_VLAN_TAG_OPER_CFG_DATA, "delete_entry_ext_vlan_tag_oper_cfg_data"},
    {OMCI_SVC_FLOW_STATE_ID_DELETE_VLAN_TAGGING_FILTER_DATA, "delete_vlan_tagging_filter_data"},
    {OMCI_SVC_FLOW_STATE_ID_DELETE_MAC_BRIDGE_PORT_CFG_DATA, "delete_mac_bridge_port_cfg_data"},
    {OMCI_SVC_FLOW_STATE_ID_UNSET_8021P_MAPPER_SERVICE_PROFILE, "unset_8021p_mapper_service_profile"},
    {OMCI_SVC_FLOW_STATE_ID_DELETE_ENTRY_MULTICAST_GEM_INTERWORKING_TP, "delete_entry_multicast_gem_interworking_tp"},
    {OMCI_SVC_FLOW_STATE_ID_DELETE_GEM_INTERWORKING_TP, "delete_gem_interworking_tp"},
    {OMCI_SVC_FLOW_STATE_ID_DELETE_8021P_MAPPER_SERVICE_PROFILE, "delete_8021p_mapper_service_profile"},
    {OMCI_SVC_FLOW_STATE_ID_DELETE_GEM_PORT_NETWORK_CTP, "delete_gem_port_network_ctp"},
    {OMCI_SVC_FLOW_STATE_ID_UNSET_TCONT, "unset_tcont"},
    {OMCI_SVC_FLOW_STATE_ID_DOWN_SEQUENCE_END, "down_sequence_end"},
    {-1}
};

omci_svc_ext_vlan_tag_oper_cfg_data_filter2str_t omci_svc_ext_vlan_tag_oper_cfg_data_filter2str[] =
{
    {OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_UNTAGGED, "untagged"},
    {OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_SINGLE_TAGGED, "single_tagged"},
    {-1}
};


static void omci_svc_flow_sm_run_cb(bcmolt_oltid olt_id, omci_svc_event_id event, bcmonu_mgmt_onu_key *onu_key, void *context);
static void omci_svc_flow_sm_rollback_cb(bcmolt_oltid olt_id, bcmonu_mgmt_onu_key *onu_key, bcmos_errno last_err, void *context);
static void omci_svc_flow_dump_match_action(bcmonu_mgmt_flow_cfg *flow);

static void omci_svc_flow_dump(bcmonu_mgmt_flow_cfg *flow)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;
    bcmolt_oltid olt_id = flow->hdr.hdr.olt_id;

    BCM_LOG(DEBUG, omci_svc_log_id, "\tdirection=%s\n", flow->key.dir == BCMONU_MGMT_FLOW_DIR_ID_UPSTREAM ? "upstream" : "downstream");
    BCM_LOG(DEBUG, omci_svc_log_id, "\tflow_type=%s\n", OMCI_SVC_FLOW_TYPE_STR(flow->data.flow_type));
    BCM_LOG(DEBUG, omci_svc_log_id, "\tgem_port_id=%u\n", flow_data->svc_port_id);
    BCM_LOG(DEBUG, omci_svc_log_id, "\talloc_id=%u%s\n", BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, agg_port_id) ? flow_data->agg_port_id : BCMONU_MGMT_AGG_PORT_ID_UNASSIGNED,
        BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, agg_port_id) ? "" : " (unassigned)");
    if (BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, uni_port))
    {
        bcmonu_mgmt_onu_key _onu_key = { .pon_ni = flow_data->onu_key.pon_ni, .onu_id = flow_data->onu_key.onu_id };
        bcmonu_mgmt_onu_key *onu_key = &_onu_key;
        omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, onu_key->pon_ni, onu_key->onu_id);
        omci_svc_uni *uni_entry;

        uni_entry = omci_svc_uni_get(onu_context, flow);
        if (uni_entry)
        {
            BCM_LOG(DEBUG, omci_svc_log_id, "\tuni_port=%u (%s=%u)\n", flow_data->uni_port, uni_entry->uni.type == BCMONU_MGMT_UNI_TYPE_PPTP ? "PPTP" : "VEIP",
                uni_entry->uni.entity_id & OMCI_SVC_ETH_UNI_PORT_ID_MASK);
        }
        else
        {
            BCM_LOG(DEBUG, omci_svc_log_id, "\tuni_port=%u \n", flow_data->uni_port);
        }
    }
    else
        BCM_LOG(DEBUG, omci_svc_log_id, "\tuni_port=unassigned\n");

    omci_svc_flow_dump_match_action(flow);

    if (ONU_MGMT_FLOW_IS_MULTICAST(flow))
    {
        BCM_LOG(DEBUG, omci_svc_log_id, "{igmp us action: type/vid/pcp=%s/%u/0x%x}\n", 
            BCMONU_MGMT_IGMP_US_PROP_IS_SET(flow_data, action, type) ? igmp_us_action_type2str[flow_data->igmp_us_action.type] : "transparent",
            flow->data.igmp_us_action.vid,
            //BCMONU_MGMT_IGMP_US_PROP_IS_SET(flow_data, action, pcp) ? flow_data->igmp_us_action.pcp : 0);
            flow_data->igmp_us_action.pcp);
    }
}

static void omci_svc_flow_dump_match_action(bcmonu_mgmt_flow_cfg *flow)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;
    BCM_LOG(DEBUG, omci_svc_log_id, "\tmatch:\n");
    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, ether_type))
        BCM_LOG(DEBUG, omci_svc_log_id, "\t\tether_type=0x%04x\n", flow_data->match.ether_type);
    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_pcp))
        BCM_LOG(DEBUG, omci_svc_log_id, "\t\to_pcp=%u\n", flow_data->match.o_pcp);
    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_vid))
        BCM_LOG(DEBUG, omci_svc_log_id, "\t\to_vid=%u\n", flow_data->match.o_vid);
    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_untagged))
        BCM_LOG(DEBUG, omci_svc_log_id, "\t\to_untagged=%s\n", (flow_data->match.o_untagged ? "yes" : "no"));
    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, i_pcp))
        BCM_LOG(DEBUG, omci_svc_log_id, "\t\ti_pcp=%u\n", flow_data->match.i_pcp);

    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, i_vid))
        BCM_LOG(DEBUG, omci_svc_log_id, "\t\ti_vid=%u\n", flow_data->match.i_vid);
    BCM_LOG(DEBUG, omci_svc_log_id, "\taction:\n");
    BCM_LOG(DEBUG, omci_svc_log_id, "\t\ttype=%s\n", BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, type) ? action_type2str[flow_data->action.type] : "none");
    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, o_pcp))
        BCM_LOG(DEBUG, omci_svc_log_id, "\t\to_pcp=%u\n", flow_data->action.o_pcp);
    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, o_vid))
        BCM_LOG(DEBUG, omci_svc_log_id, "\t\to_vid=%u\n", flow_data->action.o_vid);
    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, i_vid))
        BCM_LOG(DEBUG, omci_svc_log_id, "\t\ti_vid=%u\n", flow_data->action.i_vid);
    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, i_pcp))
        BCM_LOG(DEBUG, omci_svc_log_id, "\t\ti_pcp=%u\n", flow_data->action.i_pcp);
}

static void omci_svc_flow_dump_flow_op(omci_svc_flow_op *flow_op)
{
    bcmonu_mgmt_onu_key _onu_key = { .pon_ni = flow_op->flow.data.onu_key.pon_ni, .onu_id = flow_op->flow.data.onu_key.onu_id };
    bcmonu_mgmt_onu_key *onu_key = &_onu_key;
    bcmonu_mgmt_flow_cfg *flow = &flow_op->flow;
    bcmolt_oltid olt_id = flow->hdr.hdr.olt_id;

    OMCI_SVC_LOG(DEBUG, olt_id, onu_key, NULL, "Flow %s request:\n", flow_op->op_id == OMCI_SVC_FLOW_OP_ID_ADD ? "add" : "delete");
    omci_svc_flow_dump(&flow_op->flow);
}

void omci_svc_flow_op_queue_flush(omci_svc_onu *onu_context)
{
    omci_svc_flow_op_queue *queue = &onu_context->flow_op_queue;

    bcmos_mutex_lock(&queue->mutex.mutex);
    queue->read_count = 0;
    queue->write_count = 0;
    queue->tail = queue->queue;
    queue->head = queue->tail;
    bcmos_mutex_unlock(&queue->mutex.mutex);
}

static bcmos_errno omci_svc_flow_op_queue_enqueue(omci_svc_onu *onu_context, omci_svc_flow_op *flow_op)
{
    bcmos_errno rc = BCM_ERR_OK;
    omci_svc_flow_op_queue *queue = &onu_context->flow_op_queue;
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    bcmos_mutex_lock(&queue->mutex.mutex);

    if (queue->write_count - queue->read_count == OMCI_SVC_FLOW_OP_QUEUE_SIZE)
    {
#ifdef ENABLE_LOG
        bcmonu_mgmt_flow_cfg_data *flow_data = &flow_op->flow.data;
#endif

        BCM_LOG(ERROR, omci_svc_log_id, "Flow operations queue (PON=%u, ONU=%u) is full, flow operation will be dropped\n",
            flow_data->onu_key.pon_ni, flow_data->onu_key.onu_id);
        rc = BCM_ERR_QUEUE_FULL;
        goto exit;
    }

    /* We must memcpy because 'flow_op' might be an automatic variable on some stack. */
    memcpy(queue->tail, flow_op, sizeof(*queue->tail));
    queue->tail++;
    /* Handle wrap around of tail pointer. */
    if (queue->tail - queue->queue >= OMCI_SVC_FLOW_OP_QUEUE_SIZE)
        queue->tail = queue->queue;
    queue->write_count++;

    BCM_LOG(INFO, omci_svc_log_id, "Flow (%s) is enqueued flow_id=%d, flow dir=%s, (occupancy=%u)\n",
        flow_op->state != OMCI_SVC_FLOW_STATE_ID_ACTIVE ? "ADD":"DELETE",
        flow_op->flow.key.id, (flow_op->flow.key.dir == BCMONU_MGMT_FLOW_DIR_ID_UPSTREAM ? "upstream" : "downstream"),
        queue->write_count - queue->read_count);
    omci_svc_flow_dump_flow_op(flow_op);

    /* If this flow operation is in the head of the queue, then handle it. */
    if (queue->write_count - queue->read_count == 1)
    {
        bcmonu_mgmt_onu_key onu_key = { .pon_ni = queue->head->flow.data.onu_key.pon_ni, .onu_id = queue->head->flow.data.onu_key.onu_id };

        switch (queue->head->op_id)
        {
        case OMCI_SVC_FLOW_OP_ID_ADD:
            rc = omci_svc_flow_add_validate_cb(&(((omci_svc_flow_op *)queue->head)->flow));
            if (BCM_ERR_OK == rc)
                omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_ACTIVATE, &onu_key, NULL);
            break;
        case OMCI_SVC_FLOW_OP_ID_DELETE:
            rc = omci_svc_flow_delete_validate_cb(&(((omci_svc_flow_op *)queue->head)->flow));
            if (BCM_ERR_OK == rc)
                omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_DEACTIVATE, &onu_key, NULL);
            break;
        default:
            break;
        }

        if (BCM_ERR_OK != rc)
        {
            BCM_LOG(ERROR, omci_svc_log_id, "Validation Failed for flow %s (occupancy=%u)\n",
                    (queue->head->op_id == OMCI_SVC_FLOW_OP_ID_ADD ? "ADD":"DELETE"),
                    queue->write_count - queue->read_count);

            /* advance head pointer to skip this flow in queue */
            queue->head++;
            /* Handle wrap around of head pointer. */
            if (queue->head - queue->queue >= OMCI_SVC_FLOW_OP_QUEUE_SIZE)
                queue->head = queue->queue;
            queue->read_count++;
        }
    }

exit:
    bcmos_mutex_unlock(&queue->mutex.mutex);
    return rc;
}

/* Called at the end of flow operation handling, so when it's called the queue has at least 1 element in it. */
static void omci_svc_flow_op_queue_dequeue(omci_svc_onu *onu_context)
{
    bcmos_errno rc = BCM_ERR_OK;
    omci_svc_flow_op_queue *queue = &onu_context->flow_op_queue;
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    if (onu_context->state != OMCI_SVC_ONU_STATE_ID_ACTIVE_WORKING)
    {
        omci_svc_flow_op_queue_flush(onu_context);
        return;
    }

    bcmos_mutex_lock(&queue->mutex.mutex);

    queue->head++;
    /* Handle wrap around of head pointer. */
    if (queue->head - queue->queue >= OMCI_SVC_FLOW_OP_QUEUE_SIZE)
        queue->head = queue->queue;
    queue->read_count++;

    /* If there are still entries in the queue, then handle the first one. */
    while (queue->write_count > queue->read_count)
    {
        bcmonu_mgmt_onu_key onu_key = { .pon_ni = queue->head->flow.data.onu_key.pon_ni, .onu_id = queue->head->flow.data.onu_key.onu_id };

        BCM_LOG(INFO, omci_svc_log_id, "Handling deferred flow operation (occupancy=%u)\n", queue->write_count - queue->read_count);
        omci_svc_flow_dump_flow_op(queue->head);
        switch (queue->head->op_id)
        {
        case OMCI_SVC_FLOW_OP_ID_ADD:
            rc = omci_svc_flow_add_validate_cb(&(((omci_svc_flow_op *)queue->head)->flow));
            if (BCM_ERR_OK == rc)
                omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_ACTIVATE, &onu_key, NULL);
            break;
        case OMCI_SVC_FLOW_OP_ID_DELETE:
            rc = omci_svc_flow_delete_validate_cb(&(((omci_svc_flow_op *)queue->head)->flow));
            if (BCM_ERR_OK == rc)
                omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_DEACTIVATE, &onu_key, NULL);
            break;
        default:
            break;
        }

        if (BCM_ERR_OK != rc)
        {
            BCM_LOG(ERROR, omci_svc_log_id, "Validation Failed for deferred flow %s (occupancy=%u), ....calling next in queue\n",
                    (queue->head->op_id == OMCI_SVC_FLOW_OP_ID_ADD ? "ADD":"DELETE"),
                    queue->write_count - queue->read_count);

            /* call for the next flow op in queue */
            queue->head++;
            /* Handle wrap around of head pointer. */
            if (queue->head - queue->queue >= OMCI_SVC_FLOW_OP_QUEUE_SIZE)
                queue->head = queue->queue;
            queue->read_count++;
        }
        else
            break;
    }


    bcmos_mutex_unlock(&queue->mutex.mutex);
}

static uint16_t omci_svc_o_vid_get_value(bcmonu_mgmt_flow_cfg *flow)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;

    if (flow->key.dir == BCMONU_MGMT_FLOW_DIR_ID_DOWNSTREAM)
    {
        /* Downstream is the opposite logic for upstream. See comment in upstream case. */
        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_vid))
            return flow_data->match.o_vid;

        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, o_vid))
            return flow_data->action.o_vid;

        return OMCI_SVC_FLOW_ACTION_O_VID_ANY;
    }
    else
    {
        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, o_vid))
            return flow_data->action.o_vid;

        /* If there is no action outer VID, then we can say that the outer VID after Extended VLAN Tagging Operation Configuration Data is left the same as the match outer VID, and hence it
         * can serve as the entity ID of MAC Bridge Port Configuration Data ME, VLAN Tagging Filter ME and 802.1p Mapper Service Profile ME. */
        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_vid))
            return flow_data->match.o_vid;

        return OMCI_SVC_FLOW_ACTION_O_VID_ANY;
    }
}

static uint16_t omci_svc_o_vid_get_entity_id(bcmonu_mgmt_flow_cfg *flow)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;

    if (ONU_MGMT_FLOW_IS_UNICAST(flow) && 
        ONU_MGMT_FLOW_IS_UNTAGGED_END_TO_END(flow_data))
    {
        /** end-to-end untagged packet (i.e. untagged from UNI through to ANI) */
        return omci_svc_o_vid_get_value(flow) | (1 << OMCI_SVC_O_VID_UNTAGGED_END_TO_END_FLOW_SHIFT);
    }

    /* Else */
    return omci_svc_o_vid_get_value(flow) | ((ONU_MGMT_FLOW_IS_MULTICAST(flow) || ONU_MGMT_FLOW_IS_BROADCAST(flow)) << OMCI_SVC_O_VID_IS_MULTICAST_BROADCAST_SHIFT);
}

static omci_svc_o_vid *omci_svc_o_vid_get(omci_svc_onu *onu_context, bcmonu_mgmt_flow_cfg *flow)
{
    omci_svc_o_vid *o_vid_iter;

    DLIST_FOREACH(o_vid_iter, &onu_context->mib.o_vids, next)
    {
        if (o_vid_iter->entity_id == omci_svc_o_vid_get_entity_id(flow))
            return o_vid_iter;
    }

    return NULL;
}

static omci_svc_gem_port *omci_svc_gem_port_get(omci_svc_onu *onu_context, bcmonu_mgmt_flow_cfg *flow)
{
    omci_svc_gem_port *gem_port_iter;

    DLIST_FOREACH(gem_port_iter, &onu_context->mib.gem_ports, next)
    {
        if (gem_port_iter->gem_port_id == flow->data.svc_port_id)
            return gem_port_iter;
    }

    return NULL;
}

omci_svc_uni *omci_svc_uni_get(omci_svc_onu *onu_context, bcmonu_mgmt_flow_cfg *flow)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;
    omci_svc_uni *uni_iter;
    bcmonu_mgmt_uni_port uni_port;
    uint32_t i;

    if (BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, uni_port))
        uni_port = flow_data->uni_port;
    else
        uni_port = 0; /* Just take the first UNI. */

    /* Find the UNI port with the specified index in 'uni_port'. */
    i = 0;
    TAILQ_FOREACH(uni_iter, &onu_context->mib.unis, next)
    {
        if (i == uni_port)
            return uni_iter;
        i++;
    }

    return NULL;
}

static omci_svc_tcont *omci_svc_tcont_get(omci_svc_onu *onu_context, bcmonu_mgmt_flow_cfg *flow)
{
    omci_svc_tcont *tcont_iter;

    /* if flow does not have agg port set (e.g. multicast) then return NULL */
    if (BCMOS_FALSE == BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, agg_port_id))
    {
        return NULL;
    }

    TAILQ_FOREACH(tcont_iter, &onu_context->mib.used_tconts, next)
    {
        if (tcont_iter->tcont.agg_port_id == flow->data.agg_port_id)
        {
            return tcont_iter;
        }
    }

    return NULL;
}

static omci_svc_priority_queue *omci_svc_us_priority_queue_get(omci_svc_onu *onu_context, bcmonu_mgmt_flow_cfg *flow)
{
    omci_svc_priority_queue *priority_queue_iter;
    omci_svc_tcont *tcont_entry;

    tcont_entry = omci_svc_tcont_get(onu_context, flow);
    if (tcont_entry)
    {
        TAILQ_FOREACH(priority_queue_iter, &onu_context->mib.us_priority_queues, next)
        {
            if (priority_queue_iter->queue.port == tcont_entry->tcont.entity_id)
                return priority_queue_iter;
        }
    }

    return NULL;
}

static omci_svc_priority_queue *omci_svc_ds_priority_queue_get(omci_svc_onu *onu_context, bcmonu_mgmt_flow_cfg *flow)
{
    omci_svc_priority_queue *priority_queue_iter;
    omci_svc_uni *uni_entry;

    uni_entry = omci_svc_uni_get(onu_context, flow);
    TAILQ_FOREACH(priority_queue_iter, &onu_context->mib.ds_priority_queues, next)
    {
        if (priority_queue_iter->queue.port == uni_entry->uni.entity_id)
            return priority_queue_iter;
    }

    return NULL;
}

static omci_svc_mac_bridge_port *omci_svc_mac_bridge_port_get(omci_svc_onu *onu_context, bcmonu_mgmt_flow_cfg *flow)
{
    omci_svc_mac_bridge_port *mac_bridge_port_iter;

    TAILQ_FOREACH(mac_bridge_port_iter, &onu_context->mib.used_mac_bridge_ports, next)
    {
        if (mac_bridge_port_iter->entity_id == omci_svc_o_vid_get_entity_id(flow))
            return mac_bridge_port_iter;
    }

    return NULL;
}


#define OMCI_SVC_REVERSE_FLOW_DIR(_dir) ((_dir) == BCMONU_MGMT_FLOW_DIR_ID_UPSTREAM ? BCMONU_MGMT_FLOW_DIR_ID_DOWNSTREAM : BCMONU_MGMT_FLOW_DIR_ID_UPSTREAM)
/** 
 * @note other than "push" & "pop", there are "translate" actions which do not need any reversal.
 * @todo for later releases, there are new action types which should be included in this reverse macro.
 */
#define OMCI_SVC_REVERSE_FLOW_ACTION_TYPE(_action_type, _reversed_action_type)  \
    do \
    { \
        if ((_action_type) & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(push)) \
            (_reversed_action_type) = BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(pop); \
        else if ((_action_type) & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(pop)) \
            (_reversed_action_type) = BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(push); \
        else \
            (_reversed_action_type) = (_action_type); \
    } while(0);


/** @brief reverse the filter & action parameters for flow op for multicast & broadcast flows.
 *  @note this is applicable only if extended vlan config or vlan tag filter is to be used for mcast/bcast flows
 **/
static bcmos_errno omci_svc_flow_op_reverse_for_mcast_bcast(bcmonu_mgmt_onu_key *onu_key, omci_svc_flow_op *flow_op)
{
    bcmonu_mgmt_flow_cfg *flow, *flow_reversed;
    bcmonu_mgmt_flow_cfg_data *flow_data, *flow_reversed_data;

    flow = &flow_op->flow;
    flow_data = &flow->data;
    flow_reversed = &flow_op->flow_reversed;
    flow_reversed_data = &flow_reversed->data;
    bcmolt_oltid olt_id = flow->hdr.hdr.olt_id;

    if (ONU_MGMT_FLOW_IS_MULTICAST(flow) || ONU_MGMT_FLOW_IS_BROADCAST(flow))
    {
        memset(flow_reversed, 0, sizeof(bcmonu_mgmt_flow_cfg));

        /* for multi olt support set the olt id too */
        flow_reversed->hdr.hdr.olt_id = olt_id;

        BCMONU_MGMT_FIELD_SET(&flow_reversed->data, flow_cfg_data, flow_type, BCMONU_MGMT_FLOW_TYPE_MULTICAST);
        flow_reversed->key.dir = OMCI_SVC_REVERSE_FLOW_DIR(flow->key.dir);

        /* reverse flow match->action parameters*/
        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_vid))
            BCMONU_MGMT_FLOW_PROP_SET(flow_reversed_data, action, o_vid, flow->data.match.o_vid);
        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_pcp))
            BCMONU_MGMT_FLOW_PROP_SET(flow_reversed_data, action, o_pcp, flow->data.match.o_pcp);

        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, i_vid))
            BCMONU_MGMT_FLOW_PROP_SET(flow_reversed_data, action, i_vid, flow->data.match.i_vid);
        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, i_pcp))
            BCMONU_MGMT_FLOW_PROP_SET(flow_reversed_data, action, i_pcp, flow->data.match.i_pcp);

        /* reverse action type */
        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, type))
        {
            BCMONU_MGMT_FLOW_PROP_SET(flow_reversed_data, action, type, flow_data->action.type);
            OMCI_SVC_REVERSE_FLOW_ACTION_TYPE(flow_data->action.type, flow_reversed_data->action.type);
        }

        /* reverse flow action->match parameters*/
        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, o_vid))
            BCMONU_MGMT_FLOW_PROP_SET(flow_reversed_data, match, o_vid, flow->data.action.o_vid);
        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, o_pcp))
            BCMONU_MGMT_FLOW_PROP_SET(flow_reversed_data, match, o_pcp, flow->data.action.o_pcp);

        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, i_vid))
            BCMONU_MGMT_FLOW_PROP_SET(flow_reversed_data, match, i_vid, flow->data.action.i_vid);
        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, i_pcp))
            BCMONU_MGMT_FLOW_PROP_SET(flow_reversed_data, match, i_pcp, flow->data.action.i_pcp);

        /* set rest of the parameters */
        flow_reversed->data.svc_port_id = flow->data.svc_port_id;
        if (BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, agg_port_id))
            BCMONU_MGMT_FIELD_SET(&flow_reversed->data, flow_cfg_data, agg_port_id, flow->data.agg_port_id);
        flow_reversed->data.igmp_us_action.vid = flow->data.igmp_us_action.vid;
        flow_reversed->data.igmp_us_action.pcp = flow->data.igmp_us_action.pcp;


        OMCI_SVC_LOG(DEBUG, olt_id, onu_key, NULL, "%s Flow reversed {flow dir: %s, gem port: %d, alloc id: %d}\n", 
            ONU_MGMT_FLOW_IS_MULTICAST(flow_reversed) ? "Multicast" : "Unicast",
            flow_reversed->key.dir == BCMONU_MGMT_FLOW_DIR_ID_UPSTREAM ? "upstream" : "downstream",
            flow_reversed->data.svc_port_id, BCMONU_MGMT_FIELD_IS_SET(&flow_reversed->data, flow_cfg_data, agg_port_id) ? flow_reversed->data.agg_port_id: BCMONU_MGMT_AGG_PORT_ID_UNASSIGNED);
        OMCI_SVC_LOG(DEBUG, olt_id, onu_key, NULL, "{match.o_vid/o_pcp=%u/0x%x, action: type/o_vid/o_pcp=%s/%u/0x%x}\n", 
            flow_reversed->data.match.o_vid, 
            BCMONU_MGMT_FLOW_PROP_IS_SET(flow_reversed_data, match, o_pcp) ? flow_reversed_data->match.o_pcp : 0,
            BCMONU_MGMT_FLOW_PROP_IS_SET(flow_reversed_data, action, type) ? action_type2str[flow_reversed_data->action.type] : "none",
            flow_reversed->data.action.o_vid,
            BCMONU_MGMT_FLOW_PROP_IS_SET(flow_reversed_data, action, o_pcp) ? flow_reversed_data->action.o_pcp : 0);
        OMCI_SVC_LOG(DEBUG, olt_id, onu_key, NULL, "{match.i_vid/i_pcp=%u/0x%x, action: type/i_vid/i_pcp=%s/%u/0x%x}\n", 
            flow_reversed->data.match.i_vid, 
            BCMONU_MGMT_FLOW_PROP_IS_SET(flow_reversed_data, match, i_pcp) ? flow_reversed_data->match.i_pcp : 0,
            BCMONU_MGMT_FLOW_PROP_IS_SET(flow_reversed_data, action, type) ? action_type2str[flow_reversed_data->action.type] : "none",
            flow_reversed->data.action.i_vid,
            BCMONU_MGMT_FLOW_PROP_IS_SET(flow_reversed_data, action, i_pcp) ? flow_reversed_data->action.i_pcp : 0);
        if (ONU_MGMT_FLOW_IS_MULTICAST(flow_reversed))
        {
            OMCI_SVC_LOG(DEBUG, olt_id, onu_key, NULL, "{igmp us action: type/vid/pcp=%s/%u/0x%x}\n", 
                BCMONU_MGMT_IGMP_US_PROP_IS_SET(flow_reversed_data, action, type) ? igmp_us_action_type2str[flow_reversed_data->igmp_us_action.type] : "transparent",
                flow_reversed->data.igmp_us_action.vid,
                flow_reversed_data->igmp_us_action.pcp);
        }
    }


    return BCM_ERR_OK;
}


static omci_svc_flow_cfg_entry* omci_svc_flow_cfg_db_find_entry(bcmonu_mgmt_flow_cfg *flow)
{
    bcmonu_mgmt_flow_key *key = &flow->key;
    omci_svc_flow_cfg_entry *flow_cfg_iter;
    omci_svc_flow_cfg_entry *flow_cfg_tmp;

    TAILQ_FOREACH_SAFE(flow_cfg_iter, &omci_svc_flow_cfg_db, next, flow_cfg_tmp)
    {
        if ((flow_cfg_iter->cfg.key.id == key->id) && (flow_cfg_iter->cfg.key.dir == key->dir))
        {
            /* config exists in db */
            return flow_cfg_iter;
        }
    }

    return NULL;
}

static bcmos_errno  omci_svc_flow_cfg_db_update_entry(bcmonu_mgmt_flow_cfg *flow)
{
    omci_svc_flow_cfg_entry *flow_cfg_entry;

    flow_cfg_entry = omci_svc_flow_cfg_db_find_entry(flow);

    if (NULL == flow_cfg_entry)
    {
        /* first time config */
        flow_cfg_entry = bcmos_calloc(sizeof(omci_svc_flow_cfg_entry));
        memcpy(&flow_cfg_entry->cfg, flow, sizeof(bcmonu_mgmt_flow_cfg));
        TAILQ_INSERT_TAIL(&omci_svc_flow_cfg_db, flow_cfg_entry, next);
    }
    else
    {
        /** config already exists, just update the admin_state; */
        flow_cfg_entry->cfg.data.admin_state = flow->data.admin_state;
    }

    return BCM_ERR_OK;
}

static bcmos_errno omci_svc_flow_cfg_db_clear_entry(bcmonu_mgmt_flow_cfg *flow)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;
    bcmonu_mgmt_onu_key _onu_key = { .pon_ni = flow_data->onu_key.pon_ni, .onu_id = flow_data->onu_key.onu_id };
    bcmonu_mgmt_onu_key *onu_key = &_onu_key;
    bcmonu_mgmt_flow_key *key = &flow->key;
    omci_svc_flow_cfg_entry *flow_cfg_iter;
    omci_svc_flow_cfg_entry *flow_cfg_tmp;
    bcmolt_oltid olt_id = flow->hdr.hdr.olt_id;

    TAILQ_FOREACH_SAFE(flow_cfg_iter, &omci_svc_flow_cfg_db, next, flow_cfg_tmp)
    {
        if ((flow_cfg_iter->cfg.key.id == key->id) && (flow_cfg_iter->cfg.key.dir == key->dir))
        {
            TAILQ_REMOVE(&omci_svc_flow_cfg_db, flow_cfg_iter, next);
            bcmos_free(flow_cfg_iter);
            OMCI_SVC_LOG(INFO, olt_id, onu_key, &flow->hdr.hdr, "flow entry Clear success\n");
            break;
        }
    }
    if (NULL == flow_cfg_iter)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "flow entry Clear failed (entry was not found after admin down)\n");
        return BCM_ERR_INTERNAL;
    }

    return BCM_ERR_OK;
}

void omci_svc_flow_cfg_db_flush_for_onu(omci_svc_onu *onu_context, bcmonu_mgmt_onu_key *onu_key)
{
    omci_svc_flow_cfg_entry *flow_cfg_iter;
    omci_svc_flow_cfg_entry *flow_cfg_tmp;
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    OMCI_SVC_LOG(INFO, olt_id, onu_key, NULL, "flushing flow cfg DB for onu onu_id=%d, pon_ni=%d)\n",
            onu_key->onu_id, onu_key->pon_ni);

    TAILQ_FOREACH_SAFE(flow_cfg_iter, &omci_svc_flow_cfg_db, next, flow_cfg_tmp)
    {
        if ((flow_cfg_iter->cfg.data.onu_key.pon_ni == onu_key->pon_ni) && 
                (flow_cfg_iter->cfg.data.onu_key.onu_id == onu_key->onu_id))
        {
            TAILQ_REMOVE(&omci_svc_flow_cfg_db, flow_cfg_iter, next);
            bcmos_free(flow_cfg_iter);
        }
    }
}

bcmos_errno omci_svc_flow_set(bcmonu_mgmt_flow_cfg *flow, bcmonu_mgmt_complete_cb cb, void *context, bcmos_bool is_clear)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;
    bcmonu_mgmt_onu_key _onu_key = { .pon_ni = flow_data->onu_key.pon_ni, .onu_id = flow_data->onu_key.onu_id };
    bcmonu_mgmt_onu_key *onu_key = &_onu_key;
    omci_svc_flow_op flow_op = {};
    bcmolt_oltid olt_id = flow->hdr.hdr.olt_id;
    omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, onu_key->pon_ni, onu_key->onu_id);
    bcmos_errno rc;
    omci_svc_flow_cfg_entry *flow_cfg_entry = NULL;

    BCM_LOG(INFO, omci_svc_log_id, "Flow Cfg Set Called for olt=%d, onu_id=%d, pon_ni=%d:\n",
            olt_id, onu_key->onu_id, onu_key->pon_ni);

    /* Validation */
    rc = omci_svc_validate(onu_key, &flow->hdr.hdr);
    if (rc)
    {
        return rc;
    }

    /* dump flow */
    omci_svc_flow_dump(flow);

    /** if there a flow entry with same key in Cfg DB, must validate that this new config and existing config exactly match, other than admin state */
    flow_cfg_entry = omci_svc_flow_cfg_db_find_entry(flow);
    if (NULL != flow_cfg_entry)
    {
        /* backup & change the flow admin state temporarily to what we have in cfg DB */
        bcmonu_mgmt_admin_state original_admin_state = flow->data.admin_state;
        flow->data.admin_state = flow_cfg_entry->cfg.data.admin_state;

        if (0 != memcmp(&flow_cfg_entry->cfg, flow, sizeof(bcmonu_mgmt_flow_cfg)))
        {
            OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "flow cfg exists in OMCI svc DB for flow_id=%d, flow dir=%s, and the parameters do not match with the new config\n",
                    flow->key.id, (flow->key.dir == BCMONU_MGMT_FLOW_DIR_ID_UPSTREAM ? "upstream" : "downstream"));
            return BCM_ERR_PARM;
        }

        /* restore the flow admin state */
        flow->data.admin_state = original_admin_state;
    }

    if (!BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, admin_state))
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "Administrative state must be specified\n");
        return BCM_ERR_PARM;
    }

    if (!BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, onu_key))
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "ONU key must be specified\n");
        return BCM_ERR_PARM;
    }

    if (flow->key.dir == BCMONU_MGMT_FLOW_DIR_ID_DOWNSTREAM && ONU_MGMT_FLOW_IS_UNICAST(flow))
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "Currently downstream specific config is not supported for unicast flow. "
                "Downstream rules in ONU are automatically applied as Inverse of an upstream flow config\n");
        return BCM_ERR_NOT_SUPPORTED;
    }

    if (flow->key.dir == BCMONU_MGMT_FLOW_DIR_ID_UPSTREAM && (ONU_MGMT_FLOW_IS_MULTICAST(flow) || ONU_MGMT_FLOW_IS_BROADCAST(flow)))
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "Multicast or Broadcast flow is not supported for upstream direction\n");
        return BCM_ERR_PARM;
    }

    if (!BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, svc_port_id))
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "GEM port must be specified\n");
        return BCM_ERR_PARM;
    }

    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_vid) && flow_data->match.o_vid > MAX_VID)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "Match outer VID must be in the range 0 .. %u\n", MAX_VID);
        return BCM_ERR_RANGE;
    }

    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_untagged) && 
        (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_vid) || BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_pcp)))
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "Match for o_untagged should not be specified along with o_vid/o_pcp\n");
        return BCM_ERR_PARM;
    }

    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, o_vid) && flow_data->action.o_vid > MAX_VID)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "Action outer VID must be in the range 0 .. %u\n", MAX_VID);
        return BCM_ERR_RANGE;
    }

    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, i_vid))
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "Actions on the inner tag are not currently supported\n");
        return BCM_ERR_NOT_SUPPORTED;
    }

    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, i_pcp))
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "Actions on the inner tag are not currently supported\n");
        return BCM_ERR_NOT_SUPPORTED;
    }

    if (flow->key.dir == BCMONU_MGMT_FLOW_DIR_ID_UPSTREAM && !BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, agg_port_id))
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "Alloc ID must be specified for an upstream flow\n");
        return BCM_ERR_PARM;
    }

    if (flow->key.dir == BCMONU_MGMT_FLOW_DIR_ID_DOWNSTREAM && BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, agg_port_id))
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "Alloc ID must not be specified for a downstream flow\n");
        return BCM_ERR_PARM;
    }

    if (!BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, type))
    {
        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, o_pcp) || BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, i_pcp) ||
            BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, o_vid) || BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, i_vid))
        {
            OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "If action type is missing, no action must be specified\n");
            return BCM_ERR_PARM;
        }
    }
    else
    {
        if ((flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(push_inner_tag)) ||
            (flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(pop_inner_tag)) ||
            (flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(translate_inner_vid)) ||
            (flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(translate_inner_pcp)))
        {
            OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "Actions on the inner tag are not currently supported\n");
            return BCM_ERR_NOT_SUPPORTED;
        }

        if (flow->key.dir == BCMONU_MGMT_FLOW_DIR_ID_DOWNSTREAM && (ONU_MGMT_FLOW_IS_MULTICAST(flow) || ONU_MGMT_FLOW_IS_BROADCAST(flow)))
        {
            if (flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(push))
            {
                OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "Push action must not be specified for a downstream Multicast or Broadcast flow\n");
                return BCM_ERR_PARM;
            }

            if (flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(translate_vid))
            {
                if (flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(translate_vid) && !BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, o_vid))
                {
                    OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "If translate VID action is specified, action outer VID must exist\n");
                    return BCM_ERR_PARM;
                }
            }

            if (flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(translate_pcp))
            {
                if (!BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, o_pcp))
                {
                    OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "If translate PCP action is specified, action outer PCP must be specified\n");
                    return BCM_ERR_PARM;
                }
            }
        }
        else if (flow->key.dir == BCMONU_MGMT_FLOW_DIR_ID_UPSTREAM)
        {
            if (flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(pop))
            {
                OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "Pop action must not be specified for an upstream flow\n");
                return BCM_ERR_PARM;
            }

            if ((flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(push)) ||
                (flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(translate_vid)))
            {
                if (!BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, o_vid))
                {
                    OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "If push/translate VID action is specified, action outer VID must exist\n");
                    return BCM_ERR_PARM;
                }
            }
            else if (flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(translate_pcp))
            {
                /* PCP translation without VID translation */
                if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, o_vid))
                {
                    OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr,
                        "If translate PCP action without translate VID action is specified, action outer VID must not be specified\n");
                    return BCM_ERR_PARM;
                }
            }

            if (flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(translate_pcp))
            {
                if (!BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, o_pcp))
                {
                    OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "If translate PCP action is specified, action outer PCP must be specified\n");
                    return BCM_ERR_PARM;
                }
            }
        }
    }

    if (onu_context->state != OMCI_SVC_ONU_STATE_ID_ACTIVE_WORKING)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "Operation in wrong ONU state (%u)\n", onu_context->state);
        return BCM_ERR_STATE;
    }

    /* In case of unicast, we react only to US flows because External VLAN Tagging Operation Configuration Data ME is to be configured with upstream flows.
     * And because it has "Downstream Mode" of 0, then in downstream, the ONU should apply the inverse operation from US.
     * We assume here that there will be no sense in having unicast downstream flow configuration (unlike multicast downstream) without its parallel inverse unicast
     * upstream flow configuration. So if we get unicast downstream flow configuration first, we shouldn't worry about the fact that we wait for its parallel upstream
     * flow. */
    if (flow->key.dir == BCMONU_MGMT_FLOW_DIR_ID_DOWNSTREAM && ONU_MGMT_FLOW_IS_UNICAST(flow))
    {
        if (cb)
            cb(context, BCM_ERR_OK);
        return BCM_ERR_OK;
    }

    if (!omci_svc_uni_get(onu_context, flow))
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "No UNI with index=%u\n", flow_data->uni_port);
        return BCM_ERR_NOENT;
    }

    /* Action */
    memcpy(&flow_op.flow, flow, sizeof(bcmonu_mgmt_flow_cfg));
    flow_op.state = flow_data->admin_state == BCMONU_MGMT_ADMIN_STATE_UP ? OMCI_SVC_FLOW_STATE_ID_INACTIVE : OMCI_SVC_FLOW_STATE_ID_ACTIVE;
    flow_op.op_id = flow_data->admin_state == BCMONU_MGMT_ADMIN_STATE_UP ? OMCI_SVC_FLOW_OP_ID_ADD : OMCI_SVC_FLOW_OP_ID_DELETE;
    flow_op.cb = cb;
    flow_op.context = context;
    flow_op.is_clear = is_clear;

    /* reverse the filter & action parameters for multicast or broadcast flows */
    omci_svc_flow_op_reverse_for_mcast_bcast(onu_key, &flow_op);

    onu_context->last_err = BCM_ERR_OK;
    onu_context->sm_run_cb = omci_svc_flow_sm_run_cb;
    onu_context->sm_rollback_cb = omci_svc_flow_sm_rollback_cb;

    return omci_svc_flow_op_queue_enqueue(onu_context, &flow_op);
}

/** 
 * @brief flow get : just dump the admin state.
 * @tbd in future it needs to query ONU to dump flow parameters.
 */
bcmos_errno omci_svc_flow_get(bcmonu_mgmt_flow_cfg *flow)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;
    bcmonu_mgmt_onu_key _onu_key = { .pon_ni = flow_data->onu_key.pon_ni, .onu_id = flow_data->onu_key.onu_id };
    bcmonu_mgmt_onu_key *onu_key = &_onu_key;
    bcmos_errno rc;
    omci_svc_flow_cfg_entry *flow_cfg_entry = NULL;
    bcmolt_oltid olt_id = flow->hdr.hdr.olt_id;

    /* Validation */
    rc = omci_svc_validate(onu_key, &flow->hdr.hdr);
    if (rc)
    {
        return rc;
    }

    /* Find any stored config for the flow */
    flow_cfg_entry = omci_svc_flow_cfg_db_find_entry(flow);
    if (NULL == flow_cfg_entry)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "flow entry not found\n");
        return BCM_ERR_NOENT;
    }

    flow->data.onu_key.pon_ni = flow_cfg_entry->cfg.data.onu_key.pon_ni;
    flow->data.onu_key.onu_id = flow_cfg_entry->cfg.data.onu_key.onu_id;

     if (BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, admin_state))
        flow->data.admin_state = flow_cfg_entry->cfg.data.admin_state;
     if (BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, oper_status))
        flow->data.oper_status = (flow_cfg_entry->cfg.data.admin_state == BCMONU_MGMT_ADMIN_STATE_UP ? BCMONU_MGMT_STATUS_UP : BCMONU_MGMT_STATUS_DOWN); /* set oper_status based on admin_state */
     if (BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, svc_port_id))
        flow->data.svc_port_id = flow_cfg_entry->cfg.data.svc_port_id;
     if (BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, agg_port_id))
        flow->data.agg_port_id = flow_cfg_entry->cfg.data.agg_port_id;
     if (BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, uni_port))
        flow->data.uni_port = flow_cfg_entry->cfg.data.uni_port;
     if (BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, flow_type))
        flow->data.flow_type = flow_cfg_entry->cfg.data.flow_type;
     if (BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, match))
        flow->data.match = flow_cfg_entry->cfg.data.match;
     if (BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, action))
        flow->data.action = flow_cfg_entry->cfg.data.action;
     if (BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, igmp_us_action))
        flow->data.igmp_us_action = flow_cfg_entry->cfg.data.igmp_us_action;

    return BCM_ERR_OK;
}

bcmos_errno omci_svc_flow_clear(bcmonu_mgmt_flow_cfg *flow, bcmonu_mgmt_complete_cb cb, void *context)
{
    bcmos_errno rc;
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;
    bcmonu_mgmt_onu_key _onu_key = { .pon_ni = flow_data->onu_key.pon_ni, .onu_id = flow_data->onu_key.onu_id };
    bcmonu_mgmt_onu_key *onu_key = &_onu_key;
    omci_svc_flow_cfg_entry *flow_cfg_entry = NULL;
    bcmonu_mgmt_flow_cfg flow_cfg_new = {};
    bcmolt_oltid olt_id = flow->hdr.hdr.olt_id;

    /* Validation */
    rc = omci_svc_validate(onu_key, &flow->hdr.hdr);
    if (rc)
    {
        return rc;
    }

    /* Find any stored config for the flow */
    flow_cfg_entry = omci_svc_flow_cfg_db_find_entry(flow);
    if (NULL == flow_cfg_entry)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "flow entry not found\n");
        return BCM_ERR_NOENT;
    }

    /* now first admin down the ONU side */
    memcpy(&flow_cfg_new, &flow_cfg_entry->cfg, sizeof(bcmonu_mgmt_flow_cfg));
    flow_cfg_new.data.admin_state = BCMONU_MGMT_ADMIN_STATE_DOWN;
    rc = omci_svc_flow_set(&flow_cfg_new, cb, context, BCMOS_TRUE);

    return rc;
}

static bcmos_errno omci_svc_flow_add_validate_cb(bcmonu_mgmt_flow_cfg *flow)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;
    bcmonu_mgmt_onu_key _onu_key = { .pon_ni = flow_data->onu_key.pon_ni, .onu_id = flow_data->onu_key.onu_id };
    bcmonu_mgmt_onu_key *onu_key = &_onu_key;
    bcmolt_oltid olt_id = flow->hdr.hdr.olt_id;
    omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, onu_key->pon_ni, onu_key->onu_id);

    if (TAILQ_EMPTY(&onu_context->mib.free_tconts))
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "No free T-CONTs\n");
        return BCM_ERR_NORES;
    }

    /* If the Outer VID is not already in use, we will need to create a new MAC Bridge Port Configuration Data ME. */
    if (TAILQ_EMPTY(&onu_context->mib.free_mac_bridge_ports) && !omci_svc_o_vid_get(onu_context, flow))
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "No free MAC bridge ports\n");
        return BCM_ERR_NORES;
    }

    return BCM_ERR_OK;
}

static bcmos_errno omci_svc_flow_delete_validate_cb(bcmonu_mgmt_flow_cfg *flow)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;
    bcmonu_mgmt_onu_key _onu_key = { .pon_ni = flow_data->onu_key.pon_ni, .onu_id = flow_data->onu_key.onu_id };
    bcmonu_mgmt_onu_key *onu_key = &_onu_key;
    bcmolt_oltid olt_id = flow->hdr.hdr.olt_id;
    omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, onu_key->pon_ni, onu_key->onu_id);
    omci_svc_uni *uni_entry;
    omci_svc_tcont *tcont_entry;
    omci_svc_o_vid *o_vid_entry;
    omci_svc_mac_bridge_port *mac_bridge_port_entry;

    uni_entry = omci_svc_uni_get(onu_context, flow);
    if (!uni_entry)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "No flow has an UNI that matches the given UNI\n");
        return BCM_ERR_PARM;
    }

    if (ONU_MGMT_FLOW_IS_UNICAST(flow))
    {
        tcont_entry = omci_svc_tcont_get(onu_context, flow);
        if (!tcont_entry)
        {
            OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "flow id=%d, dir=%s, No flow has a T-CONT that matches the given alloc ID [%d]\n", 
                    flow->key.id,
                    flow->key.dir == BCMONU_MGMT_FLOW_DIR_ID_UPSTREAM ? "upstream" : "downstream",
                    flow->data.agg_port_id);
            return BCM_ERR_PARM;
        }
    }

    o_vid_entry = omci_svc_o_vid_get(onu_context, flow);
    if (!o_vid_entry)
    {
        uint16_t o_vid = omci_svc_o_vid_get_value(flow);

        if (o_vid == OMCI_SVC_FLOW_ACTION_O_VID_ANY)
            OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "No flow for any outer VID\n");
        else
            OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "No flow has an outer VID that matches the given outer VID\n");
        return BCM_ERR_PARM;
    }

    mac_bridge_port_entry = omci_svc_mac_bridge_port_get(onu_context, flow);
    if (!mac_bridge_port_entry)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, &flow->hdr.hdr, "No flow has a MAC bridge port that matches the given outer VID\n");
        return BCM_ERR_PARM;
    }

    return BCM_ERR_OK;
}

/* Up direction */
static void omci_svc_state_inactive_event_activate(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;
    omci_svc_o_vid *o_vid_entry = omci_svc_o_vid_get(onu_context, flow);
    omci_svc_gem_port *gem_port_entry = omci_svc_gem_port_get(onu_context, flow);
    bcmonu_mgmt_svc_port_id gem_port_id = flow_data->svc_port_id;
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    if (o_vid_entry)
    {
        uint16_t o_vid = o_vid_entry->entity_id & OMCI_SVC_O_VID_VALUE_MASK;

        /* The outer VID is already in use so increment its reference count. */
        o_vid_entry->ref_count++;
        if (o_vid == OMCI_SVC_FLOW_ACTION_O_VID_ANY)
            BCM_LOG(DEBUG, omci_svc_log_id, "Flow for any outer VID is already in use - reference count was incremented to %u\n", o_vid_entry->ref_count);
        else
            BCM_LOG(DEBUG, omci_svc_log_id, "Outer VID=%u is already in use - reference count was incremented to %u\n", o_vid, o_vid_entry->ref_count);
    }
    else
    {
        /* The outer VID is not in use so create a new instance for it in the linked list of outer VIDs. */
        o_vid_entry = bcmos_calloc(sizeof(*o_vid_entry));
        if (!o_vid_entry)
        {
            BCM_LOG(ERROR, omci_svc_log_id, "Memory allocation failed (sizeof=%u)\n", (uint32_t)sizeof(*o_vid_entry));
            omci_svc_flow_sm_rollback_cb(olt_id, onu_key, BCM_ERR_NOMEM, NULL);
            return;
        }
        o_vid_entry->entity_id = omci_svc_o_vid_get_entity_id(flow);
        o_vid_entry->ref_count = 1;
        DLIST_INSERT_HEAD(&onu_context->mib.o_vids, o_vid_entry, next);
    }

    if (gem_port_entry)
    {
        /* The GEM port is already in use so increment its reference count. */
        gem_port_entry->ref_count++;
        BCM_LOG(DEBUG, omci_svc_log_id, "GEM port=%u is already in use - reference count was incremented to %u\n", gem_port_id, gem_port_entry->ref_count);
    }
    else
    {
        /* The GEM port is not in use so create a new instance for it in the linked list of GEM ports. */
        gem_port_entry = bcmos_calloc(sizeof(*gem_port_entry));
        if (!gem_port_entry)
        {
            BCM_LOG(ERROR, omci_svc_log_id, "Memory allocation failed (sizeof=%u)\n", (uint32_t)sizeof(*gem_port_entry));
            omci_svc_flow_sm_rollback_cb(olt_id, onu_key, BCM_ERR_NOMEM, NULL);
            return;
        }
        gem_port_entry->gem_port_id = gem_port_id;
        gem_port_entry->ref_count = 1;
        DLIST_INSERT_HEAD(&onu_context->mib.gem_ports, gem_port_entry, next);
    }

    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_set_tcont_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow,
    void *context)
{
    *(bcmos_bool *)context = ONU_MGMT_FLOW_IS_UNICAST(flow);
}

static void omci_svc_state_set_tcont_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;
    omci_svc_tcont *tcont_entry = omci_svc_tcont_get(onu_context, flow);
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    if (tcont_entry)
    {
        /* The T-CONT is already in use so increment its reference count. */
        tcont_entry->ref_count++;
        /** @todo tmp for debug only */
        BCM_LOG(INFO, omci_svc_log_id, "T-CONT=%u is already in use - reference count was incremented to %u\n", tcont_entry->tcont.entity_id, tcont_entry->ref_count);
    }
    else
    {
        tcont_entry = TAILQ_FIRST(&onu_context->mib.free_tconts);
        tcont_entry->tcont.agg_port_id = flow_data->agg_port_id;
        tcont_entry->ref_count = 1;
        TAILQ_REMOVE(&onu_context->mib.free_tconts, tcont_entry, next);
        TAILQ_INSERT_TAIL(&onu_context->mib.used_tconts, tcont_entry, next);
    }
    /** @todo tmp for debug only */
    BCM_LOG(INFO, omci_svc_log_id, "T-CONT=%u reference count %u\n", tcont_entry->tcont.entity_id, tcont_entry->ref_count);

    omci_svc_omci_tcont_me_set(olt_id, onu_key->pon_ni, onu_key->onu_id, tcont_entry->tcont.entity_id, 1,
        OMCI_SVC_OMCI_ATTR_ID_ALLOC_ID, flow_data->agg_port_id);
}

static void omci_svc_state_set_tcont_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_create_gem_port_network_ctp_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    omci_svc_gem_port *gem_port_entry = omci_svc_gem_port_get(onu_context, flow);

    *(bcmos_bool *)context = gem_port_entry->ref_count == 1;
}

static void omci_svc_state_create_gem_port_network_ctp_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;
    bcmonu_mgmt_svc_port_id gem_port_id = flow_data->svc_port_id;
    omci_svc_tcont *tcont_entry = omci_svc_tcont_get(onu_context, flow);
    omci_svc_priority_queue *us_priority_queue_entry = ONU_MGMT_FLOW_IS_UNICAST(flow) ? omci_svc_us_priority_queue_get(onu_context, flow) : NULL;
    omci_svc_priority_queue *ds_priority_queue_entry = omci_svc_ds_priority_queue_get(onu_context, flow);
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    /** @todo check if broadcast flow needs these ME attributes or not.
     * If not needed then the inline checks for unicast or otherwise need to be more specific */
    omci_svc_omci_gem_port_net_ctp_me_create(olt_id, onu_key->pon_ni, onu_key->onu_id, gem_port_id, 8,
        OMCI_SVC_OMCI_ATTR_ID_PORT_ID_VALUE, gem_port_id,
        OMCI_SVC_OMCI_ATTR_ID_TCONT_PTR, ONU_MGMT_FLOW_IS_UNICAST(flow) ? tcont_entry->tcont.entity_id : OMCI_SVC_NULL_PTR,
        OMCI_SVC_OMCI_ATTR_ID_DIRECTION, ONU_MGMT_FLOW_IS_UNICAST(flow) ? BCM_OMCI_GEM_PORT_NET_CTP_DIRECTION_BIDIRECTIONAL : BCM_OMCI_GEM_PORT_NET_CTP_DIRECTION_ANI_TO_UNI,
        OMCI_SVC_OMCI_ATTR_ID_TRAFFIC_MGMT_PTR_US, ONU_MGMT_FLOW_IS_UNICAST(flow) ? us_priority_queue_entry->queue.entity_id : OMCI_SVC_NULL_PTR,
        OMCI_SVC_OMCI_ATTR_ID_TRAFFIC_DESC_PROF_PTR_US, ONU_MGMT_FLOW_IS_UNICAST(flow) ? OMCI_SVC_NULL_PTR : OMCI_SVC_NULL_PTR,
        OMCI_SVC_OMCI_ATTR_ID_PRI_QUEUE_PTR_DS, (ONU_MGMT_FLOW_IS_UNICAST(flow) || ONU_MGMT_FLOW_IS_MULTICAST(flow)) ? ds_priority_queue_entry->queue.entity_id : OMCI_SVC_NULL_PTR,
        OMCI_SVC_OMCI_ATTR_ID_TRAFFIC_DESC_PROF_PTR_DS, OMCI_SVC_NULL_PTR,
        OMCI_SVC_OMCI_ATTR_ID_ENCRYPTION_KEY_RING, 0); /** @note encrytion key ring is ignored by OCS stack */
}

static void omci_svc_state_create_gem_port_network_ctp_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_create_8021p_mapper_service_profile_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow_op->flow.data;

    /** no mapper svc profile should be created for end-to-end untagged packet 
      (i.e. untagged from UNI through to ANI) */
    if (ONU_MGMT_FLOW_IS_UNICAST(flow) && 
        ONU_MGMT_FLOW_IS_UNTAGGED_END_TO_END(flow_data))
    {
        *(bcmos_bool *)context = BCMOS_FALSE;
    }
    else
    {
        omci_svc_o_vid *o_vid_entry = omci_svc_o_vid_get(onu_context, flow);
        *(bcmos_bool *)context = ONU_MGMT_FLOW_IS_UNICAST(flow) && (o_vid_entry != NULL) && (o_vid_entry->ref_count == 1);
    }
}

static void omci_svc_state_create_8021p_mapper_service_profile_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    omci_svc_o_vid *o_vid_entry = omci_svc_o_vid_get(onu_context, flow);
    omci_svc_ieee_8021_p_mapper_svc_prof *me = NULL;
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    me = &o_vid_entry->ieee_8021p_mapper_service_profile_me;
    me->interwork_tp_ptr_pri_0 = OMCI_SVC_NULL_PTR;
    me->interwork_tp_ptr_pri_1 = OMCI_SVC_NULL_PTR;
    me->interwork_tp_ptr_pri_2 = OMCI_SVC_NULL_PTR;
    me->interwork_tp_ptr_pri_3 = OMCI_SVC_NULL_PTR;
    me->interwork_tp_ptr_pri_4 = OMCI_SVC_NULL_PTR;
    me->interwork_tp_ptr_pri_5 = OMCI_SVC_NULL_PTR;
    me->interwork_tp_ptr_pri_6 = OMCI_SVC_NULL_PTR;
    me->interwork_tp_ptr_pri_7 = OMCI_SVC_NULL_PTR;

    omci_svc_omci_ieee_8021_p_mapper_svc_prof_me_create(olt_id, onu_key->pon_ni, onu_key->onu_id, o_vid_entry->entity_id, 12,
        OMCI_SVC_OMCI_ATTR_ID_MAPPER_SVC_PROF_TP_PTR, OMCI_SVC_NULL_PTR,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI0, OMCI_SVC_NULL_PTR,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI1, OMCI_SVC_NULL_PTR,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI2, OMCI_SVC_NULL_PTR,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI3, OMCI_SVC_NULL_PTR,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI4, OMCI_SVC_NULL_PTR,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI5, OMCI_SVC_NULL_PTR,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI6, OMCI_SVC_NULL_PTR,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI7, OMCI_SVC_NULL_PTR,
        OMCI_SVC_OMCI_ATTR_ID_UNMARKED_FRAME_OPT, BCMOS_TRUE,
        OMCI_SVC_OMCI_ATTR_ID_DEFAULT_P_BIT_MARKING, 0,
        OMCI_SVC_OMCI_ATTR_ID_MAPPER_TP_TYPE, OMCI_SVC_OMCI_8021_P_TP_TYPE_NULL);
}

static void omci_svc_state_create_8021p_mapper_service_profile_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_create_gem_interworking_tp_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    omci_svc_gem_port *gem_port_entry = omci_svc_gem_port_get(onu_context, flow);

    *(bcmos_bool *)context = gem_port_entry->ref_count == 1;
}

static void omci_svc_state_create_gem_interworking_tp_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow,
    void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;
    bcmonu_mgmt_svc_port_id gem_port_id = flow_data->svc_port_id;
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    if (ONU_MGMT_FLOW_IS_MULTICAST(flow))
    {
        omci_svc_omci_mcast_gem_iw_tp_me_create(olt_id, onu_key->pon_ni, onu_key->onu_id, gem_port_id, 6,
            OMCI_SVC_OMCI_ATTR_ID_MCAST_GEM_PORT_NET_CTP_CON_PTR, gem_port_id,
            OMCI_SVC_OMCI_ATTR_ID_MCAST_IW_OPT, 0, /* Don't care */
            OMCI_SVC_OMCI_ATTR_ID_MCAST_SVC_PROF_PTR, 0,
            OMCI_SVC_OMCI_ATTR_ID_MCAST_GEM_IW_TP_NOT_USED_1, 0,
            OMCI_SVC_OMCI_ATTR_ID_MCAST_GAL_PROF_PTR, 0, /* Don't care */
            OMCI_SVC_OMCI_ATTR_ID_MCAST_GEM_IW_TP_NOT_USED_2, 0); /* Don't care */
    }
    else if (ONU_MGMT_FLOW_IS_UNICAST(flow))
    {
        omci_svc_uni *uni = omci_svc_uni_get(onu_context, flow);

        /** For end-to-end untagged packet (i.e. untagged from UNI through to ANI), 
          GEM IW TP points to MAC bridge svc profile, Else points to 802.1p mapper svc profile */
        omci_svc_omci_gem_iw_tp_me_create(olt_id, onu_key->pon_ni, onu_key->onu_id, gem_port_id, 5,
            OMCI_SVC_OMCI_ATTR_ID_GEM_PORT_NET_CTP_CON_PTR, gem_port_id,
            OMCI_SVC_OMCI_ATTR_ID_IW_OPT, (ONU_MGMT_FLOW_IS_UNTAGGED_END_TO_END(flow_data) ? OMCI_SVC_OMCI_IW_OPT_MAC_BRIDGED_VLAN : OMCI_SVC_OMCI_IW_OPT_802_1P_MAPPER),
            OMCI_SVC_OMCI_ATTR_ID_SVC_PROF_PTR, (ONU_MGMT_FLOW_IS_UNTAGGED_END_TO_END(flow_data) ? uni->uni.entity_id : omci_svc_o_vid_get(onu_context, flow)->entity_id),
            OMCI_SVC_OMCI_ATTR_ID_IW_TP_PTR, 0,
            OMCI_SVC_OMCI_ATTR_ID_GAL_PROF_PTR, gem_port_id);
    }
    else if (ONU_MGMT_FLOW_IS_BROADCAST(flow))
    {
        /** @note broadcast flow also uses gem_iw_tp ME like the unicast */
        omci_svc_omci_gem_iw_tp_me_create(olt_id, onu_key->pon_ni, onu_key->onu_id, gem_port_id, 5,
            OMCI_SVC_OMCI_ATTR_ID_GEM_PORT_NET_CTP_CON_PTR, gem_port_id,
            OMCI_SVC_OMCI_ATTR_ID_IW_OPT, OMCI_SVC_OMCI_IW_OPT_DS_BROADCAST,
            OMCI_SVC_OMCI_ATTR_ID_SVC_PROF_PTR, 0,
            OMCI_SVC_OMCI_ATTR_ID_IW_TP_PTR, 0,
            OMCI_SVC_OMCI_ATTR_ID_GAL_PROF_PTR, OMCI_SVC_NULL_PTR);
    }
    else
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, NULL, "Invalid flow type\n");
    }
}

static void omci_svc_state_create_gem_interworking_tp_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_add_entry_multicast_gem_interworking_tp_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    *(bcmos_bool *)context = ONU_MGMT_FLOW_IS_MULTICAST(flow);
}

static void omci_svc_state_add_entry_multicast_gem_interworking_tp_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow_op->flow.data;
    bcmonu_mgmt_svc_port_id gem_port_id = flow_data->svc_port_id;
    bcmos_errno rc = BCM_ERR_OK;
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    omci_svc_omci_mcast_gem_iw_tp_me_add_entry_ipv4_addr_table(olt_id, onu_key, flow, gem_port_id);
    if (rc != BCM_ERR_OK)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, NULL, "Add Entry Req() request failed, entity_id=%u, result=%s\n",
            gem_port_id, bcmos_strerror(rc));

        omci_svc_flow_sm_rollback_cb(olt_id, onu_key, rc, NULL);
    }
}

static void omci_svc_state_add_entry_multicast_gem_interworking_tp_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_set_8021p_mapper_service_profile_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow_op->flow.data;

    /** no mapper svc profile should be created/used for end-to-end untagged packet
      (i.e. untagged from UNI through to ANI) */
    *(bcmos_bool *)context = ONU_MGMT_FLOW_IS_UNICAST(flow) && 
                                !ONU_MGMT_FLOW_IS_UNTAGGED_END_TO_END(flow_data);
}

static void omci_svc_state_set_8021p_mapper_service_profile_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow_op->flow.data;
    bcmonu_mgmt_svc_port_id gem_port_id = flow_data->svc_port_id;
    omci_svc_o_vid *o_vid_entry = omci_svc_o_vid_get(onu_context, flow);
    uint16_t o_pcp_for_mapper = UINT16_MAX;
    omci_svc_ieee_8021_p_mapper_svc_prof *me = &o_vid_entry->ieee_8021p_mapper_service_profile_me;
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, o_pcp))
    {
        /* Map only the specified priority to the GEM port. */
        o_pcp_for_mapper = flow_data->action.o_pcp;
    }
    else if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_pcp))
    {
            o_pcp_for_mapper = flow_data->match.o_pcp;
    }

    if (o_pcp_for_mapper != UINT16_MAX)
    {
        switch (o_pcp_for_mapper)
        {
        case 0:
            me->interwork_tp_ptr_pri_0 = gem_port_id;
            break;
        case 1:
            me->interwork_tp_ptr_pri_1 = gem_port_id;
            break;
        case 2:
            me->interwork_tp_ptr_pri_2 = gem_port_id;
            break;
        case 3:
            me->interwork_tp_ptr_pri_3 = gem_port_id;
            break;
        case 4:
            me->interwork_tp_ptr_pri_4 = gem_port_id;
            break;
        case 5:
            me->interwork_tp_ptr_pri_5 = gem_port_id;
            break;
        case 6:
            me->interwork_tp_ptr_pri_6 = gem_port_id;
            break;
        case 7:
            me->interwork_tp_ptr_pri_7 = gem_port_id;
            break;
        default:
            break;
        }
    }
    else
    {
        /* Map all priorities to the GEM port. */
        me->interwork_tp_ptr_pri_0 = gem_port_id;
        me->interwork_tp_ptr_pri_1 = gem_port_id;
        me->interwork_tp_ptr_pri_2 = gem_port_id;
        me->interwork_tp_ptr_pri_3 = gem_port_id;
        me->interwork_tp_ptr_pri_4 = gem_port_id;
        me->interwork_tp_ptr_pri_5 = gem_port_id;
        me->interwork_tp_ptr_pri_6 = gem_port_id;
        me->interwork_tp_ptr_pri_7 = gem_port_id;
    }

    omci_svc_omci_ieee_8021_p_mapper_svc_prof_me_set(olt_id, onu_key->pon_ni, onu_key->onu_id, o_vid_entry->entity_id, 8,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI0, me->interwork_tp_ptr_pri_0,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI1, me->interwork_tp_ptr_pri_1,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI2, me->interwork_tp_ptr_pri_2,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI3, me->interwork_tp_ptr_pri_3,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI4, me->interwork_tp_ptr_pri_4,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI5, me->interwork_tp_ptr_pri_5,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI6, me->interwork_tp_ptr_pri_6,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI7, me->interwork_tp_ptr_pri_7);
}

static void omci_svc_state_set_8021p_mapper_service_profile_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_create_mac_bridge_port_cfg_data_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow_op->flow.data;

    /** For end-to-end untagged packet (i.e. untagged from UNI through to ANI), 
      mac bridge port config data should point to gem iw tp (not 802.1p mapper svc profile) */
    if (ONU_MGMT_FLOW_IS_UNICAST(flow) && 
        ONU_MGMT_FLOW_IS_UNTAGGED_END_TO_END(flow_data))
    {
        *(bcmos_bool *)context = BCMOS_TRUE;
    }
    else
    {
        omci_svc_o_vid *o_vid_entry = omci_svc_o_vid_get(onu_context, flow);

        /** @todo broadcast flow needs this ME config for each UNI  */
        *(bcmos_bool *)context = (ONU_MGMT_FLOW_IS_MULTICAST(flow) || ONU_MGMT_FLOW_IS_BROADCAST(flow)) ? BCMOS_TRUE : (o_vid_entry->ref_count == 1);
    }
}

static void omci_svc_state_create_mac_bridge_port_cfg_data_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;
    uint16_t entity_id = omci_svc_o_vid_get(onu_context, flow)->entity_id;
    omci_svc_mac_bridge_port *mac_bridge_port_entry;
    omci_svc_uni *uni = omci_svc_uni_get(onu_context, flow);
    uint16_t mac_bridge_port_cfg_data_entity_id = omci_svc_o_vid_get(onu_context, flow)->entity_id;
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    mac_bridge_port_entry = TAILQ_FIRST(&onu_context->mib.free_mac_bridge_ports);
    TAILQ_REMOVE(&onu_context->mib.free_mac_bridge_ports, mac_bridge_port_entry, next);
    TAILQ_INSERT_TAIL(&onu_context->mib.used_mac_bridge_ports, mac_bridge_port_entry, next);
    mac_bridge_port_entry->entity_id = mac_bridge_port_cfg_data_entity_id;


    /** For end-to-end untagged packet (i.e. untagged from UNI through to ANI), 
      mac bridge port config data should point to gem iw tp (not 802.1p mapper svc profile) */

    /* Instance (Outer VID) should have no conflicts with UNI side instance (at least OMCI_SVC_MAC_BRIDGE_PORT_CONFIG_DATA_UNI_INSTANCE_BASE). */
    /** @todo  in future we may need to support multiple UNI ports for the same VID for a mcast or broadcast flow.  */
    omci_svc_omci_mac_bridge_port_config_data_me_create(olt_id, onu_key->pon_ni, onu_key->onu_id, mac_bridge_port_cfg_data_entity_id, 10,
        OMCI_SVC_OMCI_ATTR_ID_BRIDGE_ID_PTR, uni->uni.entity_id,
        OMCI_SVC_OMCI_ATTR_ID_PORT_NUM, mac_bridge_port_entry->port_num,
        /** @note broadcast flow tp type is GEM interworking TP */
        OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_PORT_TP_TYPE,
         (ONU_MGMT_FLOW_IS_MULTICAST(flow) ? OMCI_SVC_OMCI_TP_TYPE_MCAST_GEM_IW_TP :
          (ONU_MGMT_FLOW_IS_UNICAST(flow) ? (ONU_MGMT_FLOW_IS_UNTAGGED_END_TO_END(flow_data) ? OMCI_SVC_OMCI_TP_TYPE_GEM_IW_TP : OMCI_SVC_OMCI_TP_TYPE_8021_P_MAP_SVC_PROF) :
           (ONU_MGMT_FLOW_IS_BROADCAST(flow) ? OMCI_SVC_OMCI_TP_TYPE_GEM_IW_TP : 0))),
        /** @note for broadcast it points to GEM IW TP entity */
        OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_PORT_TP_PTR,
         (ONU_MGMT_FLOW_IS_MULTICAST(flow) ? flow_data->svc_port_id :
          /* for untagged unicast flow end-to-end, this should point to GEM IW TP */
          (ONU_MGMT_FLOW_IS_UNICAST(flow) ? (ONU_MGMT_FLOW_IS_UNTAGGED_END_TO_END(flow_data) ? flow_data->svc_port_id : entity_id) :
           (ONU_MGMT_FLOW_IS_BROADCAST(flow) ? flow_data->svc_port_id : OMCI_SVC_NULL_PTR))),
        OMCI_SVC_OMCI_ATTR_ID_PORT_PRI, 0,
        OMCI_SVC_OMCI_ATTR_ID_PORT_PATH_COST, 0,
        OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_PORT_CONFIG_DATA_PORT_SPANNING_TREE_IND, 0,
        OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_DEPRECATED_1, 0,
        OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_DEPRECATED_2, 0,
        OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_PORT_CONFIG_MAC_LEARNING_DEPTH, 0);
}

static void omci_svc_state_create_mac_bridge_port_cfg_data_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_create_vlan_tagging_filter_data_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow_op->flow.data;

    /** no vlan tag filter should be created/used for end-to-end untagged packet
      (i.e. untagged from UNI through to ANI) */
    if (ONU_MGMT_FLOW_IS_UNICAST(flow) && 
        ONU_MGMT_FLOW_IS_UNTAGGED_END_TO_END(flow_data))
    {
        *(bcmos_bool *)context = BCMOS_FALSE;
    }
    else
    {
        omci_svc_o_vid *o_vid_entry = omci_svc_o_vid_get(onu_context, flow);

#ifdef OMCI_SVC_NO_WORKAROUNDS_FOR_BRCM_ONU 
        /** @note broadcast needs this ME as well */
        *(bcmos_bool *)context = o_vid_entry->ref_count == 1 && (ONU_MGMT_FLOW_IS_UNICAST(flow) || ONU_MGMT_FLOW_IS_BROADCAST(flow));
#else
        *(bcmos_bool *)context = o_vid_entry->ref_count == 1;
#endif
    }
}

static void omci_svc_state_create_vlan_tagging_filter_data_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    uint16_t entity_id = omci_svc_o_vid_get(onu_context, flow)->entity_id;
    uint16_t mac_bridge_port_cfg_data_entity_id = omci_svc_o_vid_get(onu_context, flow)->entity_id;
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    bcmos_errno rc = BCM_ERR_OK;

    /* The standard requires for the entity ID that "Through an identical ID, this managed entity is implicitly linked to an instance of the MAC bridge port configuration data ME". */
    rc = omci_svc_omci_vlan_tag_filter_data_me_create(olt_id, onu_key->pon_ni, onu_key->onu_id, mac_bridge_port_cfg_data_entity_id,
            3,
            OMCI_SVC_OMCI_ATTR_ID_NO_OF_ENTRIES, 1,
            OMCI_SVC_OMCI_ATTR_ID_VLAN_FILTER_TABLE, entity_id & OMCI_SVC_O_VID_VALUE_MASK,
            OMCI_SVC_OMCI_ATTR_ID_FORWARD_OPER, 
            ONU_MGMT_FLOW_IS_UNICAST(flow) ? BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_H_VID_INVESTIGATION_UNTAGGED_DISCARDING_C :
               (ONU_MGMT_FLOW_IS_BROADCAST(flow) ? BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_J_VID_INVESTIGATION_UNTAGGED_DISCARDING_C : BCM_OMCI_VLAN_TAG_FILTER_DATA_FORWARD_OPER_TAGGED_ACTION_J_VID_INVESTIGATION_UNTAGGED_BRIDGING_A));

    if (rc != BCM_ERR_OK)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, NULL, "%s: failed, pon_ni=%u:onu_id=%u, mac_bridge_port_cfg_data_entity_id=%u, entity_id=%u, result=%s\n",
            __FUNCTION__, onu_key->pon_ni, onu_key->onu_id, mac_bridge_port_cfg_data_entity_id, entity_id,  bcmos_strerror(rc));

        omci_svc_flow_sm_rollback_cb(olt_id, onu_key, rc, NULL);
    }
}

static void omci_svc_state_create_vlan_tagging_filter_data_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

/**
  * @brief For now handling double tag as a special case and only the basic passthrough is being targeted for now.
  */
void omci_svc_ext_vlan_tag_oper_cfg_data_entry_filter_set_double_tag(bcmonu_mgmt_onu_key *onu_key, bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table *entry,
    bcmonu_mgmt_flow_cfg *flow, unsigned long filter_mask)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;

    /* Outer filter */
    /* pbit */
    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_pcp))
        entry->outer_filter_word.filter_outer_priority  = flow_data->match.o_pcp;
    else
        entry->outer_filter_word.filter_outer_priority = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_OUTER_PRIO_DONT_FILTER;

    /* vid */
    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_vid))
        entry->outer_filter_word.filter_outer_vid = flow_data->match.o_vid;
    else
        entry->outer_filter_word.filter_outer_vid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_OUTER_VID_DONT_FILTER;

    /* tpid */
    entry->outer_filter_word.filter_outer_tpid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_OUTER_TPID_DEI_DONT_FILTER;


    /* pbit */
    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, i_pcp))
        entry->inner_filter_word.filter_inner_priority  = flow_data->match.i_pcp;
    else
        entry->inner_filter_word.filter_inner_priority = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_INNER_PRIO_DONT_FILTER;

    /* vid */
    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, i_vid))
        entry->inner_filter_word.filter_inner_vid = flow_data->match.i_vid;
    else
        entry->inner_filter_word.filter_inner_vid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_INNER_VID_DONT_FILTER;

    /* tpid */
    entry->inner_filter_word.filter_inner_tpid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_INNER_TPID_DEI_DONT_FILTER;
    entry->inner_filter_word.filter_ether_type = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_ETHER_TYPE_FILTER_NONE; /* Do not filter any Ethernet type. */
}

/**
  * @note single tagged flow has the omci config done in the inner tag of the ext vlan filter.
  */
void omci_svc_ext_vlan_tag_oper_cfg_data_entry_filter_set_single_tag(bcmonu_mgmt_onu_key *onu_key, bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table *entry,
    bcmonu_mgmt_flow_cfg *flow, unsigned long filter_mask)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;

    /* First, set all fields that are assigned the same value for all cases. */

    /* Outer filter */
    entry->outer_filter_word.filter_outer_priority = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_OUTER_PRIO_NOT_DOUBLE_TAGGED;
    entry->outer_filter_word.filter_outer_vid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_OUTER_VID_DONT_FILTER;
    entry->outer_filter_word.filter_outer_tpid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_OUTER_TPID_DEI_DONT_FILTER;

    /* Inner filter */
    entry->inner_filter_word.filter_inner_tpid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_INNER_TPID_DEI_DONT_FILTER;

    /* From here, fields are assigned different values for the different cases. */

    /* Ethernet type filter */
    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, ether_type))
    {
        switch (flow_data->match.ether_type)
        {
        case OMCI_SVC_ETHER_TYPE_IPOE:
            entry->inner_filter_word.filter_ether_type = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_ETHER_TYPE_FILTER_IPOE;
            break;
        case OMCI_SVC_ETHER_TYPE_PPPOE0:
        case OMCI_SVC_ETHER_TYPE_PPPOE1:
            entry->inner_filter_word.filter_ether_type  = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_ETHER_TYPE_FILTER_PPPOE;
            break;
        case OMCI_SVC_ETHER_TYPE_ARP:
            entry->inner_filter_word.filter_ether_type  = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_ETHER_TYPE_FILTER_ARP;
            break;
        case OMCI_SVC_ETHER_TYPE_IPV6_IPOE:
            entry->inner_filter_word.filter_ether_type  = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_ETHER_TYPE_FILTER_IPV6_IPOE;
            break;
        default:
            entry->inner_filter_word.filter_ether_type  = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_ETHER_TYPE_FILTER_NONE;
            break;
        }
    }
    else
        entry->inner_filter_word.filter_ether_type  = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_ETHER_TYPE_FILTER_NONE; /* Do not filter any Ethernet type. */

    /* Inner filter */
    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_pcp))
        entry->inner_filter_word.filter_inner_priority  = flow_data->match.o_pcp;
    else
    {
        if (filter_mask &= OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_UNTAGGED)
            entry->inner_filter_word.filter_inner_priority = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_INNER_PRIO_UNTAGGED;
        else
            entry->inner_filter_word.filter_inner_priority = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_INNER_PRIO_DONT_FILTER;
    }

    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_vid))
        entry->inner_filter_word.filter_inner_vid = flow_data->match.o_vid;
    else
        entry->inner_filter_word.filter_inner_vid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_INNER_VID_DONT_FILTER;

    BCM_LOG(DEBUG, omci_svc_log_id, "    filter_outer_tpid=\n");
    BCM_LOG(DEBUG, omci_svc_log_id, "%u(0x%x)\n", entry->outer_filter_word.filter_outer_tpid, entry->outer_filter_word.filter_outer_tpid);
    BCM_LOG(DEBUG, omci_svc_log_id, "    filter_outer_vid=\n");
    BCM_LOG(DEBUG, omci_svc_log_id, "%u(0x%02x)\n", entry->outer_filter_word.filter_outer_vid, entry->outer_filter_word.filter_outer_vid);
    BCM_LOG(DEBUG, omci_svc_log_id, "    filter_outer_priority=\n");
    BCM_LOG(DEBUG, omci_svc_log_id, "%u(0x%x)\n", entry->outer_filter_word.filter_outer_priority, entry->outer_filter_word.filter_outer_priority);

    BCM_LOG(DEBUG, omci_svc_log_id, "    filter_eth_type=\n");
    BCM_LOG(DEBUG, omci_svc_log_id, "%u(0x%x)\n", entry->inner_filter_word.filter_ether_type, entry->inner_filter_word.filter_ether_type);
    BCM_LOG(DEBUG, omci_svc_log_id, "    filter_inner_tpid=\n");
    BCM_LOG(DEBUG, omci_svc_log_id, "%u(0x%x)\n", entry->inner_filter_word.filter_inner_tpid, entry->inner_filter_word.filter_inner_tpid);
    BCM_LOG(DEBUG, omci_svc_log_id, "    filter_inner_vid=\n");
    BCM_LOG(DEBUG, omci_svc_log_id, "%u(0x%02x)\n", entry->inner_filter_word.filter_inner_vid, entry->inner_filter_word.filter_inner_vid);
    BCM_LOG(DEBUG, omci_svc_log_id, "    filter_inner_priority=\n");
    BCM_LOG(DEBUG, omci_svc_log_id, "%u(0x%x)\n", entry->inner_filter_word.filter_inner_priority, entry->inner_filter_word.filter_inner_priority);
}

void omci_svc_ext_vlan_tag_oper_cfg_data_entry_treatment_set_double_tag(bcmonu_mgmt_onu_key *onu_key, bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table *entry,
    bcmonu_mgmt_flow_cfg *flow, bcmos_bool is_add_entry)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;

    if (is_add_entry)
    {
        /* Outer treatment + tags to remove (outer treatment) */
        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, type))
        {
            BCM_LOG(ERROR, omci_svc_log_id, "Action for double tagged packets is not supported. Setting it to transparent action\n");
        }

        entry->outer_treatment_word.treatment = 0;   /* default do not remove tag */

#ifdef OMCI_SVC_NO_WORKAROUNDS_FOR_BRCM_ONU
        entry->outer_treatment_word.treatment_outer_priority = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_OUTER_PRIO_DONT_TAG; /* Keep the original priority of the tag. */
        entry->outer_treatment_word.treatment_outer_vid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_OUTER_VID_DONT_CARE; /* Keep the original VID of the tag. */
        entry->outer_treatment_word.treatment_outer_tpid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_OUTER_TPID_DEI_DONT_CARE;
        entry->inner_treatment_word.treatment_inner_priority = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_PRIO_DONT_TAG; /* Keep the original priority of the tag. */
        entry->inner_treatment_word.treatment_inner_vid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_VID_DONT_CARE; /* Keep the original VID of the tag. */
        entry->inner_treatment_word.treatment_inner_tpid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_TPID_DEI_DONT_CARE;
#else
        /* For transparent treatment, the workaround for ONU is to remove the tag/pri and add them back */
        entry->outer_treatment_word.treatment = 2;   /* remove both outer & inner tags */

        /* Outer Treatment: */
        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_pcp))
            entry->outer_treatment_word.treatment_outer_priority = flow_data->match.o_pcp;
        else
            entry->outer_treatment_word.treatment_outer_priority = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_OUTER_PRIO_COPY_FROM_OUTER_PRIO;

        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_vid))
            entry->outer_treatment_word.treatment_outer_vid = flow_data->match.o_vid;
        else
            entry->outer_treatment_word.treatment_outer_vid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_OUTER_VID_DONT_CARE;
        entry->outer_treatment_word.treatment_outer_tpid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_OUTER_TPID_DEI_DONT_CARE;

        /* Inner Treatment:  */
        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, i_pcp))
            entry->inner_treatment_word.treatment_inner_priority = flow_data->match.i_pcp;
        else
            entry->inner_treatment_word.treatment_inner_priority = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_PRIO_COPY_FROM_INNER_PRIO;

        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, i_vid))
            entry->inner_treatment_word.treatment_inner_vid = flow_data->match.i_vid;
        else
            entry->inner_treatment_word.treatment_inner_vid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_VID_DONT_CARE;
        entry->inner_treatment_word.treatment_inner_tpid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_TPID_DEI_DONT_CARE;
#endif
    }
    else
    {
        /* Remove entry from table */
        *((uint32_t *)&entry->outer_treatment_word) = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_OUTER_DELETE;
        *((uint32_t *)&entry->inner_treatment_word) = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_DELETE;
    }
}


void omci_svc_ext_vlan_tag_oper_cfg_data_entry_treatment_set_single_tag(bcmonu_mgmt_onu_key *onu_key, bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table *entry,
    bcmonu_mgmt_flow_cfg *flow, bcmos_bool is_add_entry)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;
    unsigned long filter_mask = omci_svc_filter_mask_get(flow);

    if (is_add_entry)
    {
        /* Add entry from table */
        /* First, set all fields that are assigned the same value for all cases. */
        entry->outer_treatment_word.treatment = 0;

        /* Outer treatment */
        entry->outer_treatment_word.treatment_outer_priority = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_OUTER_PRIO_DONT_TAG;
        entry->outer_treatment_word.treatment_outer_vid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_OUTER_VID_DONT_CARE;
        entry->outer_treatment_word.treatment_outer_tpid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_OUTER_TPID_DEI_DONT_CARE;

        /* From here, fields are assigned different values for the different cases. */

        /* Inner treatment + tags to remove (outer treatment) */
        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, type))
        {
            if (flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(push))
            {
                if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, o_pcp))
                    entry->inner_treatment_word.treatment_inner_priority = flow_data->action.o_pcp;
                else
                    entry->inner_treatment_word.treatment_inner_priority = 0;

                entry->inner_treatment_word.treatment_inner_vid = flow_data->action.o_vid;
                /* Even if there's outer TPID in the flow's action, we ignore it, because Extended VLAN Tagging Operation Configuration Data ME does not allow specifying a TPID for a flow
                 * (it may copy it or assign it from output TPID parameter, though). */
                entry->inner_treatment_word.treatment_inner_tpid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_TPID_DEI_SET_TPID_OUTPUT_TPID_DEI0;
            }
            else
            {
                /** PCP :  Handle PCP translation (with/without VID translation). */
                if (flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(translate_pcp))
                {
                    entry->inner_treatment_word.treatment_inner_priority = flow_data->action.o_pcp;
                    /* According to the OMCI standard, in the upstream direction, the ONU needs to remove and add a tag for a VID translation operation.
                     * Other than that, this should be kept 0 (there's no TR-156 scenario in which the ONU only pops a tag). */
                    entry->outer_treatment_word.treatment = 0x01;
                }
                else
                {
                    if (flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(translate_vid))
                    {
                        /* Although this is not a PCP translate operation, this is still a VID translate operation, 
                         * so since we remove the tag (entry->outer_treatment_word.treatment is 1), we need to re-add a tag. */
                        /** To satisfy the ONU, specify the actual P-bits from the match, rather than just saying "copy" */
#ifdef OMCI_SVC_NO_WORKAROUNDS_FOR_BRCM_ONU
                        entry->inner_treatment_word.treatment_inner_priority = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_PRIO_COPY_FROM_INNER_PRIO;
#else
                        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_pcp))
                            entry->inner_treatment_word.treatment_inner_priority = flow_data->match.o_pcp;
                        else
                            entry->inner_treatment_word.treatment_inner_priority = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_PRIO_COPY_FROM_INNER_PRIO;
#endif
                    }
                    else
                        entry->inner_treatment_word.treatment_inner_priority = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_PRIO_DONT_TAG; /* Do not add an inner tag */
                }

                /** VID: Handle VID translation (with/without PCP translation). */
                if (flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(translate_vid))
                {
                    entry->inner_treatment_word.treatment_inner_vid = flow_data->action.o_vid;
                    /* According to the OMCI standard, in the upstream direction, the ONU needs to remove and add a tag for a VID translation operation.
                     * Other than that, this should be kept 0 (there's no TR-156 scenario in which the ONU only pops a tag). */
                    entry->outer_treatment_word.treatment = 0x01;
                }
                else
                    entry->inner_treatment_word.treatment_inner_vid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_VID_DONT_CHANGE; /* Keep the original VID of the tag. */
                /** TPID : */
                entry->inner_treatment_word.treatment_inner_tpid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_TPID_DEI_COPY;
            }
        }
        else
        {
            /* Transparent Pass */
#ifdef OMCI_SVC_NO_WORKAROUNDS_FOR_BRCM_ONU
            entry->inner_treatment_word.treatment_inner_priority = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_PRIO_DONT_TAG; /* Keep the original priority of the tag. */
            entry->inner_treatment_word.treatment_inner_vid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_VID_DONT_CARE; /* Keep the original VID of the tag. */
            entry->inner_treatment_word.treatment_inner_tpid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_TPID_DEI_DONT_CARE;
#else
            entry->outer_treatment_word.treatment = 0x01;   /* remove the outer tag */

            /* For transparent treatment, the workaround for ONU is to remove the inner tag/pri and add them back */
            if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_pcp))
                entry->inner_treatment_word.treatment_inner_priority = flow_data->match.o_pcp;
            else
            {
                if (filter_mask &= OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_UNTAGGED)
                    entry->inner_treatment_word.treatment_inner_priority = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_PRIO_DONT_TAG;
                else
                    entry->inner_treatment_word.treatment_inner_priority = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_PRIO_COPY_FROM_INNER_PRIO;
            }

            if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_vid))
                entry->inner_treatment_word.treatment_inner_vid = flow_data->match.o_vid;
            else
                entry->inner_treatment_word.treatment_inner_vid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_VID_DONT_CHANGE;
            entry->inner_treatment_word.treatment_inner_tpid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_TPID_DEI_DONT_CARE;
#endif
        }
    }
    else
    {
        /* Remove entry from table */
        *((uint32_t *)&entry->outer_treatment_word) = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_OUTER_DELETE;
        *((uint32_t *)&entry->inner_treatment_word) = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_TREATMENT_INNER_DELETE;
    }

    BCM_LOG(DEBUG, omci_svc_log_id, "    treatment_outer_tpid=\n");
    BCM_LOG(DEBUG, omci_svc_log_id, "%u(0x%x)\n", entry->outer_treatment_word.treatment_outer_tpid, entry->outer_treatment_word.treatment_outer_tpid);
    BCM_LOG(DEBUG, omci_svc_log_id, "    treatment_outer_vid=\n");
    BCM_LOG(DEBUG, omci_svc_log_id, "%u(0x%02x)\n", entry->outer_treatment_word.treatment_outer_vid, entry->outer_treatment_word.treatment_outer_vid);
    BCM_LOG(DEBUG, omci_svc_log_id, "    treatment_outer_priority=\n");
    BCM_LOG(DEBUG, omci_svc_log_id, "%u(0x%x)\n", entry->outer_treatment_word.treatment_outer_priority, entry->outer_treatment_word.treatment_outer_priority);
    BCM_LOG(DEBUG, omci_svc_log_id, "    treatment=\n");
    BCM_LOG(DEBUG, omci_svc_log_id, "%u(0x%x)\n", entry->outer_treatment_word.treatment, entry->outer_treatment_word.treatment);

    BCM_LOG(DEBUG, omci_svc_log_id, "    treatment_inner_tpid=\n");
    BCM_LOG(DEBUG, omci_svc_log_id, "%u(0x%x)\n", entry->inner_treatment_word.treatment_inner_tpid, entry->inner_treatment_word.treatment_inner_tpid);
    BCM_LOG(DEBUG, omci_svc_log_id, "    treatment_inner_vid=\n");
    BCM_LOG(DEBUG, omci_svc_log_id, "%u(0x%02x)\n", entry->inner_treatment_word.treatment_inner_vid, entry->inner_treatment_word.treatment_inner_vid);
    BCM_LOG(DEBUG, omci_svc_log_id, "    treatment_inner_priority=\n");
    BCM_LOG(DEBUG, omci_svc_log_id, "%u(0x%0x)\n", entry->inner_treatment_word.treatment_inner_priority, entry->inner_treatment_word.treatment_inner_priority);
}


/**
  * @brief check if it is a double tag "match" config for the flow.
  * @note  for now we will support just double tag pass through at a minimum w/o any treatment.
  */
bcmos_bool omci_svc_is_flow_double_tagged(bcmonu_mgmt_flow_cfg *flow)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;

    return BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_vid) && BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, i_vid);
}


unsigned long omci_svc_filter_mask_get(bcmonu_mgmt_flow_cfg *flow)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;
    unsigned long filter_mask = 0;

    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_untagged) && 
            !BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_vid) && !BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_pcp))
    {
        /* if match for untagged pkt is configured then only 1 rule (untagged rule) goes out in ext vlan tag */
        filter_mask = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_UNTAGGED;
    }
    else if (!BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_untagged) && 
                 (!BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_vid) && !BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_pcp)))
    {
        /* else if no match specified, then we need to insert 2 rules - 
            one for untagged traffic and one for single-tagged traffic.
         */ 
        filter_mask = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_UNTAGGED | OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_SINGLE_TAGGED;
    }
    else
    {
        /* for all other cases of vid and/or pcp match, insert just the single tag rule */
        filter_mask = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_FILTER_SINGLE_TAGGED;
    }

    return filter_mask;
}

static void omci_svc_ext_vlan_tag_oper_cfg_data_add_entry(bcmonu_mgmt_onu_key *onu_key, bcmonu_mgmt_flow_cfg *flow, unsigned long filter_mask)
{
#ifdef ENABLE_LOG
    unsigned long full_filter_mask = omci_svc_filter_mask_get(flow);
    int pos = ffs(filter_mask);
    unsigned int next_filter;
#endif
    bcmos_errno rc = BCM_ERR_OK;
    bcmolt_oltid olt_id = flow->hdr.hdr.olt_id;
    omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, onu_key->pon_ni, onu_key->onu_id);
    omci_svc_uni *uni = omci_svc_uni_get(onu_context, flow);

#ifdef ENABLE_LOG
    next_filter = 1 << (pos - 1);
#endif
    /* popcount is a method for counting the number of asserted bits in a vector. */
    BCM_LOG(DEBUG, omci_svc_log_id, "ExtVlanTagOperConfigData Entry filter='%s' (%u rules in total)\n",
        omci_svc_ext_vlan_tag_oper_cfg_data_filter2str_conv(next_filter), __builtin_popcount(full_filter_mask));


    omci_svc_omci_ext_vlan_tag_oper_config_data_me_add_entry(onu_key, onu_context, flow, filter_mask);
    if (rc != BCM_ERR_OK)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, NULL, "Add Entry Req() request failed, entity_id=%u, result=%s\n",
            uni->uni.entity_id, bcmos_strerror(rc));

        omci_svc_flow_sm_rollback_cb(olt_id, onu_key, rc, NULL);
    }
}

static void omci_svc_state_add_entry_ext_vlan_tag_oper_cfg_data_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow_op->flow.data;

    /** no mapper svc profile should be created for end-to-end untagged packet 
      (i.e. untagged from UNI through to ANI) */
    if (ONU_MGMT_FLOW_IS_UNICAST(flow) && 
        ONU_MGMT_FLOW_IS_UNTAGGED_END_TO_END(flow_data))
    {
        *(bcmos_bool *)context = BCMOS_FALSE;
    }
    else
    {
#ifdef OMCI_SVC_NO_WORKAROUNDS_FOR_BRCM_ONU 
        *(bcmos_bool *)context = ONU_MGMT_FLOW_IS_UNICAST(flow);
#else
        *(bcmos_bool *)context = ONU_MGMT_FLOW_IS_UNICAST(flow) || ONU_MGMT_FLOW_IS_MULTICAST(flow);
#endif
    }
}

static void omci_svc_state_add_entry_ext_vlan_tag_oper_cfg_data_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    unsigned long filter_mask;

    if (ONU_MGMT_FLOW_IS_MULTICAST(flow))
        flow = &flow_op->flow_reversed;

    filter_mask = omci_svc_filter_mask_get(flow);
    onu_context->iter = (void *)filter_mask;
    omci_svc_ext_vlan_tag_oper_cfg_data_add_entry(onu_key, flow, filter_mask);
}

static void omci_svc_state_add_entry_ext_vlan_tag_oper_cfg_data_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    unsigned long filter_mask = (unsigned long)onu_context->iter;
    int pos = ffs(filter_mask);
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    if (ONU_MGMT_FLOW_IS_MULTICAST(flow) || ONU_MGMT_FLOW_IS_BROADCAST(flow))
        flow = &flow_op->flow_reversed;

    filter_mask &= ~(1 << (pos - 1));
    onu_context->iter = (void *)filter_mask;
    if (filter_mask)
        omci_svc_ext_vlan_tag_oper_cfg_data_add_entry(onu_key, flow, filter_mask);
    else
        omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_set_multicast_operations_profile_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context,
    omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow, void *context)
{
    /** @note mcast operations profile ME is not used for broadcast flow */
    *(bcmos_bool *)context = ONU_MGMT_FLOW_IS_MULTICAST(flow);
}

static void omci_svc_state_set_multicast_operations_profile_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context,
    omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow_op->flow.data;
    omci_svc_uni *uni = omci_svc_uni_get(onu_context, flow);
    bcm_omci_mcast_operations_profile_ds_igmp_and_multicast_tci ds_igmp_and_mcast_tci;
    uint16_t upstream_igmp_tci = 0;
    bcm_omci_mcast_operations_profile_upstream_igmp_tag_control us_igmp_tag_control;
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    char ds_igmp_and_mcast_tci_hex_str[3 + BCM_OMCI_CFG_DATA_DS_IGMP_AND_MULTICAST_TCI_LEN * 2]; /* 3 bytes as a hexstring: 0xAABBCC */

    /* Overwrite the default value that we configured when the ONU went up. */
    if (flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(pop))
    {
        ds_igmp_and_mcast_tci.control_type = BCM_OMCI_MCAST_OPERATIONS_PROFILE_DS_IGMP_AND_MULTICAST_TCI_CONTROL_TYPE_STRIP_OUTER_TAG;
        ds_igmp_and_mcast_tci.tci = 0;
    }
    else if (flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(translate_vid))
    {
        if (flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(translate_pcp))
        {
            /* VID translation + PCP translation */
            ds_igmp_and_mcast_tci.control_type = BCM_OMCI_MCAST_OPERATIONS_PROFILE_DS_IGMP_AND_MULTICAST_TCI_CONTROL_TYPE_REPLACE_OUTER_TCI;
            ds_igmp_and_mcast_tci.tci = flow_data->action.o_vid | (flow_data->action.o_pcp << 13);
        }
        else
        {
            /* VID translation only */
            ds_igmp_and_mcast_tci.control_type = BCM_OMCI_MCAST_OPERATIONS_PROFILE_DS_IGMP_AND_MULTICAST_TCI_CONTROL_TYPE_REPLACE_OUTER_VID;
            ds_igmp_and_mcast_tci.tci = flow_data->action.o_vid;
        }
    }
    else if (flow_data->action.type & BCMONU_MGMT_FLOW_ACTION_TYPE_MASK_GET(translate_pcp))
    {
        /* PCP translation only - priority tagged packets at the UNI (VID=0). */
        ds_igmp_and_mcast_tci.control_type = BCM_OMCI_MCAST_OPERATIONS_PROFILE_DS_IGMP_AND_MULTICAST_TCI_CONTROL_TYPE_REPLACE_OUTER_TCI;
        ds_igmp_and_mcast_tci.tci = flow_data->action.o_pcp << 13;
    }
    else
    {
        /* Transparent action */
        ds_igmp_and_mcast_tci.control_type = BCM_OMCI_MCAST_OPERATIONS_PROFILE_DS_IGMP_AND_MULTICAST_TCI_CONTROL_TYPE_TRANSPARENT;
        ds_igmp_and_mcast_tci.tci = 0;
    }
    sprintf(ds_igmp_and_mcast_tci_hex_str, "0x%02x%04x", ds_igmp_and_mcast_tci.control_type, ds_igmp_and_mcast_tci.tci);


    /** 
     * Now set the Upstream IGMP attributes 
     **/
    if (flow_data->igmp_us_action.type & BCMONU_MGMT_IGMP_US_PROP_MASK_GET(action_type, add_vlan_tag))
    {
        us_igmp_tag_control = BCM_OMCI_MCAST_OPERATIONS_PROFILE_UPSTREAM_IGMP_TAG_CONTROL_ADD_VLAN_TAG;
        upstream_igmp_tci = flow_data->igmp_us_action.vid | flow_data->igmp_us_action.pcp << 12;
    }
    else if (flow_data->igmp_us_action.type & BCMONU_MGMT_IGMP_US_PROP_MASK_GET(action_type, replace_tci))
    {
        us_igmp_tag_control = BCM_OMCI_MCAST_OPERATIONS_PROFILE_UPSTREAM_IGMP_TAG_CONTROL_REPLACE_VLAN_TAG;
        upstream_igmp_tci = flow_data->igmp_us_action.vid | flow_data->igmp_us_action.pcp << 12;
    }
    else if (flow_data->igmp_us_action.type & BCMONU_MGMT_IGMP_US_PROP_MASK_GET(action_type, replace_vid))
    {
        us_igmp_tag_control = BCM_OMCI_MCAST_OPERATIONS_PROFILE_UPSTREAM_IGMP_TAG_CONTROL_REPLACE_VLAN_ID;
        upstream_igmp_tci = flow_data->igmp_us_action.vid;
    }
    else
    {
        /* Transparent action */
        us_igmp_tag_control = BCM_OMCI_MCAST_OPERATIONS_PROFILE_UPSTREAM_IGMP_TAG_CONTROL_PASS_IGMP_MLD_TRANSPARENT;
        upstream_igmp_tci = 0;
    }


    /* call Stack API to set the attributes for the ME */
    omci_svc_omci_mcast_operations_profile_me_set(olt_id, onu_key->pon_ni, onu_key->onu_id, uni->uni.entity_id, 3,
        OMCI_SVC_OMCI_ATTR_ID_DS_IGMP_AND_MCAST_TCI, ds_igmp_and_mcast_tci_hex_str,
        OMCI_SVC_OMCI_ATTR_ID_US_IGMP_TAG_CONTROL, us_igmp_tag_control,
        OMCI_SVC_OMCI_ATTR_ID_US_IGMP_TCI, upstream_igmp_tci);
}

static void omci_svc_state_set_multicast_operations_profile_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_add_entry_multicast_operations_profile_dynamic_acl_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context,
    omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow, void *context)
{
    *(bcmos_bool *)context = ONU_MGMT_FLOW_IS_MULTICAST(flow);
}

void omci_svc_mcast_operations_profile_dynamic_acl_set(bcmonu_mgmt_onu_key *onu_key, bcm_omci_mcast_operations_profile_dynamic_access_control_list_table *entry,
    bcmonu_mgmt_flow_cfg *flow, bcmonu_mgmt_svc_port_id gem_port_id, bcmos_bool is_add_entry)
{
    bcmolt_oltid olt_id = flow->hdr.hdr.olt_id;
    omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, onu_key->pon_ni, onu_key->onu_id);

    if (is_add_entry)
    {
        /* Currently we support one dynamic ACL rule per GEM port. */
        entry->table_control =
            (BCM_OMCI_MCAST_ACL_TABLE_SET_CTRL_WRITE_ENTRY << OMCI_SVC_MULTICAST_OPERATIONS_PROFILE_DYNAMIC_ACL_SET_CTRL_SHIFT) |
            (BCM_OMCI_MCAST_ACL_ROW_PART0 << OMCI_SVC_MULTICAST_OPERATIONS_PROFILE_DYNAMIC_ACL_ROW_PART_ID_SHIFT);
        entry->gem_port_id = gem_port_id;
        entry->vlan_id = omci_svc_o_vid_get(onu_context, flow)->entity_id & OMCI_SVC_O_VID_VALUE_MASK;
        entry->src_ip = 0; /* The value 0.0.0.0 specifies that source IP address is to be ignored. */
        entry->ip_mcast_addr_start = 0xE0000000; /* 0xe0000000 == 224.0.0.0 */
        entry->ip_mcast_addr_end = 0xEFFFFFFF; /* 0xefffffff == 239.255.255.255 */
        entry->imputed_grp_bw = 0; /* 0 effectively allows this table entry to avoid max bandwidth limitations. */
    }
    else
    {
        /* Currently we support one dynamic ACL rule per GEM port. */
        entry->table_control =
            (BCM_OMCI_MCAST_ACL_TABLE_SET_CTRL_DELETE_ENTRY << OMCI_SVC_MULTICAST_OPERATIONS_PROFILE_DYNAMIC_ACL_SET_CTRL_SHIFT) |
            (BCM_OMCI_MCAST_ACL_ROW_PART0 << OMCI_SVC_MULTICAST_OPERATIONS_PROFILE_DYNAMIC_ACL_ROW_PART_ID_SHIFT);
    }
}

static void omci_svc_state_add_entry_multicast_operations_profile_dynamic_acl_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context,
    omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow_op->flow.data;
    bcmos_errno rc = BCM_ERR_OK;
    omci_svc_uni *uni = omci_svc_uni_get(onu_context, flow);
    bcmolt_oltid olt_id = flow->hdr.hdr.olt_id;

    omci_svc_omci_mcast_operations_profile_me_add_entry_dynamic_acl(onu_key, onu_context, flow, flow_data->svc_port_id);
    if (rc != BCM_ERR_OK)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, NULL, "Add Entry Req() request failed, entity_id=%u, result=%s\n",
            uni->uni.entity_id, bcmos_strerror(rc));

        omci_svc_flow_sm_rollback_cb(olt_id, onu_key, rc, NULL);
    }
}

static void omci_svc_state_add_entry_multicast_operations_profile_dynamic_acl_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_up_sequence_end_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow,
    void *context)
{
    *(bcmos_bool *)context = BCMOS_TRUE;
}

static void omci_svc_state_up_sequence_end_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow,
    void *context)
{
    flow_op->state = OMCI_SVC_FLOW_STATE_ID_ACTIVE;
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;
    bcmolt_oltid olt_id = flow->hdr.hdr.olt_id;

    OMCI_SVC_LOG(INFO, olt_id, onu_key, NULL, "%s Flow added successfully {flow id: %d, flow dir: %s, gem port: %d, alloc id: %d, uni:%d}\n",
        OMCI_SVC_FLOW_TYPE_STR(flow_data->flow_type),
        flow->key.id,
        flow->key.dir == BCMONU_MGMT_FLOW_DIR_ID_UPSTREAM ? "upstream" : "downstream",
        flow->data.svc_port_id, BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, agg_port_id) ? flow->data.agg_port_id : BCMONU_MGMT_AGG_PORT_ID_UNASSIGNED,
        flow->data.uni_port);
    OMCI_SVC_LOG(INFO, olt_id, onu_key, NULL, "{match.o_vid/o_pcp/o_untagged=%u/0x%x/%s, action: type/vid/pcp=%s/%u/0x%x}\n",
        flow->data.match.o_vid,
        BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_pcp) ? flow_data->match.o_pcp : 0,
        BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_untagged) ? (flow_data->match.o_untagged ? "yes" : "no") : "no",
        BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, type) ? action_type2str[flow_data->action.type] : "none",
        flow->data.action.o_vid,
        BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, o_pcp) ? flow_data->action.o_pcp : 0);

    OMCI_SVC_LOG(INFO, olt_id, onu_key, NULL, "{match.i_vid/i_pcp/i_untagged=%u/0x%x/%s, action: type/i_vid/i_pcp=%s/%u/0x%x}\n",
        flow->data.match.i_vid,
        BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, i_pcp) ? flow_data->match.i_pcp : 0,
        BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, i_untagged) ? (flow_data->match.i_untagged ? "yes" : "no") : "no",
        BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, type) ? action_type2str[flow_data->action.type] : "none",
        flow->data.action.i_vid,
        BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, i_pcp) ? flow_data->action.i_pcp : 0);

    if (ONU_MGMT_FLOW_IS_MULTICAST(flow))
    {
        OMCI_SVC_LOG(INFO, olt_id, onu_key, NULL, "{igmp us action: type/vid/pcp=%s/%u/0x%x}\n", 
            BCMONU_MGMT_IGMP_US_PROP_IS_SET(flow_data, action, type) ? igmp_us_action_type2str[flow_data->igmp_us_action.type] : "transparent",
            flow->data.igmp_us_action.vid,
            //BCMONU_MGMT_IGMP_US_PROP_IS_SET(flow_data, action, pcp) ? flow_data->igmp_us_action.pcp : 0);
            flow_data->igmp_us_action.pcp);
    }

    /* flow configured successfully; update flow cfg db */
    omci_svc_flow_cfg_db_update_entry(flow);

    if (flow_op->cb)
        flow_op->cb(flow_op->context, onu_context->last_err);


    omci_svc_flow_op_queue_dequeue(onu_context);
}

/* Down direction */
static void omci_svc_state_active_event_deactivate(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_delete_entry_multicast_operations_profile_dynamic_acl_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context,
    omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow, void *context)
{
    *(bcmos_bool *)context = ONU_MGMT_FLOW_IS_MULTICAST(flow);
}

static void omci_svc_state_delete_entry_multicast_operations_profile_dynamic_acl_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context,
    omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmos_errno rc = BCM_ERR_OK;
    omci_svc_uni *uni = omci_svc_uni_get(onu_context, flow);
    bcmolt_oltid olt_id = flow->hdr.hdr.olt_id;

    omci_svc_omci_mcast_operations_profile_me_remove_entry_dynamic_acl(onu_key, onu_context, flow);
    if (rc != BCM_ERR_OK)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, NULL, "Remove Entry Req() request failed, entity_id=%u, result=%s\n",
            uni->uni.entity_id, bcmos_strerror(rc));
        /* Ignore the error and continue deleting MEs, otherwise we will end up with an undefined state. */
    }
}

static void omci_svc_state_delete_entry_multicast_operations_profile_dynamic_acl_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context,
    omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_unset_multicast_operations_profile_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context,
    omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow, void *context)
{
    *(bcmos_bool *)context = ONU_MGMT_FLOW_IS_MULTICAST(flow);
}

static void omci_svc_state_unset_multicast_operations_profile_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context,
    omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow, void *context)
{
    omci_svc_uni *uni = omci_svc_uni_get(onu_context, flow);
    bcm_omci_mcast_operations_profile_ds_igmp_and_multicast_tci ds_igmp_and_mcast_tci;
    char ds_igmp_and_mcast_tci_hex_str[3 + BCM_OMCI_CFG_DATA_DS_IGMP_AND_MULTICAST_TCI_LEN * 2]; /* 3 bytes as a hexstring: 0xAABBCC */
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    /* Revert to the default value. */
    ds_igmp_and_mcast_tci.control_type = BCM_OMCI_MCAST_OPERATIONS_PROFILE_DS_IGMP_AND_MULTICAST_TCI_CONTROL_TYPE_TRANSPARENT;
    ds_igmp_and_mcast_tci.tci = 0;

    sprintf(ds_igmp_and_mcast_tci_hex_str, "0x%02x%04x", ds_igmp_and_mcast_tci.control_type, ds_igmp_and_mcast_tci.tci);
    omci_svc_omci_mcast_operations_profile_me_set(olt_id, onu_key->pon_ni, onu_key->onu_id, uni->uni.entity_id, 3,
        OMCI_SVC_OMCI_ATTR_ID_DS_IGMP_AND_MCAST_TCI, ds_igmp_and_mcast_tci_hex_str,
        OMCI_SVC_OMCI_ATTR_ID_US_IGMP_TAG_CONTROL, BCM_OMCI_MCAST_OPERATIONS_PROFILE_UPSTREAM_IGMP_TAG_CONTROL_PASS_IGMP_MLD_TRANSPARENT,
        OMCI_SVC_OMCI_ATTR_ID_US_IGMP_TCI, 0);
}

static void omci_svc_state_unset_multicast_operations_profile_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context,
    omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_ext_vlan_tag_oper_cfg_data_remove_entry(bcmolt_oltid olt_id, bcmonu_mgmt_onu_key *onu_key, bcmonu_mgmt_flow_cfg *flow, unsigned long filter_mask)
{
    bcmos_errno rc = BCM_ERR_OK;
    omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, onu_key->pon_ni, onu_key->onu_id);
    omci_svc_uni *uni = omci_svc_uni_get(onu_context, flow);

    rc = omci_svc_omci_ext_vlan_tag_oper_config_data_me_remove_entry(onu_key, onu_context, flow, filter_mask);
    if (rc != BCM_ERR_OK)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, NULL, "Ext Vlan Tag Remove Entry Req() request failed, entity_id=%u, result=%s\n",
            uni->uni.entity_id, bcmos_strerror(rc));
        /* Ignore the error and continue deleting MEs, otherwise we will end up with an undefined state. */
    }
}

static void omci_svc_state_delete_entry_ext_vlan_tag_oper_cfg_data_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow_op->flow.data;

    if (ONU_MGMT_FLOW_IS_UNICAST(flow) &&
        ONU_MGMT_FLOW_IS_UNTAGGED_END_TO_END(flow_data))
    {
        *(bcmos_bool *)context = BCMOS_FALSE;
    }
    else
    {
#ifdef OMCI_SVC_NO_WORKAROUNDS_FOR_BRCM_ONU 
        *(bcmos_bool *)context = ONU_MGMT_FLOW_IS_UNICAST(flow);
#else
        *(bcmos_bool *)context = ONU_MGMT_FLOW_IS_UNICAST(flow) || ONU_MGMT_FLOW_IS_MULTICAST(flow);
#endif
    }
}

static void omci_svc_state_delete_entry_ext_vlan_tag_oper_cfg_data_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    unsigned long filter_mask;
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    if (ONU_MGMT_FLOW_IS_MULTICAST(flow))
        flow = &flow_op->flow_reversed;

    filter_mask = omci_svc_filter_mask_get(flow);
    onu_context->iter = (void *)filter_mask;
    omci_svc_ext_vlan_tag_oper_cfg_data_remove_entry(olt_id, onu_key, flow, filter_mask);
}

static void omci_svc_state_delete_entry_ext_vlan_tag_oper_cfg_data_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    unsigned long filter_mask = (unsigned long)onu_context->iter;
    int pos = ffs(filter_mask);
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    if (ONU_MGMT_FLOW_IS_MULTICAST(flow) || ONU_MGMT_FLOW_IS_BROADCAST(flow))
        flow = &flow_op->flow_reversed;

    filter_mask &= ~(1 << (pos - 1));
    onu_context->iter = (void *)filter_mask;
    if (filter_mask)
        omci_svc_ext_vlan_tag_oper_cfg_data_remove_entry(olt_id, onu_key, flow, filter_mask);
    else
    {
        onu_context->iter = (void *)filter_mask;
        omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
    }
}

static void omci_svc_state_delete_vlan_tagging_filter_data_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow_op->flow.data;

    if (ONU_MGMT_FLOW_IS_UNICAST(flow) &&
        ONU_MGMT_FLOW_IS_UNTAGGED_END_TO_END(flow_data))
    {
        *(bcmos_bool *)context = BCMOS_FALSE;
    }
    else
    {
        omci_svc_o_vid *o_vid_entry = omci_svc_o_vid_get(onu_context, flow);

#ifdef OMCI_SVC_NO_WORKAROUNDS_FOR_BRCM_ONU 
        *(bcmos_bool *)context = o_vid_entry->ref_count == 1 && (ONU_MGMT_FLOW_IS_UNICAST(flow) || ONU_MGMT_FLOW_IS_BROADCAST(flow));
#else
        *(bcmos_bool *)context = o_vid_entry->ref_count == 1;
#endif
    }
}

static void omci_svc_state_delete_vlan_tagging_filter_data_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    uint16_t mac_bridge_port_cfg_data_entity_id = omci_svc_o_vid_get(onu_context, flow)->entity_id;
    omci_svc_omci_vlan_tag_filter_data_me_delete(olt_id, onu_key->pon_ni, onu_key->onu_id, mac_bridge_port_cfg_data_entity_id);
}

static void omci_svc_state_delete_vlan_tagging_filter_data_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_delete_mac_bridge_port_cfg_data_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow_op->flow.data;

    if (ONU_MGMT_FLOW_IS_UNICAST(flow) &&
        ONU_MGMT_FLOW_IS_UNTAGGED_END_TO_END(flow_data))
    {
        *(bcmos_bool *)context = BCMOS_TRUE;
    }
    else
    {
        omci_svc_o_vid *o_vid_entry = omci_svc_o_vid_get(onu_context, flow);

        *(bcmos_bool *)context = o_vid_entry->ref_count == 1;
    }
}

static void omci_svc_state_delete_mac_bridge_port_cfg_data_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    uint16_t mac_bridge_port_cfg_data_entity_id = omci_svc_o_vid_get(onu_context, flow)->entity_id;

    omci_svc_omci_mac_bridge_port_config_data_me_delete(olt_id, onu_key->pon_ni, onu_key->onu_id, mac_bridge_port_cfg_data_entity_id);
}

static void omci_svc_state_delete_mac_bridge_port_cfg_data_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    omci_svc_mac_bridge_port *mac_bridge_port_entry = omci_svc_mac_bridge_port_get(onu_context, flow);

    TAILQ_REMOVE(&onu_context->mib.used_mac_bridge_ports, mac_bridge_port_entry, next);
    TAILQ_INSERT_TAIL(&onu_context->mib.free_mac_bridge_ports, mac_bridge_port_entry, next);
    mac_bridge_port_entry->entity_id = 0;
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_unset_8021p_mapper_service_profile_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow_op->flow.data;

    *(bcmos_bool *)context = ONU_MGMT_FLOW_IS_UNICAST(flow) &&
                                !ONU_MGMT_FLOW_IS_UNTAGGED_END_TO_END(flow_data);
}

static void omci_svc_state_unset_8021p_mapper_service_profile_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;
    uint16_t o_pcp_for_mapper = UINT16_MAX;
    omci_svc_o_vid *o_vid_entry = omci_svc_o_vid_get(onu_context, flow);
    omci_svc_ieee_8021_p_mapper_svc_prof *me = &o_vid_entry->ieee_8021p_mapper_service_profile_me;
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, o_pcp))
    {
        /* Unmap only the specified priority to the GEM port. */
        o_pcp_for_mapper = flow_data->action.o_pcp;
    }
    else if (!BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, action, type))
    {
        if (BCMONU_MGMT_FLOW_PROP_IS_SET(flow_data, match, o_pcp))
            o_pcp_for_mapper = flow_data->match.o_pcp;
    }

    if (o_pcp_for_mapper != UINT16_MAX)
    {
        switch (o_pcp_for_mapper)
        {
        case 0:
            me->interwork_tp_ptr_pri_0 = OMCI_SVC_NULL_PTR;
            break;
        case 1:
            me->interwork_tp_ptr_pri_1 = OMCI_SVC_NULL_PTR;
            break;
        case 2:
            me->interwork_tp_ptr_pri_2 = OMCI_SVC_NULL_PTR;
            break;
        case 3:
            me->interwork_tp_ptr_pri_3 = OMCI_SVC_NULL_PTR;
            break;
        case 4:
            me->interwork_tp_ptr_pri_4 = OMCI_SVC_NULL_PTR;
            break;
        case 5:
            me->interwork_tp_ptr_pri_5 = OMCI_SVC_NULL_PTR;
            break;
        case 6:
            me->interwork_tp_ptr_pri_6 = OMCI_SVC_NULL_PTR;
            break;
        case 7:
            me->interwork_tp_ptr_pri_7 = OMCI_SVC_NULL_PTR;
            break;
        default:
            break;
        }
    }
    else
    {
        /* Unmap all priorities to the GEM port. */
        me->interwork_tp_ptr_pri_0 = OMCI_SVC_NULL_PTR;
        me->interwork_tp_ptr_pri_1 = OMCI_SVC_NULL_PTR;
        me->interwork_tp_ptr_pri_2 = OMCI_SVC_NULL_PTR;
        me->interwork_tp_ptr_pri_3 = OMCI_SVC_NULL_PTR;
        me->interwork_tp_ptr_pri_4 = OMCI_SVC_NULL_PTR;
        me->interwork_tp_ptr_pri_5 = OMCI_SVC_NULL_PTR;
        me->interwork_tp_ptr_pri_6 = OMCI_SVC_NULL_PTR;
        me->interwork_tp_ptr_pri_7 = OMCI_SVC_NULL_PTR;
    }

    omci_svc_omci_ieee_8021_p_mapper_svc_prof_me_set(olt_id, onu_key->pon_ni, onu_key->onu_id, o_vid_entry->entity_id, 8,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI0, me->interwork_tp_ptr_pri_0,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI1, me->interwork_tp_ptr_pri_1,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI2, me->interwork_tp_ptr_pri_2,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI3, me->interwork_tp_ptr_pri_3,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI4, me->interwork_tp_ptr_pri_4,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI5, me->interwork_tp_ptr_pri_5,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI6, me->interwork_tp_ptr_pri_6,
        OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI7, me->interwork_tp_ptr_pri_7);
}

static void omci_svc_state_unset_8021p_mapper_service_profile_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_delete_entry_multicast_gem_interworking_tp_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    *(bcmos_bool *)context = ONU_MGMT_FLOW_IS_MULTICAST(flow);
}

static void omci_svc_state_delete_entry_multicast_gem_interworking_tp_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow->data;
    bcmonu_mgmt_svc_port_id gem_port_id = flow_data->svc_port_id;
    bcmos_errno rc = BCM_ERR_OK;
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    omci_svc_omci_mcast_gem_iw_tp_me_remove_entry_ipv4_addr_table(olt_id, onu_key, flow, gem_port_id);
    if (rc != BCM_ERR_OK)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, NULL, "Add Entry Req() request failed, entity_id=%u, result=%s\n",
            gem_port_id, bcmos_strerror(rc));
        /* Ignore the error and continue deleting MEs, otherwise we will end up with an undefined state. */
    }
}

static void omci_svc_state_delete_entry_multicast_gem_interworking_tp_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_delete_gem_interworking_tp_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    omci_svc_gem_port *gem_port_entry = omci_svc_gem_port_get(onu_context, flow);

    *(bcmos_bool *)context = gem_port_entry->ref_count == 1;
}

static void omci_svc_state_delete_gem_interworking_tp_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow,
    void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    if (ONU_MGMT_FLOW_IS_MULTICAST(flow))
        omci_svc_omci_mcast_gem_iw_tp_me_delete(olt_id, onu_key->pon_ni, onu_key->onu_id, flow->data.svc_port_id);
    else if (ONU_MGMT_FLOW_IS_UNICAST(flow))
        omci_svc_omci_gem_iw_tp_me_delete(olt_id, onu_key->pon_ni, onu_key->onu_id, flow->data.svc_port_id);
    else if (ONU_MGMT_FLOW_IS_BROADCAST(flow))
        omci_svc_omci_gem_iw_tp_me_delete(olt_id, onu_key->pon_ni, onu_key->onu_id, flow->data.svc_port_id);
    else
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, NULL, "Invalid flow type\n");
    }
}

static void omci_svc_state_delete_gem_interworking_tp_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_delete_8021p_mapper_service_profile_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmonu_mgmt_flow_cfg_data *flow_data = &flow_op->flow.data;

    /** no mapper svc profile should be created for end-to-end untagged packet 
      (i.e. untagged from UNI through to ANI) */
    if (ONU_MGMT_FLOW_IS_UNICAST(flow) && 
        ONU_MGMT_FLOW_IS_UNTAGGED_END_TO_END(flow_data))
    {
        *(bcmos_bool *)context = BCMOS_FALSE;
    }
    else
    {
        omci_svc_o_vid *o_vid_entry = omci_svc_o_vid_get(onu_context, flow);
        *(bcmos_bool *)context = (ONU_MGMT_FLOW_IS_UNICAST(flow) && o_vid_entry->ref_count == 1);
    }
}

static void omci_svc_state_delete_8021p_mapper_service_profile_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    omci_svc_omci_ieee_8021_p_mapper_svc_prof_me_delete(olt_id, onu_key->pon_ni, onu_key->onu_id, omci_svc_o_vid_get(onu_context, flow)->entity_id);
}

static void omci_svc_state_delete_8021p_mapper_service_profile_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    omci_svc_o_vid *o_vid_entry = omci_svc_o_vid_get(onu_context, flow);
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    if (o_vid_entry->ref_count == 1)
    {
        DLIST_REMOVE(o_vid_entry, next);
        bcmos_free(o_vid_entry);
    }

    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_delete_gem_port_network_ctp_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    omci_svc_gem_port *gem_port_entry = omci_svc_gem_port_get(onu_context, flow);

    *(bcmos_bool *)context = gem_port_entry->ref_count == 1;
}

static void omci_svc_state_delete_gem_port_network_ctp_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow,
    void *context)
{
    omci_svc_gem_port *gem_port_entry = omci_svc_gem_port_get(onu_context, flow);
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    DLIST_REMOVE(gem_port_entry, next);
    bcmos_free(gem_port_entry);

    omci_svc_omci_gem_port_net_ctp_me_delete(olt_id, onu_key->pon_ni, onu_key->onu_id, flow->data.svc_port_id);
}

static void omci_svc_state_delete_gem_port_network_ctp_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op,
    bcmonu_mgmt_flow_cfg *flow, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_unset_tcont_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow,
    void *context)
{
    omci_svc_tcont *tcont_entry = omci_svc_tcont_get(onu_context, flow);

    *(bcmos_bool *)context = (ONU_MGMT_FLOW_IS_UNICAST(flow) && tcont_entry->ref_count == 1);
}

static void omci_svc_state_unset_tcont_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow, void *context)
{
    omci_svc_tcont *tcont_entry = omci_svc_tcont_get(onu_context, flow);
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    omci_svc_omci_tcont_me_set(olt_id, onu_key->pon_ni, onu_key->onu_id, tcont_entry->tcont.entity_id, 1,
        OMCI_SVC_OMCI_ATTR_ID_ALLOC_ID, OMCI_SVC_TCONT_ALLOC_ID_UNASSIGNED);
}

static void omci_svc_state_unset_tcont_event_success(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow,
    void *context)
{
    omci_svc_tcont *tcont_entry = omci_svc_tcont_get(onu_context, flow);
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    TAILQ_REMOVE(&onu_context->mib.used_tconts, tcont_entry, next);
    TAILQ_INSERT_TAIL(&onu_context->mib.free_tconts, tcont_entry, next);
    tcont_entry->tcont.agg_port_id = 0;

    omci_svc_flow_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, onu_key, NULL);
}

static void omci_svc_state_down_sequence_end_event_is_entered(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow,
    void *context)
{
    *(bcmos_bool *)context = BCMOS_TRUE;
}

static void omci_svc_state_down_sequence_end_event_start(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, omci_svc_flow_op *flow_op, bcmonu_mgmt_flow_cfg *flow,
    void *context)
{
    bcmos_errno rc;
    omci_svc_tcont *tcont_entry = omci_svc_tcont_get(onu_context, flow);
    omci_svc_o_vid *o_vid_entry = omci_svc_o_vid_get(onu_context, flow);
    omci_svc_gem_port *gem_port_entry = omci_svc_gem_port_get(onu_context, flow);
    bcmolt_oltid olt_id = flow->hdr.hdr.olt_id;

    /* Check that the linked list items for outer VID and GEM port haven't been already freed. */
    if (tcont_entry)
    {
        tcont_entry->ref_count--;
        /** @todo tmp for debugging only */
        BCM_LOG(INFO, omci_svc_log_id, "T-CONT=%u reference count decremented to %u\n", tcont_entry->tcont.entity_id, tcont_entry->ref_count);
    }
    if (o_vid_entry)
        o_vid_entry->ref_count--;
    if (gem_port_entry)
        gem_port_entry->ref_count--;

    /* Down sequence end (no need to update flow_op->state as it is going to be destructed anyway). */
    OMCI_SVC_LOG(INFO, olt_id, onu_key, NULL, "%s Flow  deleted successfully {flow id: %d, flow dir: %s, gem port: %d, alloc id: %d}\n",
            OMCI_SVC_FLOW_TYPE_STR(flow->data.flow_type),
            flow->key.id,
            flow->key.dir == BCMONU_MGMT_FLOW_DIR_ID_UPSTREAM ? "upstream" : "downstream",
            flow->data.svc_port_id, BCMONU_MGMT_FIELD_IS_SET(&flow->data, flow_cfg_data, agg_port_id) ? flow->data.agg_port_id : BCMONU_MGMT_AGG_PORT_ID_UNASSIGNED);

    /* update Cfg DB first before notifying to app or calling callbacks */
    if (BCM_ERR_OK == onu_context->last_err)
    {
        if (flow_op->is_clear)
        {
            /* clear entry from sm cfg DB */
            rc = omci_svc_flow_cfg_db_clear_entry(flow);
            if (BCM_ERR_OK != rc)
                OMCI_SVC_LOG(ERROR, olt_id, onu_key, NULL, "Flow cfg DB clear Failed\n");
            flow_op->is_clear = BCMOS_FALSE;
        }
        else
        {
            /* flow admined-down successfully; update flow cfg db */
            rc = omci_svc_flow_cfg_db_update_entry(flow);
            if (BCM_ERR_OK != rc)
                OMCI_SVC_LOG(ERROR, olt_id, onu_key, NULL, "Flow cfg DB update Failed\n");
        }
    }

    if (flow_op->cb)
        flow_op->cb(flow_op->context, onu_context->last_err);

    omci_svc_flow_op_queue_dequeue(onu_context);
}

static omci_svc_flow_sm_cb omci_svc_flow_state_machine[OMCI_SVC_FLOW_STATE_ID__NUM_OF][OMCI_SVC_EVENT_ID__NUM_OF] =
{
    /* Up direction */
    [OMCI_SVC_FLOW_STATE_ID_INACTIVE] =
    {
        [OMCI_SVC_EVENT_ID_ACTIVATE] = omci_svc_state_inactive_event_activate,
    },
    [OMCI_SVC_FLOW_STATE_ID_SET_TCONT] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_set_tcont_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_set_tcont_event_start,
        [OMCI_SVC_EVENT_ID_SET_SUCCESS] = omci_svc_state_set_tcont_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_CREATE_GEM_PORT_NETWORK_CTP] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_create_gem_port_network_ctp_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_create_gem_port_network_ctp_event_start,
        [OMCI_SVC_EVENT_ID_CREATE_SUCCESS] = omci_svc_state_create_gem_port_network_ctp_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_CREATE_8021P_MAPPER_SERVICE_PROFILE] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_create_8021p_mapper_service_profile_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_create_8021p_mapper_service_profile_event_start,
        [OMCI_SVC_EVENT_ID_CREATE_SUCCESS] = omci_svc_state_create_8021p_mapper_service_profile_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_CREATE_GEM_INTERWORKING_TP] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_create_gem_interworking_tp_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_create_gem_interworking_tp_event_start,
        [OMCI_SVC_EVENT_ID_CREATE_SUCCESS] = omci_svc_state_create_gem_interworking_tp_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_ADD_ENTRY_MULTICAST_GEM_INTERWORKING_TP] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_add_entry_multicast_gem_interworking_tp_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_add_entry_multicast_gem_interworking_tp_event_start,
        [OMCI_SVC_EVENT_ID_ADD_ENTRY_SUCCESS] = omci_svc_state_add_entry_multicast_gem_interworking_tp_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_SET_8021P_MAPPER_SERVICE_PROFILE] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_set_8021p_mapper_service_profile_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_set_8021p_mapper_service_profile_event_start,
        [OMCI_SVC_EVENT_ID_SET_SUCCESS] = omci_svc_state_set_8021p_mapper_service_profile_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_CREATE_MAC_BRIDGE_PORT_CFG_DATA] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_create_mac_bridge_port_cfg_data_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_create_mac_bridge_port_cfg_data_event_start,
        [OMCI_SVC_EVENT_ID_CREATE_SUCCESS] = omci_svc_state_create_mac_bridge_port_cfg_data_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_CREATE_VLAN_TAGGING_FILTER_DATA] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_create_vlan_tagging_filter_data_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_create_vlan_tagging_filter_data_event_start,
        [OMCI_SVC_EVENT_ID_CREATE_SUCCESS] = omci_svc_state_create_vlan_tagging_filter_data_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_ADD_ENTRY_EXT_VLAN_TAG_OPER_CFG_DATA] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_add_entry_ext_vlan_tag_oper_cfg_data_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_add_entry_ext_vlan_tag_oper_cfg_data_event_start,
        [OMCI_SVC_EVENT_ID_ADD_ENTRY_SUCCESS] = omci_svc_state_add_entry_ext_vlan_tag_oper_cfg_data_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_SET_MULTICAST_OPERATIONS_PROFILE] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_set_multicast_operations_profile_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_set_multicast_operations_profile_event_start,
        [OMCI_SVC_EVENT_ID_SET_SUCCESS] = omci_svc_state_set_multicast_operations_profile_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_ADD_ENTRY_MULTICAST_OPERATIONS_PROFILE_DYNAMIC_ACL] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_add_entry_multicast_operations_profile_dynamic_acl_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_add_entry_multicast_operations_profile_dynamic_acl_event_start,
        [OMCI_SVC_EVENT_ID_ADD_ENTRY_SUCCESS] = omci_svc_state_add_entry_multicast_operations_profile_dynamic_acl_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_UP_SEQUENCE_END] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_up_sequence_end_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_up_sequence_end_event_start,
    },
    /* Down direction */
    [OMCI_SVC_FLOW_STATE_ID_ACTIVE] =
    {
        [OMCI_SVC_EVENT_ID_DEACTIVATE] = omci_svc_state_active_event_deactivate,
    },
    [OMCI_SVC_FLOW_STATE_ID_DELETE_ENTRY_MULTICAST_OPERATIONS_PROFILE_DYNAMIC_ACL] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_delete_entry_multicast_operations_profile_dynamic_acl_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_delete_entry_multicast_operations_profile_dynamic_acl_event_start,
        [OMCI_SVC_EVENT_ID_REMOVE_ENTRY_SUCCESS] = omci_svc_state_delete_entry_multicast_operations_profile_dynamic_acl_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_UNSET_MULTICAST_OPERATIONS_PROFILE] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_unset_multicast_operations_profile_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_unset_multicast_operations_profile_event_start,
        [OMCI_SVC_EVENT_ID_SET_SUCCESS] = omci_svc_state_unset_multicast_operations_profile_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_DELETE_ENTRY_EXT_VLAN_TAG_OPER_CFG_DATA] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_delete_entry_ext_vlan_tag_oper_cfg_data_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_delete_entry_ext_vlan_tag_oper_cfg_data_event_start,
        [OMCI_SVC_EVENT_ID_REMOVE_ENTRY_SUCCESS] = omci_svc_state_delete_entry_ext_vlan_tag_oper_cfg_data_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_DELETE_VLAN_TAGGING_FILTER_DATA] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_delete_vlan_tagging_filter_data_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_delete_vlan_tagging_filter_data_event_start,
        [OMCI_SVC_EVENT_ID_DELETE_SUCCESS] = omci_svc_state_delete_vlan_tagging_filter_data_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_DELETE_MAC_BRIDGE_PORT_CFG_DATA] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_delete_mac_bridge_port_cfg_data_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_delete_mac_bridge_port_cfg_data_event_start,
        [OMCI_SVC_EVENT_ID_DELETE_SUCCESS] = omci_svc_state_delete_mac_bridge_port_cfg_data_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_UNSET_8021P_MAPPER_SERVICE_PROFILE] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_unset_8021p_mapper_service_profile_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_unset_8021p_mapper_service_profile_event_start,
        [OMCI_SVC_EVENT_ID_SET_SUCCESS] = omci_svc_state_unset_8021p_mapper_service_profile_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_DELETE_ENTRY_MULTICAST_GEM_INTERWORKING_TP] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_delete_entry_multicast_gem_interworking_tp_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_delete_entry_multicast_gem_interworking_tp_event_start,
        [OMCI_SVC_EVENT_ID_REMOVE_ENTRY_SUCCESS] = omci_svc_state_delete_entry_multicast_gem_interworking_tp_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_DELETE_GEM_INTERWORKING_TP] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_delete_gem_interworking_tp_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_delete_gem_interworking_tp_event_start,
        [OMCI_SVC_EVENT_ID_DELETE_SUCCESS] = omci_svc_state_delete_gem_interworking_tp_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_DELETE_8021P_MAPPER_SERVICE_PROFILE] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_delete_8021p_mapper_service_profile_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_delete_8021p_mapper_service_profile_event_start,
        [OMCI_SVC_EVENT_ID_DELETE_SUCCESS] = omci_svc_state_delete_8021p_mapper_service_profile_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_DELETE_GEM_PORT_NETWORK_CTP] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_delete_gem_port_network_ctp_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_delete_gem_port_network_ctp_event_start,
        [OMCI_SVC_EVENT_ID_DELETE_SUCCESS] = omci_svc_state_delete_gem_port_network_ctp_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_UNSET_TCONT] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_unset_tcont_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_unset_tcont_event_start,
        [OMCI_SVC_EVENT_ID_SET_SUCCESS] = omci_svc_state_unset_tcont_event_success,
    },
    [OMCI_SVC_FLOW_STATE_ID_DOWN_SEQUENCE_END] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_down_sequence_end_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_down_sequence_end_event_start,
    }
};

static void omci_svc_flow_sm_run_cb(bcmolt_oltid olt_id, omci_svc_event_id event, bcmonu_mgmt_onu_key *onu_key, void *context)
{
    omci_svc_flow_sm_cb cb;
    omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, onu_key->pon_ni, onu_key->onu_id);
    omci_svc_flow_op *flow_op = onu_context->flow_op_queue.head;
    bcmonu_mgmt_flow_cfg *flow = &flow_op->flow;

    OMCI_SVC_LOG(DEBUG, olt_id, onu_key, NULL, "Flow SM state='%s', event='%s'\n", omci_svc_flow_state_id2str_conv(flow_op->state), omci_svc_event_id2str_conv(event));
    if (event == OMCI_SVC_EVENT_ID_START)
    {
        bcmos_bool is_entered;

        /* Skip states which should not be entered. */
        do
        {
            flow_op->state++;
            cb = omci_svc_flow_state_machine[flow_op->state][OMCI_SVC_EVENT_ID_IS_ENTERED];
            cb(onu_key, onu_context, flow_op, flow, &is_entered);
        } while (!is_entered);
    }
    cb = omci_svc_flow_state_machine[flow_op->state][event];
    if (cb)
        cb(onu_key, onu_context, flow_op, flow, context);
    else
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, NULL, "Unexpected event='%s' in state='%s'\n", omci_svc_event_id2str_conv(event), omci_svc_flow_state_id2str_conv(flow_op->state));
}

/* Return the first callback of the given state. If there are multiple events handled in the given state, it is assumed that the first event is the "success" event. */
static omci_svc_flow_sm_cb omci_svc_flow_get_first_sm_cb(omci_svc_flow_state_id state)
{
    omci_svc_event_id event;

    for (event = OMCI_SVC_EVENT_ID__BEGIN; event < OMCI_SVC_EVENT_ID__NUM_OF; event++)
    {
        omci_svc_flow_sm_cb cb;

        cb = omci_svc_flow_state_machine[state][event];
        if (cb)
            return cb;
    }
    return NULL;
}

static void omci_svc_flow_sm_rollback_cb(bcmolt_oltid olt_id, bcmonu_mgmt_onu_key *onu_key, bcmos_errno last_err, void *context)
{
    omci_svc_flow_sm_cb cb;
    omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, onu_key->pon_ni, onu_key->onu_id);
    omci_svc_flow_op *flow_op = onu_context->flow_op_queue.head;
    bcmonu_mgmt_flow_cfg *flow = &flow_op->flow;
    static omci_svc_flow_state_id flow_state_inverse[OMCI_SVC_FLOW_STATE_ID__NUM_OF] =
    {
        [OMCI_SVC_FLOW_STATE_ID_INACTIVE] = OMCI_SVC_FLOW_STATE_ID__NUM_OF, /* No rollback */
        [OMCI_SVC_FLOW_STATE_ID_SET_TCONT] = OMCI_SVC_FLOW_STATE_ID_UNSET_TCONT,
        [OMCI_SVC_FLOW_STATE_ID_CREATE_GEM_PORT_NETWORK_CTP] = OMCI_SVC_FLOW_STATE_ID_DELETE_GEM_PORT_NETWORK_CTP,
        [OMCI_SVC_FLOW_STATE_ID_CREATE_8021P_MAPPER_SERVICE_PROFILE] = OMCI_SVC_FLOW_STATE_ID_DELETE_8021P_MAPPER_SERVICE_PROFILE,
        [OMCI_SVC_FLOW_STATE_ID_CREATE_GEM_INTERWORKING_TP] = OMCI_SVC_FLOW_STATE_ID_DELETE_GEM_INTERWORKING_TP,
        [OMCI_SVC_FLOW_STATE_ID_ADD_ENTRY_MULTICAST_GEM_INTERWORKING_TP] = OMCI_SVC_FLOW_STATE_ID_DELETE_ENTRY_MULTICAST_GEM_INTERWORKING_TP,
        [OMCI_SVC_FLOW_STATE_ID_SET_8021P_MAPPER_SERVICE_PROFILE] = OMCI_SVC_FLOW_STATE_ID_UNSET_8021P_MAPPER_SERVICE_PROFILE,
        [OMCI_SVC_FLOW_STATE_ID_CREATE_MAC_BRIDGE_PORT_CFG_DATA] = OMCI_SVC_FLOW_STATE_ID_DELETE_MAC_BRIDGE_PORT_CFG_DATA,
        [OMCI_SVC_FLOW_STATE_ID_CREATE_VLAN_TAGGING_FILTER_DATA] = OMCI_SVC_FLOW_STATE_ID_DELETE_VLAN_TAGGING_FILTER_DATA,
        [OMCI_SVC_FLOW_STATE_ID_ADD_ENTRY_EXT_VLAN_TAG_OPER_CFG_DATA] = OMCI_SVC_FLOW_STATE_ID_DELETE_ENTRY_EXT_VLAN_TAG_OPER_CFG_DATA,
        [OMCI_SVC_FLOW_STATE_ID_SET_MULTICAST_OPERATIONS_PROFILE] = OMCI_SVC_FLOW_STATE_ID_SET_MULTICAST_OPERATIONS_PROFILE,
        [OMCI_SVC_FLOW_STATE_ID_ADD_ENTRY_MULTICAST_OPERATIONS_PROFILE_DYNAMIC_ACL] = OMCI_SVC_FLOW_STATE_ID_DELETE_ENTRY_MULTICAST_OPERATIONS_PROFILE_DYNAMIC_ACL,
    };

    onu_context->last_err = last_err;

    /* If the error occurred during down sequence of during rollback, we ignore the error and continue with the state machine. */
    if (flow_op->state >= OMCI_SVC_FLOW_STATE_ID_ACTIVE)
    {
        flow_op->state++;
        cb = omci_svc_flow_get_first_sm_cb(flow_op->state);
        if (cb)
            cb(onu_key, onu_context, flow_op, flow, context);
        return;
    }

    /* If the state is marked to have no rollback, immediately end the transaction and return to the caller. */
    if (flow_state_inverse[flow_op->state] == OMCI_SVC_FLOW_STATE_ID__NUM_OF)
    {
        /* Down sequence end (no need to update flow_op->state as it is going to be destructed anyway). */
        if (flow_op->cb)
            flow_op->cb(flow_op->context, last_err);
        omci_svc_flow_op_queue_dequeue(onu_context);
        return;
    }

    flow_op->state = flow_state_inverse[flow_op->state];

    OMCI_SVC_LOG(DEBUG, olt_id, onu_key, NULL, "Starting transaction rollback from SM state='%s'\n", omci_svc_flow_state_id2str_conv(flow_op->state));
    cb = omci_svc_flow_get_first_sm_cb(flow_op->state);
    if (cb)
        cb(onu_key, onu_context, flow_op, flow, context);
}

