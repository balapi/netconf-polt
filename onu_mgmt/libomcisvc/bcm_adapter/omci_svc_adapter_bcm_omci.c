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
 * @file omci_svc_adapter_bcm_omci.c
 * @brief This is an interface to the broadcom omci stack
 * @details In general define functions in these files as a stack (ocs or broadcom) agnostic name.
 * The same set of functions will be defined in another file for the OCS stack, and the svc layer
 * will compile in one file or the other depending on a compile time switch.
 */

#include <bcmolt_api.h>
#include <bcm_dev_log.h>
#include "onu_mgmt_test.h"
#include "omci_svc_common.h"
#include "omci_svc_flow.h"
#include "omci_svc_onu.h"
#include "omci_svc.h"
#include "omci_stack_api.h"
#include "transport/omci_transport.h"
#include "omci_svc_adapter_common.h"

/*
 * Masks added to request cookie in order to distinguish SET request flavours
 */
#define OMCI_SVC_OPER_SET               0x00000000
#define OMCI_SVC_OPER_SET_ADD_ENTRY     0x00010000
#define OMCI_SVC_OPER_SET_REMOVE_ENTRY  0x00020000


/** prototype */
static bcmos_errno omci_svc_omci_ext_vlan_tag_oper_config_data_set_entry_in_table (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id,
        uint8_t num_attr, uint32_t attr_id, bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table *entry, bcmos_bool is_add_entry);
static bcmos_errno omci_svc_omci_mcast_operations_profile_set_entry_in_table (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id,
        uint8_t num_attr, uint32_t attr_id, void *entry, bcmos_bool is_add_entry);
static bcmos_errno omci_svc_omci_mcast_gem_iw_tp_set_entry_in_table (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id,
        uint8_t num_attr, uint32_t attr_id, void *entry, bcmos_bool is_add_entry);

static bcmos_errno omci_svc_transmit_cb(bcm_omci_me_key *key, void *msg_buf, uint16_t msg_len);
static void omci_svc_response_cb(bcm_omci_me_hdr *me);
static void omci_svc_mib_upload_response_cb(bcm_omci_me_hdr *me, bcm_omci_mib_upload_response *data);



/** maps omci msg result field into bcmos errno */
bcm_omci_result2bcmos_errno_t bcm_omci_result2bcmos_errno[] =
{
    /* "Good" return values */
    {BCM_OMCI_RESULT_CMD_PROC_SUCCESS, BCM_ERR_OK},
    {BCM_OMCI_RESULT_IND_MORE, BCM_ERR_OK},
    {BCM_OMCI_RESULT_IND_LAST, BCM_ERR_OK},

    /* "Bad" return values */
    {BCM_OMCI_RESULT_CMD_PROC_ERROR, BCM_ERR_INTERNAL},
    {BCM_OMCI_RESULT_CMD_NOT_SUPPORTED, BCM_ERR_NOT_SUPPORTED},
    {BCM_OMCI_RESULT_PARAM_ERROR, BCM_ERR_PARM},
    {BCM_OMCI_RESULT_UNKNOWN_ME, BCM_ERR_RANGE},
    {BCM_OMCI_RESULT_UNKNOWN_INSTANCE, BCM_ERR_RANGE},
    {BCM_OMCI_RESULT_DEVICE_BUSY, BCM_ERR_IN_PROGRESS},
    {BCM_OMCI_RESULT_INSTANCE_EXISTS, BCM_ERR_ALREADY},
    {BCM_OMCI_RESULT_RESERVED, BCM_ERR_INTERNAL},
    {BCM_OMCI_RESULT_ATTR_FAILED_OR_UNKNOWN, BCM_ERR_INTERNAL},
    {BCM_OMCI_RESULT_TL_LINK_ERROR, BCM_ERR_COMM_FAIL},
    {BCM_OMCI_RESULT_TL_ERROR, BCM_ERR_INTERNAL},
    {-1}
};


/**************************
 * Check Support for Stack
 **************************/

/**
 * @brief adapter layer routine to check if stack supports activate for ONU.
 */
bcmos_bool omci_svc_omci_if_support_activate (void)
{
    return BCMOS_FALSE;
}

/**
 * @brief adapter layer routine to check if stack supports deactivate for ONU.
 */
bcmos_bool omci_svc_omci_if_support_deactivate (void)
{
    return BCMOS_FALSE;
}

/**
 * @brief adapter layer routine to check if stack supports link up notification
 */
bcmos_bool omci_svc_omci_if_support_link_up (void)
{
    return BCMOS_FALSE;
}


/*******************
 * Requests to Stack
 ******************/

/**
 * @brief initialize bcm omci stack
 */
bcmos_errno omci_svc_omci_init(void)
{
    bcm_omci_stack_init_parms stack_init_parms = {
        .max_olts = BCM_MAX_OLTS,
        .transmit_cb = omci_svc_transmit_cb,
        .response_cb = omci_svc_response_cb,
        .mib_upload_response_cb = omci_svc_mib_upload_response_cb
    };
    bcmos_errno rc;

    /* initialize omci stack */
    rc = bcm_omci_stack_init(&stack_init_parms);
    if (rc != BCM_ERR_OK)
    {
        BCM_LOG(ERROR, omci_svc_log_id, "bcm_omci_stack_init() failed, error:%s\n",
               bcmos_strerror(rc));
        return rc;
    }

    return BCM_ERR_OK;
}

bcmos_errno omci_svc_omci_init_for_olt(bcmolt_oltid olt_id)
{
    bcm_omci_olt_init_parms olt_init_parms = {};
    bcmolt_topology_map topo_map[BCM_MAX_PONS_PER_OLT] = {};
    bcmolt_olt_cfg olt_cfg;
    bcmolt_olt_key key = {};
    bcmos_errno rc;

    /* Read OLT topology */
    BCMOLT_CFG_INIT(&olt_cfg, olt, key);
    BCMOLT_FIELD_SET_PRESENT(&olt_cfg.data, olt_cfg_data, topology);
    BCMOLT_CFG_LIST_BUF_SET(&olt_cfg, olt, &topo_map, sizeof(topo_map));

    /** test utility: for actual topo query use the onu mgmt/BAL default olt id (= 0) */
    bcmolt_oltid topo_olt_id = ONU_MGMT_TEST_SET_DEFAULT_OLT_ID(olt_id);

    rc = bcmolt_cfg_get(topo_olt_id, &olt_cfg.hdr);
    if (rc != BCM_ERR_OK)
    {
        BCM_LOG(ERROR, omci_svc_log_id, "topology query failed for OLT %u, error:%s\n",
               olt_id, bcmos_strerror(rc));
        return rc;
    }


    /* initialize OLT */
    olt_init_parms.max_pons = olt_cfg.data.topology.topology_maps.len;
    olt_init_parms.max_onus_per_pon = OMCI_SVC_PON_TOPO_MAX_ONUS_PER_PON;
    rc = bcm_omci_olt_init(olt_id, &olt_init_parms);
    if (rc != BCM_ERR_OK)
    {
        bcm_omci_stack_deinit();
        BCM_LOG(ERROR, omci_svc_log_id, "bcm_omci_olt_init() failed, error:%s\n",
               bcmos_strerror(rc));
        return rc;
    }

    return BCM_ERR_OK;
}

/**
 * @brief de-initialize bcm omci stack
 */
bcmos_errno omci_svc_omci_deinit(void)
{
    return bcm_omci_stack_deinit();
}

/**
 * @brief activate ONU context in Stack
 */
bcmos_errno omci_svc_omci_activate_req (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id)
{
    return bcm_omci_onu_init(olt_id, pon_ni, onu_id, NULL);
}

/**
 * @brief deactivate ONU context in Stack
 */
bcmos_errno omci_svc_omci_deactivate_req (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id)
{
    return bcm_omci_onu_deinit(olt_id, pon_ni, onu_id);
}

/**
 * @brief call transport layer  (through me layer), for omci mib reset
 */
bcmos_errno omci_svc_omci_mib_reset_req (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id)
{
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni,
        .onu_id = onu_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id)
    };
    return bcm_omci_mib_reset_req(&me_key);
}


/**
 * @brief call transport layer API for omci mib upload req
 */
bcmos_errno omci_svc_omci_mib_upload_req (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id)
{
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni,
        .onu_id = onu_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id)
    };
    return bcm_omci_mib_upload_req(&me_key);
}


/**
 * @note the context passed for OCS omci, is  the ME cfg structure for BCM OMCI.
 */
void omci_svc_omci_mib_upload_analyze (bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
    bcm_omci_me_hdr *me = context;

    OMCI_SVC_LOG(DEBUG, olt_id, key, NULL, "MIB upload next (class_id=%s(0x%X), entity_id=%u)\n",
            BCM_OMCI_ME_CLASS_VAL_STR(me->key.entity_class), me->key.entity_class, me->key.entity_instance);

    switch (me->key.entity_class)
    {
    case BCM_OMCI_ME_CLASS_VAL_PPTP_ETH_UNI:
        {
            omci_svc_mib_upload_add_uni(key, onu_context, me->key.entity_instance, BCMONU_MGMT_UNI_TYPE_PPTP);
        }
        break;
    case BCM_OMCI_ME_CLASS_VAL_VIRTUAL_ETH_INTF_POINT:
        {
            omci_svc_mib_upload_add_uni(key, onu_context, me->key.entity_instance, BCMONU_MGMT_UNI_TYPE_VEIP);
        }
        break;
    case BCM_OMCI_ME_CLASS_VAL_TCONT:
        {
            omci_svc_mib_upload_add_tcont(key, onu_context, me->key.entity_instance);
        }
        break;

    case BCM_OMCI_ME_CLASS_VAL_PRIORITY_QUEUE_G:
        {
            bcm_omci_priority_queue_g_cfg *bcm_omci_priority_queue = context;

            /** add port only if the attribute is present in the ME cfg */
            if (BCM_OMCI_RSP_PROP_IS_SET(bcm_omci_priority_queue, priority_queue_g, related_port))
            {
                uint16_t port = (bcm_omci_priority_queue->data.related_port[0] << 8) | bcm_omci_priority_queue->data.related_port[1]; /* [0] == Slot number, [1] == TCONT ID */

                OMCI_SVC_LOG(DEBUG, olt_id, key, NULL, "MIB upload next (class_id=%s, entity_id=%u), related_port[]: %02X, %02X, %02X, %02X, port: %d\n",
                        BCM_OMCI_ME_CLASS_VAL_STR(me->key.entity_class), me->key.entity_instance,
                        bcm_omci_priority_queue->data.related_port[0], bcm_omci_priority_queue->data.related_port[1],
                        bcm_omci_priority_queue->data.related_port[2], bcm_omci_priority_queue->data.related_port[3],
                        port);

                omci_svc_mib_upload_add_priority_queue(key, onu_context, me->key.entity_instance, port);
            }
        }

    default:
        break;
    }
}


/**
 * @brief adapter routine for gal eth profile
 */
bcmos_errno omci_svc_omci_gal_eth_prof_me_create (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... )
{
    bcmos_errno rc = BCM_ERR_OK;
    va_list arg_list;
    uint8_t attr_index;
    uint32_t attr_id = OMCI_SVC_OMCI_ATTR_ID_NONE;
    uint32_t attr_val = 0;

    /** init me cfg */
    bcm_omci_gal_eth_prof_cfg gal_eth_prof_cfg = {};
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id) };
    BCM_OMCI_HDR_INIT(&gal_eth_prof_cfg.hdr, gal_eth_prof, me_key);

    va_start(arg_list, num_attr);
    for (attr_index = 0; attr_index < num_attr; attr_index++)
    {
        attr_id = (uint32_t)va_arg(arg_list, uint32_t);
        switch (attr_id)
        {
            case OMCI_SVC_OMCI_ATTR_ID_MAX_GEM_PAYLOAD_SIZE:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&gal_eth_prof_cfg, gal_eth_prof, max_gem_payload_size, attr_val);
                break;

            default:
                BCM_LOG(ERROR, omci_svc_log_id, "%s: unhandled attr : %d\n", __FUNCTION__, attr_id);
                rc = BCM_ERR_PARM;
                break;
        }
    }
    va_end(arg_list);


    /* ME API Call: call ME layer api Create */
    if (BCM_ERR_OK == rc)
    {
        rc = bcm_omci_create_req(&gal_eth_prof_cfg.hdr);
    }

    return rc;
}

/**
 * @brief adapter routine for Extended Vlan Tagging Create or set
 */
static bcmos_errno omci_svc_omci_ext_vlan_tag_oper_config_data_me_create_or_set (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, bcmos_bool is_create, va_list arg_list)
{
    bcmos_errno rc = BCM_ERR_OK;
    uint8_t attr_index;
    uint32_t attr_id = OMCI_SVC_OMCI_ATTR_ID_NONE;
    uint32_t attr_val = 0;

    /** init me cfg */
    bcm_omci_ext_vlan_tag_oper_config_data_cfg ext_vlan_tag_oper_config_data_cfg = {};
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id) };
    BCM_OMCI_HDR_INIT(&ext_vlan_tag_oper_config_data_cfg.hdr, ext_vlan_tag_oper_config_data, me_key);

    for (attr_index = 0; attr_index < num_attr; attr_index++)
    {
        attr_id = (uint32_t)va_arg(arg_list, uint32_t);
        switch (attr_id)
        {
        case OMCI_SVC_OMCI_ATTR_ID_ASSOC_TYPE:
            attr_val = va_arg(arg_list, uint32_t);
            BCM_OMCI_REQ_PROP_SET(&ext_vlan_tag_oper_config_data_cfg, ext_vlan_tag_oper_config_data, assoc_type, attr_val);
            break;

        case OMCI_SVC_OMCI_ATTR_ID_ASSOC_ME_PTR:
            attr_val = va_arg(arg_list, uint32_t);
            BCM_OMCI_REQ_PROP_SET(&ext_vlan_tag_oper_config_data_cfg, ext_vlan_tag_oper_config_data, assoc_me_ptr, attr_val);
            break;

        case OMCI_SVC_OMCI_ATTR_ID_INPUT_TPID:
            attr_val = va_arg(arg_list, uint32_t);
            BCM_OMCI_REQ_PROP_SET(&ext_vlan_tag_oper_config_data_cfg, ext_vlan_tag_oper_config_data, input_tpid, attr_val);
            break;

        case OMCI_SVC_OMCI_ATTR_ID_OUTPUT_TPID:
            attr_val = va_arg(arg_list, uint32_t);
            BCM_OMCI_REQ_PROP_SET(&ext_vlan_tag_oper_config_data_cfg, ext_vlan_tag_oper_config_data, output_tpid, attr_val);
            break;

        case OMCI_SVC_OMCI_ATTR_ID_DS_MODE:
            attr_val = va_arg(arg_list, uint32_t);
            BCM_OMCI_REQ_PROP_SET(&ext_vlan_tag_oper_config_data_cfg, ext_vlan_tag_oper_config_data, ds_mode, attr_val);
            break;

        default:
            BCM_LOG(ERROR, omci_svc_log_id, "%s: unhandled attr : %d\n", __FUNCTION__, attr_id);
            rc = BCM_ERR_PARM;
            break;
        }
    }


    /* ME API Call: call ME layer api Create or Set */
    if (BCM_ERR_OK == rc)
    {
        if (is_create)
            rc = bcm_omci_create_req(&ext_vlan_tag_oper_config_data_cfg.hdr);
        else
            rc = bcm_omci_set_req(&ext_vlan_tag_oper_config_data_cfg.hdr);
    }

    return rc;
}

/**
 * @brief adapter routine for Extended Vlan Tagging Set
 */
bcmos_errno omci_svc_omci_ext_vlan_tag_oper_config_data_me_create (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... )
{
    va_list ap;
    bcmos_errno ret;

    va_start(ap, num_attr);
    ret = omci_svc_omci_ext_vlan_tag_oper_config_data_me_create_or_set (olt_id, pon_ni, onu_id, entity_id, num_attr, BCMOS_TRUE, ap);
    va_end(ap);

    return ret;
}

/**
 * @brief adapter routine for Extended Vlan Tagging Set
 */
bcmos_errno omci_svc_omci_ext_vlan_tag_oper_config_data_me_set (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... )
{
    va_list ap;
    bcmos_errno ret;

    va_start(ap, num_attr);
    ret = omci_svc_omci_ext_vlan_tag_oper_config_data_me_create_or_set (olt_id, pon_ni, onu_id, entity_id, num_attr, BCMOS_FALSE, ap);
    va_end(ap);

    return ret;
}



/**
 * @brief sub-adapter routine for Extended Vlan Tagging Add entry into the Table to take in as variable number of args
 * @note is_add_entry is used to indicate whether it is ADD (TRUE) or REMOVE (FALSE).
 */
static bcmos_errno omci_svc_omci_ext_vlan_tag_oper_config_data_set_entry_in_table (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id,
        uint8_t num_attr, uint32_t attr_id, bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table *entry, bcmos_bool is_add_entry)
{
    bcmos_errno rc = BCM_ERR_OK;

    /** init me cfg */
    long cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id) |
        (is_add_entry ? OMCI_SVC_OPER_SET_ADD_ENTRY : OMCI_SVC_OPER_SET_REMOVE_ENTRY);
    bcm_omci_ext_vlan_tag_oper_config_data_cfg ext_vlan_tag_oper_config_data_cfg = {};
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = cookie };
    BCM_OMCI_HDR_INIT(&ext_vlan_tag_oper_config_data_cfg.hdr, ext_vlan_tag_oper_config_data, me_key);

    switch (attr_id)
    {
        case OMCI_SVC_OMCI_ATTR_ID_RX_FRAME_VLAN_TAG_OPER_TABLE:
                BCM_OMCI_REQ_PROP_SET(&ext_vlan_tag_oper_config_data_cfg, ext_vlan_tag_oper_config_data, rx_frame_vlan_tag_oper_table, *entry);
            break;

        default:
                BCM_LOG(ERROR, omci_svc_log_id, "%s: unhandled attr : %d\n", __FUNCTION__, attr_id);
            return BCM_ERR_PARM;
            break;
    }

    rc = bcm_omci_set_req(&ext_vlan_tag_oper_config_data_cfg.hdr);

    return rc;
}

/**
 * @brief Top level adapter routine for Extended Vlan Tagging Add entry into the Table
 */
bcmos_errno omci_svc_omci_ext_vlan_tag_oper_config_data_me_add_entry (bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context , bcmonu_mgmt_flow_cfg *flow, unsigned long filter_mask)
{
    omci_svc_uni *uni = omci_svc_uni_get(onu_context, flow);
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
#ifdef ENABLE_LOG
    unsigned long full_filter_mask = omci_svc_filter_mask_get(flow);
#endif

    bcmos_errno rc = BCM_ERR_OK;
    bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table entry = {};
    bcmos_bool is_add_entry = BCMOS_TRUE;

    BCM_LOG(DEBUG, omci_svc_log_id, "%s: ext_vlan_tag_oper_config_data Entry 0x%lx/0x%lx\n", __FUNCTION__, filter_mask, full_filter_mask);

    if (omci_svc_is_flow_double_tagged(flow))
    {
        omci_svc_ext_vlan_tag_oper_cfg_data_entry_filter_set_double_tag(onu_key, &entry, flow, filter_mask);
        omci_svc_ext_vlan_tag_oper_cfg_data_entry_treatment_set_double_tag(onu_key, &entry, flow, is_add_entry);
    }
    else
    {
        omci_svc_ext_vlan_tag_oper_cfg_data_entry_filter_set_single_tag(onu_key, &entry, flow, filter_mask);
        omci_svc_ext_vlan_tag_oper_cfg_data_entry_treatment_set_single_tag(onu_key, &entry, flow, is_add_entry);
    }

    rc = omci_svc_omci_ext_vlan_tag_oper_config_data_set_entry_in_table (olt_id, onu_key->pon_ni, onu_key->onu_id, uni->uni.entity_id, 1,
            OMCI_SVC_OMCI_ATTR_ID_RX_FRAME_VLAN_TAG_OPER_TABLE, &entry, is_add_entry);

    if (rc != BCM_ERR_OK)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, NULL, "%s: failed, me_id={class_id=%s:entity_id=%u}, result=%u\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(BCM_OMCI_ME_CLASS_VAL_EXT_VLAN_TAG_OPER_CONFIG_DATA), uni->uni.entity_id, rc);
    }


    return rc;
}


/**
 * @brief Top level adapter routine for Extended Vlan Tagging Remove entry from the Table
 */
bcmos_errno omci_svc_omci_ext_vlan_tag_oper_config_data_me_remove_entry (bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, bcmonu_mgmt_flow_cfg *flow, unsigned long filter_mask)
{
    omci_svc_uni *uni = omci_svc_uni_get(onu_context, flow);
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;
#ifdef ENABLE_LOG
    unsigned long full_filter_mask = omci_svc_filter_mask_get(flow);
#endif

    bcmos_errno rc = BCM_ERR_OK;
    bcm_omci_ext_vlan_tag_oper_config_data_rx_frame_vlan_tag_oper_table entry = {};
    bcmos_bool is_add_entry = BCMOS_FALSE;

    BCM_LOG(DEBUG, omci_svc_log_id, "%s: ext_vlan_tag_oper_config_data Entry 0x%lx/0x%lx\n", __FUNCTION__, filter_mask, full_filter_mask);

    if (omci_svc_is_flow_double_tagged(flow))
    {
        omci_svc_ext_vlan_tag_oper_cfg_data_entry_filter_set_double_tag(onu_key, &entry, flow, filter_mask);
        omci_svc_ext_vlan_tag_oper_cfg_data_entry_treatment_set_double_tag(onu_key, &entry, flow, is_add_entry);
    }
    else
    {
        omci_svc_ext_vlan_tag_oper_cfg_data_entry_filter_set_single_tag(onu_key, &entry, flow, filter_mask);
        omci_svc_ext_vlan_tag_oper_cfg_data_entry_treatment_set_single_tag(onu_key, &entry, flow, is_add_entry);
    }

    rc = omci_svc_omci_ext_vlan_tag_oper_config_data_set_entry_in_table (olt_id, onu_key->pon_ni, onu_key->onu_id, uni->uni.entity_id, 1,
            OMCI_SVC_OMCI_ATTR_ID_RX_FRAME_VLAN_TAG_OPER_TABLE, &entry, is_add_entry);

    if (rc != BCM_ERR_OK)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, NULL, "%s: failed, me_id={class_id=%s:entity_id=%u}, result=%u\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(BCM_OMCI_ME_CLASS_VAL_EXT_VLAN_TAG_OPER_CONFIG_DATA), uni->uni.entity_id, rc);
    }


    return rc;
}


/**
 * @brief adapter routine for MAC bridge port SVC profile
 */
bcmos_errno omci_svc_omci_mac_bridge_svc_prof_me_create (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... )
{
    bcmos_errno rc = BCM_ERR_OK;
    va_list arg_list;
    uint8_t attr_index;
    uint32_t attr_id = OMCI_SVC_OMCI_ATTR_ID_NONE;
    uint32_t attr_val = 0;

    /** init me cfg */
    bcm_omci_mac_bridge_svc_prof_cfg  mac_bridge_svc_prof_cfg = {};
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id) };
    BCM_OMCI_HDR_INIT(&mac_bridge_svc_prof_cfg.hdr, mac_bridge_svc_prof, me_key);

    va_start(arg_list, num_attr);
    for (attr_index = 0; attr_index < num_attr; attr_index++)
    {
        attr_id = (uint32_t)va_arg(arg_list, uint32_t);
        switch (attr_id)
        {
            case OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_SVC_PROF_PORT_SPANNING_TREE_IND:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mac_bridge_svc_prof_cfg, mac_bridge_svc_prof, spanning_tree_ind, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_LEARNING_IND:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mac_bridge_svc_prof_cfg, mac_bridge_svc_prof, learning_ind, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_PORT_BRIDGING_IND:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mac_bridge_svc_prof_cfg, mac_bridge_svc_prof, port_bridging_ind, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_PRI:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mac_bridge_svc_prof_cfg, mac_bridge_svc_prof, pri, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_MAX_AGE:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mac_bridge_svc_prof_cfg, mac_bridge_svc_prof, max_age, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_HELLO_TIME:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mac_bridge_svc_prof_cfg, mac_bridge_svc_prof, hello_time, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_FORWARD_DELAY:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mac_bridge_svc_prof_cfg, mac_bridge_svc_prof, forward_delay, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_UNKNOWN_MAC_ADDR_DISCARD:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mac_bridge_svc_prof_cfg, mac_bridge_svc_prof, unknown_mac_addr_discard, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_SVC_PROF_MAC_LEARNING_DEPTH:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mac_bridge_svc_prof_cfg, mac_bridge_svc_prof, mac_learning_depth, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_DYNAMIC_FILTERING_AGEING_TIME:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mac_bridge_svc_prof_cfg, mac_bridge_svc_prof, dynamic_filtering_ageing_time, attr_val);
                break;

            default:
                BCM_LOG(ERROR, omci_svc_log_id, "%s: unhandled attr : %d\n", __FUNCTION__, attr_id);
                rc = BCM_ERR_PARM;
                break;
        }
    }
    va_end(arg_list);


    /* ME API Call: call ME layer api Create */
    if (BCM_ERR_OK == rc)
    {
        rc = bcm_omci_create_req(&mac_bridge_svc_prof_cfg.hdr);
    }

    return rc;
}




/**
 * @brief adapter routine for MAC Bridge Port Config Data ME Create
 */
bcmos_errno omci_svc_omci_mac_bridge_port_config_data_me_create (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... )
{
    bcmos_errno rc = BCM_ERR_OK;
    va_list arg_list;
    uint8_t attr_index;
    uint32_t attr_id = OMCI_SVC_OMCI_ATTR_ID_NONE;
    uint32_t attr_val = 0;

    /** init me cfg */
    bcm_omci_mac_bridge_port_config_data_cfg  mac_bridge_port_config_data_cfg = {};
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id) };
    BCM_OMCI_HDR_INIT(&mac_bridge_port_config_data_cfg.hdr, mac_bridge_port_config_data, me_key);

    va_start(arg_list, num_attr);
    for (attr_index = 0; attr_index < num_attr; attr_index++)
    {
        attr_id = (uint32_t)va_arg(arg_list, uint32_t);
        switch (attr_id)
        {
            case OMCI_SVC_OMCI_ATTR_ID_BRIDGE_ID_PTR:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mac_bridge_port_config_data_cfg, mac_bridge_port_config_data, bridge_id_ptr, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_PORT_NUM:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mac_bridge_port_config_data_cfg, mac_bridge_port_config_data, port_num, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_PORT_TP_TYPE:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mac_bridge_port_config_data_cfg, mac_bridge_port_config_data, tp_type, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_PORT_TP_PTR:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mac_bridge_port_config_data_cfg, mac_bridge_port_config_data, tp_ptr, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_PORT_PRI:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mac_bridge_port_config_data_cfg, mac_bridge_port_config_data, port_pri, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_PORT_PATH_COST:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mac_bridge_port_config_data_cfg, mac_bridge_port_config_data, port_path_cost, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_PORT_CONFIG_DATA_PORT_SPANNING_TREE_IND:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mac_bridge_port_config_data_cfg, mac_bridge_port_config_data, port_spanning_tree_ind, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_DEPRECATED_1:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mac_bridge_port_config_data_cfg, mac_bridge_port_config_data, deprecated_1, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_DEPRECATED_2:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mac_bridge_port_config_data_cfg, mac_bridge_port_config_data, deprecated_2, attr_val);
                break;

#ifdef OMCI_SVC_TODO
            case OMCI_SVC_OMCI_ATTR_ID_PORT_MAC_ADDR:
                /**@todo  mac address needs to be handled which is of type MacAddress (an array). and use BCM_OMCI_REQ_PROP_SET_ARRAY */
                break;
#endif

            case OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_PORT_CONFIG_MAC_LEARNING_DEPTH:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mac_bridge_port_config_data_cfg, mac_bridge_port_config_data, mac_learning_depth, attr_val);
                break;

            default:
                BCM_LOG(ERROR, omci_svc_log_id, "%s: unhandled attr : %d\n", __FUNCTION__, attr_id);
                rc = BCM_ERR_PARM;
                break;
        }
    }
    va_end(arg_list);


    /* ME API Call: call ME layer api Create */
    if (BCM_ERR_OK == rc)
    {
        rc = bcm_omci_create_req (&mac_bridge_port_config_data_cfg.hdr);
    }

    return rc;
}



/**
 * @brief adapter routine for MAC Bridge Port Config Data ME Delete
 */
bcmos_errno omci_svc_omci_mac_bridge_port_config_data_me_delete (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id)
{
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id),
        .entity_class = BCM_OMCI_ME_CLASS_VAL_MAC_BRIDGE_PORT_CONFIG_DATA};

    /* ME API Call: call ME layer api Delete */
    return bcm_omci_delete_req(&me_key);
}


/**
 * @brief adapter routine for Multicast Operations Profile ME Create or Set
 */
static bcmos_errno omci_svc_omci_mcast_operations_profile_me_create_or_set (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, bcmos_bool is_create, va_list arg_list )
{
    bcmos_errno rc = BCM_ERR_OK;
    uint8_t attr_index;
    uint32_t attr_id = OMCI_SVC_OMCI_ATTR_ID_NONE;
    uint32_t attr_val = 0;
    char* attr_val_ptr = NULL;

    /** init me cfg */
    bcm_omci_mcast_operations_profile_cfg mcast_operations_profile_cfg = {};
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id) };
    BCM_OMCI_HDR_INIT(&mcast_operations_profile_cfg.hdr, mcast_operations_profile, me_key);

    for (attr_index = 0; attr_index < num_attr; attr_index++)
    {
        attr_id = (uint32_t)va_arg(arg_list, uint32_t);
        switch (attr_id)
        {
            case OMCI_SVC_OMCI_ATTR_ID_IGMP_VERSION:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_operations_profile_cfg, mcast_operations_profile, igmp_version, attr_val);
                break;
            case OMCI_SVC_OMCI_ATTR_ID_IGMP_FUNC:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_operations_profile_cfg, mcast_operations_profile, igmp_function, attr_val);
                break;
            case OMCI_SVC_OMCI_ATTR_ID_IMMEDIATE_LEAVE:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_operations_profile_cfg, mcast_operations_profile, immediate_leave, attr_val);
                break;
            case OMCI_SVC_OMCI_ATTR_ID_US_IGMP_TCI:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_operations_profile_cfg, mcast_operations_profile, upstream_igmp_tci, attr_val);
                break;
            case OMCI_SVC_OMCI_ATTR_ID_US_IGMP_TAG_CONTROL:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_operations_profile_cfg, mcast_operations_profile, upstream_igmp_tag_control, attr_val);
                break;
            case OMCI_SVC_OMCI_ATTR_ID_US_IGMP_RATE:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_operations_profile_cfg, mcast_operations_profile, upstream_igmp_rate, attr_val);
                break;
            case OMCI_SVC_OMCI_ATTR_ID_ROBUSTNESS:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_operations_profile_cfg, mcast_operations_profile, robustness, attr_val);
                break;
            case OMCI_SVC_OMCI_ATTR_ID_QUERIER_IP_ADDR:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_operations_profile_cfg, mcast_operations_profile, querier_ip_address, attr_val);
                break;
            case OMCI_SVC_OMCI_ATTR_ID_QUERY_INTERVAL:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_operations_profile_cfg, mcast_operations_profile, query_interval, attr_val);
                break;
            case OMCI_SVC_OMCI_ATTR_ID_QUERY_MAX_RSP_TIME:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_operations_profile_cfg, mcast_operations_profile, query_max_response_time, attr_val);
                break;
            case OMCI_SVC_OMCI_ATTR_ID_DS_IGMP_AND_MCAST_TCI:
                attr_val_ptr = va_arg(arg_list, char*);
                char prefix1, prefix2;
                uint8_t control_type;
                uint16_t tci;

                if (!*attr_val_ptr || sscanf(attr_val_ptr, "%c%c%02hhx%04hx", &prefix1, &prefix2, &control_type, &tci) < 4 || prefix1 != '0' || prefix2 != 'x')
                {
                    BCM_LOG(ERROR, omci_svc_log_id, "%s: illegal attribute format : %d\n", __FUNCTION__, attr_id);
                    rc = BCM_ERR_PARM;
                    break;
                }

                bcm_omci_mcast_operations_profile_ds_igmp_and_multicast_tci ds_igmp_and_multicast_tci =
                {
                    .control_type = control_type,
                    .tci = tci
                };

                BCM_OMCI_REQ_PROP_SET(&mcast_operations_profile_cfg, mcast_operations_profile, ds_igmp_and_multicast_tci, ds_igmp_and_multicast_tci);
                break;

            default:
                BCM_LOG(ERROR, omci_svc_log_id, "%s: unhandled attr : %d\n", __FUNCTION__, attr_id);
                rc = BCM_ERR_PARM;
                break;
        }
    }


    /* ME API Call: call ME layer api Create or Set */
    if (BCM_ERR_OK == rc)
    {
        if (is_create)
            rc = bcm_omci_create_req(&mcast_operations_profile_cfg.hdr);
        else
            rc = bcm_omci_set_req(&mcast_operations_profile_cfg.hdr);
    }

    return rc;
}

/**
 * @brief adapter routine for Multicast Operations Profile ME Create
 */
bcmos_errno omci_svc_omci_mcast_operations_profile_me_create (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... )
{
    va_list ap;
    bcmos_errno ret;

    va_start(ap, num_attr);
    ret = omci_svc_omci_mcast_operations_profile_me_create_or_set(olt_id, pon_ni, onu_id, entity_id, num_attr, BCMOS_TRUE, ap);
    va_end(ap);

    return ret;
}

/**
 * @brief adapter routine for Multicast Operations Profile ME Set
 */
bcmos_errno omci_svc_omci_mcast_operations_profile_me_set (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... )
{
    va_list ap;
    bcmos_errno ret;

    va_start(ap, num_attr);
    ret = omci_svc_omci_mcast_operations_profile_me_create_or_set(olt_id, pon_ni, onu_id, entity_id, num_attr, BCMOS_FALSE, ap);
    va_end(ap);

    return ret;
}


/**
 * @brief adapter routine for Multicast Operations Profile ME Delete
 */
bcmos_errno omci_svc_omci_mcast_operations_profile_me_delete(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id)
{
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id),
        .entity_class = BCM_OMCI_ME_CLASS_VAL_MCAST_OPERATIONS_PROFILE};

    /* ME API Call: call ME layer api Delete */
    return bcm_omci_delete_req(&me_key);
}

/**
 * @brief Top level adapter routine for mcast operations profile Add entry into the Table
 */
bcmos_errno omci_svc_omci_mcast_operations_profile_me_add_entry_dynamic_acl(bcmonu_mgmt_onu_key *onu_key,  omci_svc_onu *onu_context, bcmonu_mgmt_flow_cfg *flow, bcmonu_mgmt_svc_port_id gem_port_id)
{
    bcmos_errno rc = BCM_ERR_OK;
    omci_svc_uni *uni = omci_svc_uni_get(onu_context, flow);
    bcmos_bool is_add_entry = BCMOS_TRUE;
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    bcm_omci_mcast_operations_profile_dynamic_access_control_list_table entry = {};

    omci_svc_mcast_operations_profile_dynamic_acl_set (onu_key, &entry, flow, gem_port_id, is_add_entry);
    rc = omci_svc_omci_mcast_operations_profile_set_entry_in_table (olt_id, onu_key->pon_ni, onu_key->onu_id, uni->uni.entity_id, 1,
            OMCI_SVC_OMCI_ATTR_ID_DYNAMIC_ACCESS_CONTROL_LIST_TABLE, &entry, is_add_entry);

    if (rc != BCM_ERR_OK)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, NULL, "%s: failed, me_id={class_id=%s:entity_id=%u}, result=%u\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(BCM_OMCI_ME_CLASS_VAL_MCAST_OPERATIONS_PROFILE), uni->uni.entity_id, rc);
    }

    return rc;
}


/**
 * @brief Top level adapter routine for mcast operations profile Remove entry from the Table
 */
bcmos_errno omci_svc_omci_mcast_operations_profile_me_remove_entry_dynamic_acl(bcmonu_mgmt_onu_key *onu_key, omci_svc_onu *onu_context, bcmonu_mgmt_flow_cfg *flow)
{
    bcmos_errno rc = BCM_ERR_OK;
    omci_svc_uni *uni = omci_svc_uni_get(onu_context, flow);
    bcmos_bool is_add_entry = BCMOS_FALSE;
    bcmolt_oltid olt_id = onu_context->onu_cfg.hdr.hdr.olt_id;

    bcm_omci_mcast_operations_profile_dynamic_access_control_list_table entry = {};

    omci_svc_mcast_operations_profile_dynamic_acl_set (onu_key, &entry, flow, 0, is_add_entry);
    rc = omci_svc_omci_mcast_operations_profile_set_entry_in_table (olt_id, onu_key->pon_ni, onu_key->onu_id, uni->uni.entity_id, 1,
            OMCI_SVC_OMCI_ATTR_ID_DYNAMIC_ACCESS_CONTROL_LIST_TABLE, &entry, is_add_entry);

    if (rc != BCM_ERR_OK)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, NULL, "%s: failed, me_id={class_id=%s:entity_id=%u}, result=%u\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(BCM_OMCI_ME_CLASS_VAL_MCAST_OPERATIONS_PROFILE), uni->uni.entity_id, rc);
    }

    return rc;
}


/**
 * @brief sub-adapter routine for mcast operations profile Add entry into the Table to take in as variable number of args
 * @note is_add_entry is used to indicate whether it is ADD (TRUE) or REMOVE (FALSE).
 */
static bcmos_errno omci_svc_omci_mcast_operations_profile_set_entry_in_table (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id,
        uint8_t num_attr, uint32_t attr_id, void *entry, bcmos_bool is_add_entry)
{
    bcmos_errno rc = BCM_ERR_OK;
    /** init me cfg */
    bcm_omci_mcast_operations_profile_cfg mcast_operations_profile_cfg = {};
    long cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id) |
        (is_add_entry ? OMCI_SVC_OPER_SET_ADD_ENTRY : OMCI_SVC_OPER_SET_REMOVE_ENTRY);
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = cookie };
    BCM_OMCI_HDR_INIT(&mcast_operations_profile_cfg.hdr, mcast_operations_profile, me_key);

    switch (attr_id)
    {
        case OMCI_SVC_OMCI_ATTR_ID_DYNAMIC_ACCESS_CONTROL_LIST_TABLE:
                BCM_OMCI_REQ_PROP_SET(&mcast_operations_profile_cfg, mcast_operations_profile, dynamic_access_control_list_table,
                        (*(bcm_omci_mcast_operations_profile_dynamic_access_control_list_table *)entry));
            break;

        default:
                BCM_LOG(ERROR, omci_svc_log_id, "%s: unhandled attr : %d\n", __FUNCTION__, attr_id);
            return BCM_ERR_PARM;
            break;
    }

    /* ME API Call: call ME layer api Create */
    rc = bcm_omci_set_req(&mcast_operations_profile_cfg.hdr);

    return rc;
}


/**
 * @brief adapter routine for Multicast Subscriber Config Info ME Create
 */
bcmos_errno omci_svc_omci_mcast_subscriber_config_info_me_create (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... )
{
    bcmos_errno rc = BCM_ERR_OK;
    va_list arg_list;
    uint8_t attr_index;
    uint32_t attr_id = OMCI_SVC_OMCI_ATTR_ID_NONE;
    uint32_t attr_val = 0;

    /** init me cfg */
    bcm_omci_mcast_subscriber_config_info_cfg mcast_subscriber_config_info_cfg = {};
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id) };
    BCM_OMCI_HDR_INIT(&mcast_subscriber_config_info_cfg.hdr, mcast_subscriber_config_info, me_key);

    va_start(arg_list, num_attr);
    for (attr_index = 0; attr_index < num_attr; attr_index++)
    {
        attr_id = (uint32_t)va_arg(arg_list, uint32_t);
        switch (attr_id)
        {
            case OMCI_SVC_OMCI_ATTR_ID_ME_TYPE:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_subscriber_config_info_cfg, mcast_subscriber_config_info, me_type, attr_val);
                break;
            case OMCI_SVC_OMCI_ATTR_ID_MCAST_OPER_S_PROF_PTR:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_subscriber_config_info_cfg, mcast_subscriber_config_info, mcast_operations_prof_ptr, attr_val);
                break;
            case OMCI_SVC_OMCI_ATTR_ID_MAX_SIMULTANEOUS_GROUPS:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_subscriber_config_info_cfg, mcast_subscriber_config_info, max_simultaneous_groups, attr_val);
                break;
            case OMCI_SVC_OMCI_ATTR_ID_MAX_MCAST_BW:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_subscriber_config_info_cfg, mcast_subscriber_config_info, max_multicast_bw, attr_val);
                break;
            case OMCI_SVC_OMCI_ATTR_ID_BW_ENFORCEMENT:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_subscriber_config_info_cfg, mcast_subscriber_config_info, bw_enforcement, attr_val);
                break;

            default:
                BCM_LOG(ERROR, omci_svc_log_id, "%s: unhandled attr : %d\n", __FUNCTION__, attr_id);
                rc = BCM_ERR_PARM;
                break;
        }
    }
    va_end(arg_list);


    /* ME API Call: call ME layer api Create */
    if (BCM_ERR_OK == rc)
    {
        rc = bcm_omci_create_req(&mcast_subscriber_config_info_cfg.hdr);
    }

    return rc;
}

/**
 * @brief adapter routine for Multicast Subscriber Config Info ME Delete
 */
bcmos_errno omci_svc_omci_mcast_subscriber_config_info_me_delete (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id)
{
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id),
        .entity_class = BCM_OMCI_ME_CLASS_VAL_MCAST_SUBSCRIBER_CONFIG_INFO };

    /* ME API Call: call ME layer api Delete */
    return bcm_omci_delete_req(&me_key);
}

/**
 * @brief adapter routine for TCONT ME set
 */
bcmos_errno omci_svc_omci_tcont_me_set (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... )
{
    bcmos_errno rc = BCM_ERR_OK;
    va_list arg_list;
    uint8_t attr_index;
    uint32_t attr_id = OMCI_SVC_OMCI_ATTR_ID_NONE;
    uint32_t attr_val = 0;

    /** init me cfg */
    bcm_omci_tcont_cfg  tcont_cfg = {};
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id) };
    BCM_OMCI_HDR_INIT(&tcont_cfg.hdr, tcont, me_key);

    va_start(arg_list, num_attr);
    for (attr_index = 0; attr_index < num_attr; attr_index++)
    {
        attr_id = (uint32_t)va_arg(arg_list, uint32_t);
        switch (attr_id)
        {
            case OMCI_SVC_OMCI_ATTR_ID_ALLOC_ID:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&tcont_cfg, tcont, alloc_id, attr_val);
                break;

            default:
                BCM_LOG(ERROR, omci_svc_log_id, "%s: unhandled attr : %d\n", __FUNCTION__, attr_id);
                rc = BCM_ERR_PARM;
                break;
        }
    }
    va_end(arg_list);


    /* ME API Call: call ME layer api Set */
    if (BCM_ERR_OK == rc)
    {
        rc = bcm_omci_set_req(&tcont_cfg.hdr);
    }

    return rc;
}




/**
 * @brief adapter routine for GEM Port Network CTP ME Create
 */
bcmos_errno omci_svc_omci_gem_port_net_ctp_me_create (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... )
{
    bcmos_errno rc = BCM_ERR_OK;
    va_list arg_list;
    uint8_t attr_index;
    uint32_t attr_id = OMCI_SVC_OMCI_ATTR_ID_NONE;
    uint32_t attr_val = 0;

    /** init me cfg */
    bcm_omci_gem_port_net_ctp_cfg  gem_port_net_ctp_cfg = {};
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id) };
    BCM_OMCI_HDR_INIT(&gem_port_net_ctp_cfg.hdr, gem_port_net_ctp, me_key);

    va_start(arg_list, num_attr);
    for (attr_index = 0; attr_index < num_attr; attr_index++)
    {
        attr_id = (uint32_t)va_arg(arg_list, uint32_t);
        switch (attr_id)
        {
            case OMCI_SVC_OMCI_ATTR_ID_PORT_ID_VALUE:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&gem_port_net_ctp_cfg, gem_port_net_ctp, port_id, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_TCONT_PTR:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&gem_port_net_ctp_cfg, gem_port_net_ctp, tcont_ptr, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_DIRECTION:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&gem_port_net_ctp_cfg, gem_port_net_ctp, direction, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_TRAFFIC_MGMT_PTR_US:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&gem_port_net_ctp_cfg, gem_port_net_ctp, traffic_mgmt_ptr_us, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_TRAFFIC_DESC_PROF_PTR_US:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&gem_port_net_ctp_cfg, gem_port_net_ctp, traffic_desc_prof_ptr_us, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_PRI_QUEUE_PTR_DS:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&gem_port_net_ctp_cfg, gem_port_net_ctp, pri_queue_ptr_ds, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_TRAFFIC_DESC_PROF_PTR_DS:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&gem_port_net_ctp_cfg, gem_port_net_ctp, traffic_desc_prof_ptr_ds, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_ENCRYPTION_KEY_RING:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&gem_port_net_ctp_cfg, gem_port_net_ctp, encryption_key_ring, attr_val);
                break;

            default:
                BCM_LOG(ERROR, omci_svc_log_id, "%s: unhandled attr : %d\n", __FUNCTION__, attr_id);
                rc = BCM_ERR_PARM;
                break;
        }
    }
    va_end(arg_list);


    /* ME API Call: call ME layer api Create */
    if (BCM_ERR_OK == rc)
    {
        rc = bcm_omci_create_req(&gem_port_net_ctp_cfg.hdr);
    }

    return rc;
}


/**
 * @brief adapter routine for GEM Port Network CTP ME Delete
 */
bcmos_errno omci_svc_omci_gem_port_net_ctp_me_delete (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id)
{
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id),
        .entity_class = BCM_OMCI_ME_CLASS_VAL_GEM_PORT_NET_CTP };

    /* ME API Call: call ME layer api Delete */
    return bcm_omci_delete_req(&me_key);
}

/**
 * @brief adapter routine for IEEE 802.1p Mapper Svc Profile ME Create or Set
 */
static bcmos_errno omci_svc_omci_ieee_8021_p_mapper_svc_prof_me_create_or_set (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, bcmos_bool is_create, va_list arg_list )
{
    bcmos_errno rc = BCM_ERR_OK;
    uint8_t attr_index;
    uint32_t attr_id = OMCI_SVC_OMCI_ATTR_ID_NONE;
    uint32_t attr_val = 0;

    /** init me cfg */
    bcm_omci_ieee_8021_p_mapper_svc_prof_cfg  ieee_8021_p_mapper_svc_prof_cfg = {};
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id) };
    BCM_OMCI_HDR_INIT(&ieee_8021_p_mapper_svc_prof_cfg.hdr, ieee_8021_p_mapper_svc_prof, me_key);

    for (attr_index = 0; attr_index < num_attr; attr_index++)
    {
        attr_id = (uint32_t)va_arg(arg_list, uint32_t);
        switch (attr_id)
        {
            case OMCI_SVC_OMCI_ATTR_ID_MAPPER_SVC_PROF_TP_PTR:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&ieee_8021_p_mapper_svc_prof_cfg, ieee_8021_p_mapper_svc_prof, tp_ptr, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI0:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&ieee_8021_p_mapper_svc_prof_cfg, ieee_8021_p_mapper_svc_prof, interwork_tp_ptr_pri_0, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI1:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&ieee_8021_p_mapper_svc_prof_cfg, ieee_8021_p_mapper_svc_prof, interwork_tp_ptr_pri_1, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI2:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&ieee_8021_p_mapper_svc_prof_cfg, ieee_8021_p_mapper_svc_prof, interwork_tp_ptr_pri_2, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI3:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&ieee_8021_p_mapper_svc_prof_cfg, ieee_8021_p_mapper_svc_prof, interwork_tp_ptr_pri_3, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI4:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&ieee_8021_p_mapper_svc_prof_cfg, ieee_8021_p_mapper_svc_prof, interwork_tp_ptr_pri_4, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI5:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&ieee_8021_p_mapper_svc_prof_cfg, ieee_8021_p_mapper_svc_prof, interwork_tp_ptr_pri_5, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI6:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&ieee_8021_p_mapper_svc_prof_cfg, ieee_8021_p_mapper_svc_prof, interwork_tp_ptr_pri_6, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_INTERWORK_TP_PTR_PRI7:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&ieee_8021_p_mapper_svc_prof_cfg, ieee_8021_p_mapper_svc_prof, interwork_tp_ptr_pri_7, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_UNMARKED_FRAME_OPT:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&ieee_8021_p_mapper_svc_prof_cfg, ieee_8021_p_mapper_svc_prof, unmarked_frame_opt, attr_val);
                break;

#ifdef OMCI_SVC_TODO
                /** @todo handle the attribute as an array */
            case OMCI_SVC_OMCI_ATTR_ID_MAPPER_SVC_PROF_DSCP_TO_P_BIT_MAPPING:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET_ARRAY(&ieee_8021_p_mapper_svc_prof_cfg, ieee_8021_p_mapper_svc_prof, dscp_to_pbit_mapping, attr_val);
                break;
#endif

            case OMCI_SVC_OMCI_ATTR_ID_DEFAULT_P_BIT_MARKING:
               attr_val = va_arg(arg_list, uint32_t);
               BCM_OMCI_REQ_PROP_SET(&ieee_8021_p_mapper_svc_prof_cfg, ieee_8021_p_mapper_svc_prof, default_pbit_assumption, attr_val);
               break;

            case OMCI_SVC_OMCI_ATTR_ID_MAPPER_TP_TYPE:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&ieee_8021_p_mapper_svc_prof_cfg, ieee_8021_p_mapper_svc_prof, mapper_tp_type, attr_val);
                break;

            default:
                BCM_LOG(ERROR, omci_svc_log_id, "%s: unhandled attr : %d\n", __FUNCTION__, attr_id);
                rc = BCM_ERR_PARM;
                break;
        }
    }


    /* ME API Call: call ME layer api Create or Set */
    if (BCM_ERR_OK == rc)
    {
        if (is_create)
            rc = bcm_omci_create_req(&ieee_8021_p_mapper_svc_prof_cfg.hdr);
        else
            rc = bcm_omci_set_req(&ieee_8021_p_mapper_svc_prof_cfg.hdr);
    }

    return rc;
}


/**
 * @brief adapter routine for IEEE 802.1p Mapper Svc Profile ME Create
 */
bcmos_errno omci_svc_omci_ieee_8021_p_mapper_svc_prof_me_create (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... )
{
    va_list ap;
    bcmos_errno ret;

    va_start(ap, num_attr);
    ret = omci_svc_omci_ieee_8021_p_mapper_svc_prof_me_create_or_set (olt_id, pon_ni, onu_id, entity_id, num_attr, BCMOS_TRUE, ap);
    va_end(ap);

    return ret;
}

/**
 * @brief adapter routine for IEEE 802.1p Mapper Svc Profile ME Set
 */
bcmos_errno omci_svc_omci_ieee_8021_p_mapper_svc_prof_me_set (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... )
{
    va_list ap;
    bcmos_errno ret;

    va_start(ap, num_attr);
    ret = omci_svc_omci_ieee_8021_p_mapper_svc_prof_me_create_or_set (olt_id, pon_ni, onu_id, entity_id, num_attr, BCMOS_FALSE, ap);
    va_end(ap);

    return ret;
}

/**
 * @brief adapter routine for IEEE 802.1p Mapper Svc Profile ME Delete
 */
bcmos_errno omci_svc_omci_ieee_8021_p_mapper_svc_prof_me_delete (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id)
{
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id),
        .entity_class = BCM_OMCI_ME_CLASS_VAL_IEEE_8021_P_MAPPER_SVC_PROF };

    /* ME API Call: call ME layer api Delete */
    return bcm_omci_delete_req(&me_key);
}



/**
 * @brief adapter routine for GEM IW TP ME Create
 */
bcmos_errno omci_svc_omci_gem_iw_tp_me_create (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... )
{
    bcmos_errno rc = BCM_ERR_OK;
    va_list arg_list;
    uint8_t attr_index;
    uint32_t attr_id = OMCI_SVC_OMCI_ATTR_ID_NONE;
    uint32_t attr_val = 0;

    /** init me cfg */
    bcm_omci_gem_iw_tp_cfg  gem_iw_tp_cfg = {};
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id) };
    BCM_OMCI_HDR_INIT(&gem_iw_tp_cfg.hdr, gem_iw_tp, me_key);

    va_start(arg_list, num_attr);
    for (attr_index = 0; attr_index < num_attr; attr_index++)
    {
        attr_id = (uint32_t)va_arg(arg_list, uint32_t);
        switch (attr_id)
        {
            case OMCI_SVC_OMCI_ATTR_ID_GEM_PORT_NET_CTP_CON_PTR:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&gem_iw_tp_cfg, gem_iw_tp, gem_port_net_ctp_conn_ptr, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_IW_OPT:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&gem_iw_tp_cfg, gem_iw_tp, iw_opt, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_SVC_PROF_PTR:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&gem_iw_tp_cfg, gem_iw_tp, svc_prof_ptr, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_IW_TP_PTR:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&gem_iw_tp_cfg, gem_iw_tp, iw_tp_ptr, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_GAL_PROF_PTR:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&gem_iw_tp_cfg, gem_iw_tp, gal_prof_ptr, attr_val);
                break;

            default:
                BCM_LOG(ERROR, omci_svc_log_id, "%s: unhandled attr : %d\n", __FUNCTION__, attr_id);
                rc = BCM_ERR_PARM;
                break;
        }
    }
    va_end(arg_list);


    /* ME API Call: call ME layer api Create */
    if (BCM_ERR_OK == rc)
    {
        rc = bcm_omci_create_req(&gem_iw_tp_cfg.hdr);
    }

    return rc;
}




/**
 * @brief adapter routine for GEM IW TP ME Delete
 */
bcmos_errno omci_svc_omci_gem_iw_tp_me_delete (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id)
{
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id),
        .entity_class = BCM_OMCI_ME_CLASS_VAL_GEM_IW_TP };

    /* ME API Call: call ME layer api Delete */
    return bcm_omci_delete_req(&me_key);
}



/**
 * @brief adapter routine for Multicast GEM IW TP ME Create
 */
bcmos_errno omci_svc_omci_mcast_gem_iw_tp_me_create (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... )
{
    bcmos_errno rc = BCM_ERR_OK;
    va_list arg_list;
    uint8_t attr_index;
    uint32_t attr_id = OMCI_SVC_OMCI_ATTR_ID_NONE;
    uint32_t attr_val = 0;

    /** init me cfg */
    bcm_omci_mcast_gem_iw_tp_cfg  mcast_gem_iw_tp_cfg = {};
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id) };
    BCM_OMCI_HDR_INIT(&mcast_gem_iw_tp_cfg.hdr, mcast_gem_iw_tp, me_key);

    va_start(arg_list, num_attr);
    for (attr_index = 0; attr_index < num_attr; attr_index++)
    {
        attr_id = (uint32_t)va_arg(arg_list, uint32_t);
        switch (attr_id)
        {
            case OMCI_SVC_OMCI_ATTR_ID_MCAST_GEM_PORT_NET_CTP_CON_PTR:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_gem_iw_tp_cfg, mcast_gem_iw_tp, gem_port_net_ctp_conn_ptr, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_MCAST_IW_OPT:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_gem_iw_tp_cfg, mcast_gem_iw_tp, iw_opt, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_MCAST_SVC_PROF_PTR:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_gem_iw_tp_cfg, mcast_gem_iw_tp, svc_prof_ptr, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_MCAST_GEM_IW_TP_NOT_USED_1:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_gem_iw_tp_cfg, mcast_gem_iw_tp, not_used_1, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_MCAST_GAL_PROF_PTR:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_gem_iw_tp_cfg, mcast_gem_iw_tp, gal_prof_ptr, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_MCAST_GEM_IW_TP_NOT_USED_2:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&mcast_gem_iw_tp_cfg, mcast_gem_iw_tp, not_used_2, attr_val);
                break;

            default:
                BCM_LOG(ERROR, omci_svc_log_id, "%s: unhandled attr : %d\n", __FUNCTION__, attr_id);
                rc = BCM_ERR_PARM;
                break;
        }
    }
    va_end(arg_list);


    /* ME API Call: call ME layer api Create */
    if (BCM_ERR_OK == rc)
    {
        rc = bcm_omci_create_req(&mcast_gem_iw_tp_cfg.hdr);
    }

    return rc;
}


/**
 * @brief adapter routine for Multicast GEM IW TP ME Delete
 */
bcmos_errno omci_svc_omci_mcast_gem_iw_tp_me_delete (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id)
{
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id),
        .entity_class = BCM_OMCI_ME_CLASS_VAL_MCAST_GEM_IW_TP };

    /* ME API Call: call ME layer api Delete */
    return bcm_omci_delete_req(&me_key);
}


/**
 * @brief Top level adapter routine for mcast gem interworking tp Add entry into the Table
 */
bcmos_errno omci_svc_omci_mcast_gem_iw_tp_me_add_entry_ipv4_addr_table (bcmolt_oltid olt_id, bcmonu_mgmt_onu_key *onu_key,  bcmonu_mgmt_flow_cfg *flow, bcmonu_mgmt_svc_port_id gem_port_id)
{
    bcmos_errno rc = BCM_ERR_OK;

    /* Do not do endianness conversion here - it will happen automatically in ME layer code. */
    bcm_omci_mcast_gem_iw_tp_ipv_4_mcast_addr_table entry =
    {
        .gem_port_id = gem_port_id,
        .mcast_addr_range_start = 0xE0000000,
        .mcast_addr_range_stop = 0xEFFFFFFF
    };

    rc = omci_svc_omci_mcast_gem_iw_tp_set_entry_in_table (olt_id, onu_key->pon_ni, onu_key->onu_id, gem_port_id, 1,
            OMCI_SVC_OMCI_ATTR_ID_IPV4_MCAST_ADDR_TABLE, &entry, BCMOS_TRUE);

    if (rc != BCM_ERR_OK)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, NULL, "%s: failed, me_id={class_id=%s:entity_id=%u}, result=%u\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(BCM_OMCI_ME_CLASS_VAL_MCAST_GEM_IW_TP), gem_port_id, rc);
    }


    return rc;
}


/**
 * @brief Top level adapter routine for mcast operations profile Remove entry from the Table
 */
bcmos_errno omci_svc_omci_mcast_gem_iw_tp_me_remove_entry_ipv4_addr_table (bcmolt_oltid olt_id, bcmonu_mgmt_onu_key *onu_key,  bcmonu_mgmt_flow_cfg *flow, bcmonu_mgmt_svc_port_id gem_port_id)
{
    bcmos_errno rc = BCM_ERR_OK;

    /* Do not do endianness conversion here - it will happen automatically in ME layer code. */
    bcm_omci_mcast_gem_iw_tp_ipv_4_mcast_addr_table entry =
    {
        .gem_port_id = gem_port_id,
        .mcast_addr_range_start = 0xE0000000,
        .mcast_addr_range_stop = 0xEFFFFFFF,
    };

    rc = omci_svc_omci_mcast_gem_iw_tp_set_entry_in_table (olt_id, onu_key->pon_ni, onu_key->onu_id, gem_port_id, 1,
            OMCI_SVC_OMCI_ATTR_ID_IPV4_MCAST_ADDR_TABLE, &entry, BCMOS_FALSE);

    if (rc != BCM_ERR_OK)
    {
        OMCI_SVC_LOG(ERROR, olt_id, onu_key, NULL, "%s: failed, me_id={class_id=%s:entity_id=%u}, result=%u\n",
            __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(BCM_OMCI_ME_CLASS_VAL_MCAST_GEM_IW_TP), gem_port_id, rc);
    }


    return rc;
}

/**
 * @brief sub-adapter routine for mcast operations profile Add entry into the Table to take in as variable number of args
 * @note is_add_entry is used to indicate whether it is ADD (TRUE) or REMOVE (FALSE).
 */
static bcmos_errno omci_svc_omci_mcast_gem_iw_tp_set_entry_in_table (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id,
        uint8_t num_attr, uint32_t attr_id, void *entry, bcmos_bool is_add_entry)
{
    bcmos_errno rc = BCM_ERR_OK;
    /** init me cfg */
    long cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id) |
        (is_add_entry ? OMCI_SVC_OPER_SET_ADD_ENTRY : OMCI_SVC_OPER_SET_REMOVE_ENTRY);
    bcm_omci_mcast_gem_iw_tp_cfg mcast_gem_iw_tp_cfg = {};
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = cookie };
    BCM_OMCI_HDR_INIT(&mcast_gem_iw_tp_cfg.hdr, mcast_gem_iw_tp, me_key);

    switch (attr_id)
    {
        case OMCI_SVC_OMCI_ATTR_ID_IPV4_MCAST_ADDR_TABLE:
                BCM_OMCI_REQ_PROP_SET(&mcast_gem_iw_tp_cfg, mcast_gem_iw_tp, ipv_4_mcast_addr_table,
                        (*(bcm_omci_mcast_gem_iw_tp_ipv_4_mcast_addr_table *)entry));
            break;

        default:
                BCM_LOG(ERROR, omci_svc_log_id, "%s: unhandled attr : %d\n", __FUNCTION__, attr_id);
            return BCM_ERR_PARM;
            break;
    }

    /* ME API Call: call ME layer api Create */
    rc = bcm_omci_set_req(&mcast_gem_iw_tp_cfg.hdr);

    return rc;
}


/**
 * @brief adapter routine for VLAN Tag Filter Data Create
 */
bcmos_errno omci_svc_omci_vlan_tag_filter_data_me_create (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id, uint8_t num_attr, ... )
{
    bcmos_errno rc = BCM_ERR_OK;
    va_list arg_list;
    uint8_t attr_index;
    uint32_t attr_id = OMCI_SVC_OMCI_ATTR_ID_NONE;
    uint32_t attr_val = 0;
    uint8_t vlan_filter_list[24] = {};
    uint8_t num_vids = 0;
    uint8_t num_vids_in_args = 0;

    /** init me cfg */
    bcm_omci_vlan_tag_filter_data_cfg  vlan_tag_filter_data_cfg = {};
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id) };
    BCM_OMCI_HDR_INIT(&vlan_tag_filter_data_cfg.hdr, vlan_tag_filter_data, me_key);

    va_start(arg_list, num_attr);
    for (attr_index = 0; attr_index < num_attr; attr_index++)
    {
        attr_id = (uint32_t)va_arg(arg_list, uint32_t);
        switch (attr_id)
        {
            case OMCI_SVC_OMCI_ATTR_ID_NO_OF_ENTRIES:
                attr_val = va_arg(arg_list, uint32_t);
                num_vids_in_args = attr_val;
                BCM_OMCI_REQ_PROP_SET(&vlan_tag_filter_data_cfg, vlan_tag_filter_data, num_of_entries, attr_val);
                break;

            case OMCI_SVC_OMCI_ATTR_ID_VLAN_FILTER_TABLE:
                attr_val = va_arg(arg_list, uint32_t);
                uint16_t vlan_filter_entry = attr_val; /** @todo add support for PBIT and CFI */

                /** @note each element in the list in ME structure is of size U8.
                 * So need to map 2 bytes of vlan_filter_entry into 2 indices in the list
                 * @todo This byte conversion needs to be done for each 2 Bytes in the vlan_filter_list
                 * (since every 2 bytes is a vlan filter entry), if more than 1 entry is used.
                 */
                vlan_filter_list[num_vids*2] = (uint8_t) ((vlan_filter_entry >> 8) & 0xFF);
                vlan_filter_list[num_vids*2+1] = (uint8_t) (vlan_filter_entry & 0xFF);
                num_vids++;
                if (num_vids >= num_vids_in_args)
                {
                    BCM_OMCI_REQ_PROP_SET_ARRAY(&vlan_tag_filter_data_cfg, vlan_tag_filter_data, vlan_filter_list, vlan_filter_list, sizeof(vlan_filter_list));
                }
                break;

            case OMCI_SVC_OMCI_ATTR_ID_FORWARD_OPER:
                attr_val = va_arg(arg_list, uint32_t);
                BCM_OMCI_REQ_PROP_SET(&vlan_tag_filter_data_cfg, vlan_tag_filter_data, forward_oper, attr_val);
                break;

            default:
                BCM_LOG(ERROR, omci_svc_log_id, "%s: unhandled attr : %d\n", __FUNCTION__, attr_id);
                rc = BCM_ERR_PARM;
                break;
        }
    }
    va_end(arg_list);


    /* ME API Call: call ME layer api Create */
    if (BCM_ERR_OK == rc)
    {
        rc = bcm_omci_create_req(&vlan_tag_filter_data_cfg.hdr);
    }

    return rc;
}

/**
 * @brief adapter routine for VLAN Tag Filter Data Delete
 */
bcmos_errno omci_svc_omci_vlan_tag_filter_data_me_delete (bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint16_t entity_id)
{
    bcm_omci_me_key me_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni, 
        .onu_id = onu_id, 
        .entity_instance = entity_id,
        .cookie = omci_svc_omci_assign_op_ref(olt_id, pon_ni, onu_id),
        .entity_class = BCM_OMCI_ME_CLASS_VAL_VLAN_TAG_FILTER_DATA };

    /* ME API Call: call ME layer api Delete */
    return bcm_omci_delete_req(&me_key);
}

/**************************
 * Confirmations from Stack
 *************************/

/** @brief called by Stack for mib upload Rsp */
static void omci_svc_adapter_mib_upload_rsp(bcm_omci_me_hdr *me_hdr, bcm_omci_me_key *key,
    bcm_omci_result result, uint32_t me_count)
{
    /* call fsm */
    omci_svc_omci_mib_upload_cnf (key->olt_id, key->logical_pon, key->onu_id, result, me_count);

    /** @note BCM omci stack needs trigger from higher layer for mib upload next requests */
    key->cookie = omci_svc_omci_assign_op_ref(key->olt_id, key->logical_pon, key->onu_id);
    bcm_omci_mib_upload_next_req(key);
}

/** @brief called by Stack on receiving a MIB Upload Next Ind from ONU
 * @note result : OMCI_SVC_OMCI_RESULT_MORE. OMCI_SVC_OMCI_RESULT_LAST, or other values
 */
static void omci_svc_adapter_mib_upload_next_rsp (bcm_omci_me_hdr *me_hdr, bcm_omci_me_key *key,
    bcm_omci_result result, bcmos_bool is_last_mib_upload_in_q)
{
    omci_svc_omci_attrid_list attrid_list  = {};
    /** @todo get the attrid list; for now svc layer is not using it */

    if (result == BCM_OMCI_RESULT_CMD_PROC_SUCCESS)
        result = is_last_mib_upload_in_q ? BCM_OMCI_RESULT_IND_LAST : BCM_OMCI_RESULT_IND_MORE;

    /* call fsm */
    omci_svc_omci_mib_upload_next_ind (key->olt_id, key->logical_pon, key->onu_id,
                            result, me_hdr, &attrid_list);

    /* if last ind already came through, svc layer should no more request for any further mib upload */
    if ((BCMOS_FALSE == is_last_mib_upload_in_q) && (BCM_OMCI_RESULT_IND_MORE == result))
    {
        /** @note BCM omci stack needs trigger from higher layer for mib upload next requests */
        key->cookie = omci_svc_omci_assign_op_ref(key->olt_id, key->logical_pon, key->onu_id);
        bcm_omci_mib_upload_next_req(key);
    }
}

/* General response handler */
static void omci_svc_response_cb(bcm_omci_me_hdr *me_hdr)
{
    bcm_omci_me_key *key = &me_hdr->key;
    bcm_omci_result result = me_hdr->rsp.result;
    uint32_t attr_id = OMCI_SVC_OMCI_ATTR_ID_NONE;

    omci_svc_omci_attrid_list omci_svc_unsupp_attrid_list  = {};
    omci_svc_omci_attrid_list omci_svc_failed_attrid_list  = {};

    switch(me_hdr->omci_msg_type)
    {
        case BCM_OMCI_MSG_TYPE_CREATE:
            /* call fsm */
            omci_svc_omci_create_cnf(key->olt_id, key->logical_pon, key->onu_id,
                me_hdr->key.entity_class, key->entity_instance, result,
                &omci_svc_unsupp_attrid_list, &omci_svc_failed_attrid_list);
            break;

        case BCM_OMCI_MSG_TYPE_DELETE:
            omci_svc_omci_delete_cnf(key->olt_id, key->logical_pon, key->onu_id,
                me_hdr->key.entity_class, key->entity_instance, result);
            break;

        case BCM_OMCI_MSG_TYPE_SET:
        {
            uint32_t set_type = (uint32_t)(key->cookie & 0xffff0000);
            if (set_type == OMCI_SVC_OPER_SET)
            {
                omci_svc_omci_set_cnf(key->olt_id, key->logical_pon, key->onu_id,
                    me_hdr->key.entity_class, key->entity_instance, result,
                    NULL, &omci_svc_unsupp_attrid_list, &omci_svc_failed_attrid_list);
            }
            else if (set_type == OMCI_SVC_OPER_SET_ADD_ENTRY)
            {
                omci_svc_omci_add_entry_cnf(key->olt_id, key->logical_pon, key->onu_id,
                    me_hdr->key.entity_class, key->entity_instance, attr_id, result);
            }
            else if (set_type == OMCI_SVC_OPER_SET_REMOVE_ENTRY)
            {
                omci_svc_omci_remove_entry_cnf(key->olt_id, key->logical_pon, key->onu_id,
                    me_hdr->key.entity_class, key->entity_instance, attr_id, result);
            }
            else
            {
                BCM_LOG(ERROR, omci_svc_log_id, "Unexpected SET type in response: 0x%08x\n", set_type);
            }
            break;
        }

        case BCM_OMCI_MSG_TYPE_MIB_RESET:
            omci_svc_omci_mib_reset_cnf (key->olt_id, key->logical_pon, key->onu_id, result);
            break;

        /*
         * MIB upload events are handled in separate callback
         */

        default:
            BCM_LOG(ERROR, omci_svc_log_id, "Unexpected response type: 0x%08x(%s)\n",
                me_hdr->omci_msg_type, BCM_OMCI_MSG_TYPE_STR(me_hdr->omci_msg_type));
            break;
    }

    bcm_omci_me_free(me_hdr);
}

/* MIB upload event handler */
static void omci_svc_mib_upload_response_cb(bcm_omci_me_hdr *me_hdr, bcm_omci_mib_upload_response *data)
{
    bcm_omci_me_key *key = &me_hdr->key;
    bcm_omci_result result = me_hdr->rsp.result;

    switch(me_hdr->omci_msg_type)
    {
        case BCM_OMCI_MSG_TYPE_MIB_UPLOAD:
            omci_svc_adapter_mib_upload_rsp(me_hdr, key, result, data->mib_upload.me_count);
            break;

        case BCM_OMCI_MSG_TYPE_MIB_UPLOAD_NEXT:
            omci_svc_adapter_mib_upload_next_rsp(me_hdr, key, result, data->mib_upload_next.is_last);
            break;

        default:
            BCM_LOG(ERROR, omci_svc_log_id, "Unexpected response type: 0x%08x(%s)\n",
                me_hdr->omci_msg_type, BCM_OMCI_MSG_TYPE_STR(me_hdr->omci_msg_type));
            break;
    }
}


/**************************************************************************************
 * The following are the handlers for send & recv to / from the Maple for the OMCI msg.
 * These functions are used by Transport layer.
 *************************************************************************************/

/**
 *  @brief  adapter for omci msg send to Maple, called by transport layer
 */
static bcmos_errno omci_svc_transmit_cb(bcm_omci_me_key *key, void *msg_buf, uint16_t msg_len)
{
    void *msg_buf_array[] = { msg_buf };
    uint16_t msg_len_array[] = { msg_len };
    return omci_svc_omci_data_req(key->olt_id, key->logical_pon, key->onu_id, 1, msg_buf_array, msg_len_array);
}

/**
 *  @brief  adapter for omci msg recv handler called by maple in some sequence
 */
void omci_svc_omci_data_ind_itu_pon(
        bcmolt_oltid olt_id,
        bcmolt_interface pon_ni,
        bcmolt_onu_id onu_id,
        uint32_t packet_size,
        bcmolt_bin_str buffer)
{
    bcmos_errno rc;
    bcm_omci_me_key omci_msg_key = {
        .olt_id = olt_id,
        .logical_pon = pon_ni,
        .onu_id = onu_id
    };

    /** call transport layer */
    rc = bcm_omci_recv_msg (&omci_msg_key, buffer.arr, buffer.len);
    if (BCM_ERR_OK != rc)
    {
        BCM_LOG(ERROR, omci_svc_log_id,
                "%s: error returned by bcm_omci_recv_msg():"
                " key: pon=%d, onu_id=%d, rc=%s\n",
                __FUNCTION__, omci_msg_key.logical_pon, omci_msg_key.onu_id, bcmos_strerror(rc));
    }

    return;
}


/** @brief Broadcom stack Maple needs to insert CRC always */
bcmos_bool omci_svc_omci_is_olt_calc_crc(bcmolt_u8_list_u32_max_2048 *buf)
{
        /** @note  for BCM stack Maple always calculates & fills in CRC/MIC */
        return BCMOS_TRUE;
}


/** @brief workaround if OMCI stack does not insert the CRC : no-op for BCM stack */
void omci_svc_omci_update_xgpon_omci_buf_len(bcmolt_u8_list_u32_max_2048 *buf) { /* no-op */ }



/**************************************************
 * Helper functions
**************************************************/

/**
 * @brief Routines for reference counter for ME configs.
 *        For now, used mainly to track ME logs for debugging, for the Broadcom stack.
 *        For future, this could be a common correlation Id used between svc layer, ME layer
 *        & Transport layer for a ME configuration.
 */
uint16_t omci_svc_omci_assign_op_ref (bcmolt_oltid olt_id, uint8_t pon_id, uint8_t onu_id)
{
    omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, pon_id, onu_id);

    return ++onu_context->op_ref;
}
