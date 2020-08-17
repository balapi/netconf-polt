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

#include <bcmos_system.h>
#include <bcm_dev_log.h>
#include "omci_svc_adapter_common.h"
#include "omci_svc_common.h"

typedef struct
{
    bcmos_bool is_initialized;
    uint32_t logical_pon;
    uint32_t max_num_of_onus;             /* as per queried topology */
    void *context;                        /* User context for OMCI svc; has a list of ONU contexts for each logical pon */
} omci_svc_topo_pon_context_t;

typedef struct
{
    bcmos_bool is_initialized;
    uint32_t max_num_of_pons;             /* value stored from OLT topo query through bal api call */
    /** @todo aspen pon_family pon_sub_family not needed for bcm omci stack */
//    bcmbal_pon_family pon_family;         /* value stored from OLT topo query through bal api call */
//    bcmbal_pon_sub_family pon_sub_family; /* value stored from OLT topo query through bal api call */
    omci_svc_topo_pon_context_t *logical_pons; /** array of pointers */
} omci_svc_topo_context_t;

static omci_svc_topo_context_t omci_svc_topo_context[BCM_MAX_OLTS_PER_LINE_CARD+1];


bcmos_errno omci_svc_topo_init_context(bcmolt_oltid olt_id, uint8_t max_pon_for_olt)
{
    if (olt_id > BCM_MAX_OLTS_PER_LINE_CARD)
        return BCM_ERR_RANGE;

    /* assign memory to an array of pointers */
    /** initialize db based on max pons that the OLT topology is configured for */
    omci_svc_topo_context[olt_id].logical_pons = bcmos_calloc(max_pon_for_olt * sizeof(omci_svc_topo_pon_context_t));
    if (NULL == omci_svc_topo_context[olt_id].logical_pons)
    {
        BCM_LOG(ERROR, omci_svc_log_id, "Memory allocation failed for omci svc topo context \n");
        return BCM_ERR_NOMEM;
    }

    omci_svc_topo_context[olt_id].max_num_of_pons = max_pon_for_olt;

    return BCM_ERR_OK;
}

bcmos_errno omci_svc_topo_pon_set_context(bcmolt_oltid olt_id, uint32_t logical_pon_id, uint32_t max_num_of_onus, void *context)
{
    if (logical_pon_id >= omci_svc_topo_context[olt_id].max_num_of_pons)
        return BCM_ERR_RANGE;

    (omci_svc_topo_context[olt_id].logical_pons[logical_pon_id]).logical_pon = logical_pon_id;
    (omci_svc_topo_context[olt_id].logical_pons[logical_pon_id]).max_num_of_onus = max_num_of_onus;
    (omci_svc_topo_context[olt_id].logical_pons[logical_pon_id]).context = context;

    return BCM_ERR_OK;
}

void *omci_svc_topo_pon_get_context(bcmolt_oltid olt_id, uint32_t logical_pon_id)
{
    if (logical_pon_id >= omci_svc_topo_context[olt_id].max_num_of_pons)
        return NULL;

    return (omci_svc_topo_context[olt_id].logical_pons[logical_pon_id]).context;
}

/** @todo aspen: not needed for broadcom omci stack */
/** @note currently BAL topology query returns sub_family as global rather than on a pon basis */
//bcmbal_pon_sub_family omci_svc_topo_pon_get_sub_family(bcmolt_oltid olt_id, uint32_t logical_pon_id)
//{
//    if (logical_pon_id >= omci_svc_topo_context[olt_id].max_num_of_pons)
//        return BCMBAL_PON_SUB_FAMILY_INVALID;
//
//    return (omci_svc_topo_context[olt_id].pon_sub_family);
//}

bcmos_bool omci_svc_topo_pon_is_valid(bcmolt_oltid olt_id, uint32_t logical_pon_id)
{
    if (logical_pon_id >= omci_svc_topo_context[olt_id].max_num_of_pons)
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

bcmos_bool omci_svc_topo_pon_is_onu_id_valid(bcmolt_oltid olt_id, uint32_t logical_pon_id, bcmolt_pon_onu_id onu_id)
{
    if (logical_pon_id >= omci_svc_topo_context[olt_id].max_num_of_pons)
        return BCMOS_FALSE;

    return (onu_id < omci_svc_topo_context[olt_id].logical_pons[logical_pon_id].max_num_of_onus);
}



#ifdef ENABLE_LOG
dev_log_id omci_svc_log_id = DEV_LOG_INVALID_ID;
#endif

omci_svc_event_id2str_t omci_svc_event_id2str[] =
{
    {OMCI_SVC_EVENT_ID_ACTIVATE, "activate"},
    {OMCI_SVC_EVENT_ID_DEACTIVATE, "deactivate"},
    {OMCI_SVC_EVENT_ID_ACTIVATE_SUCCESS, "activate_success"},
    {OMCI_SVC_EVENT_ID_DEACTIVATE_SUCCESS, "deactivate_success"},
    {OMCI_SVC_EVENT_ID_MIB_RESET_SUCCESS, "mib_reset_success"},
    {OMCI_SVC_EVENT_ID_MIB_UPLOAD_INIT_SUCCESS, "mib_upload_init_success"},
    {OMCI_SVC_EVENT_ID_MIB_UPLOAD_MORE, "mib_upload_more"},
    {OMCI_SVC_EVENT_ID_MIB_UPLOAD_LAST, "mib_upload_last"},
    {OMCI_SVC_EVENT_ID_CREATE_SUCCESS, "create_success"},
    {OMCI_SVC_EVENT_ID_SET_SUCCESS, "set_success"},
    {OMCI_SVC_EVENT_ID_DELETE_SUCCESS, "delete_success"},
    {OMCI_SVC_EVENT_ID_ADD_ENTRY_SUCCESS, "add_entry_success"},
    {OMCI_SVC_EVENT_ID_REMOVE_ENTRY_SUCCESS, "remove_entry_success"},
    {OMCI_SVC_EVENT_ID_LINK_UP, "link_up"},
    {OMCI_SVC_EVENT_ID_LINK_DOWN, "link_down"},
    {OMCI_SVC_EVENT_ID_START, "start"},
    {OMCI_SVC_EVENT_ID_IS_ENTERED, "is_entered"},
    {-1}
};

bcmos_errno omci_svc_validate(bcmonu_mgmt_onu_key *key, bcmonu_mgmt_msg *msg)
{
    /** @note olt_id is already validated in onu mgmt as part of the api call */

    if (!OMCI_SVC_PON_IS_VALID(msg->olt_id, key->pon_ni))
    {
        BCM_LOG(ERROR, omci_svc_log_id, "PON interface ID is out of range\n");
        return BCM_ERR_PARM;
    }

    if (!OMCI_SVC_PON_IS_ONU_ID_VALID(msg->olt_id, key->pon_ni, key->onu_id))
    {
        BCM_LOG(ERROR, omci_svc_log_id, "ONU ID is out of range\n");
        if (msg)
            snprintf(msg->err_text, sizeof(msg->err_text), "ONU ID is out of range\n");
        return BCM_ERR_PARM;
    }

    return BCM_ERR_OK;
}

void omci_svc_omci_create_cnf(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id,
    uint16_t me_class_id, uint16_t entity_id, omci_svc_omci_result result,
    omci_svc_omci_attrid_list *unsupp_attr_id_list, omci_svc_omci_attrid_list *failed_attr_id_list)
{
    bcmonu_mgmt_onu_key _key = { .pon_ni = pon_ni, .onu_id = onu_id }, *key = &_key;
    omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, key->pon_ni, key->onu_id);

    if (result != OMCI_SVC_OMCI_RESULT_CMD_SUCCESS)
    {
        OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "Create request failed, me_id={class_id=%s:entity_id=%u}, omci result=%s(%u)\n", OMCI_SVC_OMCI_ME_CLASS_ID_STR(me_class_id), entity_id, omci_svc_omci_result2str_conv(result), result);
        onu_context->sm_rollback_cb(olt_id, key, omci_svc_omci_result2bcmos_errno_conv(result), NULL);
        return;
    }

    OMCI_SVC_LOG(DEBUG, olt_id, key, NULL, "Create request completed successfully, me_id={class_id=%s:entity_id=%u}\n", OMCI_SVC_OMCI_ME_CLASS_ID_STR(me_class_id), entity_id);
    onu_context->sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_CREATE_SUCCESS, key, NULL);
}

void omci_svc_omci_set_cnf(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id,
    uint16_t me_class_id, uint16_t entity_id, omci_svc_omci_result result,
    omci_svc_omci_attrid_list *attr_id_list, omci_svc_omci_attrid_list *unsupp_attr_id_list, omci_svc_omci_attrid_list *failed_attr_id_list)
{
    bcmonu_mgmt_onu_key _key = { .pon_ni = pon_ni, .onu_id = onu_id }, *key = &_key;
    omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, key->pon_ni, key->onu_id);

    if (result != OMCI_SVC_OMCI_RESULT_CMD_SUCCESS)
    {
        OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "Set request failed, me_id={class_id=%s:entity_id=%u}, omci result=%s(%u)\n", OMCI_SVC_OMCI_ME_CLASS_ID_STR(me_class_id), entity_id, omci_svc_omci_result2str_conv(result), result);
        onu_context->sm_rollback_cb(olt_id, key, omci_svc_omci_result2bcmos_errno_conv(result), NULL);
        return;
    }

    OMCI_SVC_LOG(DEBUG, olt_id, key, NULL, "Set request completed successfully, me_id={class_id=%s:entity_id=%u}\n", OMCI_SVC_OMCI_ME_CLASS_ID_STR(me_class_id), entity_id);
    onu_context->sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_SET_SUCCESS, key, NULL);
}

void omci_svc_omci_delete_cnf(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id,
    uint16_t me_class_id, uint16_t entity_id, omci_svc_omci_result result)
{
    bcmonu_mgmt_onu_key _key = { .pon_ni = pon_ni, .onu_id = onu_id }, *key = &_key;
    omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, key->pon_ni, key->onu_id);

    if (result != OMCI_SVC_OMCI_RESULT_CMD_SUCCESS)
    {
        OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "Delete request failed, me_id={class_id=%s:entity_id=%u}, omci result=%s(%u)\n", OMCI_SVC_OMCI_ME_CLASS_ID_STR(me_class_id), entity_id, omci_svc_omci_result2str_conv(result), result);
        onu_context->sm_rollback_cb(olt_id, key, omci_svc_omci_result2bcmos_errno_conv(result), NULL);
        return;
    }

    OMCI_SVC_LOG(DEBUG, olt_id, key, NULL, "Delete request completed successfully, me_id={class_id=%s:entity_id=%u}\n", OMCI_SVC_OMCI_ME_CLASS_ID_STR(me_class_id), entity_id);
    onu_context->sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_DELETE_SUCCESS, key, NULL);
}

void omci_svc_omci_add_entry_cnf(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id,
    uint16_t me_class_id, uint16_t entity_id, omci_svc_omci_attr_id attr_id, omci_svc_omci_result result)
{
    bcmonu_mgmt_onu_key _key = { .pon_ni = pon_ni, .onu_id = onu_id }, *key = &_key;
    omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, key->pon_ni, key->onu_id);

    if (result != OMCI_SVC_OMCI_RESULT_CMD_SUCCESS)
    {
        OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "Add entry request failed, me_id={class_id=%s:entity_id=%u}, omci result=%s(%u)\n", OMCI_SVC_OMCI_ME_CLASS_ID_STR(me_class_id), entity_id, omci_svc_omci_result2str_conv(result), result);
        onu_context->sm_rollback_cb(olt_id, key, omci_svc_omci_result2bcmos_errno_conv(result), NULL);
        return;
    }

    OMCI_SVC_LOG(DEBUG, olt_id, key, NULL, "Add entry request completed successfully, me_id={class_id=%s:entity_id=%u}\n", OMCI_SVC_OMCI_ME_CLASS_ID_STR(me_class_id), entity_id);
    onu_context->sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_ADD_ENTRY_SUCCESS, key, NULL);
}

void omci_svc_omci_remove_entry_cnf(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id,
    uint16_t me_class_id, uint16_t entity_id, omci_svc_omci_attr_id attr_id, omci_svc_omci_result result)
{
    bcmonu_mgmt_onu_key _key = { .pon_ni = pon_ni, .onu_id = onu_id }, *key = &_key;
    omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, key->pon_ni, key->onu_id);

    if (result != OMCI_SVC_OMCI_RESULT_CMD_SUCCESS)
    {
        OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "Remove entry request failed, me_id={class_id=%s:entity_id=%u}, omci result=%s(%u)\n", OMCI_SVC_OMCI_ME_CLASS_ID_STR(me_class_id), entity_id, omci_svc_omci_result2str_conv(result), result);
        onu_context->sm_rollback_cb(olt_id, key, omci_svc_omci_result2bcmos_errno_conv(result), NULL);
        return;
    }

    OMCI_SVC_LOG(DEBUG, olt_id, key, NULL, "Remove entry request completed successfully, me_id={class_id=%s:entity_id=%u}\n", OMCI_SVC_OMCI_ME_CLASS_ID_STR(me_class_id), entity_id);
    onu_context->sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_REMOVE_ENTRY_SUCCESS, key, NULL);
}

