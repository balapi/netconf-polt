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
#include <onu_mgmt_model_api_structs.h>
#include <onu_mgmt_model_funcs.h>
#include <omci_stack_model_types.h>
#include "omci_svc_adapter_common.h"
#include "omci_svc_common.h"
#include "omci_svc_onu.h"

#define OMCI_SVC_GAL_ETHERNET_PROFILE_MAX_GEM_PAYLOAD_SIZE 4095

#define OMCI_SVC_MAC_BRIDGE_SERVICE_PROFILE_DYNAMIC_FILTERING_AGEING_TIME 300
#define OMCI_SVC_MAC_BRIDGE_SERVICE_PROFILE_MAX_AGE                       0x1e00 /* 30s in units of 1/256s */
#define OMCI_SVC_MAC_BRIDGE_SERVICE_PROFILE_HELLO_TIME                    0x0500 /* 5s in units of 1/256 */
#define OMCI_SVC_MAC_BRIDGE_SERVICE_PROFILE_FORWARD_DELAY                 0x0500 /* 5s in units of 1/256 */
/* Instances above 4096 should have no conflicts with ANI side instances (Outer VID=0-4095 or no action=4096). */
#define OMCI_SVC_MAC_BRIDGE_PORT_CONFIG_DATA_UNI_INSTANCE_BASE 4097

#define OMCI_SVC_PRIORITY_QUEUE_ENTITY_ID_US_MASK 0x8000

/** @brief list of stored ONU config; used for admin up/down and clear of ONU config */
omci_svc_onu_cfg_db_t omci_svc_onu_cfg_db;

typedef void (*omci_svc_onu_sm_cb)(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context);

BCMOLT_TYPE2STR(omci_svc_onu_state_id, static)

static omci_svc_onu_state_id2str_t omci_svc_onu_state_id2str[] =
{
    /* Up direction */
    {OMCI_SVC_ONU_STATE_ID_INACTIVE, "inactive"},
    {OMCI_SVC_ONU_STATE_ID_ACTIVATING, "activating"},
    {OMCI_SVC_ONU_STATE_ID_WAIT_FOR_LINK_UP, "wait_for_link_up"},
    {OMCI_SVC_ONU_STATE_ID_MIB_RESET, "mib_reset"},
    {OMCI_SVC_ONU_STATE_ID_MIB_UPLOAD, "mib_upload"},
    {OMCI_SVC_ONU_STATE_ID_CREATE_GAL_ETHERNET_PROFILE, "create_gal_ethernet_profile"},
    {OMCI_SVC_ONU_STATE_ID_CREATE_EXT_VLAN_TAG_OPER_CFG_DATA, "create_ext_vlan_tag_oper_cfg_data"},
    {OMCI_SVC_ONU_STATE_ID_SET_EXT_VLAN_TAG_OPER_CFG_DATA, "set_ext_vlan_tag_oper_cfg_data"},
    {OMCI_SVC_ONU_STATE_ID_CREATE_MAC_BRIDGE_SERVICE_PROFILE, "create_mac_bridge_service_profile"},
    {OMCI_SVC_ONU_STATE_ID_CREATE_MAC_BRIDGE_PORT_CFG_DATA, "create_mac_bridge_port_cfg_data"},
    {OMCI_SVC_ONU_STATE_ID_CREATE_MULTICAST_OPERATIONS_PROFILE, "create_multicast_operations_profile"},
    {OMCI_SVC_ONU_STATE_ID_CREATE_MULTICAST_SUBSCRIBER_CONFIG_INFO, "create_multicast_subscriber_config_info"},
    {OMCI_SVC_ONU_STATE_ID_UP_SEQUENCE_END, "up_sequence_end"},
    {OMCI_SVC_ONU_STATE_ID_ACTIVE_WORKING, "active_working"},

    /* Down direction - no need to delete MEs, as we will do MIB reset when the ONU will be brought up again. */
    {OMCI_SVC_ONU_STATE_ID_DEACTIVATING, "deactivating"},
    {OMCI_SVC_ONU_STATE_ID_DOWN_SEQUENCE_END, "down_sequence_end"},
    {-1}
};

onu_state_changed_cb omci_onu_state_changed = NULL;

static void omci_svc_onu_sm_run_cb(bcmolt_oltid olt_id, omci_svc_event_id event, bcmonu_mgmt_onu_key *key, void *context);
static void omci_svc_onu_sm_rollback_cb(bcmolt_oltid olt_id, bcmonu_mgmt_onu_key *key, bcmos_errno last_err, void *context);


static omci_svc_onu_cfg_entry* omci_svc_sm_cfg_db_find_entry(bcmonu_mgmt_onu_cfg *onu)
{
    bcmonu_mgmt_onu_key *key = &onu->key;
    omci_svc_onu_cfg_entry *onu_cfg_iter;
    omci_svc_onu_cfg_entry *onu_cfg_tmp;

    TAILQ_FOREACH_SAFE(onu_cfg_iter, &omci_svc_onu_cfg_db, next, onu_cfg_tmp)
    {
        if ((onu_cfg_iter->cfg.key.pon_ni == key->pon_ni) && (onu_cfg_iter->cfg.key.onu_id == key->onu_id))
        {
            /* config exists in db */
            return onu_cfg_iter;
        }
    }

    return NULL;
}

static bcmos_errno  omci_svc_sm_cfg_db_update_entry(bcmonu_mgmt_onu_cfg *onu)
{
    omci_svc_onu_cfg_entry *onu_cfg_entry;

    onu_cfg_entry = omci_svc_sm_cfg_db_find_entry(onu);

    /* FSM run was success; store the onu cfg in db */
    if (NULL == onu_cfg_entry)
    {
        /* first time config */
        onu_cfg_entry = bcmos_calloc(sizeof(omci_svc_onu_cfg_entry));
        memcpy(&onu_cfg_entry->cfg, onu, sizeof(bcmonu_mgmt_onu_cfg));
        TAILQ_INSERT_TAIL(&omci_svc_onu_cfg_db, onu_cfg_entry, next);
    }
    else
    {
        /** config already exists, just update the admin_state; */
        onu_cfg_entry->cfg.data.admin_state = onu->data.admin_state;
    }


    return BCM_ERR_OK;
}

static bcmos_errno omci_svc_sm_cfg_db_clear_entry(bcmonu_mgmt_onu_cfg *onu)
{
    bcmonu_mgmt_onu_key *key = &onu->key;
    omci_svc_onu_cfg_entry *onu_cfg_iter;
    omci_svc_onu_cfg_entry *onu_cfg_tmp;
    bcmolt_oltid olt_id = onu->hdr.hdr.olt_id;

    TAILQ_FOREACH_SAFE(onu_cfg_iter, &omci_svc_onu_cfg_db, next, onu_cfg_tmp)
    {
        if ((onu_cfg_iter->cfg.key.pon_ni == key->pon_ni) && (onu_cfg_iter->cfg.key.onu_id == key->onu_id))
        {
            TAILQ_REMOVE(&omci_svc_onu_cfg_db, onu_cfg_iter, next);
            bcmos_free(onu_cfg_iter);
            OMCI_SVC_LOG(INFO, olt_id, key, &onu->hdr.hdr, "onu entry Clear success\n");
            break;
        }
    }
    if (NULL == onu_cfg_iter)
    {
        OMCI_SVC_LOG(ERROR, olt_id, key, &onu->hdr.hdr, "onu entry Clear failed (entry was not found after admin down)\n");
        return BCM_ERR_INTERNAL;
    }

    return BCM_ERR_OK;
}

bcmos_errno omci_svc_onu_set(bcmonu_mgmt_onu_cfg *onu, bcmonu_mgmt_complete_cb cb, void *context)
{
    bcmos_errno rc;
    bcmonu_mgmt_onu_key *key = &onu->key;
    bcmolt_oltid olt_id = onu->hdr.hdr.olt_id;
    omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, key->pon_ni, key->onu_id);
    uint16_t input_tpid;
    uint16_t output_tpid;
    bcmonu_mgmt_admin_state admin_state;

    /* Validation */
    rc = omci_svc_validate(key, &onu->hdr.hdr);
    if (rc)
    {
        return rc;
    }

    /* validate cfg fields */
    if (BCMONU_MGMT_FIELD_IS_SET(&onu->data, onu_cfg_data, downstream_mode))
    {
        if ((OMCI_SVC_OMCI_EXT_VLAN_DS_MODE_INVERSE != (uint8_t)onu->data.downstream_mode) &&
            (OMCI_SVC_OMCI_EXT_VLAN_DS_MODE_MATCH_INVERSE_ON_VID_DEFAULT_FORWARD != (uint8_t)onu->data.downstream_mode) &&
            (OMCI_SVC_OMCI_EXT_VLAN_DS_MODE_MATCH_INVERSE_ON_VID_DEFAULT_DISCARD != (uint8_t)onu->data.downstream_mode))
        {
            OMCI_SVC_LOG(ERROR, olt_id, key, &onu->hdr.hdr, "ONU cfg downstrem_mode value %d is not supported\n", onu->data.downstream_mode);
            return BCM_ERR_NOT_SUPPORTED;
        }
    }
    else
    {
        /* default */
        onu->data.downstream_mode = OMCI_SVC_OMCI_EXT_VLAN_DS_MODE_INVERSE;
        OMCI_SVC_LOG(INFO, olt_id, key, &onu->hdr.hdr, "ONU cfg downstrem_mode default value is %d\n", onu->data.downstream_mode);
    }


    /* For now no need to find any stored config for the onu */

    input_tpid = BCMONU_MGMT_FIELD_IS_SET(&onu->data, onu_cfg_data, input_tpid) ? onu->data.input_tpid : onu_context->mib.input_tpid;
    output_tpid = BCMONU_MGMT_FIELD_IS_SET(&onu->data, onu_cfg_data, output_tpid) ? onu->data.output_tpid : onu_context->mib.output_tpid;
    admin_state = BCMONU_MGMT_FIELD_IS_SET(&onu->data, onu_cfg_data, admin_state) ? onu->data.admin_state : onu_context->admin_state;

    if (input_tpid != onu_context->mib.input_tpid || output_tpid != onu_context->mib.output_tpid)
    {
        if (onu_context->state != OMCI_SVC_ONU_STATE_ID_INACTIVE)
        {
            OMCI_SVC_LOG(ERROR, olt_id, key, &onu->hdr.hdr, "ONU must be inactive to set input or output TPIDs\n");
            return BCM_ERR_STATE;
        }
        if (admin_state != onu_context->admin_state)
        {
            OMCI_SVC_LOG(ERROR, olt_id, key, &onu->hdr.hdr, "Set of input or output TPIDs should not be combined with a change in admin state\n");
            return BCM_ERR_STATE;
        }
    }

    /* Action */
    onu_context->mib.input_tpid = input_tpid;
    onu_context->mib.output_tpid = output_tpid;

    /* Verify that the requested admin_state is different from current admin state */
    if (admin_state == onu_context->admin_state)
    {
        OMCI_SVC_LOG(INFO, olt_id, key, &onu->hdr.hdr, "No state change for ONU SET request (requested admin_state='%s', current admin_state=%s) (current oper_status='%s')\n",
             (admin_state == BCMONU_MGMT_ADMIN_STATE_UP ? "up" : "down"),
             (onu_context->admin_state == BCMONU_MGMT_ADMIN_STATE_UP ? "up" : "down"),
             (onu_context->oper_status == BCMONU_MGMT_STATUS_UP ? "up" : "down"));

        return BCM_ERR_OK;
    }

    /* Update the current status */
    onu_context->admin_state = admin_state;
    /* store the onu cfg in current context for FSM to access it */
#if 0
    memcpy(&onu_context->onu_cfg, onu, sizeof(bcmonu_mgmt_onu_cfg));
#else
    /* copy onu to onu_context_cfg, because onu is an arg on stack */
    if (NULL != onu_context->onu_cfg)
    {
        memcpy(onu_context->onu_cfg, onu, sizeof(bcmonu_mgmt_onu_cfg));
    }
    else
    {
        onu_context->onu_cfg = bcmos_calloc(sizeof(bcmonu_mgmt_onu_cfg));
        if (NULL == onu_context->onu_cfg)
        {
            OMCI_SVC_LOG(ERROR, olt_id, key, &onu->hdr.hdr, "memory alloc failed for onu_context->onu_cfg\n");
            return BCM_ERR_NOMEM;
        }
        memcpy(onu_context->onu_cfg, onu, sizeof(bcmonu_mgmt_onu_cfg));
    }
#endif


    OMCI_SVC_LOG(INFO, olt_id, key, &onu->hdr.hdr, "ONU SET request (admin_state='%s') (current oper_status='%s')\n",
         (admin_state == BCMONU_MGMT_ADMIN_STATE_UP ? "up" : "down"),
         (onu_context->oper_status == BCMONU_MGMT_STATUS_UP ? "up" : "down"));

    if (admin_state == BCMONU_MGMT_ADMIN_STATE_UP)
    {
        /* reset op_ref if admin request is UP */
        onu_context->op_ref = 0;
    }
    onu_context->cb = cb;
    onu_context->context = context;
    onu_context->last_err = BCM_ERR_OK;
    onu_context->sm_run_cb = omci_svc_onu_sm_run_cb;
    onu_context->sm_rollback_cb = omci_svc_onu_sm_rollback_cb;

    /* run ONU fsm */
    if (admin_state == BCMONU_MGMT_ADMIN_STATE_UP)
        omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_ACTIVATE, key, NULL);
    else
    {
        /* If ONU is deactivated, then all pending flow operations should be discarded.
         * This will happen by checking the ONU's state when processing flow operations. */
        omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_DEACTIVATE, key, NULL);
    }

    return BCM_ERR_OK;
}

bcmos_errno omci_svc_onu_get(bcmonu_mgmt_onu_cfg *onu)
{
    bcmonu_mgmt_onu_key *key = &onu->key;
    bcmolt_oltid olt_id = onu->hdr.hdr.olt_id;
    omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, key->pon_ni, key->onu_id);
    bcmos_errno rc;
    omci_svc_onu_cfg_entry *onu_cfg_entry = NULL;

    /* Validation */
    rc = omci_svc_validate(key, &onu->hdr.hdr);
    if (rc)
        return rc;

    /* Find any stored config for the onu */
    onu_cfg_entry = omci_svc_sm_cfg_db_find_entry(onu);
    if (NULL == onu_cfg_entry)
    {
        OMCI_SVC_LOG(ERROR, olt_id, key, &onu->hdr.hdr, "onu entry not found\n");
        return BCM_ERR_NOENT;
    }


    /* Action */
    if (BCMONU_MGMT_FIELD_IS_SET(&onu->data, onu_cfg_data, admin_state))
        onu->data.admin_state = onu_context->admin_state;
    if (BCMONU_MGMT_FIELD_IS_SET(&onu->data, onu_cfg_data, oper_status))
        onu->data.oper_status = onu_context->oper_status;
    if (BCMONU_MGMT_FIELD_IS_SET(&onu->data, onu_cfg_data, input_tpid))
        onu->data.input_tpid = onu_context->mib.input_tpid;
    if (BCMONU_MGMT_FIELD_IS_SET(&onu->data, onu_cfg_data, output_tpid))
        onu->data.output_tpid = onu_context->mib.output_tpid;
    if (BCMONU_MGMT_FIELD_IS_SET(&onu->data, onu_cfg_data, unis))
    {
        omci_svc_uni *uni_iter;
        uint32_t i = 0;

        TAILQ_FOREACH(uni_iter, &onu_context->mib.unis, next)
            onu->data.unis.arr[i++] = uni_iter->uni;
        onu->data.num_of_unis = onu_context->mib.num_of_unis;
    }
    if (BCMONU_MGMT_FIELD_IS_SET(&onu->data, onu_cfg_data, agg_ports))
    {
        omci_svc_tcont *tcont_iter;
        uint32_t i = 0;

        TAILQ_FOREACH(tcont_iter, &onu_context->mib.free_tconts, next)
            onu->data.agg_ports.arr[i++] = tcont_iter->tcont;
        TAILQ_FOREACH(tcont_iter, &onu_context->mib.used_tconts, next)
            onu->data.agg_ports.arr[i++] = tcont_iter->tcont;
        onu->data.num_of_agg_ports = onu_context->mib.num_of_tconts;
    }
    if (BCMONU_MGMT_FIELD_IS_SET(&onu->data, onu_cfg_data, us_priority_queues))
    {
        omci_svc_priority_queue *us_priority_queue_iter;
        uint32_t i = 0;

        TAILQ_FOREACH(us_priority_queue_iter, &onu_context->mib.us_priority_queues, next)
            onu->data.us_priority_queues.arr[i++] = us_priority_queue_iter->queue;
        onu->data.num_of_us_priority_queues = onu_context->mib.num_of_us_priority_queues;
    }
    if (BCMONU_MGMT_FIELD_IS_SET(&onu->data, onu_cfg_data, ds_priority_queues))
    {
        omci_svc_priority_queue *ds_priority_queue_iter;
        uint32_t i = 0;

        TAILQ_FOREACH(ds_priority_queue_iter, &onu_context->mib.ds_priority_queues, next)
            onu->data.ds_priority_queues.arr[i++] = ds_priority_queue_iter->queue;
        onu->data.num_of_ds_priority_queues = onu_context->mib.num_of_ds_priority_queues;
    }
    if (BCMONU_MGMT_FIELD_IS_SET(&onu->data, onu_cfg_data, downstream_mode))
    {
        onu->data.downstream_mode = onu_cfg_entry->cfg.data.downstream_mode;
    }

    return BCM_ERR_OK;
}


bcmos_errno omci_svc_onu_clear(bcmonu_mgmt_onu_cfg *onu, bcmonu_mgmt_complete_cb cb, void *context)
{
    bcmos_errno rc;
    bcmonu_mgmt_onu_key *key = &onu->key;
    bcmolt_oltid olt_id = onu->hdr.hdr.olt_id;
    omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, key->pon_ni, key->onu_id);
    omci_svc_onu_cfg_entry *onu_cfg_entry = NULL;
    bcmonu_mgmt_onu_cfg onu_cfg_new = {};

    /* Validation */
    rc = omci_svc_validate(key, &onu->hdr.hdr);
    if (rc)
    {
        if (!omci_svc_is_issu)
        {
            /** return validation error only if it not in issu mode */
            return rc;
        }
    }

    /* Find any stored config for the onu */
    onu_cfg_entry = omci_svc_sm_cfg_db_find_entry(onu);
    if (NULL == onu_cfg_entry)
    {
        if (omci_svc_is_issu)
        {
            /** @note dummy issu; just need to return OK and print some standard prints */
            OMCI_SVC_LOG(INFO, olt_id, key, &onu->hdr.hdr, "issu stub mode: onu entry Clear success\n");
            return BCM_ERR_OK;
        }
        else
        {
            OMCI_SVC_LOG(ERROR, olt_id, key, &onu->hdr.hdr, "onu entry not found\n");
            return BCM_ERR_NOENT;
        }
    }

    /* set clear flag */
    onu_context->is_clear = BCMOS_TRUE;

    /* now first admin down the ONU side */
    memcpy(&onu_cfg_new, &onu_cfg_entry->cfg, sizeof(bcmonu_mgmt_onu_cfg));
    onu_cfg_new.data.admin_state = BCMONU_MGMT_ADMIN_STATE_DOWN;
    rc = omci_svc_onu_set(&onu_cfg_new, cb, context);

    return rc;
}


static void omci_svc_state_onu_inactive_event_activate(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    bcmos_errno rc;
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;

    rc = omci_svc_omci_activate_req(olt_id, key->pon_ni, key->onu_id);
    if (rc != BCM_ERR_OK)
    {
        OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "omci_svc_omci_activate_req() failed, rc=%s\n", bcmos_strerror(rc));
        omci_svc_onu_sm_rollback_cb(olt_id, key, rc, NULL);
        return;
    }
    omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, key, NULL);
}

static void omci_svc_state_onu_inactive_event_deactivate(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;

    /* Before clearing a ONU, we first deactivate it, so OF-PAL may call omci_svc_onu_state_changed() twice. We should ignore the 2nd time. */
    OMCI_SVC_LOG(DEBUG, olt_id, key, NULL, "ONU already inactive, ignoring\n");
}

static void omci_svc_state_activating_event_is_entered(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    /** call adapter layer function to check if it should enter this state or not */
    *(bcmos_bool *)context = omci_svc_omci_if_support_activate();
}

static void omci_svc_state_activating_event_start(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
}

static void omci_svc_state_activating_event_success(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;
    omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, key, NULL);
}

static void omci_svc_state_wait_for_link_up_event_is_entered(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    *(bcmos_bool *)context = omci_svc_omci_if_support_link_up();
}

static void omci_svc_state_wait_for_link_up_event_start(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
}

static void omci_svc_state_wait_for_link_up_event_link_up(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;
    omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, key, NULL);
}

static void omci_svc_state_mib_reset_event_is_entered(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    *(bcmos_bool *)context = BCMOS_TRUE;
}

static void omci_svc_state_mib_reset_event_start(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    bcmos_errno rc;
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;

    rc = omci_svc_omci_mib_reset_req(olt_id, key->pon_ni, key->onu_id);
    if (rc != BCM_ERR_OK)
    {
        OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "omci_svc_omci_mib_reset_req() failed, rc=%s\n", bcmos_strerror(rc));
        omci_svc_onu_sm_rollback_cb(olt_id, key, rc, NULL);
    }
}

static void omci_svc_state_mib_reset_event_success(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;
    omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, key, NULL);
}

static void omci_svc_state_mib_upload_event_is_entered(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    *(bcmos_bool *)context = BCMOS_TRUE;
}

static void omci_svc_state_mib_upload_event_start(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    bcmos_errno rc;
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;

    rc = omci_svc_omci_mib_upload_req(olt_id, key->pon_ni, key->onu_id);
    if (rc != BCM_ERR_OK)
    {
        OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "omci_svc_omci_mib_upload_req() failed, rc=%s\n", bcmos_strerror(rc));
        omci_svc_onu_sm_rollback_cb(olt_id, key, rc, NULL);
    }
}

static void omci_svc_onu_mib_flush(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context)
{
    omci_svc_uni *uni_iter, *uni_tmp;
    omci_svc_tcont *tcont_iter, *tcont_tmp;
    omci_svc_priority_queue *priority_queue_iter, *priority_queue_tmp;
    omci_svc_o_vid *o_vid_iter, *o_vid_tmp;
    omci_svc_o_vid_uni *o_vid_uni_iter, *o_vid_uni_tmp;
    omci_svc_gem_port *gem_port_iter, *gem_port_tmp;
    omci_svc_mac_bridge_port *mac_bridge_port_iter, *mac_bridge_port_tmp;

    /* UNI */
    TAILQ_FOREACH_SAFE(uni_iter, &onu_context->mib.unis, next, uni_tmp)
    {
        TAILQ_REMOVE(&onu_context->mib.unis, uni_iter, next);
        onu_context->mib.num_of_unis--;
        bcmos_free(uni_iter);
    }

    /* TCONT */
    TAILQ_FOREACH_SAFE(tcont_iter, &onu_context->mib.free_tconts, next, tcont_tmp)
    {
        TAILQ_REMOVE(&onu_context->mib.free_tconts, tcont_iter, next);
        onu_context->mib.num_of_tconts--;
        bcmos_free(tcont_iter);
    }
    TAILQ_FOREACH_SAFE(tcont_iter, &onu_context->mib.used_tconts, next, tcont_tmp)
    {
        TAILQ_REMOVE(&onu_context->mib.used_tconts, tcont_iter, next);
        onu_context->mib.num_of_tconts--;
        bcmos_free(tcont_iter);
    }

    /* US priority queue */
    TAILQ_FOREACH_SAFE(priority_queue_iter, &onu_context->mib.us_priority_queues, next, priority_queue_tmp)
    {
        TAILQ_REMOVE(&onu_context->mib.us_priority_queues, priority_queue_iter, next);
        onu_context->mib.num_of_us_priority_queues--;
        bcmos_free(priority_queue_iter);
    }

    /* DS priority queue */
    TAILQ_FOREACH_SAFE(priority_queue_iter, &onu_context->mib.ds_priority_queues, next, priority_queue_tmp)
    {
        TAILQ_REMOVE(&onu_context->mib.ds_priority_queues, priority_queue_iter, next);
        onu_context->mib.num_of_ds_priority_queues--;
        bcmos_free(priority_queue_iter);
    }

    /* Outer VIDs */
    DLIST_FOREACH_SAFE(o_vid_iter, &onu_context->mib.o_vids, next, o_vid_tmp)
    {
        DLIST_REMOVE(o_vid_iter, next);
        bcmos_free(o_vid_iter);
    }

    /* ovid+uni entries */
    DLIST_FOREACH_SAFE(o_vid_uni_iter, &onu_context->mib.o_vid_unis, next, o_vid_uni_tmp)
    {
        DLIST_REMOVE(o_vid_uni_iter, next);
        bcmos_free(o_vid_uni_iter);
    }

    /* GEM ports */
    DLIST_FOREACH_SAFE(gem_port_iter, &onu_context->mib.gem_ports, next, gem_port_tmp)
    {
        DLIST_REMOVE(gem_port_iter, next);
        bcmos_free(gem_port_iter);
    }

    /* MAC bridge ports */
    TAILQ_FOREACH_SAFE(mac_bridge_port_iter, &onu_context->mib.used_mac_bridge_ports, next, mac_bridge_port_tmp)
    {
        TAILQ_REMOVE(&onu_context->mib.used_mac_bridge_ports, mac_bridge_port_iter, next);
        TAILQ_INSERT_TAIL(&onu_context->mib.free_mac_bridge_ports, mac_bridge_port_iter, next);
        mac_bridge_port_iter->entity_id = 0;
    }

    /* reset the vid+uni entity id generator */
    onu_context->o_vid_uni_entity_id_gen = 0;
}

static void omci_svc_state_mib_upload_event_init_success(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    omci_svc_onu_mib_flush(key, onu_context);
}

void omci_svc_mib_upload_add_uni(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, uint16_t entity_id, bcmonu_mgmt_uni_type type)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;

    if (onu_context->mib.num_of_unis > BCMONU_MGMT_ONU_CFG_DATA_UNIS_LENGTH)
    {
        OMCI_SVC_LOG(WARNING, olt_id, key, NULL, "ONU has more than %u UNIs, UNI index=%u with entity ID=%u is ignored\n", BCMONU_MGMT_ONU_CFG_DATA_UNIS_LENGTH,
            entity_id & OMCI_SVC_ETH_UNI_PORT_ID_MASK, entity_id);
    }
    else
    {
        omci_svc_uni *uni;

        uni = bcmos_calloc(sizeof(*uni));
        if (!uni)
        {
            BCM_LOG(ERROR, omci_svc_log_id, "Memory allocation failed (sizeof=%u)\n", (uint32_t)sizeof(*uni));
            return;
        }
        uni->uni.entity_id = entity_id;
        uni->uni.type = type;

        /* uni index is assigned on first come first serve basis */
        OMCI_SVC_LOG(DEBUG, olt_id, key, NULL, "Adding %s UNI index=%u with entity ID=%u\n", type == BCMONU_MGMT_UNI_TYPE_PPTP ? "PPTP" : "VEIP",
        onu_context->mib.num_of_unis, uni->uni.entity_id);
        onu_context->mib.num_of_unis++;
        TAILQ_INSERT_TAIL(&onu_context->mib.unis, uni, next);
    }
}

void omci_svc_mib_upload_add_tcont(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, uint16_t entity_id)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;

    if (onu_context->mib.num_of_tconts == BCMONU_MGMT_ONU_CFG_DATA_AGG_PORTS_LENGTH - 1)
        OMCI_SVC_LOG(WARNING, olt_id, key, NULL, "ONU has more than %u TCONTs, TCONT with entity ID=%u is ignored\n", BCMONU_MGMT_ONU_CFG_DATA_AGG_PORTS_LENGTH, entity_id);
    else
    {
        omci_svc_tcont *tcont;

        tcont = bcmos_calloc(sizeof(*tcont));
        if (!tcont)
        {
            BCM_LOG(ERROR, omci_svc_log_id, "Memory allocation failed (sizeof=%u)\n", (uint32_t)sizeof(*tcont));
            return;
        }
        tcont->tcont.entity_id = entity_id;

        OMCI_SVC_LOG(DEBUG, olt_id, key, NULL, "Adding TCONT with entity ID=%u\n", tcont->tcont.entity_id);
        onu_context->mib.num_of_tconts++;
        TAILQ_INSERT_TAIL(&onu_context->mib.free_tconts, tcont, next);
    }
}

void omci_svc_mib_upload_add_priority_queue(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, uint16_t entity_id, uint16_t port)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;
    bcmos_bool is_us = entity_id & OMCI_SVC_PRIORITY_QUEUE_ENTITY_ID_US_MASK;

    if ((is_us && onu_context->mib.num_of_us_priority_queues == BCMONU_MGMT_ONU_CFG_DATA_US_PRIORITY_QUEUES_LENGTH - 1) ||
        (!is_us && onu_context->mib.num_of_ds_priority_queues == BCMONU_MGMT_ONU_CFG_DATA_DS_PRIORITY_QUEUES_LENGTH - 1))
    {
        OMCI_SVC_LOG(WARNING, olt_id, key, NULL, "ONU has more than %u %s priority queues, priority queue with entity ID=%u is ignored\n",
            is_us ? BCMONU_MGMT_ONU_CFG_DATA_US_PRIORITY_QUEUES_LENGTH : BCMONU_MGMT_ONU_CFG_DATA_DS_PRIORITY_QUEUES_LENGTH,
            is_us ? "US" : "DS", entity_id);
    }
    else
    {
        omci_svc_priority_queue *priority_queue;

        priority_queue = bcmos_calloc(sizeof(*priority_queue));
        if (!priority_queue)
        {
            BCM_LOG(ERROR, omci_svc_log_id, "Memory allocation failed (sizeof=%u)\n", (uint32_t)sizeof(*priority_queue));
            return;
        }
        priority_queue->queue.entity_id = entity_id;
        priority_queue->queue.port = port;

        if (entity_id & OMCI_SVC_PRIORITY_QUEUE_ENTITY_ID_US_MASK)
        {
            OMCI_SVC_LOG(DEBUG, olt_id, key, NULL, "Adding upstream priority queue with entity ID=%u associated with TCONT=%u\n", priority_queue->queue.entity_id, priority_queue->queue.port);
            onu_context->mib.num_of_us_priority_queues++;
            TAILQ_INSERT_TAIL(&onu_context->mib.us_priority_queues, priority_queue, next);
        }
        else
        {
            OMCI_SVC_LOG(DEBUG, olt_id, key, NULL, "Adding downstream priority queue with entity ID=%u associated with UNI=%u\n",
                priority_queue->queue.entity_id, priority_queue->queue.port);
            onu_context->mib.num_of_ds_priority_queues++;
            TAILQ_INSERT_TAIL(&onu_context->mib.ds_priority_queues, priority_queue, next);
        }
    }
}

static void omci_svc_state_mib_upload_event_more(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    omci_svc_omci_mib_upload_analyze (key, onu_context, context);
}

static bcmos_errno omci_svc_mib_upload_validate(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;
    omci_svc_priority_queue *priority_queue_iter;

    /* Validate that ONU has at least one UNI (PPTP/VEIP). */
    if (TAILQ_EMPTY(&onu_context->mib.unis))
    {
        OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "ONU has neither PPTP UNIs nor Virtual Ethernet Interface Points\n");
        return BCM_ERR_NOT_SUPPORTED;
    }

    /* Validate that ONU has at least one TCONT. */
    if (TAILQ_EMPTY(&onu_context->mib.free_tconts))
    {
        OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "ONU has no TCONTS\n");
        return BCM_ERR_NOENT;
    }

    /* Validate that ONU has at least one upstream priority queue. */
    if (TAILQ_EMPTY(&onu_context->mib.us_priority_queues))
    {
        OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "ONU has no upstream priority queues\n");
        return BCM_ERR_NOENT;
    }

    /* Validate that ONU has at least one downstream priority queue. */
    if (TAILQ_EMPTY(&onu_context->mib.ds_priority_queues))
    {
        OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "ONU has no downstream priority queues\n");
        return BCM_ERR_NOENT;
    }

    /* Validate that all upstream priority queues are associated with existing TCONTs. */
    TAILQ_FOREACH(priority_queue_iter, &onu_context->mib.us_priority_queues, next)
    {
        omci_svc_tcont *tcont_iter;

        TAILQ_FOREACH(tcont_iter, &onu_context->mib.free_tconts, next)
        {
            if (tcont_iter->tcont.entity_id == priority_queue_iter->queue.port)
                break;
        }
        if (!tcont_iter)
        {
            /* Try the used TCONTS (if there is more than one TCONT, we assume the first one is the TCONT for OMCI channel, so it moves to the used TCONTs list). */
            tcont_iter = TAILQ_FIRST(&onu_context->mib.used_tconts);
            if (tcont_iter && tcont_iter->tcont.entity_id != priority_queue_iter->queue.port)
                tcont_iter = NULL;
        }

        if (!tcont_iter)
        {
            OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "Priority queue=%u is associated with TCONT=%u which doesn't exist\n",
                priority_queue_iter->queue.entity_id, priority_queue_iter->queue.port);
            return BCM_ERR_NOENT;
        }
    }

    /* Validate that all downstream priority queues are associated with existing UNIs. */
    TAILQ_FOREACH(priority_queue_iter, &onu_context->mib.ds_priority_queues, next)
    {
        omci_svc_uni *uni_iter;

        TAILQ_FOREACH(uni_iter, &onu_context->mib.unis, next)
        {
            if (uni_iter->uni.entity_id == priority_queue_iter->queue.port)
                break;
        }
        if (!uni_iter)
        {
            OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "Priority queue=%u is associated with UNI=%u which doesn't exist\n",
                priority_queue_iter->queue.entity_id, priority_queue_iter->queue.port);
            return BCM_ERR_NOENT;
        }
    }

    return BCM_ERR_OK;
}

static void omci_svc_state_mib_upload_event_last(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    bcmos_errno rc;
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;

    omci_svc_omci_mib_upload_analyze(key, onu_context, context);

    rc = omci_svc_mib_upload_validate(key, onu_context);
    if (rc != BCM_ERR_OK)
    {
        omci_svc_onu_sm_rollback_cb(olt_id, key, rc, NULL);
        return;
    }

    omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, key, NULL);
}
static void omci_svc_state_create_gal_ethernet_profile_event_is_entered(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    *(bcmos_bool *)context = BCMOS_TRUE;
}

static void omci_svc_state_create_gal_ethernet_profile_event_start(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;
    omci_svc_omci_gal_eth_prof_me_create(olt_id, key->pon_ni, key->onu_id, 1, 1,
        OMCI_SVC_OMCI_ATTR_ID_MAX_GEM_PAYLOAD_SIZE, OMCI_SVC_GAL_ETHERNET_PROFILE_MAX_GEM_PAYLOAD_SIZE);
}

static void omci_svc_state_create_gal_ethernet_profile_event_success(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;
    omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, key, NULL);
}

static void omci_svc_ext_vlan_tag_oper_cfg_data_create(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, omci_svc_uni *uni)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;
    omci_svc_omci_ext_vlan_tag_oper_config_data_me_create(olt_id, key->pon_ni, key->onu_id, uni->uni.entity_id, 2,
        OMCI_SVC_OMCI_ATTR_ID_ASSOC_TYPE, uni->uni.type == BCMONU_MGMT_UNI_TYPE_PPTP ? OMCI_SVC_OMCI_EXT_VLAN_ASSOC_TYPE_ETH_FLOW_TP : OMCI_SVC_OMCI_EXT_VLAN_ASSOC_TYPE_VIRTUAL_ETH_INTF,
        OMCI_SVC_OMCI_ATTR_ID_ASSOC_ME_PTR, uni->uni.entity_id);
}

static void omci_svc_state_create_ext_vlan_tag_oper_cfg_data_event_is_entered(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    *(bcmos_bool *)context = BCMOS_TRUE;
}

static void omci_svc_state_create_ext_vlan_tag_oper_cfg_data_event_start(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    omci_svc_uni *uni_iter;

    /* We have one Extended VLAN Tagging Operation Configuration Data ME per each UNI, so we need to traverse UNIs. */
    uni_iter = TAILQ_FIRST(&onu_context->mib.unis);
    onu_context->iter = uni_iter;
    omci_svc_ext_vlan_tag_oper_cfg_data_create(key, onu_context, uni_iter);
}

static void omci_svc_state_create_ext_vlan_tag_oper_cfg_data_event_success(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    omci_svc_uni *uni_iter = onu_context->iter;
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;

    uni_iter = TAILQ_NEXT(uni_iter, next);
    onu_context->iter = uni_iter;
    if (uni_iter)
        omci_svc_ext_vlan_tag_oper_cfg_data_create(key, onu_context, uni_iter);
    else
        omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, key, NULL);
}

static void omci_svc_ext_vlan_tag_oper_cfg_data_set(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, omci_svc_uni *uni)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;
    omci_svc_omci_ext_vlan_tag_oper_config_data_me_set(olt_id, key->pon_ni, key->onu_id, uni->uni.entity_id, 3,
        OMCI_SVC_OMCI_ATTR_ID_INPUT_TPID, onu_context->mib.input_tpid,
        OMCI_SVC_OMCI_ATTR_ID_OUTPUT_TPID, onu_context->mib.output_tpid,
        OMCI_SVC_OMCI_ATTR_ID_DS_MODE, onu_context->onu_cfg->data.downstream_mode);
}

static void omci_svc_state_set_ext_vlan_tag_oper_cfg_data_event_is_entered(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    *(bcmos_bool *)context = BCMOS_TRUE;
}

static void omci_svc_state_set_ext_vlan_tag_oper_cfg_data_event_start(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    omci_svc_uni *uni_iter;

    /* We have one Extended VLAN Tagging Operation Configuration Data ME per each UNI, so we need to traverse UNIs. */
    uni_iter = TAILQ_FIRST(&onu_context->mib.unis);
    onu_context->iter = uni_iter;
    omci_svc_ext_vlan_tag_oper_cfg_data_set(key, onu_context, uni_iter);
}

static void omci_svc_state_set_ext_vlan_tag_oper_cfg_data_event_success(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    omci_svc_uni *uni_iter = onu_context->iter;
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;

    uni_iter = TAILQ_NEXT(uni_iter, next);
    onu_context->iter = uni_iter;
    if (uni_iter)
        omci_svc_ext_vlan_tag_oper_cfg_data_set(key, onu_context, uni_iter);
    else
        omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, key, NULL);
}

static void omci_svc_mac_bridge_service_profile_create(bcmolt_oltid olt_id, bcmonu_mgmt_onu_key *key, omci_svc_uni *uni)
{
    BCM_LOG(DEBUG, omci_svc_log_id, "omci_svc_mac_bridge_service_profile_create : uni=%d\n", uni->uni.entity_id);

    omci_svc_omci_mac_bridge_svc_prof_me_create(olt_id, key->pon_ni, key->onu_id, uni->uni.entity_id, 8,
        OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_SVC_PROF_PORT_SPANNING_TREE_IND, 0,
        OMCI_SVC_OMCI_ATTR_ID_LEARNING_IND, 0,

        /** @todo not sure what this will be ??? */
        OMCI_SVC_OMCI_ATTR_ID_PORT_BRIDGING_IND, 0,
        OMCI_SVC_OMCI_ATTR_ID_PRI, 0,
        OMCI_SVC_OMCI_ATTR_ID_MAX_AGE, OMCI_SVC_MAC_BRIDGE_SERVICE_PROFILE_MAX_AGE,
        OMCI_SVC_OMCI_ATTR_ID_HELLO_TIME, OMCI_SVC_MAC_BRIDGE_SERVICE_PROFILE_HELLO_TIME,
        OMCI_SVC_OMCI_ATTR_ID_FORWARD_DELAY, OMCI_SVC_MAC_BRIDGE_SERVICE_PROFILE_FORWARD_DELAY,
        OMCI_SVC_OMCI_ATTR_ID_UNKNOWN_MAC_ADDR_DISCARD, 0
#ifdef OMCI_SVC_ENABLE_OPTIONAL_ATTRIBUTES_IN_MAC_BRIDGE_SVC_PROFILE
        ,OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_SVC_PROF_MAC_LEARNING_DEPTH, 0,
        OMCI_SVC_OMCI_ATTR_ID_DYNAMIC_FILTERING_AGEING_TIME, OMCI_SVC_MAC_BRIDGE_SERVICE_PROFILE_DYNAMIC_FILTERING_AGEING_TIME
#endif
     );
}

static void omci_svc_state_create_mac_bridge_service_profile_event_is_entered(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    *(bcmos_bool *)context = BCMOS_TRUE;
}

static void omci_svc_state_create_mac_bridge_service_profile_event_start(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    omci_svc_uni *uni_iter;
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;

    /* We have one MAC Bridge Service Profile ME per each UNI, so we need to traverse UNIs. */
    uni_iter = TAILQ_FIRST(&onu_context->mib.unis);
    onu_context->iter = uni_iter;
    omci_svc_mac_bridge_service_profile_create(olt_id, key, uni_iter);
}

static void omci_svc_state_create_mac_bridge_service_profile_event_success(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    omci_svc_uni *uni_iter = onu_context->iter;
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;

    uni_iter = TAILQ_NEXT(uni_iter, next);
    onu_context->iter = uni_iter;
    if (uni_iter)
        omci_svc_mac_bridge_service_profile_create(olt_id, key, uni_iter);
    else
        omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, key, NULL);
}

static void omci_svc_mac_bridge_port_cfg_data_create(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, omci_svc_uni *uni)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;

    omci_svc_omci_mac_bridge_port_config_data_me_create(olt_id, key->pon_ni, key->onu_id,
        OMCI_SVC_MAC_BRIDGE_PORT_CONFIG_DATA_UNI_INSTANCE_BASE + (uni->uni.entity_id & OMCI_SVC_ETH_UNI_PORT_ID_MASK), 10,
        OMCI_SVC_OMCI_ATTR_ID_BRIDGE_ID_PTR, uni->uni.entity_id,
        OMCI_SVC_OMCI_ATTR_ID_PORT_NUM, 0, /* 0 should have no conflicts with ANI side ports. */
        OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_PORT_TP_TYPE, uni->uni.type == BCMONU_MGMT_UNI_TYPE_PPTP ? OMCI_SVC_OMCI_TP_TYPE_PPTP_ETH_UNI : OMCI_SVC_OMCI_TP_TYPE_VIRTUAL_ETH_INTF,
        OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_PORT_TP_PTR, uni->uni.entity_id,
        OMCI_SVC_OMCI_ATTR_ID_PORT_PRI, 0,
        OMCI_SVC_OMCI_ATTR_ID_PORT_PATH_COST, 0,
        OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_PORT_CONFIG_DATA_PORT_SPANNING_TREE_IND, 0,
        OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_DEPRECATED_1, 0,
        OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_DEPRECATED_2, 0,
        OMCI_SVC_OMCI_ATTR_ID_MAC_BRIDGE_PORT_CONFIG_MAC_LEARNING_DEPTH, 0);
}

static void omci_svc_state_create_mac_bridge_port_cfg_data_event_is_entered(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    *(bcmos_bool *)context = BCMOS_TRUE;
}

static void omci_svc_state_create_mac_bridge_port_cfg_data_event_start(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    omci_svc_uni *uni_iter;

    /* We have one MAC Bridge Port Configuration Data ME per each UNI, so we need to traverse UNIs. */
    uni_iter = TAILQ_FIRST(&onu_context->mib.unis);
    onu_context->iter = uni_iter;
    omci_svc_mac_bridge_port_cfg_data_create(key, onu_context, uni_iter);
}

static void omci_svc_state_create_mac_bridge_port_cfg_data_event_success(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    omci_svc_uni *uni_iter = onu_context->iter;
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;

    uni_iter = TAILQ_NEXT(uni_iter, next);
    onu_context->iter = uni_iter;
    if (uni_iter)
        omci_svc_mac_bridge_port_cfg_data_create(key, onu_context, uni_iter);
    else
        omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, key, NULL);
}

static void omci_svc_multicast_operations_profile_create(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, omci_svc_uni *uni)
{
    bcm_omci_mcast_operations_profile_ds_igmp_and_multicast_tci ds_igmp_and_mcast_tci;
    char ds_igmp_and_mcast_tci_hex_str[3 + BCM_OMCI_CFG_DATA_DS_IGMP_AND_MULTICAST_TCI_LEN * 2]; /* 3 bytes as a hexstring: 0xAABBCC */
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;

    /* Write default values that may be overwritten once getting a multicast flow. */
    ds_igmp_and_mcast_tci.control_type = BCM_OMCI_MCAST_OPERATIONS_PROFILE_DS_IGMP_AND_MULTICAST_TCI_CONTROL_TYPE_TRANSPARENT;
    ds_igmp_and_mcast_tci.tci = 0;

    sprintf(ds_igmp_and_mcast_tci_hex_str, "0x%02x%04x", ds_igmp_and_mcast_tci.control_type, ds_igmp_and_mcast_tci.tci);
    omci_svc_omci_mcast_operations_profile_me_create(olt_id, key->pon_ni, key->onu_id, uni->uni.entity_id, 11,
        OMCI_SVC_OMCI_ATTR_ID_IGMP_VERSION, OMCI_SVC_OMCI_MLD_VERSION_V2,
        OMCI_SVC_OMCI_ATTR_ID_IGMP_FUNC, OMCI_SVC_OMCI_IGMP_FUNC_TRANSPARENT_IGMP_SNOOPING,
        OMCI_SVC_OMCI_ATTR_ID_IMMEDIATE_LEAVE, BCMOS_TRUE, /* This will also be compliant with TR-247 test case 6.3.9. */
        OMCI_SVC_OMCI_ATTR_ID_US_IGMP_TCI, 0, /* This has no meaning if IGMP tag control is 0. */
        OMCI_SVC_OMCI_ATTR_ID_US_IGMP_TAG_CONTROL, OMCI_SVC_OMCI_US_IGMP_TAG_CTRL_AS_IS, /* No bypass for extended VLAN tagging operation ME for upstream frames containing IGMP/MLD packets. */
        OMCI_SVC_OMCI_ATTR_ID_US_IGMP_RATE, 0, /* 0 imposes no rate limit on this traffic. */
        OMCI_SVC_OMCI_ATTR_ID_ROBUSTNESS, 0, /* 0 causes the ONU to follow the IETF recommendation to copy the robustness value from query messages originating further upstream. */
        OMCI_SVC_OMCI_ATTR_ID_QUERIER_IP_ADDR, 0, /* 0.0.0.0 specifies no querier IP address */
        OMCI_SVC_OMCI_ATTR_ID_QUERY_INTERVAL, 0, /* 0 specifies that the ONU use its own default, which may or may not be the same as the recommended default of 125 seconds. */
        OMCI_SVC_OMCI_ATTR_ID_QUERY_MAX_RSP_TIME, 0, /* 0 specifies that the ONU use its own default, which may or may not be the same as the recommended default of 100. */
        OMCI_SVC_OMCI_ATTR_ID_DS_IGMP_AND_MCAST_TCI, ds_igmp_and_mcast_tci_hex_str);
}

static void omci_svc_state_create_multicast_operations_profile_event_is_entered(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    *(bcmos_bool *)context = BCMOS_TRUE;
}

static void omci_svc_state_create_multicast_operations_profile_event_start(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    omci_svc_uni *uni_iter;

    /* We have one Multicast Operations Profile ME per each UNI, so we need to traverse UNIs. */
    uni_iter = TAILQ_FIRST(&onu_context->mib.unis);
    onu_context->iter = uni_iter;
    omci_svc_multicast_operations_profile_create(key, onu_context, uni_iter);
}

static void omci_svc_state_create_multicast_operations_profile_event_success(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    omci_svc_uni *uni_iter = onu_context->iter;
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;

    uni_iter = TAILQ_NEXT(uni_iter, next);
    onu_context->iter = uni_iter;
    if (uni_iter)
        omci_svc_multicast_operations_profile_create(key, onu_context, uni_iter);
    else
        omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, key, NULL);
}

static void omci_svc_multicast_subscriber_config_info_create(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, omci_svc_uni *uni)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;

    /* The standard requires for the entity ID that "Through an identical ID, this managed entity is implicitly linked to an instance of the MAC bridge port configuration data". */
    omci_svc_omci_mcast_subscriber_config_info_me_create(olt_id, key->pon_ni, key->onu_id,
        OMCI_SVC_MAC_BRIDGE_PORT_CONFIG_DATA_UNI_INSTANCE_BASE + (uni->uni.entity_id & OMCI_SVC_ETH_UNI_PORT_ID_MASK), 5,
        OMCI_SVC_OMCI_ATTR_ID_ME_TYPE, OMCI_SVC_OMCI_MCAST_SBR_ASSOC_TYPE_MAC_BPCD,
        OMCI_SVC_OMCI_ATTR_ID_MCAST_OPER_S_PROF_PTR, uni->uni.entity_id,
        OMCI_SVC_OMCI_ATTR_ID_MAX_SIMULTANEOUS_GROUPS, 0, /* 0 means no administrative limit. */
        OMCI_SVC_OMCI_ATTR_ID_MAX_MCAST_BW, 0, /* 0 means no administrative limit. */
        OMCI_SVC_OMCI_ATTR_ID_BW_ENFORCEMENT, BCMOS_FALSE); /* False means attempts to exceed the max multicast bandwidth be counted but honoured. */
}

static void omci_svc_state_create_multicast_subscriber_config_info_event_is_entered(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    *(bcmos_bool *)context = BCMOS_TRUE;
}

static void omci_svc_state_create_multicast_subscriber_config_info_event_start(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    omci_svc_uni *uni_iter = onu_context->iter;

    uni_iter = TAILQ_FIRST(&onu_context->mib.unis);
    onu_context->iter = uni_iter;
    omci_svc_multicast_subscriber_config_info_create(key, onu_context, uni_iter);
}

static void omci_svc_state_create_multicast_subscriber_config_info_event_success(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    omci_svc_uni *uni_iter = onu_context->iter;
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;

    uni_iter = TAILQ_NEXT(uni_iter, next);
    onu_context->iter = uni_iter;
    if (uni_iter)
        omci_svc_multicast_subscriber_config_info_create(key, onu_context, uni_iter);
    else
        omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, key, NULL);
}

static void omci_svc_state_up_sequence_end_event_is_entered(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    *(bcmos_bool *)context = BCMOS_TRUE;
}

static void omci_svc_state_up_sequence_end_event_start(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    bcmos_errno rc;
    bcmonu_mgmt_onu_cfg *onu_cfg;
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;
    onu_context->state = OMCI_SVC_ONU_STATE_ID_ACTIVE_WORKING;
    onu_context->oper_status = BCMONU_MGMT_STATUS_UP;
    OMCI_SVC_LOG(INFO, olt_id, key, NULL, "ONU added successfully (is_up=true)\n");

    /* update cfg DB first, since notify calls does a GET on the onu */
    if (BCM_ERR_OK == onu_context->last_err)
    {
        /* update sm cfg DB */
        onu_cfg = onu_context->onu_cfg;
        rc = omci_svc_sm_cfg_db_update_entry(onu_cfg);
        if (BCM_ERR_OK != rc)
            OMCI_SVC_LOG(ERROR, olt_id, key, &onu_cfg->hdr.hdr, "ONU cfg DB update Failed\n");
    }

    if (onu_context->cb)
        onu_context->cb(onu_context->context, onu_context->last_err);

    if (NULL != omci_onu_state_changed)
    {
        omci_onu_state_changed(key);
    }

}

static void omci_svc_state_active_working_event_is_entered(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    *(bcmos_bool *)context = BCMOS_TRUE;
}

/* Down direction - we do not delete the MEs we created in the "up" Sequence one by one, because when the ONU will be brought up again, we will do MIB reset for it.
 * Also, in this point, we don't know whether the DS OMCI channel in the OLT is already disconnected by BAL (if BAL "down" sequence occurred before OMCI "down" sequence"),
 * so we cannot rely on having successful ME deletion.
 * We let the user deactivate the ONU even if it is in the middle of "up" sequence.
 * This will allow us to cope with a situation in which the retransmissions of bcmolt_proxy_send() are failing (OpenCon's OMCI stack sends them periodically).
 * By calling OgMePortal__DeactivateReq(), we will stop the periodic OMCI packets. */
static void omci_svc_state_any_event_deactivate(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    /* We should not use ++ operator here, because we arrive here from different states.
     * We should change state before trying to deactivate the ONU, because the ONU deactivation might be synchronous, and thus we don't want to get OMCI_SVC_EVENT_ID_DEACTIVATE in
     * OMCI_SVC_ONU_STATE_ID_ACTIVE_WORKING state. */
    onu_context->state = OMCI_SVC_ONU_STATE_ID_DEACTIVATING;
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;

    bcmos_errno rc;
    rc = omci_svc_omci_deactivate_req(olt_id, key->pon_ni, key->onu_id);
    if (rc != BCM_ERR_OK)
    {
        OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "omci_svc_omci_deactivate_req() failed, rc=%s\n", bcmos_strerror(rc));
        omci_svc_onu_sm_rollback_cb(olt_id, key, rc, NULL);
        return;
    }

    /* check if we really want to be sitting in deactivating state, since omci stack may not support it */
    if (!omci_svc_omci_if_support_deactivate())
    {
        omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, key, NULL);
    }
}

/** @brief this is no-op handling.  Just meant to check if FSM should stay in deactivating state or move on */
static void omci_svc_state_deactivating_event_start(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;

    OMCI_SVC_LOG(ERROR, olt_id, key, NULL, " *** omci_svc_state_deactivating_event_start onu=%p, context=%p\n", onu_context, context);
}

static void omci_svc_state_deactivating_event_is_entered(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    /** call adapter layer function to check if it should enter this state or not */
    *(bcmos_bool *)context = omci_svc_omci_if_support_deactivate();
}

static void omci_svc_state_deactivating_event_success(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;
    omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_START, key, NULL);
}

static void omci_svc_state_down_sequence_end_event_is_entered(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    *(bcmos_bool *)context = BCMOS_TRUE;
}

static void omci_svc_state_down_sequence_end_event_start(bcmonu_mgmt_onu_key *key, omci_svc_onu *onu_context, void *context)
{
    bcmos_errno rc = BCM_ERR_OK;
    bcmonu_mgmt_onu_cfg *onu_cfg;
    bcmolt_oltid olt_id = onu_context->onu_cfg->hdr.hdr.olt_id;

    /* Down sequence end. */
    OMCI_SVC_LOG(INFO, olt_id, key, NULL, "ONU deleted successfully (is_up=false)\n");
    onu_context->state = OMCI_SVC_ONU_STATE_ID_INACTIVE;
    onu_context->oper_status = BCMONU_MGMT_STATUS_DOWN;

    /* update cfg DB first, since notify may do a GET on the onu */
    if (BCM_ERR_OK == onu_context->last_err)
    {
        onu_cfg = onu_context->onu_cfg;
        if (BCMOS_TRUE == onu_context->is_clear)
        {
            /* clear entry from sm cfg DB */
            rc = omci_svc_sm_cfg_db_clear_entry(onu_cfg);
            if (BCM_ERR_OK != rc)
                OMCI_SVC_LOG(ERROR, olt_id, key, &onu_cfg->hdr.hdr, "ONU cfg DB clear Failed\n");
        }
        else
        {
            /* update sm cfg DB */
            rc = omci_svc_sm_cfg_db_update_entry(onu_cfg);
            if (BCM_ERR_OK != rc)
                OMCI_SVC_LOG(ERROR, olt_id, key, &onu_cfg->hdr.hdr, "ONU cfg DB update Failed\n");
        }
    }

    /* also since ONU is down, flush any stale flow requests in queue */
    omci_svc_flow_op_queue_flush(onu_context);
    /* ... the flow cfg db as well for the onu */
    omci_svc_flow_cfg_db_flush_for_onu(onu_context, key);

    if (onu_context->cb)
        onu_context->cb(onu_context->context, onu_context->last_err);

    if (NULL != omci_onu_state_changed)
    {
        omci_onu_state_changed(key);
    }

    if (BCMOS_TRUE == onu_context->is_clear)
    {
        /* clear the onu_cfg from onu_context as well */
        bcmos_free(onu_context->onu_cfg);
        onu_context->onu_cfg = NULL;
    }
}

static omci_svc_onu_sm_cb omci_svc_onu_state_machine[OMCI_SVC_ONU_STATE_ID__NUM_OF][OMCI_SVC_EVENT_ID__NUM_OF] =
{
    /* Up direction */
    [OMCI_SVC_ONU_STATE_ID_INACTIVE] =
    {
        [OMCI_SVC_EVENT_ID_ACTIVATE] = omci_svc_state_onu_inactive_event_activate,
        [OMCI_SVC_EVENT_ID_DEACTIVATE] = omci_svc_state_onu_inactive_event_deactivate,
    },
    [OMCI_SVC_ONU_STATE_ID_ACTIVATING] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_activating_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_activating_event_start,
        [OMCI_SVC_EVENT_ID_ACTIVATE_SUCCESS] = omci_svc_state_activating_event_success,
        [OMCI_SVC_EVENT_ID_DEACTIVATE] = omci_svc_state_any_event_deactivate,
    },
    [OMCI_SVC_ONU_STATE_ID_WAIT_FOR_LINK_UP] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_wait_for_link_up_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_wait_for_link_up_event_start,
        [OMCI_SVC_EVENT_ID_LINK_UP] = omci_svc_state_wait_for_link_up_event_link_up,
        [OMCI_SVC_EVENT_ID_DEACTIVATE] = omci_svc_state_any_event_deactivate,
    },
    [OMCI_SVC_ONU_STATE_ID_MIB_RESET] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_mib_reset_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_mib_reset_event_start,
        [OMCI_SVC_EVENT_ID_MIB_RESET_SUCCESS] = omci_svc_state_mib_reset_event_success,
        [OMCI_SVC_EVENT_ID_DEACTIVATE] = omci_svc_state_any_event_deactivate,
    },
    [OMCI_SVC_ONU_STATE_ID_MIB_UPLOAD] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_mib_upload_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_mib_upload_event_start,
        [OMCI_SVC_EVENT_ID_MIB_UPLOAD_INIT_SUCCESS] = omci_svc_state_mib_upload_event_init_success,
        [OMCI_SVC_EVENT_ID_MIB_UPLOAD_MORE] = omci_svc_state_mib_upload_event_more,
        [OMCI_SVC_EVENT_ID_MIB_UPLOAD_LAST] = omci_svc_state_mib_upload_event_last,
        [OMCI_SVC_EVENT_ID_DEACTIVATE] = omci_svc_state_any_event_deactivate,
    },
    [OMCI_SVC_ONU_STATE_ID_CREATE_GAL_ETHERNET_PROFILE] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_create_gal_ethernet_profile_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_create_gal_ethernet_profile_event_start,
        [OMCI_SVC_EVENT_ID_CREATE_SUCCESS] = omci_svc_state_create_gal_ethernet_profile_event_success,
        [OMCI_SVC_EVENT_ID_DEACTIVATE] = omci_svc_state_any_event_deactivate,
    },
    [OMCI_SVC_ONU_STATE_ID_CREATE_EXT_VLAN_TAG_OPER_CFG_DATA] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_create_ext_vlan_tag_oper_cfg_data_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_create_ext_vlan_tag_oper_cfg_data_event_start,
        [OMCI_SVC_EVENT_ID_CREATE_SUCCESS] = omci_svc_state_create_ext_vlan_tag_oper_cfg_data_event_success,
        [OMCI_SVC_EVENT_ID_DEACTIVATE] = omci_svc_state_any_event_deactivate,
    },
    [OMCI_SVC_ONU_STATE_ID_SET_EXT_VLAN_TAG_OPER_CFG_DATA] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_set_ext_vlan_tag_oper_cfg_data_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_set_ext_vlan_tag_oper_cfg_data_event_start,
        [OMCI_SVC_EVENT_ID_SET_SUCCESS] = omci_svc_state_set_ext_vlan_tag_oper_cfg_data_event_success,
        [OMCI_SVC_EVENT_ID_DEACTIVATE] = omci_svc_state_any_event_deactivate,
    },
    [OMCI_SVC_ONU_STATE_ID_CREATE_MAC_BRIDGE_SERVICE_PROFILE] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_create_mac_bridge_service_profile_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_create_mac_bridge_service_profile_event_start,
        [OMCI_SVC_EVENT_ID_CREATE_SUCCESS] = omci_svc_state_create_mac_bridge_service_profile_event_success,
        [OMCI_SVC_EVENT_ID_DEACTIVATE] = omci_svc_state_any_event_deactivate,
    },
    [OMCI_SVC_ONU_STATE_ID_CREATE_MAC_BRIDGE_PORT_CFG_DATA] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_create_mac_bridge_port_cfg_data_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_create_mac_bridge_port_cfg_data_event_start,
        [OMCI_SVC_EVENT_ID_CREATE_SUCCESS] = omci_svc_state_create_mac_bridge_port_cfg_data_event_success,
        [OMCI_SVC_EVENT_ID_DEACTIVATE] = omci_svc_state_any_event_deactivate,
    },
    [OMCI_SVC_ONU_STATE_ID_CREATE_MULTICAST_OPERATIONS_PROFILE] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_create_multicast_operations_profile_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_create_multicast_operations_profile_event_start,
        [OMCI_SVC_EVENT_ID_CREATE_SUCCESS] = omci_svc_state_create_multicast_operations_profile_event_success,
        [OMCI_SVC_EVENT_ID_DEACTIVATE] = omci_svc_state_any_event_deactivate,
    },
    [OMCI_SVC_ONU_STATE_ID_CREATE_MULTICAST_SUBSCRIBER_CONFIG_INFO] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_create_multicast_subscriber_config_info_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_create_multicast_subscriber_config_info_event_start,
        [OMCI_SVC_EVENT_ID_CREATE_SUCCESS] = omci_svc_state_create_multicast_subscriber_config_info_event_success,
        [OMCI_SVC_EVENT_ID_DEACTIVATE] = omci_svc_state_any_event_deactivate,
    },
    [OMCI_SVC_ONU_STATE_ID_UP_SEQUENCE_END] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_up_sequence_end_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_up_sequence_end_event_start,
    },
    /* Down direction */
    [OMCI_SVC_ONU_STATE_ID_ACTIVE_WORKING] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_active_working_event_is_entered,
        [OMCI_SVC_EVENT_ID_DEACTIVATE] = omci_svc_state_any_event_deactivate,
    },
    [OMCI_SVC_ONU_STATE_ID_DEACTIVATING] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_deactivating_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_deactivating_event_start,
        [OMCI_SVC_EVENT_ID_DEACTIVATE_SUCCESS] = omci_svc_state_deactivating_event_success,
    },
    [OMCI_SVC_ONU_STATE_ID_DOWN_SEQUENCE_END] =
    {
        [OMCI_SVC_EVENT_ID_IS_ENTERED] = omci_svc_state_down_sequence_end_event_is_entered,
        [OMCI_SVC_EVENT_ID_START] = omci_svc_state_down_sequence_end_event_start,
    }
};

static void omci_svc_onu_sm_run_cb(bcmolt_oltid olt_id, omci_svc_event_id event, bcmonu_mgmt_onu_key *key, void *context)
{
    omci_svc_onu_sm_cb cb;
    omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, key->pon_ni, key->onu_id);

    OMCI_SVC_LOG(DEBUG, olt_id, key, NULL, "ONU SM state='%s', event='%s'\n", omci_svc_onu_state_id2str_conv(onu_context->state), omci_svc_event_id2str_conv(event));
    if (event == OMCI_SVC_EVENT_ID_START)
    {
        bcmos_bool is_entered;

        /* Skip states which should not be entered. */
        do
        {
            onu_context->state++;
            cb = omci_svc_onu_state_machine[onu_context->state][OMCI_SVC_EVENT_ID_IS_ENTERED];
            cb(key, onu_context, &is_entered);
        } while (!is_entered);
    }
    cb = omci_svc_onu_state_machine[onu_context->state][event];
    if (cb)
        cb(key, onu_context, context);
    else
        OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "Unexpected event='%s' in state='%s'\n", omci_svc_event_id2str_conv(event), omci_svc_onu_state_id2str_conv(onu_context->state));
}

/* Return the first callback of the given state. If there are multiple events handled in the given state, it is assumed that the first event is the "success" event. */
static omci_svc_onu_sm_cb omci_svc_onu_get_first_sm_cb(omci_svc_onu_state_id state)
{
    omci_svc_event_id event;

    for (event = OMCI_SVC_EVENT_ID__BEGIN; event < OMCI_SVC_EVENT_ID__NUM_OF; event++)
    {
        omci_svc_onu_sm_cb cb;

        cb = omci_svc_onu_state_machine[state][event];
        if (cb)
            return cb;
    }
    return NULL;
}

static void omci_svc_onu_sm_rollback_cb(bcmolt_oltid olt_id, bcmonu_mgmt_onu_key *key, bcmos_errno last_err, void *context)
{
    omci_svc_onu_sm_cb cb;
    omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, key->pon_ni, key->onu_id);
    static omci_svc_onu_state_id onu_state_inverse[OMCI_SVC_ONU_STATE_ID__NUM_OF] =
    {
        [OMCI_SVC_ONU_STATE_ID_INACTIVE] = OMCI_SVC_ONU_STATE_ID__NUM_OF, /* No rollback */
        [OMCI_SVC_ONU_STATE_ID_ACTIVATING] = OMCI_SVC_ONU_STATE_ID_DEACTIVATING,
        [OMCI_SVC_ONU_STATE_ID_WAIT_FOR_LINK_UP] = OMCI_SVC_ONU_STATE_ID_ACTIVE_WORKING,
        [OMCI_SVC_ONU_STATE_ID_MIB_RESET] = OMCI_SVC_ONU_STATE_ID_ACTIVE_WORKING,
        [OMCI_SVC_ONU_STATE_ID_CREATE_GAL_ETHERNET_PROFILE] = OMCI_SVC_ONU_STATE_ID_ACTIVE_WORKING,
        [OMCI_SVC_ONU_STATE_ID_CREATE_EXT_VLAN_TAG_OPER_CFG_DATA] = OMCI_SVC_ONU_STATE_ID_ACTIVE_WORKING,
        [OMCI_SVC_ONU_STATE_ID_SET_EXT_VLAN_TAG_OPER_CFG_DATA] = OMCI_SVC_ONU_STATE_ID_ACTIVE_WORKING,
        [OMCI_SVC_ONU_STATE_ID_CREATE_MAC_BRIDGE_SERVICE_PROFILE] = OMCI_SVC_ONU_STATE_ID_ACTIVE_WORKING,
        [OMCI_SVC_ONU_STATE_ID_CREATE_MAC_BRIDGE_PORT_CFG_DATA] = OMCI_SVC_ONU_STATE_ID_ACTIVE_WORKING,
        [OMCI_SVC_ONU_STATE_ID_CREATE_MULTICAST_OPERATIONS_PROFILE] = OMCI_SVC_ONU_STATE_ID_ACTIVE_WORKING,
        [OMCI_SVC_ONU_STATE_ID_CREATE_MULTICAST_SUBSCRIBER_CONFIG_INFO] = OMCI_SVC_ONU_STATE_ID_ACTIVE_WORKING,
    };

    /* If the error occurred during down sequence of during rollback, we ignore the error and continue with the state machine. */
    if (onu_context->state >= OMCI_SVC_ONU_STATE_ID_ACTIVE_WORKING)
    {
        onu_context->state++;
        cb = omci_svc_onu_get_first_sm_cb(onu_context->state);
        if (cb)
            cb(key, onu_context, context);
        return;
    }

    /* If the state is marked to have no rollback, immediately end the transaction and return to the caller. */
    if (onu_state_inverse[onu_context->state] == OMCI_SVC_ONU_STATE_ID__NUM_OF)
    {
        /* Down sequence end. */
        onu_context->state = OMCI_SVC_ONU_STATE_ID_INACTIVE;
        if (onu_context->cb)
            onu_context->cb(onu_context->context, last_err);
        return;
    }

    onu_context->last_err = last_err;
    onu_context->state = onu_state_inverse[onu_context->state];

    OMCI_SVC_LOG(DEBUG, olt_id, key, NULL, "Starting transaction rollback from SM state='%s'\n", omci_svc_onu_state_id2str_conv(onu_context->state));
    cb = omci_svc_onu_get_first_sm_cb(onu_context->state);
    if (cb)
        cb(key, onu_context, context);
}

void omci_svc_omci_activate_cnf(bcmolt_oltid olt_id, uint32_t pon_id, uint16_t onu_id, bcmos_errno result)
{
    bcmonu_mgmt_onu_key _key = { .pon_ni = pon_id, .onu_id = onu_id }, *key = &_key;

    if (result != BCM_ERR_OK)
    {
        OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "ONU activate request failed, result=%u\n", result);
        omci_svc_onu_sm_rollback_cb(olt_id, key, BCM_ERR_COMM_FAIL, NULL);
        return;
    }

    OMCI_SVC_LOG(DEBUG, olt_id, key, NULL, "ONU activate request completed successfully\n");
    omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_ACTIVATE_SUCCESS, key, NULL);
}

void omci_svc_omci_deactivate_cnf(bcmolt_oltid olt_id, uint32_t pon_id, uint16_t onu_id, bcmos_errno result)
{
    bcmonu_mgmt_onu_key _key = { .pon_ni = pon_id, .onu_id = onu_id }, *key = &_key;

    if (result != BCM_ERR_OK)
    {
        OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "ONU deactivate request failed, result=%u\n", result);
        omci_svc_onu_sm_rollback_cb(olt_id, key, BCM_ERR_COMM_FAIL, NULL);
        return;
    }

    OMCI_SVC_LOG(DEBUG, olt_id, key, NULL, "ONU deactivate request completed successfully\n");
    omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_DEACTIVATE_SUCCESS, key, NULL);
}

void omci_svc_omci_mib_reset_cnf(bcmolt_oltid olt_id, uint32_t pon_id, uint16_t onu_id, omci_svc_omci_result result)
{
    bcmonu_mgmt_onu_key _key = { .pon_ni = pon_id, .onu_id = onu_id }, *key = &_key;

    if (result != OMCI_SVC_OMCI_RESULT_CMD_SUCCESS)
    {
        OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "MIB reset request failed, omci result=%s(%u)\n", omci_svc_omci_result2str_conv(result), result);
        omci_svc_onu_sm_rollback_cb(olt_id, key, BCM_ERR_COMM_FAIL, NULL);
        return;
    }

    OMCI_SVC_LOG(DEBUG, olt_id, key, NULL, "MIB reset request completed successfully\n");
    omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_MIB_RESET_SUCCESS, key, NULL);
}

void omci_svc_omci_mib_upload_cnf(bcmolt_oltid olt_id, uint32_t pon_id, uint16_t onu_id, omci_svc_omci_result result, uint32_t me_count)
{
    bcmonu_mgmt_onu_key _key = { .pon_ni = pon_id, .onu_id = onu_id }, *key = &_key;

    if (result != OMCI_SVC_OMCI_RESULT_CMD_SUCCESS)
    {
        OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "MIB upload initiation request failed, omci result=%s(%u)\n", omci_svc_omci_result2str_conv(result), result);
        omci_svc_onu_sm_rollback_cb(olt_id, key, BCM_ERR_COMM_FAIL, NULL);
        return;
    }

    OMCI_SVC_LOG(DEBUG, olt_id, key, NULL, "MIB upload initiation request completed successfully\n");
    omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_MIB_UPLOAD_INIT_SUCCESS, key, NULL);
}

/**
 * @brief mib upload next indication from stack
 */
void omci_svc_omci_mib_upload_next_ind(bcmolt_oltid olt_id, uint32_t pon_id, uint16_t onu_id, omci_svc_omci_result result, void *me, omci_svc_omci_attrid_list *attrid_list)
{
    bcmonu_mgmt_onu_key _key = { .pon_ni = pon_id, .onu_id = onu_id }, *key = &_key;

    if (result == OMCI_SVC_OMCI_RESULT_MORE)
        omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_MIB_UPLOAD_MORE, key, me);
    else if (result == OMCI_SVC_OMCI_RESULT_LAST)
    {
        OMCI_SVC_LOG(DEBUG, olt_id, key, NULL, "MIB upload completed successfully\n");
        omci_svc_onu_sm_run_cb(olt_id, OMCI_SVC_EVENT_ID_MIB_UPLOAD_LAST, key, me);
    }
    else
    {
        OMCI_SVC_LOG(ERROR, olt_id, key, NULL, "MIB upload next failed, omci result=%s(%u)\n", omci_svc_omci_result2str_conv(result), result);
        omci_svc_onu_sm_rollback_cb(olt_id, key, BCM_ERR_COMM_FAIL, NULL);
    }
}

