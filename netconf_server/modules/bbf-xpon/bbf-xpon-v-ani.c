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

/*
 * bbf-xpon-v-ani.c
 */

#include "bbf-xpon-internal.h"
#include <onu_mgmt.h>
#include <onu_mgmt_model_funcs.h>
#include <onu_mgmt_model_metadata.h>
#include <bcmolt_utils.h>

//#include <sys/inotify.h>
#include <libnetconf2/log.h>
#include <bcmolt_netconf_module_utils.h>
#include <bcmolt_netconf_notifications.h>

/* sysrepo session */
static sr_session_ctx_t *sr_session;

static xpon_obj_list v_ani_list;
static xpon_v_ani *v_ani_array[BCM_MAX_PONS_PER_OLT][XPON_MAX_ONUS_PER_PON];

static bcmos_mutex onu_config_lock;

static void _onu_send_state_change_event(bcmolt_interface pon_ni, bcmolt_onu_id onu_id, bcmolt_serial_number *serial,
    bcmos_bool is_active);

xpon_v_ani *xpon_v_ani_get_by_id(bcmolt_interface intf_id, bcmolt_onu_id onu_id)
{
    if (intf_id >= BCM_MAX_PONS_PER_OLT || onu_id >= XPON_MAX_ONUS_PER_PON)
        return NULL;
    return v_ani_array[intf_id][onu_id];
}

static bcmolt_onu_id _v_ani_get_free_onu_id(bcmolt_interface intf_id)
{
    int onu_id;
    if (intf_id >= BCM_MAX_PONS_PER_OLT)
        return BCMOLT_ONU_ID_INVALID;
    for (onu_id = 0; onu_id < XPON_MAX_ONUS_PER_PON; onu_id++)
    {
        if (v_ani_array[intf_id][onu_id] == NULL)
            return onu_id;
    }
    return BCMOLT_ONU_ID_INVALID;
}

/* Get v_ani object by name, add a new one if
 * doesn't exist
 */
bcmos_errno xpon_v_ani_get_by_name(const char *name, xpon_v_ani **p_v_ani, bcmos_bool *is_added)
{
    xpon_obj_hdr *obj = NULL;
    bcmos_errno err;

    bcmos_mutex_lock(&onu_config_lock);
    do
    {
        err = xpon_object_get_or_add(name, XPON_OBJ_TYPE_V_ANI,
            sizeof(xpon_v_ani), &obj, is_added);
        if (err != BCM_ERR_OK)
            break;
        *p_v_ani = (xpon_v_ani *)obj;
        if (is_added != NULL && *is_added)
        {
            (*p_v_ani)->pon_ni = BCMOLT_INTERFACE_ID_INVALID;
            (*p_v_ani)->onu_id = BCMOLT_ONU_ID_INVALID;
            STAILQ_INIT(&(*p_v_ani)->gems);
            STAILQ_INIT(&(*p_v_ani)->tconts);
            STAILQ_INSERT_TAIL(&v_ani_list, obj, next);
        }
    } while (0);
    bcmos_mutex_unlock(&onu_config_lock);

    return err;
}

/* Remove channel termination object */
void xpon_v_ani_delete(xpon_v_ani *v_ani)
{
    xpon_tcont *tcont, *tcont_tmp;
    xpon_gem *gem, *gem_tmp;

    bcmos_mutex_lock(&onu_config_lock);
    STAILQ_REMOVE_SAFE(&v_ani_list, &v_ani->hdr, xpon_obj_hdr, next);
    if (v_ani->pon_ni != BCMOLT_INTERFACE_ID_INVALID &&
        v_ani->onu_id != BCMOLT_ONU_ID_INVALID &&
        v_ani_array[v_ani->pon_ni][v_ani->onu_id] == v_ani)
    {
        v_ani_array[v_ani->pon_ni][v_ani->onu_id] = NULL;
    }
    /* Remove references to GEM's and TCONT's */
    STAILQ_FOREACH_SAFE(tcont, &v_ani->tconts, next, tcont_tmp)
    {
        tcont->v_ani = NULL;
    }
    STAILQ_FOREACH_SAFE(gem, &v_ani->gems, next, gem_tmp)
    {
        gem->v_ani = NULL;
    }

    xpon_object_delete(&v_ani->hdr);
    bcmos_mutex_unlock(&onu_config_lock);
}

/* Populate netconf ONU record from OMCI SVC object */
static void _onu_populate_from_omci(const bcmonu_mgmt_onu_cfg *onu)
{
#if 0
    xmlDocPtr running = NULL;
    xmlNodePtr interfaces;
    xpon_volt_onu_info *onu_info;
    bcmos_errno err = BCM_ERR_NOMEM;

    /* Update netconf DB */
    bcmos_mutex_lock(&onu_config_lock);
    onu_ind_in_progress.intf_id = omci_subs_term->key.intf_id;
    onu_ind_in_progress.sub_term_id = omci_subs_term->key.sub_term_id;

    do
    {

        onu_info = _onu_info_get(omci_subs_term->key.intf_id, omci_subs_term->key.sub_term_id);

        /* Paranoia check. Can't happen */
        if (!onu_info)
        {
            nc_verb_error("ONU indication from ONU_MGMT for an unknown ONU: %u/%u\n",
                omci_subs_term->key.intf_id, omci_subs_term->key.sub_term_id);
            err = BCM_ERR_INTERNAL;
            break;
        }

        xpon_volt_interfaces_doc_init(&running, &interfaces, BCMOS_TRUE, NULL);
        if (!interfaces)
            break;

        /* (De)populate UNIs
         * This code should be moved to the handler called from ONU_MGMT, once it is available
         */
        onu_info->num_unis = omci_subs_term->data.num_of_unis;
        err = xpon_volt_uni_interfaces_update(interfaces, omci_subs_term->key.intf_id,
            omci_subs_term->key.sub_term_id, BCMOS_TRUE, NULL);

    } while (0);

    if (err != BCM_ERR_OK)
    {
        onu_ind_in_progress.intf_id = (bcmbal_intf_id)OFPAL_UNDEFINED;
        bcmos_mutex_unlock(&onu_config_lock);
        if (running)
            xmlFreeDoc(running);
        return;
    }

    /* Update netconf configuration */
    if (running)
        nc_config_set(running, interface_capabilities, NULL);

    onu_ind_in_progress.intf_id = (bcmbal_intf_id)OFPAL_UNDEFINED;
    bcmos_mutex_unlock(&onu_config_lock);

    return;
#endif
}

/* ONU indication callback */
static void _olt_onu_indication_cb(bcmolt_oltid olt, bcmolt_msg *msg)
{
    xpon_v_ani onu_info_tmp;
    bcmos_errno err;

    /* It is safe to cast to any ONU indication because key is the same for all */
    if (msg->subgroup != BCMOLT_ONU_AUTO_SUBGROUP_OMCI_PACKET)
    {
        NC_LOG_INFO("ONU %u.%u: indication '%s'\n",
            ((bcmolt_onu_state_change *)msg)->key.pon_ni, ((bcmolt_onu_state_change *)msg)->key.onu_id,
            BCMOLT_ENUM_STRING_VAL(bcmolt_onu_auto_subgroup, msg->subgroup));
    }
    switch(msg->subgroup)
    {
        case BCMOLT_ONU_AUTO_SUBGROUP_ONU_ACTIVATION_COMPLETED:
        {
            bcmolt_onu_onu_activation_completed *ac = (bcmolt_onu_onu_activation_completed *)msg;
            xpon_v_ani *onu_info;

            bcmos_mutex_lock(&onu_config_lock);
            onu_info = xpon_v_ani_get_by_id(ac->key.pon_ni, ac->key.onu_id);
            if (onu_info == NULL)
            {
                bcmos_mutex_unlock(&onu_config_lock);
                NC_LOG_ERR("ONU %u.%u: can't find in the data base\n", ac->key.pon_ni, ac->key.onu_id);
                break;
            }
            onu_info->registered = (ac->data.status == BCMOLT_RESULT_SUCCESS);
            onu_info_tmp = *onu_info;
            bcmos_mutex_unlock(&onu_config_lock);

            /* Ignore ACTIVATION_FAILED */
            if (ac->data.status != BCMOLT_RESULT_SUCCESS)
            {
                NC_LOG_INFO("ONU %u.%u: activation failed: '%s'\n",
                    ac->key.pon_ni, ac->key.onu_id,
                    BCMOLT_ENUM_STRING_VAL(bcmolt_onu_onu_activation_completed_data_id, ac->data.fail_reason));
                _onu_send_state_change_event(ac->key.pon_ni, ac->key.onu_id, &onu_info_tmp.serial_number, BCMOS_FALSE);
                break;
            }

            /* Do OMCI (de)init and notify status change */
            if (!bcm_tr451_onu_management_is_enabled())
            {
                bcmonu_mgmt_onu_cfg cfg;
                bcmonu_mgmt_onu_key key = {
                    .pon_ni = onu_info_tmp.pon_ni,
                    .onu_id = onu_info_tmp.onu_id
                };
                BCMONU_MGMT_CFG_INIT(&cfg, onu, key);
                BCMONU_MGMT_FIELD_SET(&cfg.data, onu_cfg_data, admin_state, BCMONU_MGMT_ADMIN_STATE_UP);
                err = bcmonu_mgmt_cfg_set(netconf_agent_olt_id(), &cfg.hdr);
                NC_LOG_INFO("onu %s: new_state=%s. OMCI initiated: %s\n",
                    onu_info_tmp.hdr.name, onu_info_tmp.registered ? "UP" : "DOWN", bcmos_strerror(err));
                if (err != BCM_ERR_OK)
                {
                    _onu_send_state_change_event(ac->key.pon_ni, ac->key.onu_id, &onu_info_tmp.serial_number, BCMOS_FALSE);
                }
            }
            else
            {
                _onu_send_state_change_event(ac->key.pon_ni, ac->key.onu_id, &onu_info_tmp.serial_number, BCMOS_TRUE);
            }
        }
        break;

        case BCMOLT_ONU_AUTO_SUBGROUP_SUFI:
        {
            bcmolt_onu_sufi *sufi = (bcmolt_onu_sufi *)msg;
            xpon_v_ani *onu_info;

            bcmos_mutex_lock(&onu_config_lock);
            onu_info = xpon_v_ani_get_by_id(sufi->key.pon_ni, sufi->key.onu_id);
            if (onu_info == NULL || !onu_info->registered)
            {
                bcmos_mutex_unlock(&onu_config_lock);
                break;
            }
            onu_info->registered = BCMOS_FALSE;
            onu_info->omci_ready = BCMOS_FALSE;
            onu_info_tmp = *onu_info;
            bcmos_mutex_unlock(&onu_config_lock);
            _onu_send_state_change_event(sufi->key.pon_ni, sufi->key.onu_id, &onu_info_tmp.serial_number, BCMOS_FALSE);
        }
        break;

        default: break;
    }

    bcmolt_msg_free(msg);
}

/* Subscriber terminal indication callback - called from ONU_MGMT */
static void _omci_onu_indication_cb(bcmonu_mgmt_cfg *omci_obj)
{
    bcmonu_mgmt_onu_cfg *onu = (bcmonu_mgmt_onu_cfg *)omci_obj;

    if (onu->hdr.hdr.err == BCM_ERR_OK)
    {
        xpon_v_ani *onu_info = xpon_v_ani_get_by_id(onu->key.pon_ni, onu->key.onu_id);
        if (onu_info != NULL)
        {
            onu_info->omci_ready = (onu->data.oper_status == BCMONU_MGMT_STATUS_UP);
            _onu_send_state_change_event(onu->key.pon_ni, onu->key.onu_id, &onu_info->serial_number, onu_info->omci_ready);
            NC_LOG_INFO("onu %s: OMCI transaction completed OK. new_state=%s.\n",
                onu_info->hdr.name, onu_info->omci_ready ? "UP" : "DOWN");
            if (onu_info->omci_ready)
            {
                _onu_populate_from_omci(onu);
            }
        }
    }
    else
    {
        xpon_v_ani *onu_info = xpon_v_ani_get_by_id(onu->key.pon_ni, onu->key.onu_id);
        NC_LOG_INFO("onu %u.%u: OMCI transaction failed (%s).\n",
            onu->key.pon_ni, onu->key.onu_id, bcmos_strerror(onu->hdr.hdr.err));
        if (onu_info != NULL)
        {
            _onu_send_state_change_event(onu->key.pon_ni, onu->key.onu_id, &onu_info->serial_number, BCMOS_FALSE);
        }
    }
}


/* ONU indication callback */
static bcmos_errno _olt_onu_ind_register_unregister(bcmos_bool is_register)
{
    bcmolt_rx_cfg cb_cfg = {
        .module = BCMOS_MODULE_ID_NETCONF_SERVER,
        .flags = BCMOLT_AUTO_FLAGS_DISPATCH,
        .obj_type = BCMOLT_OBJ_ID_ONU,
        .rx_cb = _olt_onu_indication_cb
    };
    bcmolt_oltid olt = netconf_agent_olt_id();
    bcmos_errno err;

    if (is_register)
    {
        err = bcmolt_ind_subscribe(olt, &cb_cfg);
    }
    else
    {
        err = bcmolt_ind_unsubscribe(olt, &cb_cfg);
    }
    NC_LOG_INFO("%s ONU indications\n", is_register ? "Subscribed to" : "Unsubscribed from");
    if(BCM_ERR_OK != err)
    {
        NC_LOG_ERR("Failed to %ssubscribe to/from onu indications. Error %s\n",
            is_register ? "":"un-", bcmos_strerror(err));
    }

    return err;
}

/* Register for ONU_MGMT subscriber terminal indications */
static bcmos_errno _omci_onu_ind_register_unregister(bcmos_bool is_register)
{
    bcmos_errno err = BCM_ERR_OK;

    /* Register to get subscriber terminal status change indication from OMCI service layer */
    if (is_register)
    {
        err = bcmonu_mgmt_onu_notify_register(_omci_onu_indication_cb);
    }
    else
    {
        bcmonu_mgmt_onu_notify_unregister(_omci_onu_indication_cb);
    }
    NC_LOG_INFO("%s OMCI indications\n", is_register ? "Subscribed to" : "Unsubscribed from");
    if(BCM_ERR_OK != err)
    {
        NC_LOG_ERR("Failed to %ssubscribe to OMCI subscriber terminal indications. Error %s\n",
            is_register ? "" : "un-", bcmos_strerror(err));
    }
    return err;
}

/* change onu state change event */
static void _onu_send_state_change_event(bcmolt_interface pon_ni, bcmolt_onu_id onu_id, bcmolt_serial_number *serial,
    bcmos_bool is_active)
{
    xpon_channel_termination *cterm = xpon_cterm_get_by_id(
        netconf_agent_olt_id(), pon_ni);
    xpon_v_ani *v_ani = xpon_v_ani_get_by_id(pon_ni, onu_id);
    uint8_t serial_number[8];

    if (cterm == NULL)
    {
        NC_LOG_ERR("Received ONU discovery on unexpected PON %u\n", pon_ni);
        return;
    }

    /* send event notification */
    memcpy(serial_number, serial->vendor_id.arr, 4);
    memcpy(serial_number + 4, serial->vendor_specific.arr, 4);

    bcmolt_xpon_v_ani_state_change(cterm->hdr.name, onu_id,
        serial_number, (v_ani != NULL), is_active);
}


/* Send onu discovered  */
static void _onu_send_onu_discovered(bcmolt_pon_interface_onu_discovered *od)
{
    _onu_send_state_change_event(od->key.pon_ni, od->data.onu_id, &od->data.serial_number, BCMOS_FALSE);
}

static void _onu_deactivate(bcmolt_interface pon_ni, bcmolt_onu_id onu_id)
{
    bcmolt_onu_set_onu_state set_state;
    bcmolt_onu_key key = { .pon_ni = pon_ni, .onu_id = onu_id };
    BCMOLT_OPER_INIT(&set_state, onu, set_onu_state, key);
    BCMOLT_MSG_FIELD_SET(&set_state, onu_state, BCMOLT_ONU_OPERATION_INACTIVE);
    bcmolt_oper_submit(netconf_agent_olt_id(), &set_state.hdr);

    if (!bcm_tr451_onu_management_is_enabled())
    {
        bcmonu_mgmt_onu_cfg onu_mgmt_cfg;
        bcmonu_mgmt_onu_key onu_mgmt_key = {
            .pon_ni = pon_ni,
            .onu_id = onu_id
        };
        BCMONU_MGMT_CFG_INIT(&onu_mgmt_cfg, onu, onu_mgmt_key);
        BCMONU_MGMT_FIELD_SET(&onu_mgmt_cfg.data, onu_cfg_data, admin_state, BCMONU_MGMT_ADMIN_STATE_DOWN);
        bcmonu_mgmt_cfg_set(netconf_agent_olt_id(), &onu_mgmt_cfg.hdr);
    }
}

/* Handle ONU_DISCOVERED indication */
void bbf_xpon_onu_discovered(bcmolt_oltid olt, bcmolt_msg *msg)
{
    bcmolt_pon_interface_onu_discovered *od = (bcmolt_pon_interface_onu_discovered *)msg;
    bcmos_bool auto_activated = BCMOS_FALSE;
    bcmos_errno err;

    NC_LOG_DBG("ONU_discovered: onu_id=%u serial_number=%c%c%c%c-%02x%02x%02x%02x\n",
        od->data.onu_id,
        od->data.serial_number.vendor_id.arr[0], od->data.serial_number.vendor_id.arr[1],
        od->data.serial_number.vendor_id.arr[2], od->data.serial_number.vendor_id.arr[3],
        od->data.serial_number.vendor_specific.arr[0], od->data.serial_number.vendor_specific.arr[1],
        od->data.serial_number.vendor_specific.arr[2], od->data.serial_number.vendor_specific.arr[3]);

    /* If onu_id is already assigned, that means that ONU is already provisioned.
       In this case activate it */
    if (BCMOLT_FIELD_IS_SET(&od->data, pon_interface_onu_discovered_data, onu_id) &&
        od->data.onu_id != BCMOLT_ONU_ID_INVALID)
    {
        const xpon_v_ani *onu_info = xpon_v_ani_get_by_id(od->key.pon_ni, od->data.onu_id);
        if (onu_info != NULL && onu_info->admin_state == XPON_ADMIN_STATE_ENABLED)
        {
            bcmolt_onu_set_onu_state set_state;
            bcmolt_onu_key key = { .pon_ni = od->key.pon_ni, .onu_id = od->data.onu_id };

            /* Deactivate first in case it is already active */
            _onu_deactivate(od->key.pon_ni, od->data.onu_id);

            /* Now activate */
            BCMOLT_OPER_INIT(&set_state, onu, set_onu_state, key);
            BCMOLT_MSG_FIELD_SET(&set_state, onu_state, BCMOLT_ONU_OPERATION_ACTIVE);
            err = bcmolt_oper_submit(netconf_agent_olt_id(), &set_state.hdr);
            if (err == BCM_ERR_OK)
            {
                auto_activated = BCMOS_TRUE;
            }
            else
            {
                NC_LOG_ERR("ONU activation failed for %s. Error %s-%s\n",
                    onu_info->hdr.name, bcmos_strerror(err), set_state.hdr.hdr.err_text);
            }
        }
    }

    /* Send notification if not submitted ONU activation,
       Wait for activation completion if did submit */
    if (!auto_activated)
        _onu_send_onu_discovered(od);
}

/* Ser default configuration parameters not covered by TR-385 */
static void _xpon_v_ani_set_default_cfg(bcmolt_onu_cfg *cfg)
{
    BCMOLT_MSG_FIELD_SET(cfg, itu.auto_learning, BCMOS_TRUE);
    BCMOLT_MSG_FIELD_SET(cfg, itu.xgpon.ranging_burst_profile, 0);
    BCMOLT_MSG_FIELD_SET(cfg, itu.xgpon.data_burst_profile, 1);
}

/* Apply v-ani configuration to OLT */
static bcmos_errno xpon_v_ani_apply(sr_session_ctx_t *srs, xpon_v_ani *onu_info, xpon_v_ani *onu_changes)
{
    bcmos_errno err = BCM_ERR_OK;
    xpon_channel_pair *cpair = NULL;
    xpon_channel_termination *cterm = NULL;
    bcmolt_onu_key key = { .onu_id = BCMOLT_ONU_ID_INVALID };

    /* Read current configuration */
    BUG_ON(onu_info == NULL);

    bcmos_mutex_lock(&onu_config_lock);

    cpair = (onu_changes->cpair != NULL) ? onu_changes->cpair : onu_info->cpair;
    if (cpair == NULL)
        cpair = (onu_changes->protection_cpair != NULL) ? onu_changes->protection_cpair : onu_info->protection_cpair;
    if (cpair == NULL && onu_changes->cpart != NULL)
        cpair = STAILQ_FIRST(&onu_changes->cpart->cpair_list);
    if (cpair == NULL)
    {
        NC_ERROR_REPLY(srs, NULL, "ONU configuration failed for %s. preferred-channel-pair or protection-channel-pair must be set\n",
            onu_info->hdr.name);
        return BCM_ERR_PARM;
    }
    cterm = (cpair->primary_cterm != NULL) ? cpair->primary_cterm : cpair->secondary_cterm;
    if (cterm == NULL)
    {
        NC_ERROR_REPLY(srs, NULL, "ONU configuration failed for %s. No channel-termination is associated with channel-pair %s\n",
            onu_info->hdr.name, cpair->hdr.name);
        return BCM_ERR_PARM;
    }
    onu_changes->pon_ni = key.pon_ni = cterm->pon_ni;

    if (!XPON_PROP_IS_SET(onu_changes, v_ani, onu_id) &&
        !XPON_PROP_IS_SET(onu_info, v_ani, onu_id) &&
        key.pon_ni < BCM_MAX_PONS_PER_OLT)
    {
        XPON_PROP_SET(onu_changes, v_ani, onu_id, _v_ani_get_free_onu_id(key.pon_ni));
    }
    key.onu_id = XPON_PROP_IS_SET(onu_changes, v_ani, onu_id) ? onu_changes->onu_id : onu_info->onu_id;
    if (key.onu_id > XPON_MAX_ONUS_PER_PON)
    {
        NC_ERROR_REPLY(srs, NULL, "ONU configuration failed for %s. onu-id can't be assigned\n",
            onu_info->hdr.name);
        return BCM_ERR_PARM;
    }

    /* Apply new configuration and/or set ONU state if admin_status changed. */
    do
    {
        if (XPON_PROP_IS_SET(onu_changes, v_ani, admin_state) &&
            onu_changes->admin_state == XPON_ADMIN_STATE_DISABLED)
        {
            bcmolt_onu_set_onu_state set_state;
            BCMOLT_OPER_INIT(&set_state, onu, set_onu_state, key);
            BCMOLT_MSG_FIELD_SET(&set_state, onu_state, BCMOLT_ONU_OPERATION_INACTIVE);
            err = bcmolt_oper_submit(netconf_agent_olt_id(), &set_state.hdr);
            if (err != BCM_ERR_OK)
            {
                NC_ERROR_REPLY(srs, NULL, "ONU.set_onu_state(DISABLED) failed for %s. Error %s-%s\n",
                    onu_info->hdr.name, bcmos_strerror(err), set_state.hdr.hdr.err_text);
                break;
            }
        }

        if (XPON_PROP_IS_SET(onu_changes, v_ani, admin_state) &&
            onu_changes->admin_state == XPON_ADMIN_STATE_ENABLED)
        {
            bcmolt_onu_set_onu_state set_state;
            bcmolt_onu_cfg onu_cfg;

            BCMOLT_CFG_INIT(&onu_cfg, onu, key);

            /* Copy config to OLT */
            XPON_PROP_COPY_TO_OLT(onu_changes, v_ani, serial_number, &onu_cfg, itu.serial_number);
            XPON_PROP_COPY_TO_OLT(onu_changes, v_ani, registration_id, &onu_cfg, itu.xgpon.registration_id);

            /* Set additioinal default configuration parameters not covered by TR-385 */
            _xpon_v_ani_set_default_cfg(&onu_cfg);

            err = bcmolt_cfg_set(netconf_agent_olt_id(), &onu_cfg.hdr);
            if (err != BCM_ERR_OK)
            {
                NC_ERROR_REPLY(srs, NULL, "ONU configuration failed for %s. Error %s-%s\n",
                    onu_info->hdr.name, bcmos_strerror(err), onu_cfg.hdr.hdr.err_text);
                break;
            }

            BCMOLT_OPER_INIT(&set_state, onu, set_onu_state, key);
            BCMOLT_MSG_FIELD_SET(&set_state, onu_state, BCMOLT_ONU_OPERATION_ACTIVE);
            err = bcmolt_oper_submit(netconf_agent_olt_id(), &set_state.hdr);
            if (err != BCM_ERR_OK)
            {
                NC_ERROR_REPLY(srs, NULL, "ONU.set_onu_state(ENABLED) failed for %s. Error %s-%s\n",
                    onu_info->hdr.name, bcmos_strerror(err), set_state.hdr.hdr.err_text);
                break;
            }
            onu_info->pon_ni = onu_changes->pon_ni;
        }
    } while (0);

    if (err == BCM_ERR_OK && !onu_changes->hdr.being_deleted)
    {
        /* Update stored configuration */
        XPON_PROP_COPY(onu_changes, onu_info, v_ani, admin_state);
        XPON_PROP_COPY(onu_changes, onu_info, v_ani, serial_number);
        XPON_PROP_COPY(onu_changes, onu_info, v_ani, registration_id);
        XPON_PROP_COPY(onu_changes, onu_info, v_ani, cpair);
        XPON_PROP_COPY(onu_changes, onu_info, v_ani, protection_cpair);
        XPON_PROP_COPY(onu_changes, onu_info, v_ani, onu_id);
        onu_info->cterm = cterm;
        if (onu_info->pon_ni < BCM_MAX_PONS_PER_OLT && onu_info->onu_id < XPON_MAX_ONUS_PER_PON)
            v_ani_array[onu_info->pon_ni][onu_info->onu_id] = onu_info;
    }

    bcmos_mutex_unlock(&onu_config_lock);

    return err;
}

/* Function called from sysrepo "data changed" callback */
bcmos_errno xpon_v_ani_transaction(sr_session_ctx_t *srs, nc_transact *tr)
{
    xpon_v_ani *onu_info = NULL;
    xpon_v_ani onu_changes = {};
    char keyname[32];
    nc_transact_elem *elem;
    bcmos_errno err = BCM_ERR_OK;
    bcmos_bool was_added = BCMOS_FALSE;
    char leafbuf[BCM_MAX_LEAF_LENGTH];
    const char *leaf;
    const char *iter_xpath;
    sr_val_t *val;

    elem = STAILQ_FIRST(&tr->elems);
    if (elem == NULL)
        return BCM_ERR_OK;
    val = elem->new_val ? elem->new_val : elem->old_val;
    iter_xpath = val->xpath;
    nc_xpath_key_get(iter_xpath, "name", keyname, sizeof(keyname));
    NC_LOG_DBG("Handling v-ani %s transaction\n", keyname);
    err = xpon_v_ani_get_by_name(keyname, &onu_info, &was_added);
    if (err != BCM_ERR_OK)
        return err;

    /* Go over transaction elements and map to OLT */
    STAILQ_FOREACH(elem, &tr->elems, next)
    {
        val = elem->new_val ? elem->new_val : elem->old_val;
        iter_xpath = val->xpath;
        leaf = nc_xpath_leaf_get(iter_xpath, leafbuf, sizeof(leafbuf));
        if (leaf == NULL)
            continue;

        /* Map v-ani configuration to OLT */
        if (!strcmp(leaf, "name"))
        {
            onu_changes.hdr.being_deleted = (elem->new_val == NULL);
        }
        else if (!strcmp(leaf, "enabled"))
        {
            bcmos_bool enabled = elem->new_val != NULL && val->data.bool_val;
            xpon_admin_state admin_state = enabled ? XPON_ADMIN_STATE_ENABLED : XPON_ADMIN_STATE_DISABLED;
            XPON_PROP_SET(&onu_changes, v_ani, admin_state, admin_state);
        }
        else if (!strcmp(leaf, "channel-partition"))
        {
            const char *cpart_name = val->data.string_val;
            xpon_channel_partition *cpart = NULL;
            err = xpon_cpart_get_by_name(cpart_name, &cpart, NULL);
            if (err != BCM_ERR_OK && (elem->new_val != NULL))
            {
                NC_ERROR_REPLY(srs, iter_xpath, "v-ani %s references channel-partition %s which doesn't exist\n",
                    keyname, cpart_name);
                break;
            }
            XPON_PROP_SET(&onu_changes, v_ani, cpart, cpart);
        }
        else if (!strcmp(leaf, "preferred-channel-pair"))
        {
            const char *cpair_name = val->data.string_val;
            xpon_channel_pair *cpair = NULL;
            if (elem->new_val != NULL)
            {
                err = xpon_cpair_get_by_name(cpair_name, &cpair, NULL);
                if (err != BCM_ERR_OK)
                {
                    NC_ERROR_REPLY(srs, iter_xpath, "v-ani %s references preferred-channel-pair %s which doesn't exist\n",
                        keyname, cpair_name);
                    break;
                }
            }
            XPON_PROP_SET(&onu_changes, v_ani, cpair, cpair);
        }
        else if (!strcmp(leaf, "protection-channel-pair"))
        {
            const char *cpair_name = val->data.string_val;
            xpon_channel_pair *cpair = NULL;
            if (elem->new_val != NULL)
            {
                err = xpon_cpair_get_by_name(cpair_name, &cpair, NULL);
                if (err != BCM_ERR_OK)
                {
                    NC_ERROR_REPLY(srs, iter_xpath, "v-ani %s references protection-channel-pair %s which doesn't exist\n",
                        keyname, cpair_name);
                    break;
                }
            }
            XPON_PROP_SET(&onu_changes, v_ani, protection_cpair, cpair);
        }
        else if (!strcmp(leaf, "onu-id"))
        {
            XPON_PROP_SET(&onu_changes, v_ani, onu_id, val->data.uint32_val);
        }
        else if (elem->new_val && !strcmp(leaf, BBF_XPON_V_ANI_SERIAL))
        {

            bcmolt_serial_number serial_number = {};
            /* Serial number has the following format: 4xASCII followed by 8 byte hex string */
            if (!elem->new_val->data.string_val ||
                strlen(elem->new_val->data.string_val) < 6 ||
                nc_hex_to_bin(elem->new_val->data.string_val + 4, serial_number.vendor_specific.arr,
                    sizeof(serial_number.vendor_specific)) < 0)
            {
                NC_ERROR_REPLY(srs, iter_xpath,
                    "Serial number is incorrectly formatted. Expected 4 ASCII characters followed by hex string\n");
                err = BCM_ERR_PARM;
                break;
            }
            serial_number.vendor_id.arr[0] = (uint8_t)elem->new_val->data.string_val[0];
            serial_number.vendor_id.arr[1] = (uint8_t)elem->new_val->data.string_val[1];
            serial_number.vendor_id.arr[2] = (uint8_t)elem->new_val->data.string_val[2];
            serial_number.vendor_id.arr[3] = (uint8_t)elem->new_val->data.string_val[3];
            XPON_PROP_SET(&onu_changes, v_ani, serial_number, serial_number);
        }
        else if (elem->new_val && !strcmp(leaf, BBF_XPON_V_ANI_REGISTRATION_ID))
        {
            bcmolt_bin_str_36 reg_id = {};
            int len;
            /* Registration id is hexadecimal string up to 72 bytes long */
            len = nc_hex_to_bin(elem->new_val->data.string_val, reg_id.arr, sizeof(reg_id));
            if (len < 0)
            {
                NC_ERROR_REPLY(srs, iter_xpath,
                    "Registration id is incorrectly formatted\n");
                err = BCM_ERR_PARM;
                break;
            }
            if (len)
                XPON_PROP_SET(&onu_changes, v_ani, registration_id, reg_id);
        }
    }

    /* Apply the new configuration */
    if (err == BCM_ERR_OK)
        err = xpon_v_ani_apply(srs, onu_info, &onu_changes);

    /* Delete ONU record if just added && error, or being deleted */
    if ((err != BCM_ERR_OK && was_added) || onu_changes.hdr.being_deleted)
        xpon_v_ani_delete(onu_info);

    if (onu_changes.hdr.being_deleted)
        err = BCM_ERR_OK;

    NC_LOG_DBG("v-ani transaction completed: %s\n", bcmos_strerror(err));

    return err;
}

/* Populate a single v-ani */
static int xpon_v_ani_state_populate1(sr_session_ctx_t *session, const char *xpath, struct lyd_node **parent,
    xpon_v_ani *v_ani)
{
    const struct ly_ctx *ctx = sr_get_context(sr_session_get_connection(session));

    if (strstr(xpath, "bbf-xponvani:v-ani/onu-wl-protected"))
    {
        /* not supported for now */
    }
    else if (strstr(xpath, "bbf-xponvani:v-ani/onu-present-on-this-olt"))
    {
        if (v_ani->cpair)
        {
            *parent = nc_ly_sub_value_add(ctx, *parent, xpath,
                "onu-present-on-this-channel-pair", v_ani->cpair->hdr.name);
        }
        if (v_ani->cterm)
        {
            *parent = nc_ly_sub_value_add(ctx, *parent, xpath,
                "onu-present-on-this-channel-termination", v_ani->cpair->hdr.name);
        }
    }
    else if (strstr(xpath, "bbf-xponvani:v-ani"))
    {
        if (v_ani->onu_id < XPON_MAX_ONUS_PER_PON)
        {
            char onu_id[16];
            snprintf(onu_id, sizeof(onu_id), "%u", v_ani->onu_id);
            *parent = nc_ly_sub_value_add(ctx, *parent, xpath, "onu-id", onu_id);
            *parent = nc_ly_sub_value_add(ctx, *parent, xpath, "management-tcont-alloc-id", onu_id);
            *parent = nc_ly_sub_value_add(ctx, *parent, xpath, "management-gemport-id", onu_id);
        }
    }
    else
    {
        *parent = nc_ly_sub_value_add(ctx, *parent, xpath, "admin-status",
            (XPON_PROP_IS_SET(v_ani, v_ani, admin_state) &&
                (v_ani->admin_state == XPON_ADMIN_STATE_ENABLED))?
            "up" : "down");

        *parent = nc_ly_sub_value_add(ctx, *parent, xpath, "oper-status",
            v_ani->registered ? "up" : "down");
    }

    return SR_ERR_OK;
}

/* Populate state info */
int xpon_v_ani_state_get_cb(sr_session_ctx_t *session, const char *xpath, struct lyd_node **parent)
{
    xpon_obj_hdr *hdr, *hdr_tmp;
    xpon_v_ani *v_ani;
    int sr_rc = SR_ERR_OK;
    char keyname[32];

    NC_LOG_DBG("xpath=%s\n", xpath);
    if ((strstr(xpath, "bbf-xpon") || strstr(xpath, "bbf-xponani")) && !strstr(xpath, "bbf-xponvani"))
        return SR_ERR_OK;
    if (strstr(xpath, "statistics"))
        return SR_ERR_OK;

    /* If request is unnamed, make sure that path is correct and add all
     * channel-termination nodes.
     * sysrepo will then ask attributes of each node individually
     */
    if (!strchr(xpath, '['))
    {
        char full_xpath[256];
        bcmos_mutex_lock(&onu_config_lock);
        STAILQ_FOREACH_SAFE(hdr, &v_ani_list, next, hdr_tmp)
        {
            v_ani = (xpon_v_ani *)hdr;
            snprintf(full_xpath, sizeof(full_xpath)-1, "%s[name='%s']", xpath, v_ani->hdr.name);
            sr_rc = xpon_v_ani_state_populate1(session, full_xpath, parent, v_ani);
            if (sr_rc != SR_ERR_OK)
                break;
        }
        bcmos_mutex_unlock(&onu_config_lock);

        return sr_rc;
    }

    /*
     * Specific interface
     */

    /* Just return if path refers to interface other than v_ani */
    if (nc_xpath_key_get(xpath, "name", keyname, sizeof(keyname)) != BCM_ERR_OK)
        return SR_ERR_OK;

    /* Find interface record */
    bcmos_mutex_lock(&onu_config_lock);

    if (xpon_object_get(keyname, &hdr) == BCM_ERR_OK &&
        hdr->obj_type == XPON_OBJ_TYPE_V_ANI)
    {
        sr_rc = xpon_v_ani_state_populate1(session, xpath, parent, (xpon_v_ani *)hdr);
    }

    return sr_rc;
}

bcmos_errno xpon_v_ani_init(sr_session_ctx_t *srs)
{
    bcmos_errno err = BCM_ERR_OK;

    sr_session = srs;

    STAILQ_INIT(&v_ani_list);

    err = _olt_onu_ind_register_unregister(BCMOS_TRUE);
    err = err ? err : bcmos_mutex_create(&onu_config_lock, 0, "nc_onu_lock");
    if (!bcm_tr451_onu_management_is_enabled())
    {
        err = err ? err : bcmonu_mgmt_init(BCMOS_MODULE_ID_NETCONF_SERVER);
        err = err ? err : bcmonu_mgmt_olt_init(netconf_agent_olt_id());
        err = err ? err : _omci_onu_ind_register_unregister(BCMOS_TRUE);
    }

    return err;
}

bcmos_errno xpon_v_ani_start(sr_session_ctx_t *srs)
{
    return BCM_ERR_OK;
}

void xpon_v_ani_exit(sr_session_ctx_t *srs)
{
    if (!bcm_tr451_onu_management_is_enabled())
    {
        bcmonu_mgmt_deinit(BCMOS_MODULE_ID_NETCONF_SERVER);
        _omci_onu_ind_register_unregister(BCMOS_FALSE);
    }
    _olt_onu_ind_register_unregister(BCMOS_FALSE);
    bcmos_mutex_destroy(&onu_config_lock);
}

