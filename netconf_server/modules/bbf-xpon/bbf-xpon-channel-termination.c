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
 * bbf-xpon-cterm.c
 *
 * channel_termination support code
 */
#include "bbf-xpon-internal.h"
#ifdef NETCONF_MODULE_BBF_POLT_VOMCI
#include <bcm_tr451_polt.h>
#endif

static xpon_obj_list cterm_list;
static bcmos_mutex cterm_config_lock;
static xpon_channel_termination *cterm_by_id_array[BCM_MAX_PONS_PER_OLT];

/* Disable PON interface */
static bcmos_errno _xpon_cterm_pon_disable(xpon_channel_termination *cterm);

/* Get channel-termination object by name, add a new one if
 * doesn't exist
 */
bcmos_errno xpon_cterm_get_by_name(const char *name, xpon_channel_termination **p_cterm, bcmos_bool *is_added)
{
    xpon_obj_hdr *obj = NULL;
    bcmos_errno err;

    err = xpon_object_get_or_add(name, XPON_OBJ_TYPE_CTERM,
        sizeof(xpon_channel_termination), &obj, is_added);
    if (err != BCM_ERR_OK)
        return err;
    *p_cterm = (xpon_channel_termination *)obj;
    if (is_added != NULL && *is_added)
    {
        (*p_cterm)->pon_ni = BCMOLT_INTERFACE_UNDEFINED;
        STAILQ_INIT(&(*p_cterm)->notifiable_presence_states);
        STAILQ_INSERT_TAIL(&cterm_list, obj, next);
        NC_LOG_INFO("channel-termination %s added\n", name);
    }
    return BCM_ERR_OK;
}

xpon_channel_termination *xpon_cterm_get_by_id(bcmolt_oltid olt, bcmolt_interface pon_ni)
{
    if (pon_ni >= BCM_MAX_PONS_PER_OLT)
        return NULL;
    return cterm_by_id_array[pon_ni];
}

static void xpon_cterm_notifiable_state_list_free(xpon_channel_termination *cterm)
{
    notifiable_onu_presence_state *notifiable_state;
    while((notifiable_state=STAILQ_FIRST(&cterm->notifiable_presence_states)) != NULL)
    {
        STAILQ_REMOVE_SAFE(&cterm->notifiable_presence_states, notifiable_state, notifiable_onu_presence_state, next);
        bcmos_free(notifiable_state);
    }
}

static void xpon_cterm_notifiable_state_add(xpon_channel_termination *cterm, const char *presence_state)
{
    notifiable_onu_presence_state *notifiable_state;
    notifiable_state = bcmos_calloc(sizeof(notifiable_onu_presence_state) + strlen(presence_state) + 1);
    if (notifiable_state == NULL)
    {
        NC_LOG_ERR("cterm %s: No memory for notifiable state\n", cterm->hdr.name);
        return;
    }
    notifiable_state->presence_state = (char *)(notifiable_state + 1);
    strcpy(notifiable_state->presence_state, presence_state);
    STAILQ_INSERT_TAIL(&cterm->notifiable_presence_states, notifiable_state, next);
}

static void xpon_cterm_notifiable_state_delete(xpon_channel_termination *cterm, const char *presence_state)
{
    notifiable_onu_presence_state *notifiable_state, *tmp;
    STAILQ_FOREACH_SAFE(notifiable_state, &cterm->notifiable_presence_states, next, tmp)
    {
        if (!strcmp(presence_state, notifiable_state->presence_state))
        {
            STAILQ_REMOVE_SAFE(&cterm->notifiable_presence_states, notifiable_state, notifiable_onu_presence_state, next);
            bcmos_free(notifiable_state);
            break;
        }
    }
}

bcmos_bool xpon_cterm_is_onu_state_notifiable(const char *cterm_name, const char *state)
{
    notifiable_onu_presence_state *notifiable_state, *tmp;
    xpon_channel_termination *cterm = NULL;

    if (cterm_name == NULL)
        return BCMOS_FALSE;
    xpon_cterm_get_by_name(cterm_name, &cterm, NULL);
    if (cterm == NULL)
        return BCMOS_FALSE;
    STAILQ_FOREACH_SAFE(notifiable_state, &cterm->notifiable_presence_states, next, tmp)
    {
        if (strstr(state, notifiable_state->presence_state) != NULL)
            break;
    }
    return (notifiable_state != NULL);
}

/* Remove channel termination object */
void xpon_cterm_delete(xpon_channel_termination *cterm)
{
    if (cterm->pon_ni < BCM_MAX_PONS_PER_OLT && cterm_by_id_array[cterm->pon_ni] == cterm)
        cterm_by_id_array[cterm->pon_ni] = NULL;
    STAILQ_REMOVE_SAFE(&cterm_list, &cterm->hdr, xpon_obj_hdr, next);
    NC_LOG_INFO("channel-termination %s deleted\n", cterm->hdr.name);
    xpon_cterm_notifiable_state_list_free(cterm);

    /* If cterm was created by forward reference, there is no trigger to disable PON. Do it here */
    if (cterm->hdr.created_by_forward_reference)
        _xpon_cterm_pon_disable(cterm);

    /* Remove cpair references */
    if (cterm->channel_pair_ref != NULL)
    {
        if (cterm->channel_pair_ref->primary_cterm == cterm)
            cterm->channel_pair_ref->primary_cterm = NULL;
        if (cterm->channel_pair_ref->secondary_cterm == cterm)
            cterm->channel_pair_ref->secondary_cterm = NULL;
        if (cterm->channel_pair_ref->hdr.created_by_forward_reference)
            xpon_cpair_delete(cterm->channel_pair_ref);
    }
    if (cterm->port_layer_if && cterm->port_layer_if->hdr.created_by_forward_reference)
    {
        xpon_hardware_delete(cterm->port_layer_if);
    }
    xpon_object_delete(&cterm->hdr);
}

/* Set default pon_interface object configuration values */
static void _cterm_set_pon_interface_defaults(bcmolt_pon_interface_cfg *cfg)
{
    BCMOLT_MSG_FIELD_SET(cfg, xgs_ngpon2_trx.transceiver_type, BCMOLT_XGPON_TRX_TYPE_LTH_7226_PC);
}

/* Set service discovery parameters */
static void _cterm_set_service_discovery(bcmolt_pon_interface_cfg *pon_cfg, const xpon_channel_group *cgroup)
{
    if (cgroup != NULL && cgroup->polling_period)
    {
        BCMOLT_MSG_FIELD_SET(pon_cfg, discovery.interval, cgroup->polling_period * 100); /* polling period is in 0.1 sec */
        BCMOLT_MSG_FIELD_SET(pon_cfg, discovery.control, BCMOLT_CONTROL_STATE_ENABLE);
    }
    else
    {
        BCMOLT_MSG_FIELD_SET(pon_cfg, discovery.control, BCMOLT_CONTROL_STATE_DISABLE);
    }
}

/* Disable PON interface */
static bcmos_errno _xpon_cterm_pon_disable(xpon_channel_termination *cterm)
{
    bcmolt_pon_interface_key key = { .pon_ni = cterm->pon_ni };
    bcmolt_pon_interface_set_pon_interface_state set_state;
    bcmos_errno err;

    if (cterm->pon_ni == BCMOLT_INTERFACE_UNDEFINED || cterm->admin_state != XPON_ADMIN_STATE_ENABLED)
        return BCM_ERR_OK;

    BCMOLT_OPER_INIT(&set_state, pon_interface, set_pon_interface_state, key);
    BCMOLT_MSG_FIELD_SET(&set_state, operation, BCMOLT_INTERFACE_OPERATION_INACTIVE);
    err = bcmolt_oper_submit(netconf_agent_olt_id(), &set_state.hdr);
    return err;
}

/* Apply changes for a single channel-termination */
static bcmos_errno xpon_cterm_apply(sr_session_ctx_t *srs,
    xpon_channel_termination *cterm, xpon_channel_termination *cterm_changes)
{
    bcmolt_interface pon_ni = (cterm->pon_ni != BCMOLT_INTERFACE_UNDEFINED) ? cterm->pon_ni : cterm_changes->pon_ni;
    bcmolt_pon_interface_key key;
    bcmolt_pon_interface_cfg pon_cfg;
    xpon_channel_pair *cpair = cterm_changes->channel_pair_ref ?
        cterm_changes->channel_pair_ref : cterm->channel_pair_ref;
    xpon_channel_group *cgroup = cpair ? cpair->channel_group_ref : NULL;
    xpon_admin_state admin_state = XPON_PROP_IS_SET(cterm_changes, cterm, admin_state) ?
        cterm_changes->admin_state : cterm->admin_state;
    bcmos_errno err;

    do
    {
        if (pon_ni == BCMOLT_INTERFACE_UNDEFINED)
        {
            NC_ERROR_REPLY(srs, NULL, "channel-termination %s: port-layer-if must be set\n",
                cterm->hdr.name);
            err = BCM_ERR_PARM;
            break;
        }
        if (pon_ni > BCM_MAX_PONS_PER_OLT)
        {
            NC_ERROR_REPLY(srs, NULL, "channel-termination %s: port-layer-if/parent-rel-pos is out of range 1..%d\n",
                cterm->hdr.name, BCM_MAX_PONS_PER_OLT);
            err = BCM_ERR_PARM;
            break;
        }

        /* Get current state */
        key.pon_ni = pon_ni; /* 0-based */
        if (cterm_by_id_array[key.pon_ni] != NULL && cterm_by_id_array[key.pon_ni] != cterm)
        {
            NC_ERROR_REPLY(srs, NULL, "channel-termination %s: other chennel-termination %s refers to the same pon_id %u\n",
                cterm->hdr.name, cterm_by_id_array[key.pon_ni]->hdr.name, key.pon_ni);
            err = BCM_ERR_PARM;
            break;
        }
        cterm_by_id_array[key.pon_ni] = cterm;
        cterm->pon_ni = key.pon_ni;
        BCMOLT_CFG_INIT(&pon_cfg, pon_interface, key);
        BCMOLT_MSG_FIELD_GET(&pon_cfg, state);
        err = bcmolt_cfg_get(netconf_agent_olt_id(), &pon_cfg.hdr);
        if (err != BCM_ERR_OK)
        {
            NC_ERROR_REPLY(srs, NULL, "Can't fetch PON MAC configuration for interface %s. Error %s\n",
                cterm->hdr.name, bcmos_strerror(err));
            break;
        }

        /* Do nothing if admin state didn't change */
        if (((admin_state == XPON_ADMIN_STATE_ENABLED) !=
             (pon_cfg.data.state == BCMOLT_INTERFACE_STATE_ACTIVE_WORKING)))
        {
            /* Copy NC configuration to OLT */
            bcmolt_pon_interface_set_pon_interface_state set_state;

            if (admin_state == XPON_ADMIN_STATE_ENABLED)
            {
                BCMOLT_CFG_INIT(&pon_cfg, pon_interface, key);
                _cterm_set_pon_interface_defaults(&pon_cfg);
                _cterm_set_service_discovery(&pon_cfg, cgroup);
                err = bcmolt_cfg_set(netconf_agent_olt_id(), &pon_cfg.hdr);
                if (err != BCM_ERR_OK)
                {
                    NC_ERROR_REPLY(srs, NULL, "Can't set interface %s configuration. Error %s\n",
                        cterm->hdr.name, bcmos_strerror(err));
                    break;
                }

                /* Create channel-termination.name - pon_ni mapping for TR-451 */
#ifdef NETCONF_MODULE_BBF_POLT_VOMCI
                if (bcm_tr451_onu_management_is_enabled())
                {
                    err = bcm_tr451_channel_termination_mapper_add(cterm->hdr.name, key.pon_ni);
                    if (err != BCM_ERR_OK)
                    {
                        NC_ERROR_REPLY(srs, NULL, "Failed to create channel-termination %s - pon_ni mapping for TR-451 pOLT. Error %s\n",
                            cterm->hdr.name, bcmos_strerror(err));
                        break;
                    }
                }
#endif
            }


            BCMOLT_OPER_INIT(&set_state, pon_interface, set_pon_interface_state, key);
            BCMOLT_MSG_FIELD_SET(&set_state, operation,
                (cterm_changes->admin_state == XPON_ADMIN_STATE_ENABLED) ?
                    BCMOLT_INTERFACE_OPERATION_ACTIVE_WORKING : BCMOLT_INTERFACE_OPERATION_INACTIVE);
            err = bcmolt_oper_submit(netconf_agent_olt_id(), &set_state.hdr);
            NC_LOG_DBG("set_pon_interface_state(%u, %s) --> %s\n",
                key.pon_ni, (cterm_changes->admin_state == XPON_ADMIN_STATE_ENABLED) ? "active_working" : "inactive",
                bcmos_strerror(err));
            if (err != BCM_ERR_OK)
            {
                if (err == BCM_ERR_IN_PROGRESS)
                {
                    NC_ERROR_REPLY(srs, NULL, "Interface %u operation is in progress.", key.pon_ni);
                }
                else
                {
                    NC_ERROR_REPLY(srs, NULL, "Attempt to %s interface %u failed. %s",
                        (cterm_changes->admin_state == XPON_ADMIN_STATE_ENABLED) ? "enable" : "disable",
                        key.pon_ni, bcmos_strerror(err));
                }
                break;
            }
        }
        else
        {
            /* Set onu_discovery polling. It can be done in any state */
            BCMOLT_CFG_INIT(&pon_cfg, pon_interface, key);
            _cterm_set_service_discovery(&pon_cfg, cgroup);
            err = bcmolt_cfg_set(netconf_agent_olt_id(), &pon_cfg.hdr);
            if (err != BCM_ERR_OK)
            {
                NC_ERROR_REPLY(srs, NULL, "Can't set interface %s configuration. Error %s\n",
                    cterm->hdr.name, bcmos_strerror(err));
                break;
            }
        }

    } while (0);

    if (err == BCM_ERR_OK && !cterm_changes->hdr.being_deleted)
    {
        if (cterm->port_layer_if != NULL)
            cterm->port_layer_if->cterm = NULL;
        XPON_PROP_COPY(cterm_changes, cterm, cterm, hw_ponid);
        XPON_PROP_COPY(cterm_changes, cterm, cterm, port_layer_if);
        cterm_changes->port_layer_if = NULL;
        XPON_PROP_COPY(cterm_changes, cterm, cterm, admin_state);
        if (cterm->channel_pair_ref != NULL &&
            XPON_PROP_IS_SET(cterm_changes, cterm, channel_pair_ref))
        {
            cterm->channel_pair_ref->primary_cterm = NULL;
        }
        XPON_PROP_COPY(cterm_changes, cterm, cterm, channel_pair_ref);
        if (cterm->channel_pair_ref != NULL)
            cterm->channel_pair_ref->primary_cterm = cterm;
        cterm_changes->channel_pair_ref = NULL;
        if (cterm->port_layer_if != NULL)
            cterm->port_layer_if->cterm = cterm;
    }

    return err;
}


/* Function called from sysrepo "data changed" callback */
bcmos_errno xpon_cterm_transaction(sr_session_ctx_t *srs, nc_transact *tr)
{
    char keyname[32];
    nc_transact_elem *elem;
    bcmos_errno err = BCM_ERR_OK;
    xpon_channel_termination *cterm = NULL;
    xpon_channel_termination cterm_tmp={};
    bcmos_bool was_added = BCMOS_FALSE;
    const char *iter_xpath;

    elem = STAILQ_FIRST(&tr->elems);
    if (elem == NULL)
        return BCM_ERR_OK;

    /* See if there is an existing cterm object */
    iter_xpath = elem->old_val ? elem->old_val->xpath : elem->new_val->xpath;
    nc_xpath_key_get(iter_xpath, "name", keyname, sizeof(keyname));

    NC_LOG_DBG("Handling cterm %s transaction\n", keyname);

    err = xpon_cterm_get_by_name(keyname, &cterm, &was_added);
    if (err != BCM_ERR_OK)
        return err;
    /* If channel termination exists and was already populated by forward reference - stop here */
    if (cterm->hdr.created_by_forward_reference)
    {
        cterm->hdr.created_by_forward_reference = BCMOS_FALSE;
        return BCM_ERR_OK;
    }

    cterm_tmp.pon_ni = cterm->pon_ni;
    STAILQ_INIT(&cterm_tmp.notifiable_presence_states);

    /* Go over transaction elements and map to OLT */
    STAILQ_FOREACH(elem, &tr->elems, next)
    {
        char leafbuf[BCM_MAX_LEAF_LENGTH];
        const char *leaf;
        sr_val_t *val = (elem->new_val != NULL) ? elem->new_val : elem->old_val;
        if (val == NULL)
            continue;
        iter_xpath = val->xpath;

        /* Go over supported leafs */
        leaf = nc_xpath_leaf_get(iter_xpath, leafbuf, sizeof(leafbuf));
        if (leaf == NULL)
            continue;

        if (!strcmp(leaf, "name"))
        {
            cterm_tmp.hdr.being_deleted = (elem->new_val == NULL);
        }
        else if (!strcmp(leaf, "xgs-pon-id") || !strcmp(leaf, "xgpon-pon-id"))
        {
            XPON_PROP_SET(&cterm_tmp, cterm, hw_ponid, val->data.uint32_val);
        }
        else if (strstr(leaf, "port-layer-if") != NULL)
        {
            xpon_hardware *port = NULL;
            if (elem->new_val != NULL)
            {
                const char *_name = elem->new_val ? elem->new_val->data.string_val : elem->old_val->data.string_val;
                err = xpon_hardware_get_populate(srs, _name, &port);
                if (err != BCM_ERR_OK)
                {
                    NC_ERROR_REPLY(srs, iter_xpath, "channel-termination %s references hardware component %s which doesn't exist\n",
                        keyname, _name);
                    err = BCM_ERR_PARM;
                    break;
                }
                XPON_PROP_SET(&cterm_tmp, cterm, port_layer_if, port);
                if (port != NULL)
                {
#ifdef OB_BAA
                    /* OB-BAA derives PON interface id from the port name */
                    if (!memcmp(_name, "PORT", 4) || !memcmp(_name, "port", 4))
                    {
                        const char *_port_id = _name + 4;
                        if (_port_id[0] == '_' || _port_id[0] == '-')
                            ++_port_id;
                        cterm_tmp.pon_ni = atoi(_port_id) - 1;
                    }
                    else
#endif
                    /* Note that parent-rel-pos numbering normally starts from 1 (RFC 6933) */
                    if (XPON_PROP_IS_SET(port, hardware, parent_rel_pos))
                        cterm_tmp.pon_ni = cterm->pon_ni = port->parent_rel_pos - 1;
                    else if (port->parent != NULL && XPON_PROP_IS_SET(port->parent, hardware, parent_rel_pos))
                        cterm_tmp.pon_ni = cterm->pon_ni = port->parent->parent_rel_pos - 1;
                }
            }
        }
        else if (!strcmp(leaf, "enabled"))
        {
            bcmos_bool enabled = elem->new_val && elem->new_val->data.bool_val;
            xpon_admin_state admin_state = enabled ? XPON_ADMIN_STATE_ENABLED : XPON_ADMIN_STATE_DISABLED;
            XPON_PROP_SET(&cterm_tmp, cterm, admin_state, admin_state);
        }
        else if (!strcmp(leaf, "channel-pair-ref"))
        {
            xpon_channel_pair *cpair = NULL;
            const char *cpair_name = elem->new_val ? elem->new_val->data.string_val : elem->old_val->data.string_val;
            if (elem->new_val != NULL)
            {
                xpon_obj_hdr *cpair_hdr;
                err = xpon_interface_get_populate(srs, cpair_name, XPON_OBJ_TYPE_CPAIR, &cpair_hdr);
                if (err != BCM_ERR_OK)
                {
                    NC_ERROR_REPLY(srs, iter_xpath, "channel-termination %s references channel-pair %s which doesn't exist\n",
                        keyname, cpair_name);
                    err = BCM_ERR_PARM;
                    break;
                }
                cpair = (xpon_channel_pair *)cpair_hdr;
            }
            XPON_PROP_SET(&cterm_tmp, cterm, channel_pair_ref, (xpon_channel_pair *)cpair);
            if (cpair != NULL && cpair->primary_cterm != NULL && cpair->primary_cterm != cterm)
            {
                NC_ERROR_REPLY(srs, iter_xpath, "channel-termination %s: channel-pair %s is already referenced by channel-termination %s\n",
                    keyname, cpair_name, cpair->primary_cterm->hdr.name);
                err = BCM_ERR_PARM;
                break;
            }
        }
        else if (strstr(iter_xpath, "notifiable-onu-presence-states") != NULL && val->data.identityref_val != NULL)
        {
            const char *colon = strchr(val->data.identityref_val, ':');
            const char *state = (colon == NULL) ? val->data.identityref_val : colon + 1;
            if (elem->new_val != NULL)
            {
                xpon_cterm_notifiable_state_add(cterm, state);
            }
            else
            {
                xpon_cterm_notifiable_state_delete(cterm, state);
            }
            XPON_PROP_SET_PRESENT(cterm, cterm, notifiable_presence_states);
        }
    }

    /* Apply changes for the last channel-termination */
    if (err == BCM_ERR_OK)
        err = xpon_cterm_apply(srs, cterm, &cterm_tmp);

    if ((err != BCM_ERR_OK && was_added) || cterm_tmp.hdr.being_deleted)
        xpon_cterm_delete(cterm);

    /* Cleanup auto-created channel pair in case of error */
    if (cterm_tmp.channel_pair_ref != NULL &&
        cterm_tmp.channel_pair_ref->hdr.created_by_forward_reference)
    {
        xpon_cpair_delete(cterm_tmp.channel_pair_ref);
    }
    if (cterm_tmp.port_layer_if != NULL &&
        cterm_tmp.port_layer_if->hdr.created_by_forward_reference)
    {
        xpon_hardware_delete(cterm_tmp.port_layer_if);
    }

    if (cterm_tmp.hdr.being_deleted)
        err = BCM_ERR_OK;

    NC_LOG_DBG("cterm transaction completed: %s\n", bcmos_strerror(err));

    return err;
}

/* populate a single channel-termination */
static int xpon_cterm_state_populate1(sr_session_ctx_t *session, const char *xpath, struct lyd_node **parent,
    xpon_channel_termination *cterm)
{
    const struct ly_ctx *ctx = sr_get_context(sr_session_get_connection(session));

    *parent = nc_ly_sub_value_add(ctx, *parent, xpath,
        "admin-status",
        (XPON_PROP_IS_SET(cterm, cterm, admin_state) && (cterm->admin_state == XPON_ADMIN_STATE_ENABLED))?
        "up" : "down");
    *parent = nc_ly_sub_value_add(ctx, *parent, xpath,
        "oper-status", cterm->interface_up ? "up" : "down");
#ifdef TR385_ISSUE2
    {
        char pon_id[32];
        snprintf(pon_id, sizeof(pon_id), "%u", (uint32_t)cterm->hw_ponid);
        *parent = nc_ly_sub_value_add(ctx, *parent, xpath,
            "bbf-xpon:channel-termination/pon-id-display", pon_id);
        *parent = nc_ly_sub_value_add(ctx, *parent, xpath,
            "bbf-xpon:channel-termination/location", "bbf-xpon-types:inside-olt");
    }
#endif
    return SR_ERR_OK;
}

int xpon_cterm_state_get_cb(sr_session_ctx_t *session, const char *xpath, struct lyd_node **parent)
{
    xpon_obj_hdr *hdr, *hdr_tmp;
    xpon_channel_termination *cterm;
    int sr_rc = SR_ERR_OK;
    char keyname[32];

    NC_LOG_DBG("xpath=%s\n", xpath);
    if (strstr(xpath, "bbf-xpon"))
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
        bcmos_mutex_lock(&cterm_config_lock);
        STAILQ_FOREACH_SAFE(hdr, &cterm_list, next, hdr_tmp)
        {
            cterm = (xpon_channel_termination *)hdr;
            snprintf(full_xpath, sizeof(full_xpath)-1, "%s[name='%s']", xpath, cterm->hdr.name);
            xpon_cterm_state_populate1(session, full_xpath, parent, cterm);
        }
        bcmos_mutex_unlock(&cterm_config_lock);

        return sr_rc;
    }

    /*
     * Specific interface
     */

    if (nc_xpath_key_get(xpath, "name", keyname, sizeof(keyname)) != BCM_ERR_OK)
        return SR_ERR_OK;

    /* Find interface record */
    bcmos_mutex_lock(&cterm_config_lock);
    if (xpon_object_get(keyname, &hdr) == BCM_ERR_OK &&
        hdr->obj_type == XPON_OBJ_TYPE_CTERM)
    {
        sr_rc = xpon_cterm_state_populate1(session, xpath, parent, (xpon_channel_termination *)hdr);
    }
    bcmos_mutex_unlock(&cterm_config_lock);

    return sr_rc;
}

bcmos_errno xpon_cterm_init(sr_session_ctx_t *srs)
{
    bcmos_errno err;
    STAILQ_INIT(&cterm_list);
    err = bcmos_mutex_create(&cterm_config_lock, 0, "nc_cterm_lock");
    return err;
}

bcmos_errno xpon_cterm_start(sr_session_ctx_t *srs)
{
    return BCM_ERR_OK;
}

void xpon_cterm_exit(sr_session_ctx_t *srs)
{
    bcmos_mutex_destroy(&cterm_config_lock);
}

