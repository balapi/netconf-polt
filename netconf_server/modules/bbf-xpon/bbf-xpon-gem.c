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
 * bbf-xpon-gem.c
 */

#include "bbf-xpon-internal.h"

static xpon_obj_list gem_list;
static sr_subscription_ctx_t *sr_ctx_gem_state;

/* Handle gem transaction */
static bcmos_errno _gem_apply(sr_session_ctx_t *srs, const char *xpath,
    xpon_gem *gem, xpon_gem *gem_changes)
{
    bcmolt_gem_port_id gem_port_id = XPON_PROP_IS_SET(gem_changes, gem, gemport_id) ?
        gem_changes->gemport_id : gem->gemport_id;
    bcmolt_interface pon_ni = gem->pon_ni;
    bcmolt_onu_id onu_id = BCMOLT_ONU_ID_INVALID;
    bcmos_bool is_provision = BCMOS_FALSE;
    bcmos_bool is_active = BCMOS_FALSE;
    bcmos_errno err = BCM_ERR_OK;

    if (!gem_changes->hdr.being_deleted)
    {
        if (gem_changes->type == XPON_GEM_TYPE_UNICAST)
        {
            xpon_tcont *tcont = XPON_PROP_IS_SET(gem_changes, gem, tcont) ?
                gem_changes->tcont : gem->tcont;
            xpon_v_ani *v_ani = tcont ? tcont->v_ani : NULL;
            if (v_ani != NULL)
            {
                pon_ni = v_ani->pon_ni;
                onu_id = v_ani->onu_id;
                is_active = v_ani->registered;
                gem->v_ani = v_ani;
                STAILQ_INSERT_TAIL(&v_ani->gems, gem, next);
            }
        }
        else
        {
            xpon_channel_pair *cpair = XPON_PROP_IS_SET(gem_changes, gem, interface) ?
                (xpon_channel_pair *)gem_changes->interface : (xpon_channel_pair *)gem->interface;
            xpon_channel_termination *cterm = NULL;
            if (cpair != NULL && cpair->hdr.obj_type != XPON_OBJ_TYPE_CPAIR)
            {
                cterm = cpair->primary_cterm ? cpair->primary_cterm : cpair->secondary_cterm;
                if (cterm != NULL)
                {
                    pon_ni = cterm->pon_ni;
                    is_active = (cterm->admin_state == XPON_ADMIN_STATE_ENABLED);
                }
            }
        }
        /* See if there is enough info to provision */
        is_provision = pon_ni < BCM_MAX_PONS_PER_OLT &&
            ((gem_changes->type == XPON_GEM_TYPE_UNICAST && onu_id < XPON_MAX_ONUS_PER_PON) ||
            (gem_changes->type != XPON_GEM_TYPE_UNICAST && gem_port_id != BCMOLT_GEM_PORT_ID_INVALID));
    }

    NC_LOG_DBG("gem %s: applying configuration. %s\n",
        gem->hdr.name, gem_changes->hdr.being_deleted ? "CLEAR" : "PROVISION");

    do
    {
        if (gem->state == XPON_RESOURCE_STATE_NOT_CONFIGURED)
        {
            /* Not provisioned yet */
            if (is_provision)
            {
                bcmolt_itupon_gem_cfg cfg;
                bcmolt_itupon_gem_key key = {
                    .pon_ni = pon_ni,
                    .gem_port_id = (gem_port_id != BCMOLT_GEM_PORT_ID_INVALID) ?
                        gem_port_id : BCMOLT_GEM_PORT_ID_NEXT_FREE
                };
                BCMOLT_CFG_INIT(&cfg, itupon_gem, key);
                if (gem_changes->type == XPON_GEM_TYPE_UNICAST)
                {
                    BCMOLT_MSG_FIELD_SET(&cfg, onu_id, onu_id);
                    BCMOLT_MSG_FIELD_SET(&cfg, configuration.direction, BCMOLT_GEM_PORT_DIRECTION_BIDIRECTIONAL);
                    BCMOLT_MSG_FIELD_SET(&cfg, upstream_destination_queue, BCMOLT_US_GEM_PORT_DESTINATION_DATA);
                    BCMOLT_MSG_FIELD_SET(&cfg, configuration.type, BCMOLT_GEM_PORT_TYPE_UNICAST);
                }
                else
                {
                    BCMOLT_MSG_FIELD_SET(&cfg, configuration.direction, BCMOLT_GEM_PORT_DIRECTION_DOWNSTREAM);
                    BCMOLT_MSG_FIELD_SET(&cfg, configuration.type, BCMOLT_GEM_PORT_TYPE_MULTICAST);
                }
                BCMOLT_MSG_FIELD_SET(&cfg, encryption_mode,
                    XPON_PROP_IS_SET(gem_changes, gem, downstream_aes_indicator) ?
                        gem_changes->downstream_aes_indicator : gem->downstream_aes_indicator);
                BCMOLT_MSG_FIELD_SET(&cfg, control, BCMOLT_CONTROL_STATE_ENABLE);
                gem->state = is_active ? XPON_RESOURCE_STATE_ACTIVE : XPON_RESOURCE_STATE_IN_PROGRESS;
                gem->pon_ni = pon_ni;
                err = bcmolt_cfg_set(netconf_agent_olt_id(), &cfg.hdr);
                if (err != BCM_ERR_OK)
                {
                    NC_ERROR_REPLY(srs, xpath, "gem %s: Failed to provision. Error %s (%s)\n",
                        gem->hdr.name, bcmos_strerror(err), cfg.hdr.hdr.err_text);
                    gem->state = XPON_RESOURCE_STATE_NOT_CONFIGURED;
                    break;
                }
                if (key.gem_port_id == BCMOLT_GEM_PORT_ID_NEXT_FREE)
                {
                    XPON_PROP_SET(gem_changes, gem, gemport_id, cfg.key.gem_port_id);
                    NC_LOG_DBG("gemport %s: assigned gemport-id %u\n",
                        gem->hdr.name, cfg.key.gem_port_id);
                }
            }
        }
        else
        {
            if (is_provision && !gem_changes->hdr.being_deleted)
            {
                NC_ERROR_REPLY(srs, xpath, "gem %s: can't change active gem\n", gem->hdr.name);
                err = BCM_ERR_NOT_SUPPORTED;
                break;
            }
            if (pon_ni < BCM_MAX_PONS_PER_OLT &&
                gem->gemport_id != BCMOLT_GEM_PORT_ID_INVALID)
            {
                bcmolt_itupon_gem_cfg cfg;
                bcmolt_itupon_gem_key key = {
                    .pon_ni = pon_ni,
                    .gem_port_id = gem->gemport_id
                };
                BCMOLT_CFG_INIT(&cfg, itupon_gem, key);
                bcmolt_cfg_clear(netconf_agent_olt_id(), &cfg.hdr);
                gem->state = XPON_RESOURCE_STATE_NOT_CONFIGURED;
            }
        }
    } while (0);

    if (err == BCM_ERR_OK && !gem_changes->hdr.being_deleted)
    {
        /* All good. Update NC config */
        XPON_PROP_COPY(gem_changes, gem, gem, gemport_id);
        XPON_PROP_COPY(gem_changes, gem, gem, tcont);
        gem_changes->tcont = NULL;
        XPON_PROP_COPY(gem_changes, gem, gem, interface);
        gem_changes->interface = NULL;
        XPON_PROP_COPY(gem_changes, gem, gem, traffic_class);
        XPON_PROP_COPY(gem_changes, gem, gem, downstream_aes_indicator);
        XPON_PROP_COPY(gem_changes, gem, gem, upstream_aes_indicator);
    }

    if (gem_changes->hdr.being_deleted)
    {
        xpon_gem_delete(gem);
        err = BCM_ERR_OK;
    }

    return err;
}

/* Handle gem change events */
static int _gem_change_cb(sr_session_ctx_t *srs, const char *module_name,
    const char *xpath, sr_event_t event, uint32_t request_id, void *private_ctx)
{
    sr_change_iter_t *sr_iter = NULL;
    sr_change_oper_t sr_oper;
    sr_val_t *sr_old_val = NULL, *sr_new_val = NULL;
    char keyname[32];
    char prev_keyname[32] = "";
    xpon_gem *gem = NULL;
    xpon_gem gem_changes = {};
    bcmos_bool was_added = BCMOS_FALSE;
    bcmos_bool is_multicast;
    char qualified_xpath[BCM_MAX_XPATH_LENGTH];
    const char *prev_xpath = NULL;
    int sr_rc;
    bcmos_errno err = BCM_ERR_OK;

    nc_config_lock();

    NC_LOG_INFO("xpath=%s event=%d\n", xpath, event);
    is_multicast = (strstr(xpath, "multicast-gemports/") != NULL);
    XPON_PROP_SET(&gem_changes, gem, type, is_multicast ? XPON_GEM_TYPE_MULTICAST : XPON_GEM_TYPE_UNICAST);


    /* We only handle CHANGE and ABORT events.
     * Since there is no way to reserve resources in advance and no way to fail the DONE event,
     * configuration is applied in VERIFY event.
     * There are no other verifiers, but if there are and they fail,
     * ABORT event will roll-back the changes.
     */
    if (event == SR_EV_DONE)
    {
        nc_config_unlock();
        return SR_ERR_OK;
    }

    snprintf(qualified_xpath, sizeof(qualified_xpath)-1, "%s//.", xpath);
    qualified_xpath[sizeof(qualified_xpath)-1] = 0;

    /* Go over changed elements */
    for (sr_rc = sr_get_changes_iter(srs, qualified_xpath, &sr_iter);
        (err == BCM_ERR_OK) && (sr_rc == SR_ERR_OK) &&
            (sr_rc = sr_get_change_next(srs, sr_iter, &sr_oper, &sr_old_val, &sr_new_val)) == SR_ERR_OK;
        nc_sr_free_value_pair(&sr_old_val, &sr_new_val))
    {
        const char *iter_xpath;
        char leafbuf[BCM_MAX_LEAF_LENGTH];
        const char *leaf;
        sr_val_t *val;

        if ((sr_old_val && ((sr_old_val->type == SR_LIST_T) && (sr_oper != SR_OP_MOVED))) ||
            (sr_new_val && ((sr_new_val->type == SR_LIST_T) && (sr_oper != SR_OP_MOVED))) ||
            (sr_old_val && (sr_old_val->type == SR_CONTAINER_T)) ||
            (sr_new_val && (sr_new_val->type == SR_CONTAINER_T)))
        {
            /* no semantic meaning */
            continue;
        }
        NC_LOG_DBG("old_val=%s new_val=%s\n",
            sr_old_val ? sr_old_val->xpath : "none",
            sr_new_val ? sr_new_val->xpath : "none");

        val = sr_new_val ? sr_new_val : sr_old_val;
        if (val == NULL)
            continue;
        iter_xpath = val->xpath;

        leaf = nc_xpath_leaf_get(iter_xpath, leafbuf, sizeof(leafbuf));
        if (leaf == NULL)
            continue;

        if (nc_xpath_key_get(iter_xpath, "name", keyname, sizeof(keyname)) != BCM_ERR_OK ||
            ! *keyname)
        {
            continue;
        }

        /* Handle transaction if key changed */
        if (strcmp(keyname, prev_keyname))
        {
            if (gem != NULL)
            {
                err = _gem_apply(srs, prev_xpath, gem, &gem_changes);
                if (err != BCM_ERR_OK)
                {
                    if (was_added)
                        xpon_gem_delete(gem);
                    gem = NULL;
                    break;
                }
                gem = NULL;
                memset(&gem_changes, 0, sizeof(gem_changes));
                XPON_PROP_SET(&gem_changes, gem, type, is_multicast ? XPON_GEM_TYPE_MULTICAST : XPON_GEM_TYPE_UNICAST);
            }
            err = xpon_gem_get_by_name(keyname, &gem, &was_added);
            if (err != BCM_ERR_OK)
                break;
        }
        strcpy(prev_keyname, keyname);
        prev_xpath = xpath;

        /* handle attributes */
        /* Go over supported leafs */

        if (!strcmp(leaf, "name"))
        {
            gem_changes.hdr.being_deleted = (sr_new_val == NULL);
        }
        if (gem_changes.hdr.being_deleted)
            continue;

        if (!strcmp(leaf, "gemport-id"))
        {
            XPON_PROP_SET(&gem_changes, gem, gemport_id,
                sr_new_val ? sr_new_val->data.uint32_val : BCMOLT_GEM_PORT_ID_INVALID);
        }
        else if (!strcmp(leaf, "interface"))
        {
            xpon_obj_hdr *_if = NULL;
            if (sr_new_val)
            {
                const char *_name = sr_new_val->data.string_val;
                err = xpon_interface_get_populate(srs, _name, XPON_OBJ_TYPE_ANY, &_if);
                if (err != BCM_ERR_OK)
                {
                    NC_ERROR_REPLY(srs, iter_xpath, "gem %s references interface %s which doesn't exist\n",
                        keyname, _name);
                    err = BCM_ERR_PARM;
                    break;
                }
            }
            XPON_PROP_SET(&gem_changes, gem, interface, _if);
        }
        else if (!strcmp(leaf, "tcont-ref"))
        {
            const char *_name = sr_new_val ? sr_new_val->data.string_val : sr_old_val->data.string_val;
            xpon_tcont *_tcont = NULL;
            if (sr_new_val)
            {
                err = xpon_tcont_get_populate(srs, _name, &_tcont);
                if (err != BCM_ERR_OK)
                {
                    NC_ERROR_REPLY(srs, iter_xpath, "gem %s references tcont %s which doesn't exist\n",
                        keyname, _name);
                    err = BCM_ERR_PARM;
                    break;
                }
            }
            XPON_PROP_SET(&gem_changes, gem, tcont, _tcont);
        }
        else if (!strcmp(leaf, "traffic-class"))
        {
            XPON_PROP_SET(&gem_changes, gem, traffic_class,
                sr_new_val ? sr_new_val->data.uint8_val : 0);
        }
        else if (!strcmp(leaf, "downstream-aes-indicator"))
        {
            XPON_PROP_SET(&gem_changes, gem, downstream_aes_indicator,
                sr_new_val ? sr_new_val->data.bool_val : BCMOS_FALSE);
        }
        else if (!strcmp(leaf, "upstream-aes-indicator"))
        {
            XPON_PROP_SET(&gem_changes, gem, upstream_aes_indicator,
                sr_new_val ? sr_new_val->data.bool_val : BCMOS_FALSE);
        }
        else if (!strcmp(leaf, "is-broadcast"))
        {
            bcmos_bool is_broadcast = (sr_new_val != NULL) && sr_new_val->data.bool_val;
            XPON_PROP_SET(&gem_changes, gem, type,
                is_broadcast ? XPON_GEM_TYPE_BROADCAST : XPON_GEM_TYPE_MULTICAST);
        }
    }
    if (gem != NULL)
    {
        if (err == BCM_ERR_OK)
            err = _gem_apply(srs, prev_xpath, gem, &gem_changes);
        if (err != BCM_ERR_OK && (was_added || gem_changes.hdr.being_deleted))
            xpon_gem_delete(gem);
    }

    /* Remove forward references in case of error */
    if (gem_changes.tcont != NULL && gem_changes.tcont->hdr.created_by_forward_reference)
        xpon_tcont_delete(gem_changes.tcont);
    if (gem_changes.interface != NULL && gem_changes.interface->created_by_forward_reference)
        xpon_interface_delete(gem_changes.interface);

    if (gem_changes.hdr.being_deleted)
        err = BCM_ERR_OK;

    nc_sr_free_value_pair(&sr_old_val, &sr_new_val);
    sr_free_change_iter(sr_iter);

    nc_config_unlock();

    return nc_bcmos_errno_to_sr_errno(err);
}

/* Populate a single gem */

/* Get operational status callback */
static int xpon_gem_state_populate1(sr_session_ctx_t *session, const char *xpath, struct lyd_node **parent,
    const xpon_gem *gem)
{
    int sr_rc = SR_ERR_OK;
    const struct ly_ctx *ctx = sr_get_context(sr_session_get_connection(session));

    if (XPON_PROP_IS_SET(gem, gem, gemport_id))
    {
        char gemport_id[16];
        snprintf(gemport_id, sizeof(gemport_id), "%u", gem->gemport_id);
        *parent = nc_ly_sub_value_add(ctx, *parent, xpath,
            "actual-gemport-id", gemport_id);
    }
    return sr_rc;
}

/* Get operational status callback */
static int _gem_state_get_cb(sr_session_ctx_t *session, const char *module_name,
    const char *xpath, const char *request_path, uint32_t request_id,
    struct lyd_node **parent, void *private_data)
{
    xpon_obj_hdr *hdr, *hdr_tmp;
    xpon_gem *gem;
    int sr_rc = SR_ERR_OK;
    char keyname[32];

    NC_LOG_INFO("module=%s xpath=%s request=%s\n", module_name, xpath, request_path);

    /* If request is unnamed, make sure that path is correct and add all
     * channel-termination nodes.
     * sysrepo will then ask attributes of each node individually
     */
    if (!strchr(xpath, '['))
    {
        char full_xpath[256];
        /* Add common interface properties for al;l interfaces */
        STAILQ_FOREACH_SAFE(hdr, &gem_list, next, hdr_tmp)
        {
            gem = (xpon_gem *)hdr;
            if (gem->type != XPON_GEM_TYPE_UNICAST)
                continue;
            snprintf(full_xpath, sizeof(full_xpath)-1, "%s[name='%s']", xpath, gem->hdr.name);
            sr_rc = xpon_gem_state_populate1(session, full_xpath, parent, gem);
            if (sr_rc != SR_ERR_OK)
                break;
        }
        return sr_rc;
    }

    /*
     * Specific gem
     */

    /* Just return if path refers to interface other than v_ani */
    if (nc_xpath_key_get(xpath, "name", keyname, sizeof(keyname)) != BCM_ERR_OK)
        return BCM_ERR_OK;

    if (xpon_gem_get_by_name(keyname, &gem, NULL) != BCM_ERR_OK)
        return SR_ERR_NOT_FOUND;

    sr_rc = xpon_gem_state_populate1(session, xpath, parent, gem);

    return sr_rc;
}

bcmos_errno xpon_gem_init(sr_session_ctx_t *srs)
{
    STAILQ_INIT(&gem_list);
    return BCM_ERR_OK;
}

bcmos_errno xpon_gem_start(sr_session_ctx_t *srs)
{
    int sr_rc;

    do
    {
        sr_rc = sr_module_change_subscribe(srs, BBF_XPONGEMTCONT_MODULE_NAME, BBF_XPON_GEM_PATH_BASE,
                _gem_change_cb, NULL, 0, BCM_SR_MODULE_CHANGE_SUBSCR_FLAGS,
                &sr_ctx);
        if (SR_ERR_OK == sr_rc)
        {
            NC_LOG_INFO("Subscribed to %s subtree changes.\n", BBF_XPON_GEM_PATH_BASE);
        }
        else
        {
            NC_LOG_ERR("Failed to subscribe to %s subtree changes (%s).\n",
                BBF_XPON_GEM_PATH_BASE, sr_strerror(sr_rc));
            break;
        }

        sr_rc = sr_module_change_subscribe(srs, BBF_XPON_MODULE_NAME, BBF_XPON_MULTICAST_GEM_PATH_BASE,
                _gem_change_cb, NULL, 0, BCM_SR_MODULE_CHANGE_SUBSCR_FLAGS,
                &sr_ctx);
        if (SR_ERR_OK == sr_rc)
        {
            NC_LOG_INFO("Subscribed to %s subtree changes.\n", BBF_XPON_MULTICAST_GEM_PATH_BASE);
        }
        else
        {
            NC_LOG_ERR("Failed to subscribe to %s subtree changes (%s).\n",
                BBF_XPON_GEM_PATH_BASE, sr_strerror(sr_rc));
            break;
        }

        /* Subscribe for operational data retrieval */
        sr_rc = sr_oper_get_items_subscribe(srs, BBF_XPONGEMTCONT_MODULE_NAME, BBF_XPON_GEM_STATE_PATH_BASE,
            _gem_state_get_cb, NULL, 0, &sr_ctx_gem_state);
        if (SR_ERR_OK != sr_rc)
        {
            NC_LOG_ERR("Failed to subscribe to %s subtree operation data retrieval (%s).",
                BBF_XPON_GEM_STATE_PATH_BASE, sr_strerror(sr_rc));
            break;
        }
    } while (0);

    return nc_sr_errno_to_bcmos_errno(sr_rc);
}

void xpon_gem_exit(sr_session_ctx_t *srs)
{
    if (sr_ctx_gem_state != NULL)
        sr_unsubscribe(sr_ctx_gem_state);
}

/* Find or add gem object */
bcmos_errno xpon_gem_get_by_name(const char *name, xpon_gem **p_gem, bcmos_bool *is_added)
{
    xpon_obj_hdr *obj = NULL;
    bcmos_errno err;

    err = xpon_object_get_or_add(name, XPON_OBJ_TYPE_GEM,
        sizeof(xpon_gem), &obj, is_added);
    if (err != BCM_ERR_OK)
        return err;
    *p_gem = (xpon_gem *)obj;
    if (is_added != NULL && *is_added)
    {
        (*p_gem)->gemport_id = BCMOLT_GEM_PORT_ID_INVALID;
        (*p_gem)->state = XPON_RESOURCE_STATE_NOT_CONFIGURED;
        (*p_gem)->pon_ni = BCMOLT_INTERFACE_UNDEFINED;
        STAILQ_INSERT_TAIL(&gem_list, obj, next);
        NC_LOG_INFO("gem %s added\n", name);
    }
    return BCM_ERR_OK;
}

/* Remove gem object */
void xpon_gem_delete(xpon_gem *gem)
{
    STAILQ_REMOVE_SAFE(&gem_list, &gem->hdr, xpon_obj_hdr, next);
    NC_LOG_INFO("gem %s deleted\n", gem->hdr.name);
    if (gem->v_ani != NULL)
        STAILQ_REMOVE(&gem->v_ani->gems, gem, xpon_gem, next);
    if (gem->tcont != NULL && gem->tcont->hdr.created_by_forward_reference)
        xpon_tcont_delete(gem->tcont);
    if (gem->interface != NULL && gem->interface->created_by_forward_reference)
        xpon_interface_delete(gem->interface);
    xpon_object_delete(&gem->hdr);
}

/* Get GEM port by traffic class */
const xpon_gem *xpon_gem_get_by_traffic_class(const xpon_v_ani_v_enet *iface, uint8_t tc)
{
    xpon_v_ani *v_ani = iface->v_ani;
    const xpon_gem *gem, *gem_tmp;
    if (v_ani == NULL)
        return NULL;
    STAILQ_FOREACH_SAFE(gem, &v_ani->gems, next, gem_tmp)
    {
        if (gem->traffic_class == tc && (gem->interface == &iface->hdr || gem->interface == NULL))
            break;
    }
    return gem;
}
