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
 * bbf-hardware.c
 */

#include "bbf-xpon-internal.h"

static xpon_obj_list hardware_list;
static sr_subscription_ctx_t *sr_ctx_state;

static xpon_hardware_class _hardware_class(const char *name)
{
    const char *pname;
    xpon_hardware_class _class = XPON_HARDWARE_CLASS_UNKNOWN;

    if (name == NULL)
        return XPON_HARDWARE_CLASS_UNKNOWN;
    pname = strchr(name, ':');
    if (pname != NULL)
        ++pname;
    else
        pname = name;

    /* Ignore unknown names */
    if (!strcmp(name, "chassis"))
        _class = XPON_HARDWARE_CLASS_CHASSIS;
    else if (!strcmp(name, "board"))
        _class = XPON_HARDWARE_CLASS_BOARD;
    else if (!strcmp(name, "cage"))
        _class = XPON_HARDWARE_CLASS_CAGE;
    else if (!strcmp(name, "transceiver"))
        _class = XPON_HARDWARE_CLASS_TRANSCEIVER;
    else if (!strcmp(name, "transceiver-link"))
        _class = XPON_HARDWARE_CLASS_TRANSCEIVER_LINK;

    return _class;
}

static bcmos_errno xpon_hardware_attribute_populate(sr_session_ctx_t *srs, xpon_hardware *component,
    sr_val_t *sr_old_val, sr_val_t *sr_new_val)
{
    const char *iter_xpath;
    char leafbuf[BCM_MAX_LEAF_LENGTH];
    const char *leaf;
    bcmos_errno err = BCM_ERR_OK;

    NC_LOG_DBG("old_val=%s new_val=%s type=%d\n",
        sr_old_val ? sr_old_val->xpath : "none",
        sr_new_val ? sr_new_val->xpath : "none",
        sr_old_val ? sr_old_val->type : sr_new_val->type);

    if ((sr_old_val && (sr_old_val->type == SR_LIST_T)) ||
        (sr_new_val && (sr_new_val->type == SR_LIST_T)) ||
        (sr_old_val && (sr_old_val->type == SR_CONTAINER_T)) ||
        (sr_new_val && (sr_new_val->type == SR_CONTAINER_T)))
    {
        /* no semantic meaning */
        return BCM_ERR_OK;
    }

    iter_xpath = sr_new_val ? sr_new_val->xpath : sr_old_val->xpath;
    leaf = nc_xpath_leaf_get(iter_xpath, leafbuf, sizeof(leafbuf));
    if (leaf == NULL)
    {
        /* no semantic meaning */
        return BCM_ERR_OK;
    }

    /* handle attributes */
    /* Go over supported leafs */

    if (!strcmp(leaf, "name"))
    {
        component->hdr.being_deleted = (sr_new_val == NULL);
    }
    else if (!strcmp(leaf, "parent-rel-pos"))
    {
        XPON_PROP_SET(component, hardware, parent_rel_pos,
            sr_new_val ? sr_new_val->data.uint32_val : BCMOLT_PARENT_REL_POS_INVALID);
    }
    else if (!strcmp(leaf, "parent"))
    {
        xpon_hardware *_component = NULL;
        if (sr_new_val)
        {
            const char *_name = sr_new_val ? sr_new_val->data.string_val : sr_old_val->data.string_val;
            err = xpon_hardware_get_populate(srs, _name, &_component);
            if (err != BCM_ERR_OK)
            {
                NC_ERROR_REPLY(srs, iter_xpath, "hardware component %s references parent %s which doesn't exist\n",
                    component->hdr.name, _name);
            }
        }
        XPON_PROP_SET(component, hardware, parent, _component);
    }
    else if (!strcmp(leaf, "class"))
    {
        const char *class_name = (sr_new_val != NULL) ? sr_new_val->data.string_val : NULL;
        XPON_PROP_SET(component, hardware, class, _hardware_class(class_name));
    }
    else if (!strcmp(leaf, "expected-model"))
    {
        if (sr_new_val != NULL)
        {
            strncpy(component->expected_model, sr_new_val->data.string_val, sizeof(component->expected_model) - 1);
            XPON_PROP_SET_PRESENT(component, hardware, expected_model);
        }
        else
        {
            component->expected_model[0] = 0;
            XPON_PROP_CLEAR(component, hardware, expected_model);
        }
    }
    else
    {
        NC_LOG_DBG("xpath %s ignored\n", iter_xpath);
    }

    return BCM_ERR_OK;
}

/* Handle gem change events */
static int _hardware_change_cb(sr_session_ctx_t *srs, const char *module_name,
    const char *xpath, sr_event_t event, uint32_t request_id, void *private_ctx)
{
    sr_change_iter_t *sr_iter = NULL;
    sr_change_oper_t sr_oper;
    sr_val_t *sr_old_val = NULL, *sr_new_val = NULL;
    char keyname[32];
    char prev_keyname[32] = "";
    xpon_hardware *component = NULL;
    bcmos_bool was_added = BCMOS_FALSE;
    char qualified_xpath[BCM_MAX_XPATH_LENGTH];
    int sr_rc;
    bcmos_errno err = BCM_ERR_OK;
    bcmos_bool skip = BCMOS_FALSE;

    nc_config_lock();

    NC_LOG_INFO("xpath=%s event=%d\n", xpath, event);

    /* We only handle CHANGE and ABORT events.
     * Since there is no way to reserve resources in advance and no way to fail the DONE event,
     * configuration is applied in CHANGE event.
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

        sr_val_t *val = sr_new_val ? sr_new_val : sr_old_val;
        if (val == NULL)
            continue;

        iter_xpath = val->xpath;
        if (nc_xpath_key_get(iter_xpath, "name", keyname, sizeof(keyname)) != BCM_ERR_OK ||
            ! *keyname)
        {
            continue;
        }

        /* Handle transaction if key changed */
        if (strcmp(keyname, prev_keyname))
        {
            if (component != NULL)
            {
                if (component->hdr.being_deleted)
                    xpon_hardware_delete(component);
                component = NULL;
            }
            err = xpon_hardware_get_by_name(keyname, &component, &was_added);
            if (err != BCM_ERR_OK)
                break;
            skip = component->hdr.created_by_forward_reference;
            component->hdr.created_by_forward_reference = BCMOS_FALSE;
        }
        strcpy(prev_keyname, keyname);

        /* Populate attribute based on the changed value */
        if (!skip)
        {
            err = xpon_hardware_attribute_populate(srs, component, sr_old_val, sr_new_val);
        }
    }
    if (component != NULL)
    {
        if (component->hdr.being_deleted)
        {
            xpon_hardware_delete(component);
            component = NULL;
        }
        else
        {
            component->hdr.created_by_forward_reference = BCMOS_FALSE;
        }
    }

    nc_sr_free_value_pair(&sr_old_val, &sr_new_val);
    sr_free_change_iter(sr_iter);

    nc_config_unlock();

    return nc_bcmos_errno_to_sr_errno(err);
}

/* Get operational status callback */
static int _hardware_state_get_cb(sr_session_ctx_t *session, const char *module_name,
    const char *xpath, const char *request_path, uint32_t request_id,
    struct lyd_node **parent, void *private_data)
{
    NC_LOG_INFO("module=%s xpath=%s request=%s\n", module_name, xpath, request_path);
    /* ToDo */
    return SR_ERR_OK;
}

bcmos_errno xpon_hardware_init(sr_session_ctx_t *srs)
{
    STAILQ_INIT(&hardware_list);
    return BCM_ERR_OK;
}

bcmos_errno xpon_hardware_start(sr_session_ctx_t *srs)
{
    int sr_rc;

    do
    {
        sr_rc = sr_module_change_subscribe(srs, IETF_HARDWARE_MODULE_NAME, BBF_HARDWARE_PATH_BASE,
                _hardware_change_cb, NULL, 0, BCM_SR_MODULE_CHANGE_SUBSCR_FLAGS,
                &sr_ctx);
        if (SR_ERR_OK == sr_rc)
        {
            NC_LOG_INFO("Subscribed to %s subtree changes.\n", BBF_HARDWARE_PATH_BASE);
        }
        else
        {
            NC_LOG_ERR("Failed to subscribe to %s subtree changes (%s).\n",
                BBF_HARDWARE_PATH_BASE, sr_strerror(sr_rc));
            break;
        }

        /* Subscribe for operational data retrieval */
        sr_rc = sr_oper_get_items_subscribe(srs, IETF_HARDWARE_MODULE_NAME, BBF_HARDWARE_STATE_PATH_BASE,
            _hardware_state_get_cb, NULL, 0, &sr_ctx_state);
        if (SR_ERR_OK != sr_rc)
        {
            NC_LOG_ERR("Failed to subscribe to %s subtree operation data retrieval (%s).",
                BBF_HARDWARE_PATH_BASE, sr_strerror(sr_rc));
            break;
        }
    } while (0);

    return nc_sr_errno_to_bcmos_errno(sr_rc);
}

void xpon_hardware_exit(sr_session_ctx_t *srs)
{
    if (sr_ctx_state != NULL)
        sr_unsubscribe(sr_ctx_state);
}

/* Find or add hardware-component object. Populate from sysrepo session if added */
bcmos_errno xpon_hardware_get_populate(sr_session_ctx_t *srs, const char *name, xpon_hardware **p_component)
{
    bcmos_bool is_added = BCMOS_FALSE;
    bcmos_errno err;
    char query_xpath[256];
    sr_val_t *values = NULL;
    size_t value_cnt = 0;
    int i;
    int sr_rc;

    err = xpon_hardware_get_by_name(name, p_component, &is_added);
    if (err != BCM_ERR_OK)
        return err;
    if (is_added)
    {
        snprintf(query_xpath, sizeof(query_xpath)-1,
            BBF_HARDWARE_PATH_BASE "[name='%s']//.", (*p_component)->hdr.name);
        sr_rc = sr_get_items(srs, query_xpath, 0, SR_OPER_DEFAULT, &values, &value_cnt);
        if (sr_rc)
        {
            NC_LOG_ERR("sr_get_items(%s) -> %s\n", query_xpath, sr_strerror(sr_rc));
            xpon_hardware_delete(*p_component);
            *p_component = NULL;
            return BCM_ERR_PARM;
        }
        NC_LOG_DBG("Populating hardware-component from xpath '%s'. values %u\n",
            query_xpath, (unsigned)value_cnt);

        for (i = 0; i < value_cnt && err == BCM_ERR_OK; i++)
        {
            err = xpon_hardware_attribute_populate(srs, *p_component, NULL, &values[i]);
        }
        sr_free_values(values, value_cnt);
        if (err != BCM_ERR_OK)
        {
            xpon_hardware_delete(*p_component);
            *p_component = NULL;
        }
        else
        {
            (*p_component)->hdr.created_by_forward_reference = BCMOS_TRUE;
        }
    }
    return err;
}

/* Find or add hardware-component object */
bcmos_errno xpon_hardware_get_by_name(const char *name, xpon_hardware **p_component, bcmos_bool *is_added)
{
    xpon_obj_hdr *obj = NULL;
    bcmos_errno err;

    err = xpon_object_get_or_add(name, XPON_OBJ_TYPE_HARDWARE,
        sizeof(xpon_hardware), &obj, is_added);
    if (err != BCM_ERR_OK)
        return err;
    *p_component = (xpon_hardware *)obj;
    if (is_added != NULL && *is_added)
    {
        STAILQ_INSERT_TAIL(&hardware_list, obj, next);
        (*p_component)->parent_rel_pos = BCMOLT_PARENT_REL_POS_INVALID;
        NC_LOG_INFO("hardware component %s added\n", name);
    }
    return BCM_ERR_OK;
}

/* Remove gem object */
void xpon_hardware_delete(xpon_hardware *component)
{
    STAILQ_REMOVE_SAFE(&hardware_list, &component->hdr, xpon_obj_hdr, next);
    if (component->cterm != NULL)
        component->cterm->port_layer_if = NULL;
    if (component->parent && component->parent->hdr.created_by_forward_reference)
    {
        xpon_hardware_delete(component->parent);
        component->parent = NULL;
    }
    NC_LOG_INFO("hardware component %s deleted\n", component->hdr.name);
    xpon_object_delete(&component->hdr);
}
