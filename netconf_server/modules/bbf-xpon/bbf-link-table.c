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

/* Handle gem transaction */
static bcmos_errno _link_apply(sr_session_ctx_t *srs, const char *xpath,
    xpon_obj_hdr *from_if, xpon_obj_hdr *to_if, bcmos_bool deleted)
{
    bcmos_errno err = BCM_ERR_PARM;

    BUG_ON(from_if == NULL);

    switch(from_if->obj_type)
    {
        case XPON_OBJ_TYPE_V_ANI:
        {
            xpon_v_ani *v_ani = (xpon_v_ani *)from_if;
            if (deleted || to_if == NULL)
            {
                xpon_unlink((xpon_obj_hdr **)&v_ani->linked_ani);
                deleted = BCMOS_TRUE;
            }
            else
            {
                if (to_if->obj_type == XPON_OBJ_TYPE_ANI)
                {
                    xpon_ani *ani = (xpon_ani *)to_if;
                    ani->linked_v_ani = v_ani;
                    v_ani->linked_ani = ani;
                    /* Try to create ONU flows */
                    err = xpon_create_onu_flows_on_onu(srs, v_ani);
                }
            }
            break;
        }

        case XPON_OBJ_TYPE_ANI:
        {
            xpon_ani *ani = (xpon_ani *)from_if;
            if (deleted || to_if == NULL)
            {
                xpon_unlink((xpon_obj_hdr **)&ani->linked_v_ani);
                deleted = BCMOS_TRUE;
            }
            else
            {
                if (to_if->obj_type == XPON_OBJ_TYPE_V_ANI)
                {
                    xpon_v_ani *v_ani = (xpon_v_ani *)to_if;
                    ani->linked_v_ani = v_ani;
                    v_ani->linked_ani = ani;
                    /* Try to create ONU flows */
                    err = xpon_create_onu_flows_on_onu(srs, (xpon_v_ani *)to_if);
                }
            }
            break;
        }

        case XPON_OBJ_TYPE_ENET:
        case XPON_OBJ_TYPE_ANI_V_ENET:
        {
            xpon_obj_hdr **p_from_linked_if;
            if (from_if->obj_type == XPON_OBJ_TYPE_ENET)
            {
                p_from_linked_if = &((xpon_enet *)from_if)->linked_if;
            }
            else
            {
                p_from_linked_if = &((xpon_ani_v_enet *)from_if)->linked_if;
            }
            if (deleted || to_if == NULL)
            {
                xpon_unlink(p_from_linked_if);
                deleted = BCMOS_TRUE;
            }
            else
            {
                if (to_if->obj_type == XPON_OBJ_TYPE_V_ANI_V_ENET)
                {
                    xpon_v_ani_v_enet *v_enet = (xpon_v_ani_v_enet *)to_if;
                    v_enet->linked_if = from_if;
                    *p_from_linked_if = to_if;
                    err = BCM_ERR_OK;
                    /* Try to create ONU flows only if ani and v-ani are already linked */
                    if (v_enet->v_ani != NULL && v_enet->v_ani->linked_ani != NULL)
                        err = xpon_create_onu_flows_on_uni(srs, from_if);
                }
            }
            break;
        }

        case XPON_OBJ_TYPE_V_ANI_V_ENET:
        {
            xpon_v_ani_v_enet *v_enet = (xpon_v_ani_v_enet *)from_if;
            if (deleted || to_if == NULL)
            {
                xpon_unlink(&v_enet->linked_if);
                deleted = BCMOS_TRUE;
            }
            else
            {
                xpon_obj_hdr **p_to_linked_if = NULL;
                if (to_if->obj_type == XPON_OBJ_TYPE_ENET)
                {
                    p_to_linked_if = &((xpon_enet *)to_if)->linked_if;
                }
                else if (to_if->obj_type == XPON_OBJ_TYPE_ANI_V_ENET)
                {
                    p_to_linked_if = &((xpon_ani_v_enet *)to_if)->linked_if;
                }
                if (p_to_linked_if != NULL)
                {
                    v_enet->linked_if = to_if;
                    *p_to_linked_if = from_if;
                    err = BCM_ERR_OK;
                    /* Try to create ONU flows only if ani and v-ani are already linked */
                    if (v_enet->v_ani != NULL && v_enet->v_ani->linked_ani != NULL)
                        err = xpon_create_onu_flows_on_uni(srs, to_if);
                }
            }
            break;
        }

        default:
            break;
    }

    if (deleted)
        err = BCM_ERR_OK;

    if (err != BCM_ERR_OK)
    {
        NC_ERROR_REPLY(srs, xpath, "link-table: failed to link interfaces %s and %s. Error '%s'\n",
            from_if ? from_if->name : "<none>", to_if ? to_if->name : "<none>", bcmos_strerror(err));
        return err;
    }

    NC_LOG_DBG("%s interfaces %s and %s\n", deleted ? "Unlinked" : "Linked",
        from_if ? from_if->name : "<none>", to_if ? to_if->name : "<none>");

    return BCM_ERR_OK;
}

/* Handle gem change events */
static int _link_change_cb(sr_session_ctx_t *srs,
#ifdef SYSREPO_LIBYANG_V2
    uint32_t sub_id,
#endif
    const char *module_name, const char *xpath, sr_event_t event,
    uint32_t request_id, void *private_ctx)
{
    sr_change_iter_t *sr_iter = NULL;
    sr_change_oper_t sr_oper;
    sr_val_t *sr_old_val = NULL, *sr_new_val = NULL;
    xpon_obj_hdr *from_if = NULL, *to_if = NULL;
    const char *prev_xpath = NULL;
    char qualified_xpath[BCM_MAX_XPATH_LENGTH];
    char keyname[32];
    char prev_keyname[32] = "";
    bcmos_bool being_deleted = BCMOS_FALSE;
    int sr_rc;
    bcmos_errno err = BCM_ERR_OK;

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

        if (nc_xpath_key_get(iter_xpath, "from-interface", keyname, sizeof(keyname)) != BCM_ERR_OK ||
            ! *keyname)
        {
            continue;
        }

        /* Handle transaction if key changed */
        if (strcmp(keyname, prev_keyname))
        {
            if (from_if != NULL)
            {
                err = _link_apply(srs, prev_xpath, from_if, to_if, being_deleted);
                if (err != BCM_ERR_OK)
                    break;

                from_if = NULL;
                to_if = NULL;
            }
            strcpy(prev_keyname, keyname);

            if (!strcmp(leaf, "from-interface") && sr_new_val != NULL)
            {
                err = xpon_interface_get_populate(srs, keyname, XPON_OBJ_TYPE_ANY, &from_if);
                if (err != BCM_ERR_OK)
                {
                    NC_ERROR_REPLY(srs, iter_xpath, "link-table: can't find from-interface %s\n", keyname);
                    break;
                }
            }
        }
        prev_xpath = xpath;

        /* handle attributes */
        /* Go over supported leafs */
        if (!strcmp(leaf, "from-interface"))
        {
            being_deleted = (sr_new_val == NULL);
        }
        if (!strcmp(leaf, "to-interface") && sr_new_val != NULL && !being_deleted)
        {
            err = xpon_interface_get_populate(srs, sr_new_val->data.string_val, XPON_OBJ_TYPE_ANY, &to_if);
            if (err != BCM_ERR_OK)
            {
                NC_ERROR_REPLY(srs, iter_xpath, "link-table: can't find to-interface %s\n", keyname);
                break;
            }
        }
    }
    if (from_if != NULL && err == BCM_ERR_OK)
    {
        err = _link_apply(srs, prev_xpath, from_if, to_if, being_deleted);
    }

    /* Cleanup forward references in case of error */
    if (err != BCM_ERR_OK)
    {
        if (from_if != NULL && from_if->created_by_forward_reference)
            xpon_interface_delete(from_if);
        if (to_if != NULL && to_if->created_by_forward_reference)
            xpon_interface_delete(to_if);
    }

    nc_sr_free_value_pair(&sr_old_val, &sr_new_val);
    sr_free_change_iter(sr_iter);

    nc_config_unlock();

    return nc_bcmos_errno_to_sr_errno(err);
}

bcmos_errno xpon_link_init(sr_session_ctx_t *srs)
{
    return BCM_ERR_OK;
}

bcmos_errno xpon_link_start(sr_session_ctx_t *srs)
{
    int sr_rc;

    sr_rc = sr_module_change_subscribe(srs, BBF_LINK_TABLE_MODULE_NAME, BBF_LINK_TABLE_PATH_BASE,
            _link_change_cb, NULL, 0, BCM_SR_MODULE_CHANGE_SUBSCR_FLAGS,
            &sr_ctx);
    if (SR_ERR_OK == sr_rc)
    {
        NC_LOG_INFO("Subscribed to %s subtree changes.\n", BBF_LINK_TABLE_PATH_BASE);
    }
    else
    {
        NC_LOG_ERR("Failed to subscribe to %s subtree changes (%s).\n",
            BBF_LINK_TABLE_PATH_BASE, sr_strerror(sr_rc));
        return nc_sr_errno_to_bcmos_errno(sr_rc);
    }

    return BCM_ERR_OK;
}

void xpon_link_exit(sr_session_ctx_t *srs)
{
}

void xpon_unlink(xpon_obj_hdr **p_link)
{
    if (*p_link == NULL)
        return;
    switch((*p_link)->obj_type)
    {
        case XPON_OBJ_TYPE_V_ANI:
            ((xpon_v_ani *)(*p_link))->linked_ani = NULL;
            break;
        case XPON_OBJ_TYPE_ANI:
            ((xpon_ani *)(*p_link))->linked_v_ani = NULL;
            break;
        case XPON_OBJ_TYPE_ENET:
            ((xpon_enet *)(*p_link))->linked_if = NULL;
            break;
        case XPON_OBJ_TYPE_V_ANI_V_ENET:
            ((xpon_v_ani_v_enet *)(*p_link))->linked_if = NULL;
            break;
        case XPON_OBJ_TYPE_ANI_V_ENET:
            ((xpon_ani_v_enet *)(*p_link))->linked_if = NULL;
            break;
        default:
            NC_LOG_ERR("can't unlink interface %s. Unsupported type for unlink\n", (*p_link)->name);
            break;
    }
    *p_link = NULL;
}
