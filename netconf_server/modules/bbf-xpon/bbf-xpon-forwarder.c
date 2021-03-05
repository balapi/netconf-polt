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
 * bbf-xpon-forwarder.c
 */
#include "bbf-xpon-internal.h"

static xpon_obj_list forwarder_list;
static xpon_obj_list fwd_split_horizon_prof_list;
static xpon_obj_list fwd_db_list;

static bcmos_errno xpon_fwd_split_horizon_prof_init(sr_session_ctx_t *srs);
static bcmos_errno xpon_fwd_split_horizon_prof_start(sr_session_ctx_t *srs);
static void xpon_fwd_split_horizon_prof_exit(sr_session_ctx_t *srs);

static bcmos_errno xpon_fwd_db_init(sr_session_ctx_t *srs);
static bcmos_errno xpon_fwd_db_start(sr_session_ctx_t *srs);
static void xpon_fwd_db_exit(sr_session_ctx_t *srs);

static void forwarder_ports_delete(xpon_forwarder *fwd, xpon_forwarder_port *stop_at);
static void forwarder_port_delete(xpon_forwarder *fwd, xpon_forwarder_port *port);
static xpon_forwarder_port *forwarder_ports_move(xpon_forwarder *from_fwd, xpon_forwarder *to_fwd);

/*
 * forwarder object
 */

static bcmos_errno _forwarder_apply(sr_session_ctx_t *srs, const char *xpath,
    xpon_forwarder *fwd, xpon_forwarder *changes)
{
    bcmos_errno err = BCM_ERR_OK;
    xpon_forwarder_port *port, *tmp;
    xpon_forwarder_port *old_last;
    xpon_forwarder org = *fwd;

    if (changes->hdr.being_deleted)
    {
        xpon_forwarder_delete(fwd);
        return BCM_ERR_OK;
    }

    /* Check that there are no port duplicates. Can't change existing ports */
    STAILQ_FOREACH_SAFE(port, &changes->ports, next, tmp)
    {
        xpon_forwarder_port *old_port = xpon_fwd_port_get(fwd, port->name);
        if (old_port != NULL || port->being_deleted)
        {
            NC_ERROR_REPLY(srs, xpath, "can't modify the existing forwarder. port %s\n", port->name);
            return BCM_ERR_NOT_SUPPORTED;
        }

        /* We only support forwarder on the OLT side */
        if (!port->being_deleted)
        {
            if (port->subif == NULL)
            {
                NC_ERROR_REPLY(srs, xpath, "sub-interface must be set on port %s\n", port->name);
                return BCM_ERR_PARM;
            }
            if (!port->subif->is_olt_subif)
            {
                NC_ERROR_REPLY(srs, xpath, "ONU forwarding is not supported. port %s\n", port->name);
                return BCM_ERR_NOT_SUPPORTED;
            }
            if (port->subif->forwarder_port != NULL && port->subif->forwarder_port != port)
            {
                NC_ERROR_REPLY(srs, xpath, "subif %s already belong to another forwarder %s\n",
                    port->subif->hdr.name, port->subif->forwarder_port->name);
                return BCM_ERR_NOT_SUPPORTED;
            }
        }
    }

    /* Move ports */
    old_last = forwarder_ports_move(changes, fwd);
    XPON_PROP_COPY(changes, fwd, forwarder, mac_learning_db);
    XPON_PROP_COPY(changes, fwd, forwarder, split_horizon_profile);

    /* Apply new configuration */
    err = xpon_apply_flow_create(srs, fwd);
    if (err != BCM_ERR_OK)
    {
        forwarder_ports_delete(fwd, old_last);

        if (!XPON_PROP_IS_SET(&org, forwarder, mac_learning_db))
            XPON_PROP_CLEAR(fwd, forwarder, mac_learning_db);
        else
            XPON_PROP_COPY(&org, fwd, forwarder, mac_learning_db);

        if (!XPON_PROP_IS_SET(&org, forwarder, split_horizon_profile))
            XPON_PROP_CLEAR(fwd, forwarder, split_horizon_profile);
        else
            XPON_PROP_COPY(&org, fwd, forwarder, split_horizon_profile);

        return err;
    }

    return BCM_ERR_OK;
}

/* Data store change indication callback */
static int bbf_xpon_forwarder_change_cb(sr_session_ctx_t *srs, const char *module_name,
    const char *xpath, sr_event_t event, uint32_t request_id, void *private_ctx)
{
    sr_change_iter_t *sr_iter = NULL;
    sr_change_oper_t sr_oper;
    sr_val_t *sr_old_val = NULL, *sr_new_val = NULL;
    char keyname[32];
    char prev_keyname[32] = "";
    xpon_forwarder *obj = NULL;
    xpon_forwarder changes = {};
    int sr_rc;
    bcmos_bool was_added = BCMOS_FALSE;
    const char *prev_xpath = NULL;
    xpon_forwarder_port *port = NULL;
    char qualified_xpath[BCM_MAX_XPATH_LENGTH];
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

    STAILQ_INIT(&changes.ports);

    snprintf(qualified_xpath, sizeof(qualified_xpath)-1, "%s//.", xpath);
    qualified_xpath[sizeof(qualified_xpath)-1] = 0;

    /* Go over changed elements */
    for (sr_rc = sr_get_changes_iter(srs, qualified_xpath, &sr_iter);
        (err == BCM_ERR_OK) && (sr_rc == SR_ERR_OK) &&
            (sr_rc = sr_get_change_next(srs, sr_iter, &sr_oper, &sr_old_val, &sr_new_val)) == SR_ERR_OK;
        nc_sr_free_value_pair(&sr_old_val, &sr_new_val))
    {
        const char *iter_xpath;
        const char *port_xpath;
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
            if (obj != NULL)
            {
                err = _forwarder_apply(srs, prev_xpath, obj, &changes);
                forwarder_ports_delete(&changes, NULL);
                if (err != BCM_ERR_OK)
                {
                    if (was_added)
                        xpon_forwarder_delete(obj);
                    obj = NULL;
                    break;
                }
                obj = NULL;
                memset(&changes, 0, sizeof(changes));
                STAILQ_INIT(&changes.ports);
            }
            err = xpon_forwarder_get_by_name(keyname, &obj, &was_added);
            if (err != BCM_ERR_OK)
                break;
        }
        strcpy(prev_keyname, keyname);
        prev_xpath = iter_xpath;

        if (changes.hdr.being_deleted)
            continue;

        /* leaf name appear in multiple places. Check xpath first */
        if ((port_xpath=strstr(iter_xpath, "ports/port")) != NULL)
        {
            if (!strcmp(leaf, "name"))
            {
                err = xpon_fwd_port_add(&changes, val->data.string_val, &port);
                if (err != BCM_ERR_OK)
                    break;
                if (sr_new_val == NULL)
                    port->being_deleted = BCMOS_TRUE;
                XPON_PROP_SET_PRESENT(&changes, forwarder, ports);
            }
            else if (!strcmp(leaf, "sub-interface"))
            {
                xpon_obj_hdr *subif = NULL;
                if (port == NULL)
                {
                    NC_LOG_ERR("unexpected leaf %s for unknown port\n", leaf);
                    err = BCM_ERR_INTERNAL;
                    break;
                }
                if (sr_new_val)
                {
                    const char *if_name = sr_new_val->data.string_val;
                    err = xpon_interface_get_populate(srs, if_name, XPON_OBJ_TYPE_VLAN_SUBIF, &subif);
                    if (err != BCM_ERR_OK)
                    {
                        NC_ERROR_REPLY(srs, iter_xpath, "forwarder port %s references %s %s which doesn't exist\n",
                            keyname, leaf, if_name);
                        err = BCM_ERR_PARM;
                        break;
                    }
                }
                port->subif = (xpon_vlan_subif *)subif;
            }
        }
        else if ((port_xpath=strstr(iter_xpath, "port-groups/port")) != NULL)
        {
            NC_LOG_INFO("xpath ignored: %s\n", iter_xpath);
        }
        else
        {
            if (!strcmp(leaf, "name"))
            {
                changes.hdr.being_deleted = (sr_new_val == NULL);
            }
            else if (!strcmp(leaf, "forwarding-database"))
            {
                xpon_fwd_db *db = NULL;
                if (sr_new_val)
                {
                    const char *db_name = sr_new_val->data.string_val;
                    err = xpon_fwd_db_get_by_name(db_name, &db, NULL);
                    if (err != BCM_ERR_OK)
                    {
                        NC_ERROR_REPLY(srs, iter_xpath, "forwarder %s references %s %s which doesn't exist\n",
                            keyname, leaf, db_name);
                        err = BCM_ERR_PARM;
                        break;
                    }
                }
                XPON_PROP_SET(&changes, forwarder, mac_learning_db, db);
            }
            else if (!strcmp(leaf, "split-horizon-profile"))
            {
                xpon_fwd_split_horizon_profile *prof = NULL;
                if (sr_new_val)
                {
                    const char *prof_name = sr_new_val->data.string_val;
                    err = xpon_fwd_split_horizon_profile_get_by_name(prof_name, &prof, NULL);
                    if (err != BCM_ERR_OK)
                    {
                        NC_ERROR_REPLY(srs, iter_xpath, "forwarder %s references %s %s which doesn't exist\n",
                            keyname, leaf, prof_name);
                        err = BCM_ERR_PARM;
                        break;
                    }
                }
                XPON_PROP_SET(&changes, forwarder, split_horizon_profile, prof);
            }
            else
            {
                NC_LOG_INFO("xpath ignored: %s\n", iter_xpath);
            }
        }
    }

    if (obj != NULL)
    {
        if (err == BCM_ERR_OK)
            err = _forwarder_apply(srs, prev_xpath, obj, &changes);
        if (err != BCM_ERR_OK && (was_added || changes.hdr.being_deleted))
            xpon_forwarder_delete(obj);
    }
    if (changes.hdr.being_deleted)
        err = BCM_ERR_OK;
    forwarder_ports_delete(&changes, NULL);

    nc_sr_free_value_pair(&sr_old_val, &sr_new_val);
    sr_free_change_iter(sr_iter);

    nc_config_unlock();

    return nc_bcmos_errno_to_sr_errno(err);
}


bcmos_errno xpon_forwarder_init(sr_session_ctx_t *srs)
{
    STAILQ_INIT(&forwarder_list);
    xpon_fwd_split_horizon_prof_init(srs);
    xpon_fwd_db_init(srs);
    return BCM_ERR_OK;
}

bcmos_errno xpon_forwarder_start(sr_session_ctx_t *srs)
{
    bcmos_errno err = BCM_ERR_OK;
    int sr_rc;
    /* subscribe to events */
    sr_rc = sr_module_change_subscribe(srs, BBF_L2_FORWARDING_MODULE_NAME, BBF_FORWARDING_TABLE_PATH_BASE,
            bbf_xpon_forwarder_change_cb, NULL, 10, BCM_SR_MODULE_CHANGE_SUBSCR_FLAGS,
            &sr_ctx);
    if (SR_ERR_OK == sr_rc)
    {
        NC_LOG_INFO("Subscribed to %s subtree changes.\n", BBF_FORWARDING_TABLE_PATH_BASE);
    }
    else
    {
        NC_LOG_ERR("Failed to subscribe to %s subtree changes (%s).\n",
            BBF_FORWARDING_TABLE_PATH_BASE, sr_strerror(sr_rc));
        err = nc_sr_errno_to_bcmos_errno(sr_rc);
    }
    err = err ? err : xpon_fwd_split_horizon_prof_start(srs);
    err = err ? err : xpon_fwd_db_start(srs);

    return nc_sr_errno_to_bcmos_errno(sr_rc);
}

void xpon_forwarder_exit(sr_session_ctx_t *srs)
{
    xpon_fwd_split_horizon_prof_exit(srs);
    xpon_fwd_db_exit(srs);
}

/* Get forwarder object by name, add a new one if
 * doesn't exist
 */
bcmos_errno xpon_forwarder_get_by_name(const char *name, xpon_forwarder **p_obj, bcmos_bool *is_added)
{
    xpon_obj_hdr *obj = NULL;
    bcmos_errno err;

    err = xpon_object_get_or_add(name, XPON_OBJ_TYPE_FORWARDER,
        sizeof(xpon_forwarder), &obj, is_added);
    if (err != BCM_ERR_OK)
        return err;
    *p_obj = (xpon_forwarder *)obj;
    if (is_added != NULL && *is_added)
    {
        STAILQ_INIT(&(*p_obj)->ports);
        STAILQ_INSERT_TAIL(&forwarder_list, obj, next);
        NC_LOG_INFO("forwarder %s added\n", name);
    }
    return BCM_ERR_OK;
}

static void forwarder_port_delete(xpon_forwarder *fwd, xpon_forwarder_port *port)
{
    STAILQ_REMOVE_SAFE(&fwd->ports, port, xpon_forwarder_port, next);
    if (port->subif != NULL)
    {
        xpon_apply_flow_delete(NULL, port->subif, fwd);
        port->subif->forwarder_port = NULL;
        if (port->subif->hdr.created_by_forward_reference)
            xpon_vlan_subif_delete(port->subif);
    }
    bcmos_free(port);
    if (STAILQ_EMPTY(&fwd->ports))
        XPON_PROP_CLEAR(fwd, forwarder, ports);
}

static void forwarder_ports_delete(xpon_forwarder *fwd, xpon_forwarder_port *stop_at)
{
    xpon_forwarder_port *port, *tmp;
    STAILQ_FOREACH_SAFE(port, &fwd->ports, next, tmp)
    {
        if (port == stop_at)
            break;
        forwarder_port_delete(fwd, port);
    }
}

static xpon_forwarder_port *forwarder_ports_move(xpon_forwarder *from_fwd, xpon_forwarder *to_fwd)
{
    xpon_forwarder_port *port, *tmp;
    xpon_forwarder_port *last = STAILQ_LAST(&from_fwd->ports, xpon_forwarder_port, next);

    if (!XPON_PROP_IS_SET(from_fwd, forwarder, ports))
        return last;

    STAILQ_FOREACH_SAFE(port, &from_fwd->ports, next, tmp)
    {
        if (port->being_deleted)
        {
            xpon_fwd_port_delete(to_fwd, port->name);
            forwarder_port_delete(from_fwd, port);
        }
        else
        {
            STAILQ_REMOVE_SAFE(&from_fwd->ports, port, xpon_forwarder_port, next);
            port->forwarder = to_fwd;
            if (port->subif != NULL)
                port->subif->forwarder_port = port;
            STAILQ_INSERT_TAIL(&to_fwd->ports, port, next);
        }
    }
    XPON_PROP_SET_PRESENT(to_fwd, forwarder, ports);
    return last;
}

/* Delete forwarder object */
void xpon_forwarder_delete(xpon_forwarder *obj)
{
    STAILQ_REMOVE_SAFE(&forwarder_list, &obj->hdr, xpon_obj_hdr, next);
    /* Remove ports */
    forwarder_ports_delete(obj, NULL);
    NC_LOG_INFO("forwarder %s deleted\n", obj->hdr.name);
    xpon_object_delete(&obj->hdr);
}

/* Add forwarding port */
bcmos_errno xpon_fwd_port_add(xpon_forwarder *fwd, const char *name, xpon_forwarder_port **p_port)
{
    xpon_forwarder_port *port;
    port = bcmos_calloc(sizeof(*port) + strlen(name) + 1);
    if (port == NULL)
        return BCM_ERR_NOMEM;
    strcpy((char *)(port + 1), name);
    port->name = (const char *)(port + 1);
    port->forwarder = fwd;
    STAILQ_INSERT_TAIL(&fwd->ports, port, next);
    *p_port = port;
    return BCM_ERR_OK;
}

bcmos_errno xpon_fwd_port_delete(xpon_forwarder *fwd, const char *name)
{
    xpon_forwarder_port *port = xpon_fwd_port_get(fwd, name);
    if (port == NULL)
        return BCM_ERR_NOENT;
    forwarder_port_delete(fwd, port);
    return BCM_ERR_OK;
}

xpon_forwarder_port* xpon_fwd_port_get(xpon_forwarder *fwd, const char *name)
{
    xpon_forwarder_port *port, *tmp;
    STAILQ_FOREACH_SAFE(port, &fwd->ports, next, tmp)
    {
        if (!strcmp(port->name, name))
            break;
    }
    return port;
}

uint32_t xpon_fwd_port_num_of(xpon_forwarder *fwd)
{
    xpon_forwarder_port *port, *tmp;
    uint32_t num_of = 0;
    STAILQ_FOREACH_SAFE(port, &fwd->ports, next, tmp)
    {
        ++num_of;
    }
    return num_of;
}

/*
 * forwarding-database object
 */

/* Data store change indication callback */
static int bbf_xpon_fwd_db_change_cb(sr_session_ctx_t *srs, const char *module_name,
    const char *xpath, sr_event_t event, uint32_t request_id, void *private_ctx)
{
    sr_change_iter_t *sr_iter = NULL;
    sr_change_oper_t sr_oper;
    sr_val_t *sr_old_val = NULL, *sr_new_val = NULL;
    char keyname[32];
    char prev_keyname[32] = "";
    xpon_fwd_db *obj = NULL;
    int sr_rc;
    bcmos_bool was_added = BCMOS_FALSE;
    char qualified_xpath[BCM_MAX_XPATH_LENGTH];
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

        if (nc_xpath_key_get(iter_xpath, "name", keyname, sizeof(keyname)) != BCM_ERR_OK ||
            ! *keyname)
        {
            continue;
        }

        /* Handle transaction if key changed */
        if (strcmp(keyname, prev_keyname))
        {
            if (obj != NULL && obj->hdr.being_deleted)
            {
                xpon_fwd_db_delete(obj);
                obj = NULL;
            }
            err = xpon_fwd_db_get_by_name(keyname, &obj, &was_added);
            if (err != BCM_ERR_OK)
                break;
        }
        strcpy(prev_keyname, keyname);

        /* handle attributes */
        /* Go over supported leafs */

        if (!strcmp(leaf, "name"))
        {
            obj->hdr.being_deleted = (sr_new_val == NULL);
        }
        else if (!strcmp(leaf, "shared-forwarding-database"))
        {
            XPON_PROP_SET(obj, fwd_db, shared_database,
                sr_new_val ? sr_new_val->data.bool_val : BCMOS_FALSE);
        }
        else
        {
            NC_LOG_INFO("xpath ignored: %s\n", iter_xpath);
        }
    }

    if (obj != NULL && (obj->hdr.being_deleted || (err != BCM_ERR_OK && was_added)))
    {
        if (obj->hdr.being_deleted)
            err = BCM_ERR_OK;
        xpon_fwd_db_delete(obj);
    }

    nc_sr_free_value_pair(&sr_old_val, &sr_new_val);
    sr_free_change_iter(sr_iter);

    nc_config_unlock();

    return nc_bcmos_errno_to_sr_errno(err);
}


static bcmos_errno xpon_fwd_db_init(sr_session_ctx_t *srs)
{
    STAILQ_INIT(&fwd_db_list);
    return BCM_ERR_OK;
}

static bcmos_errno xpon_fwd_db_start(sr_session_ctx_t *srs)
{
    int sr_rc;
    /* subscribe to events */
    sr_rc = sr_module_change_subscribe(srs, BBF_L2_FORWARDING_MODULE_NAME, BBF_FWD_DATABASE_PATH_BASE,
            bbf_xpon_fwd_db_change_cb, NULL, 0, BCM_SR_MODULE_CHANGE_SUBSCR_FLAGS,
            &sr_ctx);
    if (SR_ERR_OK == sr_rc)
    {
        NC_LOG_INFO("Subscribed to %s subtree changes.\n", BBF_FWD_DATABASE_PATH_BASE);
    }
    else
    {
        NC_LOG_ERR("Failed to subscribe to %s subtree changes (%s).\n",
            BBF_FWD_DATABASE_PATH_BASE, sr_strerror(sr_rc));
    }

    return nc_sr_errno_to_bcmos_errno(sr_rc);
}

static void xpon_fwd_db_exit(sr_session_ctx_t *srs)
{
}

/* Get forwarding-database object by name, add a new one if
 * doesn't exist
 */
bcmos_errno xpon_fwd_db_get_by_name(const char *name, xpon_fwd_db **p_obj, bcmos_bool *is_added)
{
    xpon_obj_hdr *obj = NULL;
    bcmos_errno err;

    err = xpon_object_get_or_add(name, XPON_OBJ_TYPE_FWD_DB,
        sizeof(xpon_fwd_db), &obj, is_added);
    if (err != BCM_ERR_OK)
        return err;
    *p_obj = (xpon_fwd_db *)obj;
    if (is_added != NULL && *is_added)
    {
        STAILQ_INSERT_TAIL(&fwd_db_list, obj, next);
        NC_LOG_INFO("forwarding-database %s added\n", name);
    }
    return BCM_ERR_OK;
}

/* Delete forwarding-database object */
void xpon_fwd_db_delete(xpon_fwd_db *obj)
{
    STAILQ_REMOVE_SAFE(&fwd_db_list, &obj->hdr, xpon_obj_hdr, next);
    NC_LOG_INFO("forwarding-database %s deleted\n", obj->hdr.name);
    xpon_object_delete(&obj->hdr);
}

/*
 * split-horizon-profile object
 */

/* Data store change indication callback */
static int bbf_xpon_fwd_split_horizon_prof_change_cb(sr_session_ctx_t *srs, const char *module_name,
    const char *xpath, sr_event_t event, uint32_t request_id, void *private_ctx)
{
    sr_change_iter_t *sr_iter = NULL;
    sr_change_oper_t sr_oper;
    sr_val_t *sr_old_val = NULL, *sr_new_val = NULL;
    char keyname[32];
    char prev_keyname[32] = "";
    char qualified_xpath[BCM_MAX_XPATH_LENGTH];
    xpon_fwd_split_horizon_profile *obj = NULL;
    int sr_rc;
    bcmos_bool was_added = BCMOS_FALSE;
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

        if (nc_xpath_key_get(iter_xpath, "name", keyname, sizeof(keyname)) != BCM_ERR_OK ||
            ! *keyname)
        {
            continue;
        }

        /* Handle transaction if key changed */
        if (strcmp(keyname, prev_keyname))
        {
            if (obj != NULL && obj->hdr.being_deleted)
            {
                xpon_fwd_split_horizon_profile_delete(obj);
                obj = NULL;
            }
            err = xpon_fwd_split_horizon_profile_get_by_name(keyname, &obj, &was_added);
            if (err != BCM_ERR_OK)
                break;
        }
        strcpy(prev_keyname, keyname);

        /* handle attributes */
        /* Go over supported leafs */

        if (!strcmp(leaf, "name"))
        {
            obj->hdr.being_deleted = (sr_new_val == NULL);
        }
        else if (!strcmp(leaf, "in-interface-usage"))
        {
            XPON_PROP_SET(obj, fwd_split_horizon_profile, in_interface_usage,
                sr_new_val ?
                    xpon_map_iface_usage(sr_new_val->data.identityref_val) :
                    BBF_INTERFACE_USAGE_UNDEFINED);
        }
        else if (!strcmp(leaf, "out-interface-usage"))
        {
            XPON_PROP_SET(obj, fwd_split_horizon_profile, out_interface_usage,
                sr_new_val ?
                    xpon_map_iface_usage(sr_new_val->data.identityref_val) :
                    BBF_INTERFACE_USAGE_UNDEFINED);
        }
        else
        {
            NC_LOG_INFO("xpath ignored: %s\n", iter_xpath);
        }
    }

    if (obj != NULL && (obj->hdr.being_deleted || (err != BCM_ERR_OK && was_added)))
    {
        if (obj->hdr.being_deleted)
            err = BCM_ERR_OK;
        xpon_fwd_split_horizon_profile_delete(obj);
    }

    nc_sr_free_value_pair(&sr_old_val, &sr_new_val);
    sr_free_change_iter(sr_iter);

    nc_config_unlock();

    return nc_bcmos_errno_to_sr_errno(err);
}


static bcmos_errno xpon_fwd_split_horizon_prof_init(sr_session_ctx_t *srs)
{
    STAILQ_INIT(&fwd_split_horizon_prof_list);
    return BCM_ERR_OK;
}

static bcmos_errno xpon_fwd_split_horizon_prof_start(sr_session_ctx_t *srs)
{
    int sr_rc;
    /* subscribe to events */
    sr_rc = sr_module_change_subscribe(srs, BBF_L2_FORWARDING_MODULE_NAME, BBF_FWD_SPLIT_HORIZON_PROFILE_PATH_BASE,
            bbf_xpon_fwd_split_horizon_prof_change_cb, NULL, 0, BCM_SR_MODULE_CHANGE_SUBSCR_FLAGS,
            &sr_ctx);
    if (SR_ERR_OK == sr_rc)
    {
        NC_LOG_INFO("Subscribed to %s subtree changes.\n", BBF_FWD_SPLIT_HORIZON_PROFILE_PATH_BASE);
    }
    else
    {
        NC_LOG_ERR("Failed to subscribe to %s subtree changes (%s).\n",
            BBF_FWD_SPLIT_HORIZON_PROFILE_PATH_BASE, sr_strerror(sr_rc));
    }

    return nc_sr_errno_to_bcmos_errno(sr_rc);
}

static void xpon_fwd_split_horizon_prof_exit(sr_session_ctx_t *srs)
{
}

/* Get split-horizon-profile object by name, add a new one if
 * doesn't exist
 */
bcmos_errno xpon_fwd_split_horizon_profile_get_by_name(const char *name, xpon_fwd_split_horizon_profile **p_obj, bcmos_bool *is_added)
{
    xpon_obj_hdr *obj = NULL;
    bcmos_errno err;

    err = xpon_object_get_or_add(name, XPON_OBJ_TYPE_FWD_SPLIT_HORIZON_PROFILE,
        sizeof(xpon_fwd_split_horizon_profile), &obj, is_added);
    if (err != BCM_ERR_OK)
        return err;
    *p_obj = (xpon_fwd_split_horizon_profile *)obj;
    if (is_added != NULL && *is_added)
    {
        STAILQ_INSERT_TAIL(&fwd_split_horizon_prof_list, obj, next);
        NC_LOG_INFO("fwd_split_horizon_prof %s added\n", name);
    }
    return BCM_ERR_OK;
}

/* Delete split-horizon-profile object */
void xpon_fwd_split_horizon_profile_delete(xpon_fwd_split_horizon_profile *obj)
{
    STAILQ_REMOVE_SAFE(&fwd_split_horizon_prof_list, &obj->hdr, xpon_obj_hdr, next);
    NC_LOG_INFO("split-horizon-profile %s deleted\n", obj->hdr.name);
    xpon_object_delete(&obj->hdr);
}
