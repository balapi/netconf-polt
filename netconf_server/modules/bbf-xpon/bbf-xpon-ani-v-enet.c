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
 * bbf-xpon-ani-v-enet.c
 */

#include "bbf-xpon-internal.h"
#include <onu_mgmt.h>
#include <onu_mgmt_model_funcs.h>
#include <onu_mgmt_model_metadata.h>
#include <bcmolt_utils.h>

//#include <sys/inotify.h>
#include <libnetconf2/log.h>
#include <bcmolt_netconf_module_utils.h>

/* sysrepo session */
static sr_session_ctx_t *sr_session;

static xpon_obj_list ani_v_enet_list;

static bcmos_mutex config_lock;

/* Get ani object by name, add a new one if
 * doesn't exist
 */
bcmos_errno xpon_ani_v_enet_get_by_name(const char *name, xpon_ani_v_enet **p_enet, bcmos_bool *is_added)
{
    xpon_obj_hdr *obj = NULL;
    bcmos_errno err;

    bcmos_mutex_lock(&config_lock);
    do
    {
        err = xpon_object_get_or_add(name, XPON_OBJ_TYPE_ANI,
            sizeof(xpon_ani_v_enet), &obj, is_added);
        if (err != BCM_ERR_OK)
            break;
        *p_enet = (xpon_ani_v_enet *)obj;
        if (is_added != NULL && *is_added)
        {
            STAILQ_INIT(&(*p_enet)->subifs);
            STAILQ_INSERT_TAIL(&ani_v_enet_list, obj, next);
        }
    } while (0);
    bcmos_mutex_unlock(&config_lock);

    return err;
}

/* Remove channel termination object */
void xpon_ani_v_enet_delete(xpon_ani_v_enet *ani_v_enet)
{
    bcmos_mutex_lock(&config_lock);
    xpon_vlan_subif *subif, *subif_tmp;
    STAILQ_REMOVE_SAFE(&ani_v_enet_list, &ani_v_enet->hdr, xpon_obj_hdr, next);
    STAILQ_FOREACH_SAFE(subif, &ani_v_enet->subifs, next, subif_tmp)
    {
        xpon_vlan_subif_delete(subif);
    }
    xpon_unlink(&ani_v_enet->linked_if);
    if (ani_v_enet->ani && ani_v_enet->ani->hdr.created_by_forward_reference)
        xpon_ani_delete(ani_v_enet->ani);

    xpon_object_delete(&ani_v_enet->hdr);
    bcmos_mutex_unlock(&config_lock);
}

/* Apply ani configuration to OLT */
static bcmos_errno xpon_ani_v_enet_apply(sr_session_ctx_t *srs, xpon_ani_v_enet *info, xpon_ani_v_enet *changes)
{
    bcmos_errno err = BCM_ERR_OK;

    /* Read current configuration */
    BUG_ON(info == NULL);

    bcmos_mutex_lock(&config_lock);

    if (err == BCM_ERR_OK && !changes->hdr.being_deleted)
    {
        /* Update stored configuration */
        XPON_PROP_COPY(changes, info, ani_v_enet, ani);
        changes->ani = NULL;
    }

    bcmos_mutex_unlock(&config_lock);

    return err;
}

/* Function called from sysrepo "data changed" callback */
bcmos_errno xpon_ani_v_enet_transaction(sr_session_ctx_t *srs, nc_transact *tr)
{
    xpon_ani_v_enet *info = NULL;
    xpon_ani_v_enet changes = {};
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
    NC_LOG_DBG("Handling ani-v-enet %s transaction\n", keyname);
    err = xpon_ani_v_enet_get_by_name(keyname, &info, &was_added);
    if (err != BCM_ERR_OK)
        return err;
    /* If the interface has already been created by forward reference - stop here */
    if (info->hdr.created_by_forward_reference)
    {
        info->hdr.created_by_forward_reference = BCMOS_FALSE;
        return BCM_ERR_OK;
    }

    /* Go over transaction elements and map to OLT */
    STAILQ_FOREACH(elem, &tr->elems, next)
    {
        val = elem->new_val;
        iter_xpath = elem->new_val ? elem->new_val->xpath : elem->old_val->xpath;
        leaf = nc_xpath_leaf_get(iter_xpath, leafbuf, sizeof(leafbuf));
        if (leaf == NULL)
            continue;

        /* Map ani configuration to OLT */
        if (!strcmp(leaf, "name"))
        {
            changes.hdr.being_deleted = (val == NULL);
        }
        else if (!strcmp(leaf, "ani"))
        {
            xpon_obj_hdr *ani = NULL;
            if (elem->new_val != NULL)
            {
                const char *ani_name = elem->new_val->data.string_val;
                err = xpon_interface_get_populate(srs, ani_name, XPON_OBJ_TYPE_ANI, &ani);
                if (err != BCM_ERR_OK)
                {
                    NC_ERROR_REPLY(srs, iter_xpath, "ani-v-enet %s references ani %s which doesn't exist\n",
                        keyname, ani_name);
                    err = BCM_ERR_INTERNAL;
                    break;
                }
            }
            XPON_PROP_SET(&changes, ani_v_enet, ani, (xpon_ani *)ani);
        }
    }

    /* Apply the new configuration */
    if (err == BCM_ERR_OK)
        err = xpon_ani_v_enet_apply(srs, info, &changes);

    /* Delete ONU record if just added && error, or being deleted */
    if ((err != BCM_ERR_OK && was_added) || changes.hdr.being_deleted)
        xpon_ani_v_enet_delete(info);

    if (changes.ani && changes.ani->hdr.created_by_forward_reference)
        xpon_ani_delete(changes.ani);

    if (changes.hdr.being_deleted)
        err = BCM_ERR_OK;

    NC_LOG_DBG("ani-v-enet transaction completed: %s\n", bcmos_strerror(err));

    return err;
}

/* Populate a single ani */
static int xpon_ani_v_enet_state_populate1(sr_session_ctx_t *session, const char *xpath, struct lyd_node **parent,
    xpon_ani_v_enet *ani)
{
    return SR_ERR_OK;
}

/* Populate state info */
int xpon_ani_v_enet_state_get_cb(sr_session_ctx_t *session, const char *xpath, struct lyd_node **parent)
{
    xpon_obj_hdr *hdr, *hdr_tmp;
    xpon_ani_v_enet *ani;
    int sr_rc = SR_ERR_OK;
    char keyname[32];

    NC_LOG_DBG("xpath=%s\n", xpath);
    if (strstr(xpath, "bbf-xpon") && !strstr(xpath, "bbf-xponvani:olt-v-enet"))
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
        bcmos_mutex_lock(&config_lock);
        STAILQ_FOREACH_SAFE(hdr, &ani_v_enet_list, next, hdr_tmp)
        {
            ani = (xpon_ani_v_enet *)hdr;
            snprintf(full_xpath, sizeof(full_xpath)-1, "%s[name='%s']", xpath, ani->hdr.name);
            sr_rc = xpon_ani_v_enet_state_populate1(session, full_xpath, parent, ani);
            if (sr_rc != SR_ERR_OK)
                break;
        }
        bcmos_mutex_unlock(&config_lock);

        return sr_rc;
    }

    /*
     * Specific interface
     */

    /* Just return if path refers to interface other than ani */
    if (nc_xpath_key_get(xpath, "name", keyname, sizeof(keyname)) != BCM_ERR_OK)
        return SR_ERR_OK;

    /* Find interface record */
    bcmos_mutex_lock(&config_lock);

    if (xpon_object_get(keyname, &hdr) == BCM_ERR_OK &&
        hdr->obj_type == XPON_OBJ_TYPE_ANI)
    {
        sr_rc = xpon_ani_v_enet_state_populate1(session, xpath, parent, (xpon_ani_v_enet *)hdr);
    }

    return sr_rc;
}

bcmos_errno xpon_ani_v_enet_init(sr_session_ctx_t *srs)
{
    bcmos_errno err = BCM_ERR_OK;

    sr_session = srs;

    STAILQ_INIT(&ani_v_enet_list);

    err = err ? err : bcmos_mutex_create(&config_lock, 0, "ani_v_enet_lock");

    return err;
}

bcmos_errno xpon_ani_v_enet_start(sr_session_ctx_t *srs)
{
    return BCM_ERR_OK;
}

void xpon_ani_v_enet_exit(sr_session_ctx_t *srs)
{
    bcmos_mutex_destroy(&config_lock);
}

