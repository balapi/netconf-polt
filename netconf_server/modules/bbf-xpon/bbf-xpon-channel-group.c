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
 * bbf-xpon-channel-group.c
 */
#include "bbf-xpon-internal.h"

static xpon_obj_list cgroup_list;

bcmos_errno xpon_cgroup_init(sr_session_ctx_t *srs)
{
    STAILQ_INIT(&cgroup_list);
    return BCM_ERR_OK;
}

bcmos_errno xpon_cgroup_start(sr_session_ctx_t *srs)
{
    return BCM_ERR_OK;
}

void xpon_cgroup_exit(sr_session_ctx_t *srs)
{

}

bcmos_errno xpon_cgroup_transaction(sr_session_ctx_t *srs, nc_transact *tr)
{
    xpon_channel_group *cgroup = NULL;
    xpon_channel_group cgroup_tmp = {};
    char keyname[32]={};
    nc_transact_elem *elem;
    bcmos_errno err = BCM_ERR_OK;
    const char *iter_xpath;
    bcmos_bool was_added = BCMOS_FALSE;

    /* See if there is an existing cgroup object */
    elem = STAILQ_FIRST(&tr->elems);
    if (elem == NULL)
        return BCM_ERR_OK;
    iter_xpath = elem->old_val ? elem->old_val->xpath : elem->new_val->xpath;
    nc_xpath_key_get(iter_xpath, "name", keyname, sizeof(keyname));
    NC_LOG_DBG("Handling cgroup %s transaction\n", keyname);
    err = xpon_cgroup_get_by_name(keyname, &cgroup, &was_added);
    if (err != BCM_ERR_OK)
        return err;
    /* If the channel group has already been created by forward reference - stop here */
    if (cgroup->hdr.created_by_forward_reference)
    {
        cgroup->hdr.created_by_forward_reference = BCMOS_FALSE;
        return BCM_ERR_OK;
    }

    /* Go over transaction elements and map to BAL */
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
            cgroup_tmp.hdr.being_deleted = (elem->new_val == NULL);
        }
        else if (!strcmp(leaf, "polling-period"))
        {
            XPON_PROP_SET(&cgroup_tmp, cgroup, polling_period,
                elem->new_val ? elem->new_val->data.uint32_val : 100); /* 100 is the defalt value */
        }
    }

    if (err == BCM_ERR_OK)
    {
        XPON_PROP_COPY(&cgroup_tmp, cgroup, cgroup, polling_period);
    }

    if ((err != BCM_ERR_OK && was_added) || cgroup_tmp.hdr.being_deleted)
        xpon_cgroup_delete(cgroup);

    if (cgroup_tmp.hdr.being_deleted)
        err = BCM_ERR_OK;

    NC_LOG_DBG("cgroup transaction completed: %s\n", bcmos_strerror(err));

    return err;
}

/* Find or add channel group object */
bcmos_errno xpon_cgroup_get_by_name(const char *name, xpon_channel_group **p_cgroup, bcmos_bool *is_added)
{
    xpon_obj_hdr *obj = NULL;
    bcmos_errno err;

    err = xpon_object_get_or_add(name, XPON_OBJ_TYPE_CGROUP,
        sizeof(xpon_channel_group), &obj, is_added);
    if (err != BCM_ERR_OK)
        return err;
    *p_cgroup = (xpon_channel_group *)obj;
    if (is_added != NULL && *is_added)
    {
        STAILQ_INSERT_TAIL(&cgroup_list, obj, next);
        NC_LOG_INFO("channel-group %s added\n", name);
    }
    return BCM_ERR_OK;
}

/* Remove channel group object */
void xpon_cgroup_delete(xpon_channel_group *cgroup)
{
    STAILQ_REMOVE_SAFE(&cgroup_list, &cgroup->hdr, xpon_obj_hdr, next);
    NC_LOG_INFO("channel-group %s deleted\n", cgroup->hdr.name);
    xpon_object_delete(&cgroup->hdr);
}
