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
 * bbf-xpon-channel-partition.c
 */
#include "bbf-xpon-internal.h"

static xpon_obj_list cpart_list;

bcmos_errno xpon_cpart_init(sr_session_ctx_t *srs)
{
    STAILQ_INIT(&cpart_list);
    return BCM_ERR_OK;
}

bcmos_errno xpon_cpart_start(sr_session_ctx_t *srs)
{
    return BCM_ERR_OK;
}

void xpon_cpart_exit(sr_session_ctx_t *srs)
{

}

/* Find or add channel partition object */
bcmos_errno xpon_cpart_get_by_name(const char *name, xpon_channel_partition **p_cpart, bcmos_bool *is_added)
{
    xpon_obj_hdr *obj = NULL;
    bcmos_errno err;

    err = xpon_object_get_or_add(name, XPON_OBJ_TYPE_CPART,
        sizeof(xpon_channel_partition), &obj, is_added);
    if (err != BCM_ERR_OK)
        return err;
    *p_cpart = (xpon_channel_partition *)obj;
    if (is_added != NULL && *is_added)
    {
        STAILQ_INSERT_TAIL(&cpart_list, obj, next);
        STAILQ_INIT(&(*p_cpart)->cpair_list);
        NC_LOG_INFO("channel-partition %s added\n", name);
    }
    return BCM_ERR_OK;
}

/* Remove channel partition object */
void xpon_cpart_delete(xpon_channel_partition *cpart)
{
    STAILQ_REMOVE_SAFE(&cpart_list, &cpart->hdr, xpon_obj_hdr, next);
    NC_LOG_INFO("channel-partition %s deleted\n", cpart->hdr.name);
    if (cpart->channel_group_ref != NULL && cpart->channel_group_ref->hdr.created_by_forward_reference)
        xpon_cgroup_delete(cpart->channel_group_ref);
    xpon_object_delete(&cpart->hdr);
}

bcmos_errno xpon_cpart_transaction(sr_session_ctx_t *srs, nc_transact *tr)
{
    xpon_channel_partition *cpart = NULL;
    xpon_channel_partition cpart_tmp = {};
    char keyname[32]={};
    nc_transact_elem *elem;
    bcmos_errno err = BCM_ERR_OK;
    const char *iter_xpath;
    bcmos_bool was_added = BCMOS_FALSE;

    /* See if there is an existing cpart object */
    elem = STAILQ_FIRST(&tr->elems);
    if (elem == NULL)
        return BCM_ERR_OK;
    iter_xpath = elem->old_val ? elem->old_val->xpath : elem->new_val->xpath;
    nc_xpath_key_get(iter_xpath, "name", keyname, sizeof(keyname));
    NC_LOG_DBG("Handling cpart %s transaction\n", keyname);
    err = xpon_cpart_get_by_name(keyname, &cpart, &was_added);
    if (err != BCM_ERR_OK)
        return err;
    /* If the channel partition has already been created by forward reference - stop here */
    if (cpart->hdr.created_by_forward_reference)
    {
        cpart->hdr.created_by_forward_reference = BCMOS_FALSE;
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
            cpart_tmp.hdr.being_deleted = (elem->new_val == NULL);
        }
        else if (!strcmp(leaf, "channel-group-ref"))
        {
            xpon_obj_hdr *cgroup = NULL;
            if (elem->new_val != NULL)
            {
                const char *cgroup_name = elem->new_val->data.string_val;
                err = xpon_interface_get_populate(srs, cgroup_name, XPON_OBJ_TYPE_CGROUP, &cgroup);
                if (err != BCM_ERR_OK)
                {
                    NC_ERROR_REPLY(srs, iter_xpath, "channel-pair %s references channel-group %s which doesn't exist\n",
                        keyname, cgroup_name);
                    err = BCM_ERR_INTERNAL;
                    break;
                }
            }
            XPON_PROP_SET(&cpart_tmp, cpart, channel_group_ref, (xpon_channel_group *)cgroup);
        }
        else if (!strstr(iter_xpath, "/tm-root/"))
        {
            if (elem->new_val != NULL)
            {
                err = xpon_tm_root_attribute_populate(srs, &cpart->tm_root, elem->old_val, elem->new_val);
                if (err == BCM_ERR_OK)
                    XPON_PROP_SET_PRESENT(cpart, cpart, tm_root);
            }
            else
            {
                if (XPON_PROP_IS_SET(cpart, cpart, tm_root))
                {
                    xpon_tm_root_delete(srs, &cpart->tm_root);
                    XPON_PROP_CLEAR(cpart, cpart, tm_root);
                }
            }
        }
    }

    if (err == BCM_ERR_OK)
    {
        XPON_PROP_COPY(&cpart_tmp, cpart, cpart, channel_group_ref);
        cpart_tmp.channel_group_ref = NULL;
    }

    if ((err != BCM_ERR_OK && was_added) || cpart_tmp.hdr.being_deleted)
        xpon_cpart_delete(cpart);

    if (cpart_tmp.channel_group_ref != NULL && cpart_tmp.channel_group_ref->hdr.created_by_forward_reference)
        xpon_cgroup_delete(cpart_tmp.channel_group_ref);

    if (cpart_tmp.hdr.being_deleted)
        err = BCM_ERR_OK;

    NC_LOG_DBG("cpart transaction completed: %s\n", bcmos_strerror(err));

    return err;
}


