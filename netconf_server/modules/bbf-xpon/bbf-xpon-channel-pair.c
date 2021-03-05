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
 * bbf-xpon-channel-pair.c
 */
#include "bbf-xpon-internal.h"

static xpon_obj_list cpair_list;

/* Get channel-PAIR object by name, add a new one if
 * doesn't exist
 */
bcmos_errno xpon_cpair_get_by_name(const char *name, xpon_channel_pair **p_cpair, bcmos_bool *is_added)
{
    xpon_obj_hdr *obj = NULL;
    bcmos_errno err;

    err = xpon_object_get_or_add(name, XPON_OBJ_TYPE_CPAIR,
        sizeof(xpon_channel_pair), &obj, is_added);
    if (err != BCM_ERR_OK)
        return err;
    *p_cpair = (xpon_channel_pair *)obj;
    if (is_added != NULL && *is_added)
    {
        STAILQ_INSERT_TAIL(&cpair_list, obj, next);
        NC_LOG_INFO("channel-pair %s added\n", name);
    }
    return BCM_ERR_OK;
}

/* Remove channel-pair object */
void xpon_cpair_delete(xpon_channel_pair *cpair)
{
    NC_LOG_INFO("channel-pair %s deleted\n", cpair->hdr.name);
    STAILQ_REMOVE_SAFE(&cpair_list, &cpair->hdr, xpon_obj_hdr, next);
    if (cpair->channel_partition_ref != NULL)
    {
        STAILQ_REMOVE_SAFE(&cpair->channel_partition_ref->cpair_list, cpair, xpon_channel_pair, next);
    }
    if (cpair->primary_cterm != NULL && cpair->primary_cterm->channel_pair_ref == cpair)
    {
        cpair->primary_cterm->channel_pair_ref = NULL;
    }
    if (cpair->secondary_cterm != NULL && cpair->secondary_cterm->channel_pair_ref == cpair)
    {
        cpair->secondary_cterm->channel_pair_ref = NULL;
    }
    /* Cleanup forward references */
    if (cpair->channel_partition_ref != NULL &&
        cpair->channel_partition_ref->hdr.created_by_forward_reference)
    {
        xpon_cpart_delete(cpair->channel_partition_ref);
    }
    if (cpair->channel_group_ref != NULL &&
        cpair->channel_group_ref->hdr.created_by_forward_reference)
    {
        xpon_cgroup_delete(cpair->channel_group_ref);
    }
    if (cpair->wavelen_prof_ref != NULL && cpair->wavelen_prof_ref->hdr.created_by_forward_reference)
    {
        xpon_wavelen_prof_delete(cpair->wavelen_prof_ref);
    }
    xpon_object_delete(&cpair->hdr);
}

bcmos_errno xpon_cpair_transaction(sr_session_ctx_t *srs, nc_transact *tr)
{
    xpon_channel_pair *cpair = NULL;
    xpon_channel_pair cpair_tmp = {};
    char keyname[32]={};
    nc_transact_elem *elem;
    bcmos_errno err = BCM_ERR_OK;
    const char *iter_xpath;
    bcmos_bool was_added = BCMOS_FALSE;

    /* See if there is an existing cpair object */
    elem = STAILQ_FIRST(&tr->elems);
    if (elem == NULL)
        return BCM_ERR_OK;
    iter_xpath = elem->old_val ? elem->old_val->xpath : elem->new_val->xpath;
    nc_xpath_key_get(iter_xpath, "name", keyname, sizeof(keyname));
    NC_LOG_DBG("Handling cpair %s transaction\n", keyname);
    err = xpon_cpair_get_by_name(keyname, &cpair, &was_added);
    if (err != BCM_ERR_OK)
        return err;
    /* If cpair exists and was already populated by forward reference - stop here */
    if (cpair->hdr.created_by_forward_reference)
    {
        cpair->hdr.created_by_forward_reference = BCMOS_FALSE;
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
            cpair_tmp.hdr.being_deleted = (elem->new_val == NULL);
        }
        else if (!strcmp(leaf, "channel-partition-ref"))
        {
            xpon_obj_hdr *cpart = NULL;
            if (elem->new_val != NULL)
            {
                const char *cpart_name = elem->new_val->data.string_val;
                err = xpon_interface_get_populate(srs, cpart_name, XPON_OBJ_TYPE_CPART, &cpart);
                if (err != BCM_ERR_OK)
                {
                    NC_ERROR_REPLY(srs, iter_xpath, "channel-pair %s references channel-partition %s which doesn't exist\n",
                        keyname, cpart_name);
                    err = BCM_ERR_INTERNAL;
                    break;
                }
            }
            XPON_PROP_SET(&cpair_tmp, cpair, channel_partition_ref, (xpon_channel_partition *)cpart);
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
            XPON_PROP_SET(&cpair_tmp, cpair, channel_group_ref, (xpon_channel_group *)cgroup);
        }
        else if (!strcmp(leaf, "wavelength-prof-ref"))
        {
            xpon_wavelength_profile *prof = NULL;
            if (elem->new_val != NULL)
            {
                const char *prof_name = elem->new_val->data.string_val;
                err = xpon_wavelen_prof_get_populate(srs, prof_name, &prof);
                if (err != BCM_ERR_OK)
                {
                    NC_ERROR_REPLY(srs, iter_xpath, "channel-pair %s references wavelength-profile %s which doesn't exist\n",
                        keyname, prof_name);
                    err = BCM_ERR_INTERNAL;
                    break;
                }
            }
            XPON_PROP_SET(&cpair_tmp, cpair, wavelen_prof_ref, prof);
        }
    }

    if (err == BCM_ERR_OK)
    {
        if (XPON_PROP_IS_SET(&cpair_tmp, cpair, channel_partition_ref))
        {
            if (cpair->channel_partition_ref != NULL)
                STAILQ_REMOVE(&cpair->channel_partition_ref->cpair_list, cpair, xpon_channel_pair, next);
            if (cpair_tmp.channel_partition_ref != NULL)
                STAILQ_INSERT_TAIL(&cpair_tmp.channel_partition_ref->cpair_list, cpair, next);
        }
        XPON_PROP_COPY(&cpair_tmp, cpair, cpair, channel_partition_ref);
        XPON_PROP_COPY(&cpair_tmp, cpair, cpair, channel_group_ref);
        XPON_PROP_COPY(&cpair_tmp, cpair, cpair, wavelen_prof_ref);
        cpair_tmp.channel_partition_ref = NULL;
        cpair_tmp.channel_group_ref = NULL;
        cpair_tmp.wavelen_prof_ref = NULL;
    }

    if ((err != BCM_ERR_OK && was_added) || cpair_tmp.hdr.being_deleted)
        xpon_cpair_delete(cpair);

    /* Cleanup references auto-populated from operational data */
    if (err != BCM_ERR_OK)
    {
        if (cpair_tmp.channel_partition_ref != NULL &&
            cpair_tmp.channel_partition_ref->hdr.created_by_forward_reference)
        {
            xpon_cpart_delete(cpair_tmp.channel_partition_ref);
        }
        if (cpair_tmp.channel_group_ref != NULL &&
            cpair_tmp.channel_group_ref->hdr.created_by_forward_reference)
        {
            xpon_cgroup_delete(cpair_tmp.channel_group_ref);
        }
        if (cpair_tmp.wavelen_prof_ref != NULL &&
            cpair_tmp.wavelen_prof_ref->hdr.created_by_forward_reference)
        {
            xpon_wavelen_prof_delete(cpair_tmp.wavelen_prof_ref);
        }
    }

    if (cpair_tmp.hdr.being_deleted)
        err = BCM_ERR_OK;

    NC_LOG_DBG("cpair transaction completed: %s\n", bcmos_strerror(err));

    return err;
}

/* Populate a single channel-pair */
static int xpon_cpair_state_populate1(sr_session_ctx_t *session, const char *xpath, struct lyd_node **parent,
    xpon_channel_pair *cpair)
{
    if (!strstr(xpath, "bbf-xpon:channel-pair"))
    {
        const struct ly_ctx *ctx = sr_get_context(sr_session_get_connection(session));
        *parent = nc_ly_sub_value_add(ctx, *parent, xpath,
            "bbf-xpon:channel-pair/primary-ct-assigned", cpair->primary_cterm ? "true" : "false");
        *parent = nc_ly_sub_value_add(ctx, *parent, xpath,
            "bbf-xpon:channel-pair/secondary-ct-assigned", cpair->secondary_cterm ? "true" : "false");
    }
    return SR_ERR_OK;
}

/* Populate state info */
int xpon_cpair_state_get_cb(sr_session_ctx_t *session, const char *xpath, struct lyd_node **parent)
{
    xpon_obj_hdr *hdr, *hdr_tmp;
    xpon_channel_pair *cpair;
    char keyname[32];
    int sr_rc = SR_ERR_OK;

    NC_LOG_DBG("xpath=%s\n", xpath);
    if (strstr(xpath, "bbf-xpon") && !strstr(xpath, "channel-pair"))
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
        /* Add common interface properties for all interfaces */
        STAILQ_FOREACH_SAFE(hdr, &cpair_list, next, hdr_tmp)
        {
            cpair = (xpon_channel_pair *)hdr;
            snprintf(full_xpath, sizeof(full_xpath)-1, "%s[name='%s']", xpath, cpair->hdr.name);
            sr_rc = xpon_cpair_state_populate1(session, full_xpath, parent, cpair);
            if (sr_rc != SR_ERR_OK)
                break;
        }
        return sr_rc;
    }

    /*
     * Specific interface
     */

    if (nc_xpath_key_get(xpath, "name", keyname, sizeof(keyname)) != BCM_ERR_OK)
        return SR_ERR_OK;

    if (xpon_object_get(keyname, &hdr) == BCM_ERR_OK &&
        hdr->obj_type == XPON_OBJ_TYPE_CPAIR)
    {
        sr_rc = xpon_cpair_state_populate1(session, xpath, parent, (xpon_channel_pair *)hdr);
    }

    return sr_rc;
}

bcmos_errno xpon_cpair_init(sr_session_ctx_t *srs)
{
    STAILQ_INIT(&cpair_list);
    return BCM_ERR_OK;
}

bcmos_errno xpon_cpair_start(sr_session_ctx_t *srs)
{
    return BCM_ERR_OK;
}

void xpon_cpair_exit(sr_session_ctx_t *srs)
{
}



