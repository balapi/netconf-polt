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
 * bbf-xpon-xpon.c
 */
#include "bbf-xpon-internal.h"

static xpon_obj_list wavelen_prof_list;

/* Populate wavelength profile attribute */

static bcmos_errno bbf_xpon_wavelen_prof_attribute_populate(sr_session_ctx_t *srs, xpon_wavelength_profile *prof,
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
    if (!strcmp(leaf, "name"))
    {
        prof->hdr.being_deleted = (sr_new_val == NULL);
    }
    else if (!strcmp(leaf, "upstream-channel-id"))
    {
        if (sr_new_val)
            XPON_PROP_SET(prof, wavelen_profile, us_channel_id, sr_new_val->data.uint8_val);
        else
            XPON_PROP_CLEAR(prof, wavelen_profile, us_channel_id);
    }
    else if (!strcmp(leaf, "downstream-channel-id"))
    {
        if (sr_new_val)
            XPON_PROP_SET(prof, wavelen_profile, ds_channel_id, sr_new_val->data.uint8_val);
        else
            XPON_PROP_CLEAR(prof, wavelen_profile, ds_channel_id);
    }
    else if (!strcmp(leaf, "downstream-wavelength"))
    {
        if (sr_new_val)
            XPON_PROP_SET(prof, wavelen_profile, ds_wavelength, sr_new_val->data.uint32_val);
        else
            XPON_PROP_CLEAR(prof, wavelen_profile, ds_wavelength);
    }
    else
    {
        NC_LOG_INFO("wavelength-profile: attribute %s is not supported. Ignored\n", iter_xpath);
    }

    return err;
}

/* Wavelength profile change callback */

/* Data store change indication callback */
static int bbf_xpon_wavelen_prof_change_cb(sr_session_ctx_t *srs,
#ifdef SYSREPO_LIBYANG_V2
    uint32_t sub_id,
#endif
    const char *module_name, const char *xpath, sr_event_t event, uint32_t request_id, void *private_ctx)
{
    sr_change_iter_t *sr_iter = NULL;
    sr_change_oper_t sr_oper;
    sr_val_t *sr_old_val = NULL, *sr_new_val = NULL;
    char keyname[32];
    char prev_keyname[32] = "";
    xpon_wavelength_profile *prof = NULL;
    int sr_rc;
    char qualified_xpath[BCM_MAX_XPATH_LENGTH];
    bcmos_errno err = BCM_ERR_OK;
    bcmos_bool skip = BCMOS_FALSE;

    nc_config_lock();

    NC_LOG_INFO("xpath=%s event=%d\n", xpath, event);

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
            bcmos_bool is_added;
            if (prof != NULL && prof->hdr.being_deleted)
            {
                xpon_wavelen_prof_delete(prof);
                prof = NULL;
            }
            err = xpon_wavelen_prof_get_by_name(keyname, &prof, &is_added);
            if (err != BCM_ERR_OK)
                break;
            skip = prof->hdr.created_by_forward_reference;
            prof->hdr.created_by_forward_reference = BCMOS_FALSE;
        }
        strcpy(prev_keyname, keyname);

        /* Populate attribute based on the changed value */
        if (!skip)
        {
            err = bbf_xpon_wavelen_prof_attribute_populate(srs, prof, sr_old_val, sr_new_val);
        }
    }

    if (prof != NULL)
    {
        if (prof->hdr.being_deleted)
            xpon_wavelen_prof_delete(prof);
        else
            prof->hdr.created_by_forward_reference = BCMOS_FALSE;
    }

    nc_sr_free_value_pair(&sr_old_val, &sr_new_val);
    sr_free_change_iter(sr_iter);

    nc_config_unlock();

    return nc_bcmos_errno_to_sr_errno(err);
}

bcmos_errno xpon_wavelen_prof_init(sr_session_ctx_t *srs)
{
    STAILQ_INIT(&wavelen_prof_list);
    return BCM_ERR_OK;
}

bcmos_errno xpon_wavelen_prof_start(sr_session_ctx_t *srs)
{
    int sr_rc;
    /* subscribe to events */
    sr_rc = sr_module_change_subscribe(srs, BBF_XPON_MODULE_NAME, BBF_XPON_WAVELEN_PROFILE_PATH_BASE,
            bbf_xpon_wavelen_prof_change_cb, NULL, 0, BCM_SR_MODULE_CHANGE_SUBSCR_FLAGS,
            &sr_ctx);
    if (SR_ERR_OK == sr_rc)
    {
        NC_LOG_INFO("Subscribed to %s subtree changes.\n", BBF_XPON_WAVELEN_PROFILE_PATH_BASE);
    }
    else
    {
        NC_LOG_ERR("Failed to subscribe to %s subtree changes (%s).\n",
            BBF_XPON_INTERFACE_PATH_BASE, sr_strerror(sr_rc));
    }

    return nc_sr_errno_to_bcmos_errno(sr_rc);
}

void xpon_wavelen_prof_exit(sr_session_ctx_t *srs)
{
}

/* Find or add hardware-component object. Populate from sysrepo session if added */
bcmos_errno xpon_wavelen_prof_get_populate(sr_session_ctx_t *srs, const char *name, xpon_wavelength_profile **p_prof)
{
    bcmos_bool is_added = BCMOS_FALSE;
    bcmos_errno err;
    char query_xpath[256];
    sr_val_t *values = NULL;
    size_t value_cnt = 0;
    int i;
    int sr_rc;

    err = xpon_wavelen_prof_get_by_name(name, p_prof, &is_added);
    if (err != BCM_ERR_OK)
        return err;
    if (is_added)
    {
        snprintf(query_xpath, sizeof(query_xpath)-1,
            BBF_XPON_WAVELEN_PROFILE_PATH_BASE "[name='%s']//.", (*p_prof)->hdr.name);
        sr_rc = sr_get_items(srs, query_xpath, 0, SR_OPER_DEFAULT, &values, &value_cnt);
        if (sr_rc)
        {
            NC_LOG_ERR("sr_get_items(%s) -> %s\n", query_xpath, sr_strerror(sr_rc));
            xpon_wavelen_prof_delete(*p_prof);
            *p_prof = NULL;
            return BCM_ERR_PARM;
        }
        NC_LOG_DBG("Populating wavelength-profile from xpath '%s'. values %u\n",
            query_xpath, (unsigned)value_cnt);

        for (i = 0; i < value_cnt && err == BCM_ERR_OK; i++)
        {
            err = bbf_xpon_wavelen_prof_attribute_populate(srs, *p_prof, NULL, &values[i]);
        }
        sr_free_values(values, value_cnt);

        if (err == BCM_ERR_OK)
        {
            (*p_prof)->hdr.created_by_forward_reference = BCMOS_TRUE;
        }
        else
        {
            xpon_wavelen_prof_delete(*p_prof);
            *p_prof = NULL;
        }
    }
    return err;
}

/* Get wavelength profile object by name, add a new one if
 * doesn't exist
 */
bcmos_errno xpon_wavelen_prof_get_by_name(const char *name, xpon_wavelength_profile **p_prof, bcmos_bool *is_added)
{
    xpon_obj_hdr *obj = NULL;
    bcmos_errno err;

    err = xpon_object_get_or_add(name, XPON_OBJ_TYPE_WAVELENGTH_PROFILE,
        sizeof(xpon_wavelength_profile), &obj, is_added);
    if (err != BCM_ERR_OK)
        return err;
    *p_prof = (xpon_wavelength_profile *)obj;
    if (is_added != NULL && *is_added)
    {
        STAILQ_INSERT_TAIL(&wavelen_prof_list, obj, next);
        NC_LOG_INFO("wavelength-profile %s added\n", name);
    }
    return BCM_ERR_OK;
}

/* Remove channel-pair object */
void xpon_wavelen_prof_delete(xpon_wavelength_profile *prof)
{
    STAILQ_REMOVE_SAFE(&wavelen_prof_list, &prof->hdr, xpon_obj_hdr, next);
    NC_LOG_INFO("wavelength-profile %s deleted\n", prof->hdr.name);
    xpon_object_delete(&prof->hdr);
}



