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
 * bbf-l2-dhcpv4-relay.c
 */

#include "bbf-xpon-internal.h"
#include "dhcp-relay-utils.h"

static xpon_obj_list dhcpr_profile_list;

/* Apply DHCP relay profile configuration */
static bcmos_errno _dhcpr_prof_apply(sr_session_ctx_t *srs, const char *xpath,
    xpon_dhcpr_profile *prof, xpon_dhcpr_profile *prof_changes)
{
    bcmos_errno err = BCM_ERR_OK;
    bcmos_bool was_set = BCMOS_FALSE;

    if (prof_changes->hdr.being_deleted)
    {
        xpon_dhcpr_prof_delete(prof);
        return BCM_ERR_OK;
    }

    /* All good. Update NC config */
    XPON_PROP_COPY(prof_changes, prof, dhcpr_profile, max_packet_size);
    XPON_PROP_COPY(prof_changes, prof, dhcpr_profile, suboptions);

    if (prof->circuit_id_syntax != NULL)
    {
        bcmos_free(prof->circuit_id_syntax);
        prof->circuit_id_syntax = NULL;
        XPON_PROP_CLEAR(prof, dhcpr_profile, circuit_id_syntax);
        was_set = BCMOS_TRUE;
    }
    if (prof_changes->circuit_id_syntax != NULL)
    {
        XPON_PROP_SET(prof, dhcpr_profile, circuit_id_syntax, prof_changes->circuit_id_syntax);
        prof_changes->circuit_id_syntax = NULL;
    }

    if (prof->remote_id_syntax != NULL)
    {
        bcmos_free(prof->remote_id_syntax);
        prof->remote_id_syntax = NULL;
        XPON_PROP_CLEAR(prof, dhcpr_profile, remote_id_syntax);
        was_set = BCMOS_TRUE;
    }
    if (prof_changes->remote_id_syntax != NULL)
    {
        XPON_PROP_SET(prof, dhcpr_profile, remote_id_syntax, prof_changes->remote_id_syntax);
        prof_changes->remote_id_syntax = NULL;
    }
    XPON_PROP_COPY(prof_changes, prof, dhcpr_profile, start_numbering_from_zero);
    XPON_PROP_COPY(prof_changes, prof, dhcpr_profile, use_leading_zeros);
    if (was_set)
        dhcp_relay_profile_delete(prof->hdr.name);

    if (prof->circuit_id_syntax != NULL || prof->remote_id_syntax != NULL)
        err = dhcp_relay_profile_add(prof);

    return err;
}

/* Populate dhcp-relay-profile attribute */
static bcmos_errno _dhcpr_prof_attribute_populate(sr_session_ctx_t *srs,
    xpon_dhcpr_profile *prof, sr_val_t *sr_old_val, sr_val_t *sr_new_val)
{
    const char *iter_xpath;
    char leafbuf[BCM_MAX_LEAF_LENGTH];
    const char *leaf;
    sr_val_t *val = (sr_new_val != NULL) ? sr_new_val : sr_old_val;
    bcmos_errno err = BCM_ERR_OK;

    NC_LOG_DBG("old_val=%s new_val=%s type=%d\n",
        sr_old_val ? sr_old_val->xpath : "none",
        sr_new_val ? sr_new_val->xpath : "none",
        sr_old_val ? sr_old_val->type : sr_new_val->type);

    if (val->type == SR_LIST_T || val->type == SR_CONTAINER_T)
    {
        /* no semantic meaning */
        return BCM_ERR_OK;
    }

    iter_xpath = val->xpath;
    leaf = nc_xpath_leaf_get(iter_xpath, leafbuf, sizeof(leafbuf));
    if (leaf == NULL)
    {
        /* no semantic meaning */
        return BCM_ERR_OK;
    }

    do
    {
        /* Go over supported leafs */
        if (!strcmp(leaf, "name"))
        {
            prof->hdr.being_deleted = (sr_new_val == NULL);
        }
        else if (!strcmp(leaf, "max-packet-size"))
        {
            XPON_PROP_SET(prof, dhcpr_profile, max_packet_size, val->data.uint16_val);
        }
        else if (!strcmp(leaf, "default-circuit-id-syntax"))
        {
            XPON_PROP_SET(prof, dhcpr_profile, circuit_id_syntax,
                val->data.string_val ? bcmos_strdup(val->data.string_val) : NULL);
        }
        else if (!strcmp(leaf, "default-remote-id-syntax"))
        {
            XPON_PROP_SET(prof, dhcpr_profile, remote_id_syntax,
                val->data.string_val ? bcmos_strdup(val->data.string_val) : NULL);
        }
        else if (!strcmp(leaf, "start-numbering-from-zero"))
        {
            XPON_PROP_SET(prof, dhcpr_profile, start_numbering_from_zero, val->data.bool_val);
        }
        else if (!strcmp(leaf, "use-leading-zeroes"))
        {
            XPON_PROP_SET(prof, dhcpr_profile, use_leading_zeros, val->data.bool_val);
        }
        else if (!strcmp(leaf, "suboptions"))
        {
            dhcp_relay_option82_suboptions suboptions = prof->suboptions | prof->suboptions;
            dhcp_relay_option82_suboptions new_suboption = DHCP_RELAY_OPTION82_SUBOPTION_NONE;
            if (val->data.enum_val != NULL)
            {
                if (!strcmp(val->data.enum_val, "circuit-id"))
                    new_suboption |= DHCP_RELAY_OPTION82_SUBOPTION_CIRCUIT_ID;
                else if (!strcmp(val->data.enum_val, "remote-id"))
                    new_suboption |= DHCP_RELAY_OPTION82_SUBOPTION_REMOTE_ID;
                else if (!strcmp(val->data.enum_val, "access-loop-characteristics"))
                    new_suboption |= DHCP_RELAY_OPTION82_SUBOPTION_ACCESS_LOOP;
            }
            if (sr_new_val != NULL)
                suboptions |= new_suboption;
            else
                suboptions &= ~new_suboption;
            XPON_PROP_SET(prof, dhcpr_profile, suboptions, suboptions);
        }
    } while (0);

    return err;
}

static int _dhcpr_prof_change_cb(sr_session_ctx_t *srs,
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
    xpon_dhcpr_profile *prof = NULL;
    xpon_dhcpr_profile prof_changes = {};
    bcmos_bool was_added = BCMOS_FALSE;
    const char *prev_xpath = NULL;
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
            if (prof != NULL)
            {
                err = _dhcpr_prof_apply(srs, prev_xpath, prof, &prof_changes);
                if (err != BCM_ERR_OK)
                {
                    if (was_added)
                        xpon_dhcpr_prof_delete(prof);
                    prof = NULL;
                    break;
                }
                prof = NULL;
                memset(&prof_changes, 0, sizeof(prof_changes));
            }
            err = xpon_dhcpr_prof_get_by_name(keyname, &prof, &was_added);
            if (err != BCM_ERR_OK)
                break;
            skip = prof->hdr.created_by_forward_reference;
            prof->hdr.created_by_forward_reference = BCMOS_FALSE;
        }
        strcpy(prev_keyname, keyname);
        prev_xpath = iter_xpath;

        /* handle attributes */
        if (!skip)
        {
            err = _dhcpr_prof_attribute_populate(srs, &prof_changes, sr_old_val, sr_new_val);
        }
    }

    if (prof != NULL)
    {
        if (err == BCM_ERR_OK)
            err = _dhcpr_prof_apply(srs, prev_xpath, prof, &prof_changes);
        if (err != BCM_ERR_OK && (was_added || prof_changes.hdr.being_deleted))
            xpon_dhcpr_prof_delete(prof);
    }
    if (prof_changes.hdr.being_deleted)
        err = BCM_ERR_OK;

    if (prof_changes.circuit_id_syntax != NULL)
        bcmos_free(prof_changes.circuit_id_syntax);
    if (prof_changes.remote_id_syntax != NULL)
        bcmos_free(prof_changes.remote_id_syntax);

    nc_sr_free_value_pair(&sr_old_val, &sr_new_val);
    sr_free_change_iter(sr_iter);

    nc_config_unlock();

    return nc_bcmos_errno_to_sr_errno(err);
}

bcmos_errno xpon_dhcpr_init(sr_session_ctx_t *srs)
{
    bcmos_errno err;
    STAILQ_INIT(&dhcpr_profile_list);
    err = dhcp_relay_init();
    return err;
}

bcmos_errno xpon_dhcpr_start(sr_session_ctx_t *srs)
{
    int sr_rc;

    /* subscribe to events */
    sr_rc = sr_module_change_subscribe(srs, BBF_L2_DHCPV4_RELAY_MODULE_NAME, BBF_XPON_DHCPR_PROFILE_PATH_BASE,
            _dhcpr_prof_change_cb, NULL, 0, BCM_SR_MODULE_CHANGE_SUBSCR_FLAGS,
            &sr_ctx);
    if (SR_ERR_OK == sr_rc)
    {
        NC_LOG_INFO("Subscribed to %s subtree changes.\n", BBF_XPON_DHCPR_PROFILE_PATH_BASE);
    }
    else
    {
        NC_LOG_ERR("Failed to subscribe to %s subtree changes (%s).\n",
            BBF_XPON_DHCPR_PROFILE_PATH_BASE, sr_strerror(sr_rc));
        return nc_sr_errno_to_bcmos_errno(sr_rc);
    }

    return BCM_ERR_OK;
}

void xpon_dhcpr_exit(sr_session_ctx_t *srs)
{
}

/* Get DHCP relay profile object by name, add a new one if doesn't exist and populate from operational data */
bcmos_errno xpon_dhcpr_prof_get_populate(sr_session_ctx_t *srs, const char *name, xpon_dhcpr_profile **p_obj)
{
    bcmos_bool is_added = BCMOS_FALSE;
    bcmos_errno err;
    char query_xpath[256];
    sr_val_t *values = NULL;
    size_t value_cnt = 0;
    int i;
    int sr_rc;

    err = xpon_dhcpr_prof_get_by_name(name, p_obj, &is_added);
    if (err != BCM_ERR_OK)
        return err;
    if (is_added)
    {
        snprintf(query_xpath, sizeof(query_xpath)-1,
            BBF_XPON_DHCPR_PROFILE_PATH_BASE "[name='%s']//.", name);
        sr_rc = sr_get_items(srs, query_xpath, 0, SR_OPER_DEFAULT, &values, &value_cnt);
        if (sr_rc)
        {
            NC_LOG_ERR("sr_get_items(%s) -> %s\n", query_xpath, sr_strerror(sr_rc));
            xpon_dhcpr_prof_delete(*p_obj);
            *p_obj = NULL;
            return BCM_ERR_PARM;
        }
        NC_LOG_DBG("Populating from xpath '%s'. values %u\n",
            query_xpath, (unsigned)value_cnt);

        for (i = 0; i < value_cnt && err == BCM_ERR_OK; i++)
        {
            err = _dhcpr_prof_attribute_populate(srs, *p_obj, NULL, &values[i]);
        }
        sr_free_values(values, value_cnt);
        if (err != BCM_ERR_OK)
        {
            xpon_dhcpr_prof_delete(*p_obj);
            *p_obj = NULL;
        }
        else
        {
            (*p_obj)->hdr.created_by_forward_reference = BCMOS_TRUE;
        }
    }
    return err;
}

/* Find or add dhcp-relay-profile object */
bcmos_errno xpon_dhcpr_prof_get_by_name(const char *name, xpon_dhcpr_profile **p_prof, bcmos_bool *is_added)
{
    xpon_obj_hdr *obj = NULL;
    bcmos_errno err;

    err = xpon_object_get_or_add(name, XPON_OBJ_TYPE_DHCPR_PROFILE,
        sizeof(xpon_dhcpr_profile), &obj, is_added);
    if (err != BCM_ERR_OK)
        return err;
    *p_prof = (xpon_dhcpr_profile *)obj;
    if (is_added != NULL && *is_added)
    {
        STAILQ_INSERT_TAIL(&dhcpr_profile_list, obj, next);
        NC_LOG_INFO("dhcp-relay-descriptor-profile %s added\n", name);
    }
    return BCM_ERR_OK;
}

/* Remove dhcp-relay-profile object */
void xpon_dhcpr_prof_delete(xpon_dhcpr_profile *prof)
{
    STAILQ_REMOVE_SAFE(&dhcpr_profile_list, &prof->hdr, xpon_obj_hdr, next);
    if (prof->circuit_id_syntax != NULL || prof->remote_id_syntax != NULL)
        dhcp_relay_profile_delete(prof->hdr.name);
    if (prof->circuit_id_syntax != NULL)
        bcmos_free(prof->circuit_id_syntax);
    if (prof->remote_id_syntax != NULL)
        bcmos_free(prof->remote_id_syntax);
    NC_LOG_INFO("dhcp-relay-profile %s deleted\n", prof->hdr.name);
    xpon_object_delete(&prof->hdr);
}
