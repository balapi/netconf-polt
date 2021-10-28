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
 * bbf-xpon-tcont.c
 */

#include "bbf-xpon-internal.h"

static xpon_obj_list tcont_list;
static xpon_obj_list td_profile_list;
static sr_subscription_ctx_t *sr_ctx_tcont_state;

#define MAX_DYN_TCONTS_PER_PON  1024
#define DYN_TCONT_BASE          1024
static xpon_tcont *tcont_array[BCM_MAX_PONS_PER_OLT][MAX_DYN_TCONTS_PER_PON];

#define TCONT_BW_GRANULARITY    16000
#define TCONT_ROUND_BW_TO_GRANULARITY(_bw)  \
    (((_bw + TCONT_BW_GRANULARITY - 1) / TCONT_BW_GRANULARITY) * TCONT_BW_GRANULARITY)


/* Get free dynamic tcont index */
static uint16_t _tcont_get_free_index(bcmolt_interface pon_ni)
{
    int alloc_id;
    if (pon_ni >= BCM_MAX_PONS_PER_OLT)
        return ALLOC_ID_UNDEFINED;
    for (alloc_id = 0; alloc_id < MAX_DYN_TCONTS_PER_PON; alloc_id++)
    {
        if (tcont_array[pon_ni][alloc_id] == NULL)
            return alloc_id + DYN_TCONT_BASE;
    }
    return ALLOC_ID_UNDEFINED;
}

/* Apply traffic descriptor profile configuration */
static bcmos_errno _td_prof_apply(sr_session_ctx_t *srs, const char *xpath,
    xpon_td_profile *prof, xpon_td_profile *prof_changes)
{
    if (prof_changes->hdr.being_deleted)
    {
        xpon_td_prof_delete(prof);
        return BCM_ERR_OK;
    }
    /* Validate parameters */
    if (prof_changes->additional_bw_eligiblity == BCMOLT_ADDITIONAL_BW_ELIGIBILITY_NON_ASSURED &&
        !prof_changes->assured_bw)
    {
        NC_ERROR_REPLY(srs, xpath, "traffic-descriptor-profile %s: assured-bandwidth is required for non-assured-sharing\n",
            prof->hdr.name);
        return BCM_ERR_PARM;
    }
    if (prof_changes->additional_bw_eligiblity == BCMOLT_ADDITIONAL_BW_ELIGIBILITY_BEST_EFFORT &&
        !prof_changes->max_bw)
    {
        NC_ERROR_REPLY(srs, xpath, "traffic-descriptor-profile %s: maximum-bandwidth is required for best-effort-sharing\n",
            prof->hdr.name);
        return BCM_ERR_PARM;
    }

    /* All good. Update NC config */
    XPON_PROP_COPY(prof_changes, prof, td_profile, fixed_bw);
    XPON_PROP_COPY(prof_changes, prof, td_profile, assured_bw);
    XPON_PROP_COPY(prof_changes, prof, td_profile, max_bw);
    XPON_PROP_COPY(prof_changes, prof, td_profile, additional_bw_eligiblity);
    XPON_PROP_COPY(prof_changes, prof, td_profile, priority);
    XPON_PROP_COPY(prof_changes, prof, td_profile, weight);

    return BCM_ERR_OK;
}

static bcmos_errno _td_prof_attribute_populate(sr_session_ctx_t *srs, xpon_td_profile *prof,
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

    /* Go over supported leafs */
    if (!strcmp(leaf, "name"))
    {
        prof->hdr.being_deleted = (sr_new_val == NULL);
    }
    else if (!strcmp(leaf, "fixed-bandwidth"))
    {
        XPON_PROP_SET(prof, td_profile, fixed_bw, sr_new_val ? sr_new_val->data.uint64_val / 8 : 0);
    }
    else if (!strcmp(leaf, "assured-bandwidth"))
    {
        XPON_PROP_SET(prof, td_profile, assured_bw, sr_new_val ? sr_new_val->data.uint64_val / 8 : 0);
    }
    else if (!strcmp(leaf, "maximum-bandwidth"))
    {
        XPON_PROP_SET(prof, td_profile, max_bw, sr_new_val ? sr_new_val->data.uint64_val / 8 : 0);
    }
    else if (!strcmp(leaf, "additional-bw-eligibility-indicator"))
    {
        bcmolt_additional_bw_eligibility elig;
        if (sr_new_val)
        {
            if (!strcmp(sr_new_val->data.enum_val,  "non-assured-sharing"))
                elig = BCMOLT_ADDITIONAL_BW_ELIGIBILITY_NON_ASSURED;
            else if (!strcmp(sr_new_val->data.enum_val,  "best-effort-sharing"))
                elig = BCMOLT_ADDITIONAL_BW_ELIGIBILITY_BEST_EFFORT;
            else
                elig = BCMOLT_ADDITIONAL_BW_ELIGIBILITY_NONE;
        }
        else
        {
            elig = BCMOLT_ADDITIONAL_BW_ELIGIBILITY_NONE;
        }
        XPON_PROP_SET(prof, td_profile, additional_bw_eligiblity, elig);
    }
    else if (!strcmp(leaf, "priority"))
    {
        XPON_PROP_SET(prof, td_profile, priority, sr_new_val ? sr_new_val->data.uint8_val : 0);
    }
    else if (!strcmp(leaf, "weight"))
    {
        XPON_PROP_SET(prof, td_profile, weight, sr_new_val ? sr_new_val->data.uint8_val : 0);
    }
    else
    {
        NC_LOG_INFO("Attribute %s is not supported\n", iter_xpath);
    }

    return err;
}

static int _td_prof_change_cb(sr_session_ctx_t *srs,
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
    xpon_td_profile *prof = NULL;
    xpon_td_profile prof_changes = {};
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
                err = _td_prof_apply(srs, prev_xpath, prof, &prof_changes);
                if (err != BCM_ERR_OK)
                {
                    if (was_added)
                        xpon_td_prof_delete(prof);
                    prof = NULL;
                    break;
                }
                prof = NULL;
            }
            err = xpon_td_prof_get_by_name(keyname, &prof, &was_added);
            if (err != BCM_ERR_OK)
                break;
            skip = prof->hdr.created_by_forward_reference;
            prof->hdr.created_by_forward_reference = BCMOS_FALSE;
            memset(&prof_changes, 0, sizeof(prof_changes));
        }
        strcpy(prev_keyname, keyname);
        prev_xpath = iter_xpath;

        /* Populate attribute based on the changed value */
        if (!skip)
        {
            err = _td_prof_attribute_populate(srs, &prof_changes, sr_old_val, sr_new_val);
        }
    }

    if (prof != NULL)
    {
        if (err == BCM_ERR_OK)
        {
            err = _td_prof_apply(srs, prev_xpath, prof, &prof_changes);
            if (err == BCM_ERR_OK && !prof_changes.hdr.being_deleted)
            {
                prof->hdr.created_by_forward_reference = BCMOS_FALSE;
            }
        }
        if (err != BCM_ERR_OK && (was_added || prof_changes.hdr.being_deleted))
            xpon_td_prof_delete(prof);
    }

    if (prof_changes.hdr.being_deleted)
        err = BCM_ERR_OK;

    nc_config_unlock();

    return nc_bcmos_errno_to_sr_errno(err);
}

/* Handle tcont transaction */
static bcmos_errno _tcont_apply(sr_session_ctx_t *srs, const char *xpath,
    xpon_tcont *tcont, xpon_tcont *tcont_changes)
{
    xpon_td_profile *td_prof = XPON_PROP_IS_SET(tcont_changes, tcont, td_profile) ?
        tcont_changes->td_profile : tcont->td_profile;
    uint16_t alloc_id = XPON_PROP_IS_SET(tcont_changes, tcont, alloc_id) ?
        tcont_changes->alloc_id : tcont->alloc_id;
    bcmos_bool is_provision = BCMOS_FALSE;
    bcmos_errno err = BCM_ERR_OK;

    NC_LOG_DBG("tcont %s: applying configuration. %s\n",
        tcont->hdr.name, tcont_changes->hdr.being_deleted ? "CLEAR": "PROVISION");

    do
    {
        if (tcont->state == XPON_RESOURCE_STATE_NOT_CONFIGURED)
        {
            xpon_v_ani *v_ani = XPON_PROP_IS_SET(tcont_changes, tcont, v_ani) ?
                tcont_changes->v_ani : tcont->v_ani;

            if (!tcont_changes->hdr.being_deleted)
            {
                /* See if there is enough info to provision
                - pon_ni
                - onu_id
                - td_profile
                */
                is_provision = v_ani != NULL && td_prof != NULL &&
                    v_ani->pon_ni < BCM_MAX_PONS_PER_OLT &&
                    v_ani->onu_id < XPON_MAX_ONUS_PER_PON;
            }

            /* Not provisioned yet */
            if (is_provision)
            {
                bcmolt_itupon_alloc_cfg cfg;
                bcmolt_itupon_alloc_key key = {
                    .pon_ni = v_ani->pon_ni,
                    .alloc_id = alloc_id
                };
                if (alloc_id == ALLOC_ID_UNDEFINED)
                {
                    /* Try to auto-assign */
                    alloc_id = _tcont_get_free_index(v_ani->pon_ni);
                    if (alloc_id == ALLOC_ID_UNDEFINED)
                    {
                        NC_ERROR_REPLY(srs, xpath, "tcont %s: can't assign alloc-id\n",
                            tcont->hdr.name);
                        err = BCM_ERR_NOT_SUPPORTED;
                        break;
                    }
                    XPON_PROP_SET(tcont_changes, tcont, alloc_id, alloc_id);
                    key.alloc_id = alloc_id;
                }
                BCMOLT_CFG_INIT(&cfg, itupon_alloc, key);
                BCMOLT_MSG_FIELD_SET(&cfg, onu_id, v_ani->onu_id);
                /* all fields in itupon_alloc.sla must be set */
                BCMOLT_MSG_FIELD_SET(&cfg, sla.additional_bw_eligibility,
                    XPON_PROP_IS_SET(td_prof, td_profile, additional_bw_eligiblity) ?
                        td_prof->additional_bw_eligiblity : BCMOLT_ADDITIONAL_BW_ELIGIBILITY_BEST_EFFORT);
                BCMOLT_MSG_FIELD_SET(&cfg, sla.cbr_rt_bw, 0);
                BCMOLT_MSG_FIELD_SET(&cfg, sla.cbr_nrt_bw,
                    TCONT_ROUND_BW_TO_GRANULARITY(
                        XPON_PROP_IS_SET(td_prof, td_profile, fixed_bw) ? td_prof->fixed_bw : 0));
                BCMOLT_MSG_FIELD_SET(&cfg, sla.guaranteed_bw,
                    TCONT_ROUND_BW_TO_GRANULARITY(
                        XPON_PROP_IS_SET(td_prof, td_profile, assured_bw) ? td_prof->assured_bw : 0));
                BCMOLT_MSG_FIELD_SET(&cfg, sla.maximum_bw,
                    TCONT_ROUND_BW_TO_GRANULARITY(
                        XPON_PROP_IS_SET(td_prof, td_profile, max_bw) ? td_prof->max_bw : 0));
                BCMOLT_MSG_FIELD_SET(&cfg, sla.alloc_type, BCMOLT_ALLOC_TYPE_NSR);
                BCMOLT_MSG_FIELD_SET(&cfg, sla.cbr_rt_compensation, BCMOS_FALSE);
                BCMOLT_MSG_FIELD_SET(&cfg, sla.cbr_nrt_ap_index, 0);
                BCMOLT_MSG_FIELD_SET(&cfg, sla.cbr_rt_ap_index, 0);
                BCMOLT_MSG_FIELD_SET(&cfg, sla.weight,
                    XPON_PROP_IS_SET(td_prof, td_profile, weight) ?
                        td_prof->weight : 0);
                BCMOLT_MSG_FIELD_SET(&cfg, sla.priority,
                    XPON_PROP_IS_SET(td_prof, td_profile, priority) ?
                        td_prof->priority : 0);
                tcont->state = XPON_RESOURCE_STATE_IN_PROGRESS;
                tcont->pon_ni = key.pon_ni;
                err = bcmolt_cfg_set(netconf_agent_olt_id(), &cfg.hdr);
                if (err != BCM_ERR_OK)
                {
                    NC_ERROR_REPLY(srs, xpath, "tcont %s: Failed to provision. Error %s (%s)\n",
                        tcont->hdr.name, bcmos_strerror(err), cfg.hdr.hdr.err_text);
                    tcont->state = XPON_RESOURCE_STATE_NOT_CONFIGURED;
                    break;
                }
                NC_LOG_DBG("%s: provisioned ALLOC_ID %u\n", xpath, alloc_id);
            }
        }
        else
        {
            if (is_provision)
            {
                NC_ERROR_REPLY(srs, xpath, "tcont %s: can't change active tcont\n", tcont->hdr.name);
                err = BCM_ERR_NOT_SUPPORTED;
                break;
            }
            if (tcont->pon_ni != BCMOLT_INTERFACE_UNDEFINED &&
                tcont->alloc_id != ALLOC_ID_UNDEFINED)
            {
                bcmolt_itupon_alloc_cfg cfg;
                bcmolt_itupon_alloc_key key = {
                    .pon_ni = tcont->v_ani->pon_ni,
                    .alloc_id = tcont->alloc_id
                };
                BCMOLT_CFG_INIT(&cfg, itupon_alloc, key);
                bcmolt_cfg_clear(netconf_agent_olt_id(), &cfg.hdr);
                tcont->state = XPON_RESOURCE_STATE_NOT_CONFIGURED;
                NC_LOG_DBG("%s: cleared ALLOC_ID %u\n", xpath, tcont->alloc_id);
            }
        }
    } while (0);

    if (err == BCM_ERR_OK && !tcont_changes->hdr.being_deleted)
    {
        /* All good. Update NC config */
        XPON_PROP_COPY(tcont_changes, tcont, tcont, alloc_id);
        XPON_PROP_COPY(tcont_changes, tcont, tcont, v_ani);
        tcont_changes->v_ani = NULL;
        XPON_PROP_COPY(tcont_changes, tcont, tcont, td_profile);
        tcont_changes->td_profile = NULL;
        if (alloc_id != ALLOC_ID_UNDEFINED && alloc_id >= DYN_TCONT_BASE &&
            (alloc_id - DYN_TCONT_BASE < MAX_DYN_TCONTS_PER_PON) &&
            is_provision)
        {
            tcont_array[tcont->pon_ni][alloc_id - DYN_TCONT_BASE] = tcont;
        }
    }

    if (tcont_changes->hdr.being_deleted)
    {
        xpon_tcont_delete(tcont);
        err = BCM_ERR_OK;
    }

    return err;
}

static bcmos_errno _tcont_attribute_populate(sr_session_ctx_t *srs, xpon_tcont *tcont,
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
        tcont->hdr.being_deleted = (sr_new_val == NULL);
    }
    else if (!strcmp(leaf, "alloc-id"))
    {
        if (sr_new_val)
            XPON_PROP_SET(tcont, tcont, alloc_id, sr_new_val->data.uint16_val);
        else
            XPON_PROP_SET(tcont, tcont, alloc_id, ALLOC_ID_UNDEFINED);
    }
    else if (!strcmp(leaf, "interface-reference"))
    {
        xpon_v_ani *v_ani = NULL;
        if (sr_new_val)
        {
            const char *v_ani_name = sr_new_val->data.string_val;
            xpon_obj_hdr *v_ani_hdr = NULL;
            err = xpon_interface_get_populate(srs, v_ani_name, XPON_OBJ_TYPE_V_ANI, &v_ani_hdr);
            if (err != BCM_ERR_OK)
            {
                NC_ERROR_REPLY(srs, iter_xpath, "tcont %s references v-ani %s which doesn't exist\n",
                    tcont->hdr.name, v_ani_name);
                err = BCM_ERR_PARM;
            }
            v_ani = (xpon_v_ani *)v_ani_hdr;
        }
        XPON_PROP_SET(tcont, tcont, v_ani, v_ani);
    }
    else if (!strcmp(leaf, "traffic-descriptor-profile-ref"))
    {
        xpon_td_profile *td_prof = NULL;
        if (sr_new_val)
        {
            const char *td_name = sr_new_val->data.string_val;
            err = xpon_td_prof_get_populate(srs, td_name, &td_prof);
            if (err != BCM_ERR_OK)
            {
                NC_ERROR_REPLY(srs, iter_xpath, "tcont %s references traffic-descriptor-profile %s which doesn't exist\n",
                    tcont->hdr.name, td_name);
                err = BCM_ERR_PARM;
            }
        }
        XPON_PROP_SET(tcont, tcont, td_profile, td_prof);
    }
    else
    {
        NC_LOG_INFO("Attribute %s is not supported\n", iter_xpath);
    }

    return err;
}

/* Handle tcont change events */
static int _tcont_change_cb(sr_session_ctx_t *srs,
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
    xpon_tcont *tcont = NULL;
    xpon_tcont tcont_changes = {};
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
            if (tcont != NULL)
            {
                err = _tcont_apply(srs, prev_xpath, tcont, &tcont_changes);
                if (err != BCM_ERR_OK)
                {
                    if (was_added)
                        xpon_tcont_delete(tcont);
                    tcont = NULL;
                    break;
                }
                tcont = NULL;
            }
            err = xpon_tcont_get_by_name(keyname, &tcont, &was_added);
            if (err != BCM_ERR_OK)
                break;
            skip = tcont->hdr.created_by_forward_reference;
            tcont->hdr.created_by_forward_reference = BCMOS_FALSE;
            memset(&tcont_changes, 0, sizeof(tcont_changes));
        }
        strcpy(prev_keyname, keyname);
        prev_xpath = xpath;

        /* Populate attribute based on the changed value */
        if (!skip)
        {
            err = _tcont_attribute_populate(srs, tcont, sr_old_val, sr_new_val);
        }
    }

    if (tcont != NULL)
    {
        if (err == BCM_ERR_OK)
        {
            err = _tcont_apply(srs, prev_xpath, tcont, &tcont_changes);
            if (err == BCM_ERR_OK && !tcont_changes.hdr.being_deleted)
                tcont->hdr.created_by_forward_reference = BCMOS_FALSE;
        }
        if (err != BCM_ERR_OK && (was_added || tcont_changes.hdr.being_deleted))
            xpon_tcont_delete(tcont);
    }
    if (tcont_changes.td_profile != NULL && tcont_changes.td_profile->hdr.created_by_forward_reference)
        xpon_td_prof_delete(tcont_changes.td_profile);
    if (tcont_changes.v_ani != NULL && tcont_changes.v_ani->hdr.created_by_forward_reference)
        xpon_v_ani_delete(tcont_changes.v_ani);

    if (tcont_changes.hdr.being_deleted)
        err = BCM_ERR_OK;

    nc_sr_free_value_pair(&sr_old_val, &sr_new_val);
    sr_free_change_iter(sr_iter);

    nc_config_unlock();

    return nc_bcmos_errno_to_sr_errno(err);
}

/* Populate a single tcont */

/* Get operational status callback */
static int xpon_tcont_state_populate1(sr_session_ctx_t *session, const char *xpath, struct lyd_node **parent,
    const xpon_tcont *tcont)
{
    const struct ly_ctx *ctx = sr_get_context(sr_session_get_connection(session));
    int sr_rc = SR_ERR_OK;

    if (XPON_PROP_IS_SET(tcont, tcont, alloc_id))
    {
        char alloc_id[16];
        snprintf(alloc_id, sizeof(alloc_id), "%u", tcont->alloc_id);
        *parent = nc_ly_sub_value_add(ctx, *parent, xpath,
            "actual-alloc-id", alloc_id);
    }
    return sr_rc;
}

/* Get operational status callback */
static int _tcont_state_get_cb(sr_session_ctx_t *session,
#ifdef SYSREPO_LIBYANG_V2
    uint32_t sub_id,
#endif
    const char *module_name, const char *xpath, const char *request_path, uint32_t request_id,
    struct lyd_node **parent, void *private_data)
{
    xpon_obj_hdr *hdr, *hdr_tmp;
    xpon_tcont *tcont;
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
        STAILQ_FOREACH_SAFE(hdr, &tcont_list, next, hdr_tmp)
        {
            tcont = (xpon_tcont *)hdr;
            snprintf(full_xpath, sizeof(full_xpath)-1, "%s[name='%s']", xpath, tcont->hdr.name);
            sr_rc = xpon_tcont_state_populate1(session, full_xpath, parent, tcont);
            if (sr_rc != SR_ERR_OK)
                break;
        }
        return sr_rc;
    }

    /*
     * Specific tcont
     */

    /* Just return if path refers to interface other than v_ani */
    if (nc_xpath_key_get(xpath, "name", keyname, sizeof(keyname)) != BCM_ERR_OK)
        return BCM_ERR_OK;

    if (xpon_tcont_get_by_name(keyname, &tcont, NULL) != BCM_ERR_OK)
        return SR_ERR_NOT_FOUND;

    sr_rc = xpon_tcont_state_populate1(session, xpath, parent, tcont);

    return sr_rc;
}

bcmos_errno xpon_tcont_init(sr_session_ctx_t *srs)
{
    STAILQ_INIT(&tcont_list);
    STAILQ_INIT(&td_profile_list);
    return BCM_ERR_OK;
}

bcmos_errno xpon_tcont_start(sr_session_ctx_t *srs)
{
    int sr_rc;

    /* subscribe to events */
    sr_rc = sr_module_change_subscribe(srs, BBF_XPONGEMTCONT_MODULE_NAME, BBF_XPON_TD_PROFILE_PATH_BASE,
            _td_prof_change_cb, NULL, 0, BCM_SR_MODULE_CHANGE_SUBSCR_FLAGS,
            &sr_ctx);
    if (SR_ERR_OK == sr_rc)
    {
        NC_LOG_INFO("Subscribed to %s subtree changes.\n", BBF_XPON_TD_PROFILE_PATH_BASE);
    }
    else
    {
        NC_LOG_ERR("Failed to subscribe to %s subtree changes (%s).\n",
            BBF_XPON_TD_PROFILE_PATH_BASE, sr_strerror(sr_rc));
        return nc_sr_errno_to_bcmos_errno(sr_rc);
    }

    sr_rc = sr_module_change_subscribe(srs, BBF_XPONGEMTCONT_MODULE_NAME, BBF_XPON_TCONT_PATH_BASE,
            _tcont_change_cb, NULL, 0, BCM_SR_MODULE_CHANGE_SUBSCR_FLAGS,
            &sr_ctx);
    if (SR_ERR_OK == sr_rc)
    {
        NC_LOG_INFO("Subscribed to %s subtree changes.\n", BBF_XPON_TCONT_PATH_BASE);
    }
    else
    {
        NC_LOG_ERR("Failed to subscribe to %s subtree changes (%s).\n",
            BBF_XPON_TCONT_PATH_BASE, sr_strerror(sr_rc));
        return nc_sr_errno_to_bcmos_errno(sr_rc);
    }

    /* Subscribe for operational data retrieval */
    sr_rc = sr_oper_get_items_subscribe(srs, BBF_XPONGEMTCONT_MODULE_NAME, BBF_XPON_TCONT_STATE_PATH_BASE,
        _tcont_state_get_cb, NULL, 0, &sr_ctx_tcont_state);

    if (SR_ERR_OK != sr_rc) {
        NC_LOG_ERR("Failed to subscribe to %s subtree operation data retrieval (%s).",
            BBF_XPON_TCONT_STATE_PATH_BASE, sr_strerror(sr_rc));
        return nc_sr_errno_to_bcmos_errno(sr_rc);
    }

    return BCM_ERR_OK;
}

void xpon_tcont_exit(sr_session_ctx_t *srs)
{
    if (sr_ctx_tcont_state != NULL)
        sr_unsubscribe(sr_ctx_tcont_state);
}

/* Find or add & populate tcont object */
bcmos_errno xpon_tcont_get_populate(sr_session_ctx_t *srs, const char *name, xpon_tcont **p_tcont)
{
    bcmos_bool is_added = BCMOS_FALSE;
    bcmos_errno err;
    char query_xpath[256];
    sr_val_t *values = NULL;
    size_t value_cnt = 0;
    int i;
    int sr_rc;

    err = xpon_tcont_get_by_name(name, p_tcont, &is_added);
    if (err != BCM_ERR_OK)
        return err;
    if (is_added)
    {
        snprintf(query_xpath, sizeof(query_xpath)-1,
            BBF_XPON_TCONT_PATH_BASE "[name='%s']//.", (*p_tcont)->hdr.name);
        sr_rc = sr_get_items(srs, query_xpath, 0, SR_OPER_DEFAULT, &values, &value_cnt);
        if (sr_rc)
        {
            NC_LOG_ERR("sr_get_items(%s) -> %s\n", query_xpath, sr_strerror(sr_rc));
            xpon_tcont_delete(*p_tcont);
            *p_tcont = NULL;
            return BCM_ERR_PARM;
        }
        NC_LOG_DBG("Populating %s from xpath '%s'. values %u\n",
            BBF_XPON_TCONT_PATH_BASE, query_xpath, (unsigned)value_cnt);

        for (i = 0; i < value_cnt && err == BCM_ERR_OK; i++)
        {
            err = _tcont_attribute_populate(srs, *p_tcont, NULL, &values[i]);
        }
        sr_free_values(values, value_cnt);
        if (err != BCM_ERR_OK)
        {
            xpon_tcont_delete(*p_tcont);
            *p_tcont = NULL;
        }
        else
        {
            (*p_tcont)->hdr.created_by_forward_reference = BCMOS_TRUE;
        }
    }
    return err;
}

/* Find or add tcont object */
bcmos_errno xpon_tcont_get_by_name(const char *name, xpon_tcont **p_tcont, bcmos_bool *is_added)
{
    xpon_obj_hdr *obj = NULL;
    bcmos_errno err;

    err = xpon_object_get_or_add(name, XPON_OBJ_TYPE_TCONT,
        sizeof(xpon_tcont), &obj, is_added);
    if (err != BCM_ERR_OK)
        return err;
    *p_tcont = (xpon_tcont *)obj;
    if (is_added != NULL && *is_added)
    {
        (*p_tcont)->alloc_id = ALLOC_ID_UNDEFINED;
        (*p_tcont)->state = XPON_RESOURCE_STATE_NOT_CONFIGURED;
        (*p_tcont)->pon_ni = BCMOLT_INTERFACE_UNDEFINED;
        STAILQ_INSERT_TAIL(&tcont_list, obj, next);
        NC_LOG_INFO("tcont %s added\n", name);
    }
    return BCM_ERR_OK;
}

/* Remove tcont object */
void xpon_tcont_delete(xpon_tcont *tcont)
{
    STAILQ_REMOVE_SAFE(&tcont_list, &tcont->hdr, xpon_obj_hdr, next);
    NC_LOG_INFO("tcont %s deleted\n", tcont->hdr.name);
    if (tcont->alloc_id != ALLOC_ID_UNDEFINED &&
        tcont->alloc_id >= DYN_TCONT_BASE &&
        tcont->v_ani && tcont->v_ani->pon_ni < BCM_MAX_PONS_PER_OLT)
    {
        BUG_ON(tcont->alloc_id - DYN_TCONT_BASE >= MAX_DYN_TCONTS_PER_PON);
        tcont_array[tcont->v_ani->pon_ni][tcont->alloc_id - DYN_TCONT_BASE] = NULL;
    }
    if (tcont->td_profile != NULL && tcont->td_profile->hdr.created_by_forward_reference)
        xpon_td_prof_delete(tcont->td_profile);
    if (tcont->v_ani != NULL && tcont->v_ani->hdr.created_by_forward_reference)
        xpon_v_ani_delete(tcont->v_ani);
    xpon_object_delete(&tcont->hdr);
}

/* Find TD profile. Create and popupate from OPERATIVE data if not found */
bcmos_errno xpon_td_prof_get_populate(sr_session_ctx_t *srs, const char *name, xpon_td_profile **p_prof)
{
    bcmos_bool is_added = BCMOS_FALSE;
    bcmos_errno err;
    char query_xpath[256];
    sr_val_t *values = NULL;
    size_t value_cnt = 0;
    int i;
    int sr_rc;

    err = xpon_td_prof_get_by_name(name, p_prof, &is_added);
    if (err != BCM_ERR_OK)
        return err;
    if (is_added)
    {
        snprintf(query_xpath, sizeof(query_xpath)-1,
            BBF_XPON_TD_PROFILE_PATH_BASE "[name='%s']//.", (*p_prof)->hdr.name);
        sr_rc = sr_get_items(srs, query_xpath, 0, SR_OPER_DEFAULT, &values, &value_cnt);
        if (sr_rc)
        {
            NC_LOG_ERR("sr_get_items(%s) -> %s\n", query_xpath, sr_strerror(sr_rc));
            xpon_td_prof_delete(*p_prof);
            *p_prof = NULL;
            return BCM_ERR_PARM;
        }
        NC_LOG_DBG("Populating %s from xpath '%s'. values %u\n",
            BBF_XPON_TD_PROFILE_PATH_BASE, query_xpath, (unsigned)value_cnt);

        for (i = 0; i < value_cnt && err == BCM_ERR_OK; i++)
        {
            err = _td_prof_attribute_populate(srs, *p_prof, NULL, &values[i]);
        }
        sr_free_values(values, value_cnt);
        if (err != BCM_ERR_OK)
        {
            xpon_td_prof_delete(*p_prof);
            *p_prof = NULL;
        }
        else
        {
            (*p_prof)->hdr.created_by_forward_reference = BCMOS_TRUE;
        }
    }
    return err;
}

/* Find or add traffic descriptor profile object */
bcmos_errno xpon_td_prof_get_by_name(const char *name, xpon_td_profile **p_prof, bcmos_bool *is_added)
{
    xpon_obj_hdr *obj = NULL;
    bcmos_errno err;

    err = xpon_object_get_or_add(name, XPON_OBJ_TYPE_TRAFFIC_DESCR_PROFILE,
        sizeof(xpon_td_profile), &obj, is_added);
    if (err != BCM_ERR_OK)
        return err;
    *p_prof = (xpon_td_profile *)obj;
    if (is_added != NULL && *is_added)
    {
        STAILQ_INSERT_TAIL(&td_profile_list, obj, next);
        NC_LOG_INFO("traffic-descriptor-profile %s added\n", name);
    }
    return BCM_ERR_OK;
}

/* Remove traffic descriptor profile object */
void xpon_td_prof_delete(xpon_td_profile *prof)
{
    STAILQ_REMOVE_SAFE(&td_profile_list, &prof->hdr, xpon_obj_hdr, next);
    NC_LOG_INFO("traffic-descriptor-profile %s deleted\n", prof->hdr.name);
    xpon_object_delete(&prof->hdr);
}
