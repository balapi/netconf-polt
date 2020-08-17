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

static xpon_obj_list qos_classifier_list;
static xpon_obj_list qos_policy_list;
static xpon_obj_list qos_policy_profile_list;

static void qos_policy_classifier_remove(xpon_qos_classifier *obj);
static void qos_policy_profile_policy_remove(xpon_qos_policy *obj);

/*
 * qos-classifier object
 */

/* Data store change indication callback */
static int bbf_xpon_qos_classifier_change_cb(sr_session_ctx_t *srs, const char *module_name,
    const char *xpath, sr_event_t event, uint32_t request_id, void *private_ctx)
{
    sr_change_iter_t *sr_iter = NULL;
    sr_change_oper_t sr_oper;
    sr_val_t *sr_old_val = NULL, *sr_new_val = NULL;
    char keyname[32];
    char prev_keyname[32] = "";
    xpon_qos_classifier *obj = NULL;
    int sr_rc;
    bcmos_bool was_added = BCMOS_FALSE;
    char qualified_xpath[BCM_MAX_XPATH_LENGTH];
    bcmos_errno err = BCM_ERR_OK;

    NC_LOG_INFO("xpath=%s event=%d\n", xpath, event);

    /* We only handle CHANGE and ABORT events.
     * Since there is no way to reserve resources in advance and no way to fail the DONE event,
     * configuration is applied in CHANGE event.
     * There are no other verifiers, but if there are and they fail,
     * ABORT event will roll-back the changes.
     */
    if (event == SR_EV_DONE)
        return SR_ERR_OK;

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
        const char *match_xpath;
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
                xpon_qos_classifier_delete(obj);
                obj = NULL;
            }
            err = xpon_qos_classifier_get_by_name(keyname, &obj, &was_added);
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
        else if ((match_xpath=strstr(iter_xpath, "match-criteria")) != NULL)
        {
            /* Validate */
            if (sr_new_val != NULL)
            {
                if (strstr(iter_xpath, "match-all") == NULL &&
                    strstr(iter_xpath, "dscp-range") == NULL &&
                    strstr(iter_xpath, "any-protocol") == NULL &&
                    strstr(iter_xpath, "pbit-marking-list") == NULL)
                {
                    NC_LOG_WARN("IGNORED: unsupported match-criteria: %s\n", iter_xpath);
                    continue;
                }
                if (strstr(iter_xpath, "dscp-range") != NULL &&
                    ((sr_new_val->type != SR_ENUM_T && sr_new_val->type != SR_STRING_T) ||
                        strcmp(sr_new_val->data.string_val, "any")))
                {
                    NC_LOG_ERR("IGNORED: unsupported match-criteria: dscp-range: %s\n", iter_xpath);
                    // NC_ERROR_REPLY(srs, iter_xpath, "unsupported match-criteria: dscp-range\n");
                    // err = BCM_ERR_NOT_SUPPORTED;
                    // break;
                }
                if (strstr(iter_xpath, "pbit-marking-list") != NULL)
                {
                    char index_str[16] = "";
                    bbf_tag_index_type tag_index;
                    bbf_dot1q_tag *tag;

                    nc_xpath_key_get(match_xpath, "index", index_str, sizeof(index_str));
                    /* Only indexes 0 and 1 are supported */
                    if (!strcmp(index_str, "0"))
                        tag_index = BBF_TAG_INDEX_TYPE_OUTER;
                    else if (!strcmp(index_str, "1"))
                        tag_index = BBF_TAG_INDEX_TYPE_INNER;
                    else
                    {
                        NC_LOG_ERR("tag index %s is invalid\n", index_str);
                        err = BCM_ERR_NOT_SUPPORTED;
                        break;
                    }
                    tag = &obj->match.vlan_tag_match.tags[tag_index];
                    if (strstr(leaf, "pbit-value") != NULL)
                    {
                        obj->match.vlan_tag_match.tag_match_types[tag_index] = BBF_VLAN_TAG_MATCH_TYPE_VLAN_TAGGED;
                        if (strstr(match_xpath, "/any") == NULL)
                        {
                            if (val->type != SR_UINT8_T)
                            {
                                NC_LOG_ERR("pbit-value is not supported: %s\n", match_xpath);
                                err = BCM_ERR_NOT_SUPPORTED;
                                break;
                            }
                            BBF_DOT1Q_TAG_PROP_SET(tag, pbit, val->data.uint8_val);
                        }
                    }
                    if (obj->match.vlan_tag_match.num_tags < tag_index + 1)
                        obj->match.vlan_tag_match.num_tags = tag_index + 1;
                }
            }
        }
        else if (strstr(leaf, "scheduling-traffic-class") != NULL)
        {
            if (sr_new_val != NULL)
            {
                XPON_PROP_SET(obj, qos_classifier, traffic_class, sr_new_val->data.uint32_val);
            }
        }
        else if (strstr(leaf, "filter-operation") != NULL)
        {
            if (sr_new_val != NULL &&
                strstr(sr_new_val->data.identityref_val, "match-any-filter") == NULL &&
                strstr(sr_new_val->data.identityref_val, "match-all-filter") == NULL)
            {
                NC_ERROR_REPLY(srs, iter_xpath, "unsupported filter-operation %s\n", sr_new_val->data.identityref_val);
                err = BCM_ERR_NOT_SUPPORTED;
                break;
            }
        }
    }

    if (obj != NULL && (obj->hdr.being_deleted || (err != BCM_ERR_OK && was_added)))
    {
        if (obj->hdr.being_deleted)
            err = BCM_ERR_OK;
        xpon_qos_classifier_delete(obj);
    }

    nc_sr_free_value_pair(&sr_old_val, &sr_new_val);
    sr_free_change_iter(sr_iter);

    return nc_bcmos_errno_to_sr_errno(err);
}


bcmos_errno xpon_qos_classifier_init(sr_session_ctx_t *srs)
{
    STAILQ_INIT(&qos_classifier_list);
    return BCM_ERR_OK;
}

bcmos_errno xpon_qos_classifier_start(sr_session_ctx_t *srs)
{
    int sr_rc;
    /* subscribe to events */
    sr_rc = sr_module_change_subscribe(srs, BBF_QOS_CLASSIFIERS_MODULE_NAME, BBQ_QOS_CLASSIFIER_PATH_BASE,
            bbf_xpon_qos_classifier_change_cb, NULL, 0, BCM_SR_MODULE_CHANGE_SUBSCR_FLAGS,
            &sr_ctx);
    if (SR_ERR_OK == sr_rc)
    {
        NC_LOG_INFO("Subscribed to %s subtree changes.\n", BBQ_QOS_CLASSIFIER_PATH_BASE);
    }
    else
    {
        NC_LOG_ERR("Failed to subscribe to %s subtree changes (%s).\n",
            BBQ_QOS_CLASSIFIER_PATH_BASE, sr_strerror(sr_rc));
    }

    return nc_sr_errno_to_bcmos_errno(sr_rc);
}

void xpon_qos_classifier_exit(sr_session_ctx_t *srs)
{
}

/* Get qos-classifier object by name, add a new one if
 * doesn't exist
 */
bcmos_errno xpon_qos_classifier_get_by_name(const char *name, xpon_qos_classifier **p_obj, bcmos_bool *is_added)
{
    xpon_obj_hdr *obj = NULL;
    bcmos_errno err;

    err = xpon_object_get_or_add(name, XPON_OBJ_TYPE_QOS_CLASSIFIER,
        sizeof(xpon_qos_classifier), &obj, is_added);
    if (err != BCM_ERR_OK)
        return err;
    *p_obj = (xpon_qos_classifier *)obj;
    if (is_added != NULL && *is_added)
    {
        STAILQ_INSERT_TAIL(&qos_classifier_list, obj, next);
        NC_LOG_INFO("qos_classifier %s added\n", name);
    }
    return BCM_ERR_OK;
}

/* Delete qos-classifier object */
void xpon_qos_classifier_delete(xpon_qos_classifier *obj)
{
    STAILQ_REMOVE_SAFE(&qos_classifier_list, &obj->hdr, xpon_obj_hdr, next);
    /* Remove references to classifier from policy */
    qos_policy_classifier_remove(obj);
    NC_LOG_INFO("qos-classifier %s deleted\n", obj->hdr.name);
    xpon_object_delete(&obj->hdr);
}

/*
 * qos-policy object
 */

/* add qos_policy to policy profile */
static bcmos_errno qos_policy_classifier_add(xpon_qos_policy *policy, xpon_qos_classifier *classifier)
{
    if (policy->num_classifiers >= XPON_MAX_QOS_CLASSIFIERS_PER_QOS_POLICY)
        return BCM_ERR_TOO_MANY;
    policy->classifier[policy->num_classifiers++] = classifier;
    return BCM_ERR_OK;
}

/* remove qos_classifier from policy */
static void qos_policy_classifier_remove1(xpon_qos_policy *policy, xpon_qos_classifier *classifier)
{
    int i;
    for (i = 0; i < policy->num_classifiers; i++)
    {
        if (policy->classifier[i] == classifier)
        {
            if (policy->num_classifiers - i - 1)
            {
                memcpy(&policy->classifier[i], &policy->classifier[i+1],
                    (policy->num_classifiers - i - 1) * sizeof(policy->classifier[0]));
            }
            --policy->num_classifiers;
            break;
        }
    }
}

/* remove qos_classifier from all policies that reference it */
static void qos_policy_classifier_remove(xpon_qos_classifier *classifier)
{
    xpon_obj_hdr *obj, *obj_tmp;
    STAILQ_FOREACH_SAFE(obj, &qos_policy_list, next, obj_tmp)
    {
        xpon_qos_policy *policy = (xpon_qos_policy *)obj;
        qos_policy_classifier_remove1(policy, classifier);
    }
}

/* Data store change indication callback */
static int bbf_xpon_qos_policy_change_cb(sr_session_ctx_t *srs, const char *module_name,
    const char *xpath, sr_event_t event, uint32_t request_id, void *private_ctx)
{
    sr_change_iter_t *sr_iter = NULL;
    sr_change_oper_t sr_oper;
    sr_val_t *sr_old_val = NULL, *sr_new_val = NULL;
    char keyname[32];
    char prev_keyname[32] = "";
    char qualified_xpath[BCM_MAX_XPATH_LENGTH];
    xpon_qos_policy *obj = NULL;
    int sr_rc;
    bcmos_bool was_added = BCMOS_FALSE;
    bcmos_errno err = BCM_ERR_OK;

    NC_LOG_INFO("xpath=%s event=%d\n", xpath, event);

    /* We only handle CHANGE and ABORT events.
     * Since there is no way to reserve resources in advance and no way to fail the DONE event,
     * configuration is applied in CHANGE event.
     * There are no other verifiers, but if there are and they fail,
     * ABORT event will roll-back the changes.
     */
    if (event == SR_EV_DONE)
        return SR_ERR_OK;

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
                xpon_qos_policy_delete(obj);
                obj = NULL;
            }
            err = xpon_qos_policy_get_by_name(keyname, &obj, &was_added);
            if (err != BCM_ERR_OK)
                break;
        }
        strcpy(prev_keyname, keyname);

        /* handle attributes */
        /* Go over supported leafs */
        if (strstr(iter_xpath, "classifiers") != NULL)
        {
            if (!strcmp(leaf, "name"))
            {
                xpon_qos_classifier *classifier = NULL;
                bcmos_bool classifier_was_added = BCMOS_FALSE;
                if (val->data.string_val != NULL)
                {
                    err = xpon_qos_classifier_get_by_name(val->data.string_val, &classifier, &classifier_was_added);
                    if (err != BCM_ERR_OK)
                        break;
                }
                if (sr_new_val != NULL)
                {

                    err = qos_policy_classifier_add(obj, classifier);
                    if (err != BCM_ERR_OK)
                        break;
                }
                else
                {
                    qos_policy_classifier_remove1(obj, classifier);
                    if (classifier_was_added)
                        xpon_qos_classifier_delete(classifier);
                }
            }
        }
        else if (!strcmp(leaf, "name"))
        {
            obj->hdr.being_deleted = (sr_new_val == NULL);
        }
    }

    if (obj != NULL && (obj->hdr.being_deleted || (err != BCM_ERR_OK && was_added)))
    {
        if (obj->hdr.being_deleted)
            err = BCM_ERR_OK;
        xpon_qos_policy_delete(obj);
    }

    nc_sr_free_value_pair(&sr_old_val, &sr_new_val);
    sr_free_change_iter(sr_iter);

    return nc_bcmos_errno_to_sr_errno(err);
}


bcmos_errno xpon_qos_policy_init(sr_session_ctx_t *srs)
{
    STAILQ_INIT(&qos_policy_list);
    return BCM_ERR_OK;
}

bcmos_errno xpon_qos_policy_start(sr_session_ctx_t *srs)
{
    int sr_rc;
    /* subscribe to events */
    sr_rc = sr_module_change_subscribe(srs, BBF_QOS_POLICIES_MODULE_NAME, BBQ_QOS_POLICY_PATH_BASE,
            bbf_xpon_qos_policy_change_cb, NULL, 0, BCM_SR_MODULE_CHANGE_SUBSCR_FLAGS,
            &sr_ctx);
    if (SR_ERR_OK == sr_rc)
    {
        NC_LOG_INFO("Subscribed to %s subtree changes.\n", BBQ_QOS_POLICY_PATH_BASE);
    }
    else
    {
        NC_LOG_ERR("Failed to subscribe to %s subtree changes (%s).\n",
            BBQ_QOS_POLICY_PATH_BASE, sr_strerror(sr_rc));
    }

    return nc_sr_errno_to_bcmos_errno(sr_rc);
}

void xpon_qos_policy_exit(sr_session_ctx_t *srs)
{
}

/* Get qos-policy object by name, add a new one if
 * doesn't exist
 */
bcmos_errno xpon_qos_policy_get_by_name(const char *name, xpon_qos_policy **p_obj, bcmos_bool *is_added)
{
    xpon_obj_hdr *obj = NULL;
    bcmos_errno err;

    err = xpon_object_get_or_add(name, XPON_OBJ_TYPE_QOS_POLICY,
        sizeof(xpon_qos_policy), &obj, is_added);
    if (err != BCM_ERR_OK)
        return err;
    *p_obj = (xpon_qos_policy *)obj;
    if (is_added != NULL && *is_added)
    {
        STAILQ_INSERT_TAIL(&qos_policy_list, obj, next);
        NC_LOG_INFO("qos_policy %s added\n", name);
    }
    return BCM_ERR_OK;
}

/* Delete qos-policy object */
void xpon_qos_policy_delete(xpon_qos_policy *obj)
{
    STAILQ_REMOVE_SAFE(&qos_policy_list, &obj->hdr, xpon_obj_hdr, next);
    /* Remove references to policy from policy profile */
    qos_policy_profile_policy_remove(obj);
    NC_LOG_INFO("qos-policy %s deleted\n", obj->hdr.name);
    xpon_object_delete(&obj->hdr);
}

/*
 * qos-policy-profile object
 */

/* add qos_policy to policy profile */
static bcmos_errno qos_policy_profile_policy_add(xpon_qos_policy_profile *prof, xpon_qos_policy *policy)
{
    if (prof->num_policies >= XPON_MAX_QOS_POLICIES_PER_QOS_POLICY_PROFILE)
        return BCM_ERR_TOO_MANY;
    prof->policy[prof->num_policies++] = policy;
    return BCM_ERR_OK;
}

/* remove qos_policy  from all policy profiles reference it */
static void qos_policy_profile_policy_remove1(xpon_qos_policy_profile *prof, xpon_qos_policy *policy)
{
    int i;
    for (i = 0; i < prof->num_policies; i++)
    {
        if (prof->policy[i] == policy)
        {
            memcpy(&prof->policy[i], prof->policy[i+1],
                (prof->num_policies - i - 1) * sizeof(prof->policy[0]));
            --prof->num_policies;
            break;
        }
    }
}

/* remove qos_policy  from all policy profiles reference it */
static void qos_policy_profile_policy_remove(xpon_qos_policy *policy)
{
    xpon_obj_hdr *obj, *obj_tmp;
    STAILQ_FOREACH_SAFE(obj, &qos_policy_profile_list, next, obj_tmp)
    {
        xpon_qos_policy_profile *prof = (xpon_qos_policy_profile *)obj;
        qos_policy_profile_policy_remove1(prof, policy);
    }
}

/* Data store change indication callback */
static int bbf_xpon_qos_policy_profile_change_cb(sr_session_ctx_t *srs, const char *module_name,
    const char *xpath, sr_event_t event, uint32_t request_id, void *private_ctx)
{
    sr_change_iter_t *sr_iter = NULL;
    sr_change_oper_t sr_oper;
    sr_val_t *sr_old_val = NULL, *sr_new_val = NULL;
    char keyname[32];
    char prev_keyname[32] = "";
    char qualified_xpath[BCM_MAX_XPATH_LENGTH];
    xpon_qos_policy_profile *obj = NULL;
    int sr_rc;
    bcmos_bool was_added = BCMOS_FALSE;
    bcmos_errno err = BCM_ERR_OK;

    NC_LOG_INFO("xpath=%s event=%d\n", xpath, event);

    /* We only handle CHANGE and ABORT events.
     * Since there is no way to reserve resources in advance and no way to fail the DONE event,
     * configuration is applied in CHANGE event.
     * There are no other verifiers, but if there are and they fail,
     * ABORT event will roll-back the changes.
     */
    if (event == SR_EV_DONE)
        return SR_ERR_OK;

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
                xpon_qos_policy_profile_delete(obj);
                obj = NULL;
            }
            err = xpon_qos_policy_profile_get_by_name(keyname, &obj, &was_added);
            if (err != BCM_ERR_OK)
                break;
        }
        strcpy(prev_keyname, keyname);

        /* handle attributes */
        /* Go over supported leafs */
        if (strstr(iter_xpath, "policy-list") != NULL)
        {
            if (!strcmp(leaf, "name"))
            {
                xpon_qos_policy *policy = NULL;
                bcmos_bool policy_was_added = BCMOS_FALSE;
                if (val->data.string_val != NULL)
                {
                    err = xpon_qos_policy_get_by_name(val->data.string_val, &policy, &policy_was_added);
                    if (err != BCM_ERR_OK)
                        break;
                }
                if (sr_new_val != NULL)
                {
                    err = qos_policy_profile_policy_add(obj, policy);
                    if (err != BCM_ERR_OK)
                        break;
                }
                else
                {
                    qos_policy_profile_policy_remove1(obj, policy);
                    if (policy_was_added)
                        xpon_qos_policy_delete(policy);
                }
            }
        }
        else if (!strcmp(leaf, "name"))
        {
            obj->hdr.being_deleted = (sr_new_val == NULL);
        }
    }

    if (obj != NULL && (obj->hdr.being_deleted || (err != BCM_ERR_OK && was_added)))
    {
        if (obj->hdr.being_deleted)
            err = BCM_ERR_OK;
        xpon_qos_policy_profile_delete(obj);
    }

    nc_sr_free_value_pair(&sr_old_val, &sr_new_val);
    sr_free_change_iter(sr_iter);

    return nc_bcmos_errno_to_sr_errno(err);
}


bcmos_errno xpon_qos_policy_profile_init(sr_session_ctx_t *srs)
{
    STAILQ_INIT(&qos_policy_profile_list);
    return BCM_ERR_OK;
}

bcmos_errno xpon_qos_policy_profile_start(sr_session_ctx_t *srs)
{
    int sr_rc;
    /* subscribe to events */
    sr_rc = sr_module_change_subscribe(srs, BBF_QOS_POLICIES_MODULE_NAME, BBQ_QOS_POLICY_PROFILE_PATH_BASE,
            bbf_xpon_qos_policy_profile_change_cb, NULL, 0, BCM_SR_MODULE_CHANGE_SUBSCR_FLAGS,
            &sr_ctx);
    if (SR_ERR_OK == sr_rc)
    {
        NC_LOG_INFO("Subscribed to %s subtree changes.\n", BBQ_QOS_POLICY_PROFILE_PATH_BASE);
    }
    else
    {
        NC_LOG_ERR("Failed to subscribe to %s subtree changes (%s).\n",
            BBQ_QOS_POLICY_PROFILE_PATH_BASE, sr_strerror(sr_rc));
    }

    return nc_sr_errno_to_bcmos_errno(sr_rc);
}

void xpon_qos_policy_profile_exit(sr_session_ctx_t *srs)
{
}

/* Get qos-policy-profile object by name, add a new one if
 * doesn't exist
 */
bcmos_errno xpon_qos_policy_profile_get_by_name(const char *name, xpon_qos_policy_profile **p_obj, bcmos_bool *is_added)
{
    xpon_obj_hdr *obj = NULL;
    bcmos_errno err;

    err = xpon_object_get_or_add(name, XPON_OBJ_TYPE_QOS_POLICY_PROFILE,
        sizeof(xpon_qos_policy_profile), &obj, is_added);
    if (err != BCM_ERR_OK)
        return err;
    *p_obj = (xpon_qos_policy_profile *)obj;
    if (is_added != NULL && *is_added)
    {
        STAILQ_INSERT_TAIL(&qos_policy_profile_list, obj, next);
        NC_LOG_INFO("qos_policy_profile %s added\n", name);
    }
    return BCM_ERR_OK;
}

/* Delete qos-policy-profile object */
void xpon_qos_policy_profile_delete(xpon_qos_policy_profile *obj)
{
    STAILQ_REMOVE_SAFE(&qos_policy_profile_list, &obj->hdr, xpon_obj_hdr, next);
    NC_LOG_INFO("qos-policy-profile %s deleted\n", obj->hdr.name);
    xpon_object_delete(&obj->hdr);
}

/* check if qos classifier matches ingress rule */
static bcmos_bool qos_classifier_is_ingress_rule_match(const xpon_qos_classifier *qos_class, const bbf_subif_ingress_rule *rule)
{
    /* TODO: */
    return BCMOS_TRUE;
}

/* check if qos classifier matches sub-interface */
static bcmos_bool qos_classifier_is_subif_match(const xpon_qos_classifier *qos_class, const xpon_vlan_subif *subif,
    const bbf_subif_ingress_rule *rule)
{
    return qos_classifier_is_ingress_rule_match(qos_class, rule);
}

/* find qos classifier matching the subif filter */
const xpon_qos_classifier *xpon_qos_classifier_get_by_profile_subif(const xpon_qos_policy_profile *prof,
    const xpon_vlan_subif *subif, const bbf_subif_ingress_rule *rule)
{
    const xpon_qos_classifier *qos_class;
    int i, j;

    /* TODO: review this. There might be multiple matches leading to multiple BAL flows.
       for now just find the 1st matching classifier */
    for (i = 0; i < prof->num_policies; i++)
    {
        const xpon_qos_policy *policy = prof->policy[i];
        BUG_ON(policy == NULL);
        for (j = 0; j < policy->num_classifiers; j++)
        {
            qos_class = policy->classifier[j];
            BUG_ON(qos_class == NULL);
            if (qos_classifier_is_subif_match(qos_class, subif, rule))
                return qos_class;
        }
    }
    return NULL;
}

/* find qos classifier on the onu side, residing on onu subif such that
    its egress rule matches the OLT subif's egress rule
*/
const xpon_qos_classifier *xpon_qos_classifier_get_by_if_subif(const xpon_vlan_subif *olt_subif,
    const bbf_subif_ingress_rule *olt_rule, const xpon_obj_hdr *ani_if)
{
    const xpon_subif_list *onu_subifs;
    const xpon_vlan_subif *onu_subif, *onu_subif_tmp;
    const bbf_subif_ingress_rule *onu_rule, *onu_rule_tmp;
    const xpon_qos_classifier *qos_class;

    if (ani_if->obj_type == XPON_OBJ_TYPE_ANI_V_ENET)
        onu_subifs = &(((const xpon_ani_v_enet *)ani_if)->subifs);
    else if (ani_if->obj_type == XPON_OBJ_TYPE_ENET)
        onu_subifs = &(((const xpon_enet *)ani_if)->subifs);
    else
    {
        NC_LOG_ERR("Unexpected object %s\n", ani_if->name);
        return NULL;
    }

    /* We need to go over sub-interfaces of ani_v_enet and find those with egress matching
       ingress of olt_subif
    */
    bbf_match_criteria olt_match = olt_rule->match;

    /* No go over ONU sub-interfaces */
    STAILQ_FOREACH_SAFE(onu_subif, onu_subifs, next, onu_subif_tmp)
    {
        if (onu_subif->qos_policy_profile == NULL)
            continue;

        STAILQ_FOREACH_SAFE(onu_rule, &onu_subif->ingress, next, onu_rule_tmp)
        {
            bbf_match_criteria onu_match = onu_rule->match;

            /* calculate egress packet match.
               We are taking packet traveling upstream via ONU UNI and eventually ariving to olt_subif
            */
            xpon_apply_actions_to_match(&onu_match, &onu_rule->rewrite);
            xpon_apply_actions_to_match(&onu_match, &onu_subif->egress_rewrite);

            /* check match */
            if (xpon_is_match(&onu_match, &olt_match))
            {
                qos_class = xpon_qos_classifier_get_by_profile_subif(onu_subif->qos_policy_profile,
                    olt_subif, olt_rule);
                if (qos_class != NULL)
                    return qos_class;
            }
        }
    }

    return NULL;
}
