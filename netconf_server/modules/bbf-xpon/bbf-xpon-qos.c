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

/* Populate qos_classifier attribute */
static bcmos_errno xpon_qos_classifier_attribute_populate(sr_session_ctx_t *srs,
    xpon_qos_classifier *obj, sr_val_t *sr_old_val, sr_val_t *sr_new_val)
{
    const char *iter_xpath;
    char leafbuf[BCM_MAX_LEAF_LENGTH];
    const char *leaf;
    const char *match_xpath;
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
                    strstr(iter_xpath, "pbit-marking-list") == NULL &&
                    strstr(iter_xpath, "tag") == NULL)
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
                else if (strstr(iter_xpath, "pbit-marking-list") != NULL ||
                         strstr(iter_xpath, "in-pbit-list") != NULL)
                {
                    char index_str[16] = "";
                    bbf_tag_index_type tag_index;
                    int pbit_value = -1;

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
                            pbit_value = val->data.uint8_val;
                        }
                    }
                    else if (strstr(leaf, "in-pbit-list") != NULL)
                    {
                        const char *pbit_list = val->data.string_val;
                        if (pbit_list != NULL)
                        {
                            if (strchr(pbit_list, ',') || strchr(pbit_list, '-'))
                            {
                                NC_LOG_ERR("Multiple pbit-values not supported: %s\n", match_xpath);
                                err = BCM_ERR_NOT_SUPPORTED;
                                break;
                            }
                            pbit_value = atoi(pbit_list);
                        }
                    }
                    if (pbit_value >= 0)
                    {
                        obj->match.vlan_tag_match.tag_match_types[tag_index] = BBF_VLAN_TAG_MATCH_TYPE_VLAN_TAGGED;
                        BBF_DOT1Q_TAG_PROP_SET(&obj->match.vlan_tag_match.tags[tag_index], pbit, pbit_value);
                        if (obj->match.vlan_tag_match.num_tags < tag_index + 1)
                            obj->match.vlan_tag_match.num_tags = tag_index + 1;
                    }
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
    } while (0);

    return err;
}

/* Data store change indication callback */
static int xpon_qos_classifier_change_cb(sr_session_ctx_t *srs, const char *module_name,
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
            if (obj != NULL && obj->hdr.being_deleted)
            {
                xpon_qos_classifier_delete(obj);
                obj = NULL;
            }
            err = xpon_qos_classifier_get_by_name(keyname, &obj, &was_added);
            if (err != BCM_ERR_OK)
                break;
            skip = obj->hdr.created_by_forward_reference;
            obj->hdr.created_by_forward_reference = BCMOS_FALSE;
        }
        strcpy(prev_keyname, keyname);

        /* handle attributes */
        if (!skip)
        {
            err = xpon_qos_classifier_attribute_populate(srs, obj, sr_old_val, sr_new_val);
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

    nc_config_unlock();

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
            xpon_qos_classifier_change_cb, NULL, 0, BCM_SR_MODULE_CHANGE_SUBSCR_FLAGS,
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

/* Get qos-classifier object by name, add a new one if doesn't exist and populate from operational data */
bcmos_errno xpon_qos_classifier_get_populate(sr_session_ctx_t *srs, const char *name, xpon_qos_classifier **p_obj)
{
    bcmos_bool is_added = BCMOS_FALSE;
    bcmos_errno err;
    char query_xpath[256];
    sr_val_t *values = NULL;
    size_t value_cnt = 0;
    int i;
    int sr_rc;

    err = xpon_qos_classifier_get_by_name(name, p_obj, &is_added);
    if (err != BCM_ERR_OK)
        return err;
    if (is_added)
    {
        snprintf(query_xpath, sizeof(query_xpath)-1,
            BBQ_QOS_CLASSIFIER_PATH_BASE "[name='%s']//.", name);
        sr_rc = sr_get_items(srs, query_xpath, 0, SR_OPER_DEFAULT, &values, &value_cnt);
        if (sr_rc)
        {
            NC_LOG_ERR("sr_get_items(%s) -> %s\n", query_xpath, sr_strerror(sr_rc));
            xpon_qos_classifier_delete(*p_obj);
            *p_obj = NULL;
            return BCM_ERR_PARM;
        }
        NC_LOG_DBG("Populating from xpath '%s'. values %u\n",
            query_xpath, (unsigned)value_cnt);

        for (i = 0; i < value_cnt && err == BCM_ERR_OK; i++)
        {
            err = xpon_qos_classifier_attribute_populate(srs, *p_obj, NULL, &values[i]);
        }
        sr_free_values(values, value_cnt);
        if (err != BCM_ERR_OK)
        {
            xpon_qos_classifier_delete(*p_obj);
            *p_obj = NULL;
        }
        else
        {
            (*p_obj)->hdr.created_by_forward_reference = BCMOS_TRUE;
        }
    }
    return err;
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
    classifier->policy = policy;
    return BCM_ERR_OK;
}

/* remove qos_classifier from policy */
static void qos_policy_classifier_remove1(xpon_qos_policy *policy, xpon_qos_classifier *classifier)
{
    int i;
    for (i = 0; i < policy->num_classifiers; i++)
    {
        if (policy->classifier[i] == classifier || classifier == NULL)
        {
            if (policy->classifier[i]->hdr.created_by_forward_reference)
            {
                xpon_qos_classifier_delete(policy->classifier[i]);
            }
            if (policy->num_classifiers - i - 1)
            {
                memcpy(&policy->classifier[i], &policy->classifier[i+1],
                    (policy->num_classifiers - i - 1) * sizeof(policy->classifier[0]));
            }
            --policy->num_classifiers;
            if (classifier != NULL)
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

/* Populate qos_policy attribute */
static bcmos_errno xpon_qos_policy_attribute_populate(sr_session_ctx_t *srs,
    xpon_qos_policy *obj, sr_val_t *sr_old_val, sr_val_t *sr_new_val)
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
        if (strstr(iter_xpath, "classifiers") != NULL)
        {
            if (!strcmp(leaf, "name"))
            {
                xpon_qos_classifier *classifier = NULL;
                if (sr_new_val != NULL)
                {
                    err = xpon_qos_classifier_get_populate(srs, val->data.string_val, &classifier);
                    if (err != BCM_ERR_OK)
                        break;
                    err = qos_policy_classifier_add(obj, classifier);
                    if (err != BCM_ERR_OK)
                    {
                        if (classifier->hdr.created_by_forward_reference)
                            xpon_qos_classifier_delete(classifier);
                        break;
                    }
                }
                else
                {
                    xpon_qos_classifier_get_by_name(val->data.string_val, &classifier, NULL);
                    if (classifier != NULL)
                        qos_policy_classifier_remove1(obj, classifier);
                }
            }
        }
        else if (!strcmp(leaf, "name"))
        {
            obj->hdr.being_deleted = (sr_new_val == NULL);
        }
    } while (0);

    return err;
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
            if (obj != NULL && obj->hdr.being_deleted)
            {
                xpon_qos_policy_delete(obj);
                obj = NULL;
            }
            err = xpon_qos_policy_get_by_name(keyname, &obj, &was_added);
            if (err != BCM_ERR_OK)
                break;
            skip = obj->hdr.created_by_forward_reference;
            obj->hdr.created_by_forward_reference = BCMOS_FALSE;
        }
        strcpy(prev_keyname, keyname);

        /* handle attributes */
        if (!skip)
        {
            err = xpon_qos_policy_attribute_populate(srs, obj, sr_old_val, sr_new_val);
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

    nc_config_unlock();

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

/* Get qos-policy object by name, add a new one if doesn't exist and populate from operational data */
bcmos_errno xpon_qos_policy_get_populate(sr_session_ctx_t *srs, const char *name, xpon_qos_policy **p_obj)
{
    bcmos_bool is_added = BCMOS_FALSE;
    bcmos_errno err;
    char query_xpath[256];
    sr_val_t *values = NULL;
    size_t value_cnt = 0;
    int i;
    int sr_rc;

    err = xpon_qos_policy_get_by_name(name, p_obj, &is_added);
    if (err != BCM_ERR_OK)
        return err;
    if (is_added)
    {
        snprintf(query_xpath, sizeof(query_xpath)-1,
            BBQ_QOS_POLICY_PATH_BASE "[name='%s']//.", name);
        sr_rc = sr_get_items(srs, query_xpath, 0, SR_OPER_DEFAULT, &values, &value_cnt);
        if (sr_rc)
        {
            NC_LOG_ERR("sr_get_items(%s) -> %s\n", query_xpath, sr_strerror(sr_rc));
            xpon_qos_policy_delete(*p_obj);
            *p_obj = NULL;
            return BCM_ERR_PARM;
        }
        NC_LOG_DBG("Populating from xpath '%s'. values %u\n",
            query_xpath, (unsigned)value_cnt);

        for (i = 0; i < value_cnt && err == BCM_ERR_OK; i++)
        {
            err = xpon_qos_policy_attribute_populate(srs, *p_obj, NULL, &values[i]);
        }
        sr_free_values(values, value_cnt);
        if (err != BCM_ERR_OK)
        {
            xpon_qos_policy_delete(*p_obj);
            *p_obj = NULL;
        }
        else
        {
            (*p_obj)->hdr.created_by_forward_reference = BCMOS_TRUE;
        }
    }
    return err;
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
    /* Remove all references to qos_classifers */
    qos_policy_classifier_remove1(obj, NULL);
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
    policy->profile = prof;
    return BCM_ERR_OK;
}

/* remove qos_policy  from all policy profiles reference it */
static void qos_policy_profile_policy_remove1(xpon_qos_policy_profile *prof, xpon_qos_policy *policy)
{
    int i;
    for (i = 0; i < prof->num_policies; i++)
    {
        if (prof->policy[i] == policy || policy == NULL)
        {
            if (prof->policy[i]->hdr.created_by_forward_reference)
                xpon_qos_policy_delete(prof->policy[i]);
            memcpy(&prof->policy[i], prof->policy[i+1],
                (prof->num_policies - i - 1) * sizeof(prof->policy[0]));
            --prof->num_policies;
            if (policy != NULL)
                break;
        }
    }
}

/* remove qos-policy  from all policy profiles reference it */
static void qos_policy_profile_policy_remove(xpon_qos_policy *policy)
{
    xpon_obj_hdr *obj, *obj_tmp;
    STAILQ_FOREACH_SAFE(obj, &qos_policy_profile_list, next, obj_tmp)
    {
        xpon_qos_policy_profile *prof = (xpon_qos_policy_profile *)obj;
        qos_policy_profile_policy_remove1(prof, policy);
    }
}

/* Populate qos-policy-profile attribute */
static bcmos_errno xpon_qos_policy_profile_attribute_populate(sr_session_ctx_t *srs,
    xpon_qos_policy_profile *obj, sr_val_t *sr_old_val, sr_val_t *sr_new_val)
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
        if (strstr(iter_xpath, "policy-list") != NULL)
        {
            if (!strcmp(leaf, "name"))
            {
                xpon_qos_policy *policy = NULL;
                if (sr_new_val != NULL)
                {
                    err = xpon_qos_policy_get_populate(srs, val->data.string_val, &policy);
                    if (err != BCM_ERR_OK)
                        break;
                    err = qos_policy_profile_policy_add(obj, policy);
                    if (err != BCM_ERR_OK)
                    {
                        if (policy->hdr.created_by_forward_reference)
                            xpon_qos_policy_delete(policy);
                        break;
                    }
                }
                else
                {
                    xpon_qos_policy_get_by_name(val->data.string_val, &policy, NULL);
                    if (policy != NULL)
                        qos_policy_profile_policy_remove1(obj, policy);
                }
            }
        }
        else if (!strcmp(leaf, "name"))
        {
            obj->hdr.being_deleted = (sr_new_val == NULL);
        }
    } while (0);

    return err;
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
            if (obj != NULL && obj->hdr.being_deleted)
            {
                xpon_qos_policy_profile_delete(obj);
                obj = NULL;
            }
            err = xpon_qos_policy_profile_get_by_name(keyname, &obj, &was_added);
            if (err != BCM_ERR_OK)
                break;
            skip = obj->hdr.created_by_forward_reference;
            obj->hdr.created_by_forward_reference = BCMOS_FALSE;
        }
        strcpy(prev_keyname, keyname);

        /* handle attributes */
        if (!skip)
        {
            err = xpon_qos_policy_profile_attribute_populate(srs, obj, sr_old_val, sr_new_val);
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

    nc_config_unlock();

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

/* Get qos-policy-profile object by name, add a new one if doesn't exist and populate from operational data */
bcmos_errno xpon_qos_policy_profile_get_populate(sr_session_ctx_t *srs, const char *name,
    xpon_qos_policy_profile **p_obj)
{
    bcmos_bool is_added = BCMOS_FALSE;
    bcmos_errno err;
    char query_xpath[256];
    sr_val_t *values = NULL;
    size_t value_cnt = 0;
    int i;
    int sr_rc;

    err = xpon_qos_policy_profile_get_by_name(name, p_obj, &is_added);
    if (err != BCM_ERR_OK)
        return err;
    if (is_added)
    {
        snprintf(query_xpath, sizeof(query_xpath)-1,
            BBQ_QOS_POLICY_PROFILE_PATH_BASE "[name='%s']//.", name);
        sr_rc = sr_get_items(srs, query_xpath, 0, SR_OPER_DEFAULT, &values, &value_cnt);
        if (sr_rc)
        {
            NC_LOG_ERR("sr_get_items(%s) -> %s\n", query_xpath, sr_strerror(sr_rc));
            xpon_qos_policy_profile_delete(*p_obj);
            *p_obj = NULL;
            return BCM_ERR_PARM;
        }
        NC_LOG_DBG("Populating from xpath '%s'. values %u\n",
            query_xpath, (unsigned)value_cnt);

        for (i = 0; i < value_cnt && err == BCM_ERR_OK; i++)
        {
            err = xpon_qos_policy_profile_attribute_populate(srs, *p_obj, NULL, &values[i]);
        }
        sr_free_values(values, value_cnt);
        if (err != BCM_ERR_OK)
        {
            xpon_qos_policy_profile_delete(*p_obj);
            *p_obj = NULL;
        }
        else
        {
            (*p_obj)->hdr.created_by_forward_reference = BCMOS_TRUE;
        }
    }
    return err;
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
    qos_policy_profile_policy_remove1(obj, NULL);
    NC_LOG_INFO("qos-policy-profile %s deleted\n", obj->hdr.name);
    xpon_object_delete(&obj->hdr);
}

/* check if qos classifier matches ingress rule */
static bcmos_bool qos_classifier_is_ingress_rule_match(const xpon_qos_classifier *qos_class, const bbf_subif_ingress_rule *rule)
{
    /* TODO: */
    return BCMOS_TRUE;
}

/* Find qos_policy index in qos_profile */
static int qos_policy_index_get(const xpon_qos_policy_profile *prof, const xpon_qos_policy *policy)
{
    int i;
    if (policy == NULL)
        return 0;
    for (i = 0; i < prof->num_policies; i++)
    {
        if (prof->policy[i] == policy)
            break;
    }
    return i;
}

/* Find qos_classifier index in qos_profile */
static int qos_class_index_get(const xpon_qos_policy *policy,  const xpon_qos_classifier *class)
{
    int i;
    if (policy == NULL)
        return 0;
    for (i = 0; i < policy->num_classifiers; i++)
    {
        if (policy->classifier[i] == class)
            break;
    }
    return i;
}

/* Iterate QoS classifiers. Find the next classifier matching the subif filter */
const xpon_qos_classifier *xpon_qos_classifier_get_next(const xpon_qos_policy_profile *prof,
    const bbf_subif_ingress_rule *rule, const xpon_qos_classifier *prev)
{
    const xpon_qos_classifier *qos_class;
    const xpon_qos_policy *policy = (prev != NULL) ? prev->policy : NULL;
    int start_policy_idx = qos_policy_index_get(prof, policy);
    int start_class_idx = qos_class_index_get(policy, prev);
    int i, j;

    /* Progress */
    if (prev != NULL)
        ++start_class_idx;

    for (i = start_policy_idx; i < prof->num_policies; i++)
    {
        policy = prof->policy[i];
        BUG_ON(policy == NULL);
        for (j = start_class_idx; j < policy->num_classifiers; j++)
        {
            qos_class = policy->classifier[j];
            BUG_ON(qos_class == NULL);
            if (qos_classifier_is_ingress_rule_match(qos_class, rule))
                return qos_class;
        }
        start_class_idx = 0;
    }
    return NULL;
}
