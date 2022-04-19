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
 * bbf-xpon-vlan_subif.c
 */
#include "bbf-xpon-internal.h"
#include <onu_mgmt.h>
#include <onu_mgmt_model_funcs.h>
#include <onu_mgmt_model_metadata.h>
#include <dhcp-relay-utils.h>

static xpon_obj_list vlan_subif_list;
static void subif_remove_from_lower_list(xpon_obj_hdr *lower_obj, xpon_vlan_subif *subif);
static void subif_add_to_lower_list(xpon_obj_hdr *lower_obj, xpon_vlan_subif *subif);

bcmos_errno xpon_vlan_subif_init(sr_session_ctx_t *srs)
{
    STAILQ_INIT(&vlan_subif_list);
    return BCM_ERR_OK;
}

bcmos_errno xpon_vlan_subif_start(sr_session_ctx_t *srs)
{
    return BCM_ERR_OK;
}

void xpon_vlan_subif_exit(sr_session_ctx_t *srs)
{

}

int xpon_vlan_subif_state_get_cb(sr_session_ctx_t *session, const char *xpath, struct lyd_node **parent)
{
    return 0;
}

static void _vlan_subif_init(xpon_vlan_subif *subif)
{
    STAILQ_INIT(&subif->ingress);
}

/* Find or add vlan-subif object */
bcmos_errno xpon_vlan_subif_get_by_name(const char *name, xpon_vlan_subif **p_vlan_subif, bcmos_bool *is_added)
{
    xpon_obj_hdr *obj = NULL;
    bcmos_errno err;

    err = xpon_object_get_or_add(name, XPON_OBJ_TYPE_VLAN_SUBIF,
        sizeof(xpon_vlan_subif), &obj, is_added);
    if (err != BCM_ERR_OK)
        return err;
    *p_vlan_subif = (xpon_vlan_subif *)obj;
    if (is_added != NULL && *is_added)
    {
        _vlan_subif_init(*p_vlan_subif);
        STAILQ_INSERT_TAIL(&vlan_subif_list, obj, next);
        NC_LOG_INFO("vlan_subif %s added\n", name);
    }
    return BCM_ERR_OK;
}

/* Remove vlan-subif object */
void xpon_vlan_subif_delete(xpon_vlan_subif *vlan_subif)
{
    bbf_subif_ingress_rule *ingress, *ingress_tmp;
    if (vlan_subif->forwarder_port != NULL)
        vlan_subif->forwarder_port->subif = NULL;
    STAILQ_REMOVE_SAFE(&vlan_subif_list, &vlan_subif->hdr, xpon_obj_hdr, next);
    if (vlan_subif->subif_lower_layer != NULL)
    {
        subif_remove_from_lower_list(vlan_subif->subif_lower_layer, vlan_subif);
    }
    STAILQ_FOREACH_SAFE(ingress, &vlan_subif->ingress, next, ingress_tmp)
    {
        xpon_vlan_subif_ingress_rule_delete(vlan_subif, ingress);
    }
    if (vlan_subif->subif_lower_layer && vlan_subif->subif_lower_layer->created_by_forward_reference)
        xpon_interface_delete(vlan_subif->subif_lower_layer);
    if (vlan_subif->qos_policy_profile != NULL && vlan_subif->qos_policy_profile->hdr.created_by_forward_reference)
        xpon_qos_policy_profile_delete(vlan_subif->qos_policy_profile);
    if (vlan_subif->dhcpr.profile != NULL && vlan_subif->dhcpr.profile->hdr.created_by_forward_reference)
        xpon_dhcpr_prof_delete(vlan_subif->dhcpr.profile);

    NC_LOG_INFO("vlan_subif %s deleted\n", vlan_subif->hdr.name);
    xpon_object_delete(&vlan_subif->hdr);
}

/*
 * ingress/egress rule haleprs
 */

/* find / add ingress rule */
bcmos_errno xpon_vlan_subif_ingress_rule_get(xpon_vlan_subif *subif, const char *name,
    bbf_subif_ingress_rule **p_rule, bcmos_bool *is_added)
{
    bbf_subif_ingress_rule *rule, *tmp;

    STAILQ_FOREACH_SAFE(rule, &subif->ingress, next, tmp)
    {
        if (!strcmp(rule->name, name))
            break;
    }
    *p_rule = rule;
    if (rule != NULL)
        return BCM_ERR_OK;

    /* Not found. can add new ? */
    if (is_added == NULL)
        return BCM_ERR_NOENT;

    /* add new */
    rule = bcmos_calloc(sizeof(*rule) + strlen(name) + 1);
    if (rule == NULL)
        return BCM_ERR_NOMEM;
    rule->name = (char *)(rule + 1);
    strcpy((char *)(long)rule->name, name);
    for(int i = 0; i < BCM_SIZEOFARRAY(rule->flows); i++)
    {
        rule->flows[i].flow_id = BCM_FLOW_ID_INVALID;
    }
    rule->group_id = BCM_GROUP_ID_INVALID;
    rule->base_gemport_id = -1;
    for(int i = 0; i < BCM_SIZEOFARRAY(rule->priority_to_tc); i++)
    {
        rule->priority_to_tc[i] = -1;
    }
    rule->ds_iwf_flow_id = -1;
    rule->pon_ni = -1;
#ifdef MFC_RELAY
    rule->mfc_acl_id = BCMOLT_ACCESS_CONTROL_ID_INVALID;
#endif

    STAILQ_INSERT_TAIL(&subif->ingress, rule, next);
    *is_added = BCMOS_TRUE;
    *p_rule = rule;
    NC_LOG_DBG("subif %s: added ingress rule %s\n", subif->hdr.name, name);

    return BCM_ERR_OK;
}

#ifdef MFC_RELAY

static bcmolt_access_control_id mfcr_access_control_id = 1;

/* Map flow classifier */
static bcmos_errno vlan_map_acl_classifier(bbf_subif_ingress_rule *rule, bcmolt_access_control_cfg *acl_cfg)
{
    bcmos_errno err = BCM_ERR_OK;
    bbf_match_criteria match = rule->match;

    if (match.vlan_tag_match.num_tags &&
        match.vlan_tag_match.tag_match_types[BBF_TAG_INDEX_TYPE_OUTER] != BBF_VLAN_TAG_MATCH_TYPE_ALL)
    {
        const bbf_dot1q_tag *tag;

        BCMOLT_MSG_FIELD_SET(acl_cfg, classifier.pkt_tag_type,
            (match.vlan_tag_match.tag_match_types[BBF_TAG_INDEX_TYPE_OUTER] == BBF_VLAN_TAG_MATCH_TYPE_UNTAGGED) ?
                BCMOLT_PKT_TAG_TYPE_UNTAGGED :
                    (match.vlan_tag_match.num_tags == 1) ?
                        BCMOLT_PKT_TAG_TYPE_SINGLE_TAG : BCMOLT_PKT_TAG_TYPE_DOUBLE_TAG);
        if (match.vlan_tag_match.num_tags)
        {
            tag = &match.vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_OUTER];
            if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, vlan_id))
                BCMOLT_MSG_FIELD_SET(acl_cfg, classifier.o_vid, tag->vlan_id);
            if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, pbit))
                BCMOLT_MSG_FIELD_SET(acl_cfg, classifier.o_pbits, tag->pbit);
        }
        if (match.vlan_tag_match.num_tags > 1)
        {
            tag = &match.vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_INNER];
            if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, vlan_id))
                BCMOLT_MSG_FIELD_SET(acl_cfg, classifier.i_vid, tag->vlan_id);
            if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, pbit))
                BCMOLT_MSG_FIELD_SET(acl_cfg, classifier.i_pbits, tag->pbit);
        }
    }
    if (match.protocol_match.match_type != BBF_PROTOCOL_MATCH_ANY)
    {
        BCMOLT_MSG_FIELD_SET(acl_cfg, classifier.ether_type,
            xpon_map_protocol_match_to_ether_type(&match.protocol_match));
    }
    if (match.dest_ip.ipv4.u32)
    {
        BCMOLT_MSG_FIELD_SET(acl_cfg, classifier.dst_ip, match.dest_ip.ipv4);
    }

    return err;
}

/* Delete ACL rule for MFC Relay */
static void vlan_subif_mfc_acl_delete(bcmolt_access_control_id acl_id)
{
    bcmolt_access_control_key acl_key = {.id = acl_id};
    bcmolt_access_control_cfg acl_cfg;
    BCMOLT_CFG_INIT(&acl_cfg, access_control, acl_key);
    bcmolt_cfg_clear(netconf_agent_olt_id(), &acl_cfg.hdr);
}

/* Create ACL rule for MFC Relay */
static bcmos_errno vlan_subif_mfc_acl_create(sr_session_ctx_t *srs, xpon_vlan_subif *subif, bbf_subif_ingress_rule *rule)
{
    bcmolt_access_control_key acl_key = {.id = mfcr_access_control_id++};
    bcmolt_access_control_cfg acl_cfg;
    bcmos_errno err;

    do
    {
        BCMOLT_CFG_INIT(&acl_cfg, access_control, acl_key);
        err = vlan_map_acl_classifier(rule, &acl_cfg);
        if (err != BCM_ERR_OK)
            break;

        BCMOLT_MSG_FIELD_SET(&acl_cfg, forwarding_action.action, BCMOLT_ACCESS_CONTROL_FWD_ACTION_TYPE_TRAP_TO_HOST);
        BCMOLT_MSG_FIELD_SET(&acl_cfg, statistics_control, BCMOLT_CONTROL_STATE_ENABLE);
        BCMOLT_MSG_FIELD_SET(&acl_cfg, cookie, (long)subif->hdr.name);
        err = bcmolt_cfg_set(netconf_agent_olt_id(), &acl_cfg.hdr);
        if (err != BCM_ERR_OK)
        {
            NC_ERROR_REPLY(srs, NULL, "%s: Failed to create access_control object. Error %s\n",
                subif->hdr.name, bcmos_strerror(err));
            break;
        }
    } while (0);

    return err;
}

#endif /* #ifdef MFC_RELAY */

/* delete ingress rule */
void xpon_vlan_subif_ingress_rule_delete(xpon_vlan_subif *subif, bbf_subif_ingress_rule *rule)
{
    STAILQ_REMOVE_SAFE(&subif->ingress, rule, bbf_subif_ingress_rule, next);
    if (rule->dhcpr_iface != NULL)
        dhcp_relay_interface_delete(rule->dhcpr_iface);
#ifdef MFC_RELAY
    if (rule->mfc_acl_id != BCMOLT_ACCESS_CONTROL_ID_INVALID)
    {
        vlan_subif_mfc_acl_delete(rule->mfc_acl_id);
    }
    if (rule->mfc_endpoint != NULL)
        bcmos_free((void *)(long)rule->mfc_endpoint);
#endif
    bcmos_free(rule);
}

static void vlan_subif_ingress_rule_copy(xpon_vlan_subif *from, xpon_vlan_subif *to)
{
    bbf_subif_ingress_rule *rule, *rule_tmp;
    STAILQ_FOREACH_SAFE(rule, &from->ingress, next, rule_tmp)
    {
        STAILQ_REMOVE_SAFE(&from->ingress, rule, bbf_subif_ingress_rule, next);
        STAILQ_INSERT_TAIL(&to->ingress, rule, next);
    }
    XPON_PROP_SET_PRESENT(to, vlan_subif, ingress);
}

/* add subif to list on its lower interface */
static void subif_add_to_lower_list(xpon_obj_hdr *lower_obj, xpon_vlan_subif *subif)
{
    if (lower_obj->obj_type == XPON_OBJ_TYPE_ENET)
    {
        xpon_enet *lower = (xpon_enet *)lower_obj;
        STAILQ_INSERT_TAIL(&lower->subifs, subif, next);
    }
    else if (lower_obj->obj_type == XPON_OBJ_TYPE_V_ANI_V_ENET)
    {
        xpon_v_ani_v_enet *lower = (xpon_v_ani_v_enet *)lower_obj;
        STAILQ_INSERT_TAIL(&lower->subifs, subif, next);
    }
    else if (lower_obj->obj_type == XPON_OBJ_TYPE_ANI_V_ENET)
    {
        xpon_ani_v_enet *lower = (xpon_ani_v_enet *)lower_obj;
        STAILQ_INSERT_TAIL(&lower->subifs, subif, next);
    }
}

/* remove subif from list on its lower interface */
static void subif_remove_from_lower_list(xpon_obj_hdr *lower_obj, xpon_vlan_subif *subif)
{
    if (lower_obj->obj_type == XPON_OBJ_TYPE_ENET)
    {
        xpon_enet *lower = (xpon_enet *)lower_obj;
        STAILQ_REMOVE_SAFE(&lower->subifs, subif, xpon_vlan_subif, next);
    }
    else if (lower_obj->obj_type == XPON_OBJ_TYPE_V_ANI_V_ENET)
    {
        xpon_v_ani_v_enet *lower = (xpon_v_ani_v_enet *)lower_obj;
        STAILQ_REMOVE_SAFE(&lower->subifs, subif, xpon_vlan_subif, next);
    }
    else if (lower_obj->obj_type == XPON_OBJ_TYPE_ANI_V_ENET)
    {
        xpon_ani_v_enet *lower = (xpon_ani_v_enet *)lower_obj;
        STAILQ_REMOVE_SAFE(&lower->subifs, subif, xpon_vlan_subif, next);
    }
}

/* Apply transaction */
static bcmos_errno xpon_vlan_subif_apply(sr_session_ctx_t *srs, xpon_vlan_subif *info, xpon_vlan_subif *changes)
{
    xpon_obj_hdr *old_subif_lower_layer = info->subif_lower_layer;
    bcmos_errno err = BCM_ERR_OK;

    if (changes->hdr.being_deleted)
    {
        xpon_apply_flow_delete(srs, info, NULL);
        xpon_vlan_subif_delete(info);
        return BCM_ERR_OK;
    }

    /* Since we don't support changes in "active" subif, copy properties now
       to simplify propagation to ONU management */
    XPON_PROP_COPY(changes, info, vlan_subif, egress_rewrite);
    XPON_PROP_COPY(changes, info, vlan_subif, subif_lower_layer);
    changes->subif_lower_layer = NULL;
    XPON_PROP_COPY(changes, info, vlan_subif, qos_policy_profile);
    changes->qos_policy_profile = NULL;
    XPON_PROP_COPY(changes, info, vlan_subif, usage);
    if (XPON_PROP_IS_SET(changes, vlan_subif, ingress))
        vlan_subif_ingress_rule_copy(changes, info);
    if (!info->is_olt_subif)
        info->is_olt_subif = changes->is_olt_subif;
    if (old_subif_lower_layer != NULL && info->subif_lower_layer != old_subif_lower_layer)
    {
        subif_remove_from_lower_list(old_subif_lower_layer, info);
    }
    if (info->subif_lower_layer != NULL && info->subif_lower_layer != old_subif_lower_layer)
    {
        subif_add_to_lower_list(info->subif_lower_layer, info);
    }
    XPON_PROP_COPY(changes, info, vlan_subif, dhcpr);
    changes->dhcpr.profile = NULL;

    /* Try to create ONU flows */
    if (!info->is_olt_subif && info->subif_lower_layer != NULL && !bcm_tr451_onu_management_is_enabled())
    {
        /* Create ONU flows. Ignore BCM_ERR_STATE. It just means that part of the provisioning isn't ready */
        xpon_obj_hdr *uni = info->subif_lower_layer;
        xpon_v_ani_v_enet *v_ani_v_enet = NULL;
        if (uni->obj_type == XPON_OBJ_TYPE_ANI_V_ENET)
            v_ani_v_enet = (xpon_v_ani_v_enet *)((xpon_ani_v_enet *)uni)->linked_if;
        else if (uni->obj_type == XPON_OBJ_TYPE_ENET)
            v_ani_v_enet = (xpon_v_ani_v_enet *)((xpon_enet *)uni)->linked_if;
        if (v_ani_v_enet != NULL)
            err = xpon_create_onu_flows_on_subif(srs, info->subif_lower_layer, info);
    }

#ifdef MFC_RELAY
    if (err == BCM_ERR_OK)
    {
        bbf_subif_ingress_rule *rule, *rule_tmp;
        STAILQ_FOREACH_SAFE(rule, &info->ingress, next, rule_tmp)
        {
            if (rule->mfc_action != BBF_MFC_ACTION_NONE && rule->mfc_endpoint != NULL)
            {
                err = vlan_subif_mfc_acl_create(srs, info, rule);
                if (err != BCM_ERR_OK)
                    break;
            }
        }
    }
#endif

    return err;
}

/* parse flexible-rewrite transaction */
static bcmos_errno _xpon_vlan_rewrite(sr_session_ctx_t *srs, bbf_flexible_rewrite *rewrite,
    sr_val_t *val, const char *rewrite_xpath)
{
    bcmos_errno err = BCM_ERR_OK;
    char leafbuf[BCM_MAX_LEAF_LENGTH];
    const char *leaf;

    leaf = nc_xpath_leaf_get(rewrite_xpath, leafbuf, sizeof(leafbuf));
    if (strstr(leaf, "pop-tags") != NULL)
        rewrite->num_pop_tags = val->data.uint8_val;
    else if (strstr(rewrite_xpath, "push-tag") != NULL)
    {
        char index_str[16] = "";
        bbf_tag_index_type tag_index = 0;
        bbf_dot1q_tag *tag;

        nc_xpath_key_get(rewrite_xpath, "index", index_str, sizeof(index_str));
        /* Only indexes 0 and 1 are supported */
        if (!strcmp(index_str, "0"))
            tag_index = BBF_TAG_INDEX_TYPE_OUTER;
        else if (!strcmp(index_str, "1"))
            tag_index = BBF_TAG_INDEX_TYPE_INNER;
        else
        {
            NC_ERROR_REPLY(srs, val->xpath, "tag index %s is invalid\n", index_str);
            err = BCM_ERR_PARM;
        }
        tag = &rewrite->push_tags[tag_index];
        if (rewrite->num_push_tags < tag_index + 1)
            rewrite->num_push_tags = tag_index + 1;
        if (!strcmp(leaf, "vlan-id"))
        {
            if (val->type == SR_UINT16_T)
            {
                BBF_DOT1Q_TAG_PROP_SET(tag, vlan_id, val->data.uint16_val);
            }
            else
            {
                NC_ERROR_REPLY(srs, val->xpath, "tag value is not supported\n");
                err = BCM_ERR_NOT_SUPPORTED;
            }
        }
        else if (strstr(leaf, "tag-type") != NULL)
        {
            uint16_t tag_type = 0x8100;
            if (val->type == SR_IDENTITYREF_T)
            {
                if (strstr(val->data.identityref_val, "c-vlan") != NULL)
                    tag_type = 0x8100;
                else if (strstr(val->data.identityref_val, "s-vlan") != NULL)
                    tag_type = 0x88a8;
            } else if (val->type == SR_UINT16_T)
            {
                tag_type = val->data.uint16_val;
            }
            BBF_DOT1Q_TAG_PROP_SET(tag, tag_type, tag_type);
        }
        else if (!strcmp(leaf, "write-pbit-0"))
        {
            BBF_DOT1Q_TAG_PROP_SET(tag, pbit, 0);
        }
        else if (!strcmp(leaf, "write-pbit"))
        {
            BBF_DOT1Q_TAG_PROP_SET(tag, pbit, val->data.uint8_val);
        }
        else if (!strcmp(leaf, "write-dei-0"))
        {
            BBF_DOT1Q_TAG_PROP_SET(tag, dei, 0);
        }
        else if (!strcmp(leaf, "write-dei-1"))
        {
            BBF_DOT1Q_TAG_PROP_SET(tag, dei, 1);
        }
    }
    return err;
}

bcmos_errno xpon_vlan_subif_transaction(sr_session_ctx_t *srs, nc_transact *tr)
{
    xpon_vlan_subif *vlan_subif = NULL;
    xpon_vlan_subif changes = {};
    char keyname[32]={};
    nc_transact_elem *elem;
    bcmos_errno err = BCM_ERR_OK;
    const char *iter_xpath;
    bcmos_bool was_added = BCMOS_FALSE;

    /* See if there is an existing vlan_subif object */
    elem = STAILQ_FIRST(&tr->elems);
    if (elem == NULL)
        return BCM_ERR_OK;
    iter_xpath = elem->old_val ? elem->old_val->xpath : elem->new_val->xpath;
    nc_xpath_key_get(iter_xpath, "name", keyname, sizeof(keyname));
    NC_LOG_DBG("Handling vlan_subif %s transaction\n", keyname);
    err = xpon_vlan_subif_get_by_name(keyname, &vlan_subif, &was_added);
    if (err != BCM_ERR_OK)
        return err;

    _vlan_subif_init(&changes);
    changes.hdr.name = vlan_subif->hdr.name;

    /* Go over transaction elements and map to BAL */
    STAILQ_FOREACH(elem, &tr->elems, next)
    {
        const char *rule_xpath;
        const char *rewrite_xpath;
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

        /* Sub-interface contains lists which are also idxentified by "name".
           Therefore, xpath must be checked first, before checking the leaf */
        if ((rule_xpath = strstr(iter_xpath, "inline-frame-processing/ingress-rule/rule")) != NULL)
        {
            char rule_name[32] = "";
            bbf_subif_ingress_rule *ingress_rule = NULL;
            bcmos_bool rule_added;

            nc_xpath_key_get(rule_xpath, "name", rule_name, sizeof(rule_name));

            /* Find/get ingress rule by name */
            xpon_vlan_subif_ingress_rule_get(&changes, rule_name, &ingress_rule, &rule_added);
            if (ingress_rule == NULL)
                break;
            if (!strcmp(leaf, "name"))
                ingress_rule->being_deleted  = (elem->new_val == NULL);
            else if (!strcmp(leaf, "priority"))
                ingress_rule->priority = val->data.uint16_val;
            else if (strstr(rule_xpath, "flexible-match") != NULL)
            {
                const char *flex_match;

                /* Handle flexible match */
                if ((flex_match=strstr(rule_xpath, "match-criteria")))
                {
                    err = xpon_add_flexible_match(srs, &ingress_rule->match, flex_match,
                        elem->old_val, elem->new_val);
                    if (err != BCM_ERR_OK)
                        break;
                }
            }
            else if ((rewrite_xpath = strstr(rule_xpath, "ingress-rewrite")) != NULL)
            {
                err = _xpon_vlan_rewrite(srs, &ingress_rule->rewrite, val, rewrite_xpath);
                if (err != BCM_ERR_OK)
                    break;
            }
#ifdef MFC_RELAY
            else if (strstr(rule_xpath, "control-relay") != NULL)
            {
                if (!strcmp(leaf, "action"))
                {
                    const char *action = val->data.string_val;
                    if (action)
                    {
                        if (strstr(action, "redirect") != NULL)
                            ingress_rule->mfc_action = BBF_MFC_ACTION_REDIRECT;
                        else if (strstr(action, "copy") != NULL)
                        {
                            ingress_rule->mfc_action = BBF_MFC_ACTION_COPY;
                            NC_ERROR_REPLY(srs, rule_xpath, "control-relay COPY action is not supported\n");
                            err = BCM_ERR_NOT_SUPPORTED;
                            break;
                        }
                        else
                        {
                            NC_ERROR_REPLY(srs, rule_xpath, "control-relay action is invalid\n");
                            err = BCM_ERR_PARM;
                            break;
                        }
                    }
                }
                else if (!strcmp(leaf, "resulting-endpoint"))
                {
                    ingress_rule->mfc_endpoint = bcmos_strdup(val->data.string_val);
                }
            }
#endif
            /* Got rule */
            XPON_PROP_SET_PRESENT(&changes, vlan_subif, ingress);
        }
        else if ((rewrite_xpath = strstr(iter_xpath, "inline-frame-processing/egress-rewrite")) != NULL)
        {
            err = _xpon_vlan_rewrite(srs, &changes.egress_rewrite, val, rewrite_xpath);
            if (err != BCM_ERR_OK)
                break;
            XPON_PROP_SET_PRESENT(&changes, vlan_subif, egress_rewrite);
        }
        else if (!strcmp(leaf, "name"))
        {
            changes.hdr.being_deleted = (elem->new_val == NULL);
        }
        else if (strstr(iter_xpath, "subif-lower-layer/interface"))
        {
            xpon_obj_hdr *hdr = NULL;
            if (elem->new_val != NULL)
            {
                const char *if_name = elem->new_val->data.string_val;

                err = xpon_interface_get_populate(srs, if_name, XPON_OBJ_TYPE_ANY, &hdr);
                if (err != BCM_ERR_OK)
                {
                    NC_ERROR_REPLY(srs, iter_xpath, "vlan-subif %s references subif-lower-layer interface %s which doesn't exist\n",
                        keyname, if_name);
                    break;
                }
                XPON_PROP_SET(&changes, vlan_subif, subif_lower_layer, hdr);
                /* We only support vlan-subif s on enet anf v-ani-v-enet interfaces */
                if (hdr->obj_type != XPON_OBJ_TYPE_V_ANI_V_ENET &&
                    hdr->obj_type != XPON_OBJ_TYPE_ENET)
                {
                    NC_ERROR_REPLY(srs, iter_xpath, "vlan-subif %s references subif-lower-layer interface %s of unexpected type\n",
                        keyname, if_name);
                    break;
                }
                if (hdr->obj_type == XPON_OBJ_TYPE_V_ANI_V_ENET)
                {
                    changes.is_olt_subif = BCMOS_TRUE;
                }
                else if (hdr->obj_type == XPON_OBJ_TYPE_ENET)
                {
                    xpon_enet *enet = (xpon_enet *)hdr;
                    if (enet->usage == BBF_INTERFACE_USAGE_NETWORK_PORT)
                    {
                        changes.is_olt_subif = BCMOS_TRUE;
                        XPON_PROP_SET(&changes, vlan_subif, usage, BBF_INTERFACE_USAGE_NETWORK_PORT);
                    }
                }
            }
        }
        else if (!strcmp(leaf, "interface-usage"))
        {
            XPON_PROP_SET(&changes, vlan_subif, usage,
                xpon_map_iface_usage(elem->new_val ? elem->new_val->data.identityref_val : NULL));
            if (changes.usage == BBF_INTERFACE_USAGE_NETWORK_PORT)
                changes.is_olt_subif = BCMOS_TRUE;
        }
        else if (strstr(leaf, "ingress-qos-policy-profile") != NULL)
        {
            xpon_qos_policy_profile *prof = NULL;
            if (elem->new_val != NULL && val->data.string_val != NULL)
            {
                err = xpon_qos_policy_profile_get_populate(srs, val->data.string_val, &prof);
                if (err != BCM_ERR_OK)
                    break;
            }
            XPON_PROP_SET(&changes, vlan_subif, qos_policy_profile, prof);
        }
        else if (strstr(iter_xpath, "l2-dhcpv4-relay") != NULL)
        {
            XPON_PROP_SET_PRESENT(&changes, vlan_subif, dhcpr);
            if (!strcmp(leaf, "enable"))
                changes.dhcpr.enabled = (elem->new_val != NULL && elem->new_val->data.bool_val);
            else if (!strcmp(leaf, "trusted-port"))
                changes.dhcpr.trusted = (elem->new_val != NULL && elem->new_val->data.bool_val);
            else if (!strcmp(leaf, "profile-ref"))
            {
                xpon_dhcpr_profile *prof = NULL;
                if (elem->new_val != NULL && val->data.string_val != NULL)
                {
                    err = xpon_dhcpr_prof_get_populate(srs, val->data.string_val, &prof);
                    if (err != BCM_ERR_OK)
                    {
                        NC_ERROR_REPLY(srs, iter_xpath, "subif %s references l2-dhcpv4-relay profile %s which doesn't exist\n",
                            keyname, val->data.string_val);
                        err = BCM_ERR_PARM;
                        break;
                    }
                }
                changes.dhcpr.profile = prof;
            }
        }
    }

    if (err == BCM_ERR_OK)
    {
        err = xpon_vlan_subif_apply(srs, vlan_subif, &changes);
    }

    if (err != BCM_ERR_OK && (was_added || changes.hdr.being_deleted))
        xpon_vlan_subif_delete(vlan_subif);

    /* Clear forward references if any */
    if (changes.subif_lower_layer != NULL && changes.subif_lower_layer->created_by_forward_reference)
        xpon_interface_delete(changes.subif_lower_layer);
    if (changes.qos_policy_profile != NULL && changes.qos_policy_profile->hdr.created_by_forward_reference)
        xpon_qos_policy_profile_delete(changes.qos_policy_profile);
    if (changes.dhcpr.profile != NULL && changes.dhcpr.profile->hdr.created_by_forward_reference)
        xpon_dhcpr_prof_delete(changes.dhcpr.profile);
    if (!STAILQ_EMPTY(&changes.ingress))
    {
        bbf_subif_ingress_rule *rule, *rule_tmp;
        STAILQ_FOREACH_SAFE(rule, &changes.ingress, next, rule_tmp)
        {
            xpon_vlan_subif_ingress_rule_delete(&changes, rule);
        }
    }

    if (changes.hdr.being_deleted)
        err = BCM_ERR_OK;

    NC_LOG_DBG("vlan_subif transaction completed: %s\n", bcmos_strerror(err));

    return err;
}

/* Find matching rule such that
   (from_rule & from_ingress_action) & from_egress_action MATCHES
    (to_rule & to_ingress_action) & to_egress_action
 */
bbf_subif_ingress_rule *xpon_vlan_subif_ingress_rule_get_match(const bbf_subif_ingress_rule *from_rule,
    xpon_vlan_subif *to_subif)
{
    bbf_subif_ingress_rule *to_rule, *to_rule_tmp;

    /* We need to go over to_subif's rules and find those with egress matching
       egress of from_rule
    */
    bbf_match_criteria from_match_plus_actions = from_rule->match;
    /* calculate egress packet match */
    xpon_apply_actions_to_match(&from_match_plus_actions, &from_rule->rewrite);
    xpon_apply_actions_to_match(&from_match_plus_actions, &to_subif->egress_rewrite);

    /* No go over ONU sub-interfaces */
    STAILQ_FOREACH_SAFE(to_rule, &to_subif->ingress, next, to_rule_tmp)
    {
        /* check match */
        if (xpon_is_match(&from_match_plus_actions, &to_rule->match))
        {
            break;
        }
    }

    return to_rule;
}

/* Go over subifs on an interface and find the next subif and rule matching
    "from_subif" and "from_rule" */
bcmos_errno xpon_vlan_subif_subif_rule_get_next_match(const bbf_subif_ingress_rule *from_rule,
    xpon_obj_hdr *to_if, xpon_vlan_subif **p_to_subif, bbf_subif_ingress_rule **p_to_rule)
{
    xpon_subif_list *to_subifs;
    xpon_vlan_subif *to_subif = *p_to_subif;
    bbf_subif_ingress_rule *to_rule = *p_to_rule;

    if (to_if->obj_type == XPON_OBJ_TYPE_ANI_V_ENET)
        to_subifs = &(((xpon_ani_v_enet *)to_if)->subifs);
    else if (to_if->obj_type == XPON_OBJ_TYPE_ENET)
        to_subifs = &(((xpon_enet *)to_if)->subifs);
    else
    {
        NC_LOG_ERR("Unexpected object %s\n", to_if->name);
        return BCM_ERR_PARM;
    }

    /* No go over the 'to' sub-interfaces */
    if (to_subif == NULL)
    {
        to_subif = STAILQ_FIRST(to_subifs);
        to_rule = NULL;
    }
    while (to_subif != NULL)
    {
        if (to_rule == NULL)
        {
            to_rule = STAILQ_FIRST(&to_subif->ingress);
        }
        else
        {
            to_rule = STAILQ_NEXT(to_rule, next);
        }
        while (to_rule != NULL)
        {
            bbf_match_criteria to_match_plus_actions = to_rule->match;
            xpon_apply_actions_to_match(&to_match_plus_actions, &to_rule->rewrite);

            /* check match */
            if (xpon_is_match(&to_match_plus_actions, &from_rule->match))
            {
                break;
            }
            to_rule = STAILQ_NEXT(to_rule, next);
        }
        if (to_rule != NULL)
            break;
        to_subif = STAILQ_NEXT(to_subif, next);
        to_rule = NULL;
    }
    *p_to_subif = to_subif;
    *p_to_rule = to_rule;

    if (to_subif == NULL || to_rule == NULL)
        return BCM_ERR_NOENT;

    return BCM_ERR_OK;
}

#ifdef MFC_RELAY
bcmos_errno bbf_xpon_get_vsi_and_rule_by_acl_id(bcmolt_access_control_id acl_id,
    const char **p_vsi_name, const char **p_rule_name, const char **p_endpoint_name)
{
    /* Fetch access_control object cookie. It contains a pointer to vsi name */
    bcmolt_access_control_key acl_key = { .id = acl_id };
    bcmolt_access_control_cfg acl;
    const char *vsi_name;
    xpon_vlan_subif *vsi;
    bbf_subif_ingress_rule *rule, *rule_tmp;
    bcmos_errno err;

    BCMOLT_CFG_INIT(&acl, access_control, acl_key);
    BCMOLT_MSG_FIELD_GET(&acl, cookie);
    err = bcmolt_cfg_get(netconf_agent_olt_id(), &acl.hdr);
    if (err != BCM_ERR_OK)
        return err;
    if (!acl.data.cookie)
        return BCM_ERR_NOENT;
    vsi_name = (const char *)(long)acl.data.cookie;

    err = xpon_vlan_subif_get_by_name(vsi_name, &vsi, NULL);
    if (err != BCM_ERR_OK)
        return err;

    /* Go over all rules and find the rule with specified acl_id */
    STAILQ_FOREACH_SAFE(rule, &vsi->ingress, next, rule_tmp)
    {
        if (rule->mfc_acl_id == acl_id)
            break;
    }
    if (rule == NULL)
        return BCM_ERR_NOENT;
    *p_vsi_name = vsi_name;
    *p_rule_name = rule->name;
    *p_endpoint_name = rule->mfc_endpoint;

    return err;
}

bcmos_errno bbf_xpon_get_intf_by_vsi_rule_prty(
    const char *vsi_name, const char *rule_name, uint8_t prty,
    bcmolt_flow_key *flow_key, bcmolt_flow_intf_ref *intf_ref,
    bcmolt_service_port_id *svc_port_id)
{
    xpon_vlan_subif *vsi;
    bbf_subif_ingress_rule *rule, *rule_tmp;
    xpon_obj_hdr *lower;
    const xpon_gem *gem = NULL;
    bcmos_errno err;
    int tc;

    if (vsi_name == NULL || rule_name == NULL)
        return BCM_ERR_PARM;

    /* Find vsi and ingress rule */
    err = xpon_vlan_subif_get_by_name(vsi_name, &vsi, NULL);
    if (err != BCM_ERR_OK)
        return err;

    STAILQ_FOREACH_SAFE(rule, &vsi->ingress, next, rule_tmp)
    {
        if (!strcmp(rule->name, rule_name))
            break;
    }
    if (rule == NULL)
        return BCM_ERR_NOENT;

    tc = (rule->priority_to_tc[prty] > 0) ? rule->priority_to_tc[prty] : 0;
    if (rule->flows[tc].flow_id != BCM_FLOW_ID_INVALID)
    {
        flow_key->flow_id = rule->flows[tc].flow_id;
        /* Prelimenary flow_type setting */
        if ((rule->flows[tc].flow_dir & XPON_FLOW_DIR_MULTICAST) != 0)
            flow_key->flow_type = BCMOLT_FLOW_TYPE_MULTICAST;
        gem = rule->flows[tc].gem;
    }

    /* Find physical interface under the VSI */
    lower = vsi->subif_lower_layer;
    while (lower != NULL && lower->obj_type == XPON_OBJ_TYPE_VLAN_SUBIF)
        lower = ((xpon_vlan_subif *)lower)->subif_lower_layer;
    if (lower == NULL)
        return BCM_ERR_INTERNAL;
    switch(lower->obj_type)
    {
        case XPON_OBJ_TYPE_ENET:
            {
                xpon_enet *enet = (xpon_enet *)lower;
                intf_ref->intf_id = enet->intf_id;
                intf_ref->intf_type = BCMOLT_INTERFACE_TYPE_NNI;
                if (flow_key->flow_type != BCMOLT_FLOW_TYPE_MULTICAST)
                    flow_key->flow_type = BCMOLT_FLOW_TYPE_DOWNSTREAM;
                *svc_port_id = 0;
                break;
            }

        case XPON_OBJ_TYPE_V_ANI_V_ENET:
            {
                xpon_v_ani_v_enet *v_enet = (xpon_v_ani_v_enet *)lower;
                if (v_enet->v_ani == NULL)
                {
                    err = BCM_ERR_INTERNAL;
                    break;
                }
                intf_ref->intf_id = v_enet->v_ani->pon_ni;
                intf_ref->intf_type = BCMOLT_INTERFACE_TYPE_PON;
                if (gem == NULL)
                {
                    gem = STAILQ_FIRST(&v_enet->v_ani->gems);
                    if (gem == NULL)
                    {
                        NC_LOG_ERR("No GEM ports provisioned on v-ani %s. Can't inhect at ingress for VSI %s, rule %s\n",
                            v_enet->v_ani->hdr.name, vsi_name, rule_name);
                        err = BCM_ERR_PARM;
                        break;
                    }
                }
                *svc_port_id = gem->gemport_id;
                flow_key->flow_type = BCMOLT_FLOW_TYPE_UPSTREAM;
                break;
            }

        default:
            NC_LOG_ERR("Unexpected lower interface '%s' of VSI '%s'\n", lower->name, vsi->hdr.name);
            err = BCM_ERR_INTERNAL;
            break;
    }

    return err;
}
#endif
