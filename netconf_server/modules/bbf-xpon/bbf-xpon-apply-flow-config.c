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
 * bbf-xpon-apply-flow-config.c
 */
#include "bbf-xpon-internal.h"
#include <onu_mgmt.h>
#include <onu_mgmt_model_ids.h>
#include <onu_mgmt_model_funcs.h>
#include <onu_mgmt_model_metadata.h>
#include <dhcp-relay-utils.h>

/* TODO: TEMPORARY: */
static uint16_t global_flow_id;
static uint16_t global_onu_flow_id;
static uint16_t global_group_id = 1;

/* Uncomment the following define to create downstream ONU flows.
   As of now it is not required because ONU management stack does it automatically,
   symmetrically with the upstrteam flow */
/* #define CREATE_DOWNSTREAM_ONU_FLOWS */

static bcmos_errno xpon_find_rule_gem(
    sr_session_ctx_t *srs,
    xpon_vlan_subif *acc_if, bbf_subif_ingress_rule *rule,
    const xpon_v_ani_v_enet *v_ani_v_enet,
    bcmos_bool stop_on_error);

/*
 * ONU management handlers
 */
static bcmos_errno delete_onu_flow(bcmolt_flow_id flow_id, bcmonu_mgmt_flow_dir_id dir)
{
    bcmos_errno err = BCM_ERR_OK;
    if (!bcm_tr451_onu_management_is_enabled())
    {
        bcmonu_mgmt_flow_cfg cfg; /* declare main API struct */
        bcmonu_mgmt_flow_key key = { .id = flow_id, .dir = dir };
        BCMONU_MGMT_CFG_INIT(&cfg, flow, key);
        err = bcmonu_mgmt_cfg_clear(netconf_agent_olt_id(), &cfg.hdr);
    }
    return err;
}

/*
 * BAL helpers
 */

static bcmos_errno delete_bal_flow(bcmolt_flow_id flow_id, bcmolt_flow_type flow_type)
{
    bcmolt_flow_key key = { .flow_id = flow_id, .flow_type = flow_type };
    bcmolt_flow_cfg cfg;
    bcmos_errno err;

    BCMOLT_CFG_INIT(&cfg, flow, key);
    err = bcmolt_cfg_clear(netconf_agent_olt_id(), &cfg.hdr);
    NC_LOG_DBG("Deleted %s BAL flow %u. Result '%s'\n",
        (flow_type == BCMOLT_FLOW_TYPE_DOWNSTREAM) ? "DS" : "US", flow_id, bcmos_strerror(err));
    return err;
}

static bcmos_errno delete_bal_group(bcmolt_group_id group_id)
{
    bcmolt_group_key key = { .id = group_id };
    bcmolt_group_cfg cfg;

    BCMOLT_CFG_INIT(&cfg, group, key);
    return bcmolt_cfg_clear(netconf_agent_olt_id(), &cfg.hdr);
}

/* Apply delete */
bcmos_errno xpon_apply_flow_delete(sr_session_ctx_t *srs, xpon_vlan_subif *subif, xpon_forwarder *forwarder)
{
    bbf_subif_ingress_rule *rule, *rule_tmp;
    STAILQ_FOREACH_SAFE(rule, &subif->ingress, next, rule_tmp)
    {
        for(int i = 0; i < BCM_SIZEOFARRAY(rule->flows); i++)
        {
            if (rule->flows[i].flow_id != BCM_FLOW_ID_INVALID)
            {
                if ((rule->flows[i].flow_dir & XPON_FLOW_DIR_UPSTREAM) != 0)
                {
                    /* Delete BAL/ONU flow */
                    if (subif->is_olt_subif)
                        delete_bal_flow(rule->flows[i].flow_id, BCMOLT_FLOW_TYPE_UPSTREAM);
                    else
                        delete_onu_flow(rule->flows[i].flow_id, BCMONU_MGMT_FLOW_DIR_ID_UPSTREAM);
                }
                if ((rule->flows[i].flow_dir & XPON_FLOW_DIR_DOWNSTREAM) != 0)
                {
                    /* Delete BAL/ONU flow */
                    if (subif->is_olt_subif)
                        delete_bal_flow(rule->flows[i].flow_id, BCMOLT_FLOW_TYPE_DOWNSTREAM);
#ifdef CREATE_DOWNSTREAM_ONU_FLOWS
                    else
                        delete_onu_flow(rule->flows[i].flow_id, BCMONU_MGMT_FLOW_DIR_ID_DOWNSTREAM);
#endif
                }
                if ((rule->flows[i].flow_dir & XPON_FLOW_DIR_MULTICAST) != 0)
                {
                    /* Delete BAL flow */
                    if (subif->is_olt_subif)
                        delete_bal_flow(rule->flows[i].flow_id, BCMOLT_FLOW_TYPE_MULTICAST);
                }
                rule->flows[i].flow_id = BCM_FLOW_ID_INVALID;
                rule->flows[i].flow_dir = 0;
                rule->flows[i].gem = NULL;
                rule->flows[i].qos_class = NULL;
            }
            if (subif->usage == BBF_INTERFACE_USAGE_NETWORK_PORT && rule->group_id != BCM_GROUP_ID_INVALID)
            {
                delete_bal_group(rule->group_id);
                rule->group_id = BCM_GROUP_ID_INVALID;
            }
        }

#ifndef BCM_OPEN_SOURCE
        if (bcmolt_is_per_flow_mode())
        {
            if (rule->ds_rule)
            {
                xpon_iwf_delete_ds_flows(srs, rule);
            }
            else
            {
                xpon_iwf_delete_us_flows(srs, rule);
            }
        }
#endif
    }

    if (forwarder != NULL)
    {
        /* group forwarder or 1-1 ? */
        if (forwarder->mac_learning_db != NULL)
        {
            /* ToDo: remove group */
            subif->forwarder_port = NULL;
        }
        else
        {
            xpon_forwarder_port *port, *tmp;
            STAILQ_FOREACH_SAFE(port, &forwarder->ports, next, tmp)
            {
                if (port->subif != subif && port->subif != NULL)
                    xpon_apply_flow_delete(srs, port->subif, NULL);
            }
        }
    }
    return BCM_ERR_OK;
}


/* Map protocol match type to ether type */
static uint16_t xpon_map_protocol_match_to_ether_type(const bbf_protocol_match *protocol_match)
{
    uint16_t eth_type = 0;
    switch(protocol_match->match_type)
    {
        case BBF_PROTOCOL_MATCH_PPPOE_DISCOVERY:
            eth_type = ETHER_TYPE_PPPOE_DISCOVERY;
            break;
        case BBF_PROTOCOL_MATCH_PPPOE_DATA:
            eth_type = ETHER_TYPE_PPPOE_DATA;
            break;
        case BBF_PROTOCOL_MATCH_ARP:
            eth_type = ETHER_TYPE_ARP;
            break;
        case BBF_PROTOCOL_MATCH_DOT1X:
            eth_type = ETHER_TYPE_DOT1X;
            break;
        case BBF_PROTOCOL_MATCH_LACP:
            eth_type = ETHER_TYPE_LACP;
            break;
        case BBF_PROTOCOL_MATCH_IPV4:
            eth_type = ETHER_TYPE_IPV4;
            break;
        case BBF_PROTOCOL_MATCH_IPV6:
            eth_type = ETHER_TYPE_IPV6;
            break;
        case BBF_PROTOCOL_MATCH_SPECIFIC:
            eth_type = protocol_match->ether_type;
            break;
        default:
            NC_LOG_ERR("Match by 0x%x is not supported\n", protocol_match->match_type);
    }
    return eth_type;
}

/* Map flow classifier */
static bcmos_errno xpon_map_bal_flow_classifier(bbf_subif_ingress_rule *rule, const xpon_qos_classifier *qos_class,
    bcmolt_flow_cfg *flow_cfg)
{
    bcmos_errno err = BCM_ERR_OK;
    bbf_match_criteria match = rule->match;

    /* Combine match cryteria with qos classifier */
    if (qos_class != NULL && !bcmolt_is_per_flow_mode())
    {
        err = xpon_merge_match(&match, &qos_class->match);
    }

    if (match.vlan_tag_match.num_tags &&
        match.vlan_tag_match.tag_match_types[BBF_TAG_INDEX_TYPE_OUTER] != BBF_VLAN_TAG_MATCH_TYPE_ALL)
    {
        const bbf_dot1q_tag *tag;
        BCMOLT_MSG_FIELD_SET(flow_cfg, classifier.pkt_tag_type,
            (match.vlan_tag_match.tag_match_types[BBF_TAG_INDEX_TYPE_OUTER] == BBF_VLAN_TAG_MATCH_TYPE_UNTAGGED) ?
                BCMOLT_PKT_TAG_TYPE_UNTAGGED :
                    (match.vlan_tag_match.num_tags == 1) ?
                        BCMOLT_PKT_TAG_TYPE_SINGLE_TAG : BCMOLT_PKT_TAG_TYPE_DOUBLE_TAG);
        if (match.vlan_tag_match.num_tags)
        {
            tag = &match.vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_OUTER];
            if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, vlan_id))
                BCMOLT_MSG_FIELD_SET(flow_cfg, classifier.o_vid, tag->vlan_id);
            if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, pbit))
                BCMOLT_MSG_FIELD_SET(flow_cfg, classifier.o_pbits, tag->pbit);
        }
        if (match.vlan_tag_match.num_tags > 1)
        {
            tag = &match.vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_INNER];
            if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, vlan_id))
                BCMOLT_MSG_FIELD_SET(flow_cfg, classifier.i_vid, tag->vlan_id);
            if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, pbit))
                BCMOLT_MSG_FIELD_SET(flow_cfg, classifier.i_pbits, tag->pbit);
        }
    }
    if (match.protocol_match.match_type != BBF_PROTOCOL_MATCH_ANY)
    {
        BCMOLT_MSG_FIELD_SET(flow_cfg, classifier.ether_type,
            xpon_map_protocol_match_to_ether_type(&match.protocol_match));
    }

    return err;
}

/* Create US/DS/MCAST BAL flow */
static bcmos_errno xpon_create_bal_flow(sr_session_ctx_t *srs, bcmolt_flow_type type,
    bbf_subif_ingress_rule *rule, const bbf_flexible_rewrite *actions,
    const xpon_enet *nni, const xpon_v_ani *v_ani, uint8_t traffic_class)
{
    bbf_subif_ingress_rule_flow *tc_flow = &rule->flows[traffic_class];
    bcmolt_flow_key flow_key = { .flow_type = type };
    bcmolt_flow_cfg flow_cfg;
    bcmolt_action_cmd_id cmd_id = 0;
    bcmolt_tm_sched_id sched_id = 0;
    bcmos_errno err;

    if (!bcmolt_is_per_flow_mode())
    {
        if (traffic_class >= BCM_SIZEOFARRAY(rule->flows))
            return BCM_ERR_PARM;
        if (tc_flow->gem == NULL || tc_flow->qos_class == NULL)
        {
            err = BCM_ERR_INTERNAL;
            NC_ERROR_REPLY(srs, NULL,
                "GEM port and/or qos_class is unassigned. Failed to create %s OLT flow. Error %s\n",
                bcmolt_enum_stringval(bcmolt_flow_type_string_table, type),
                bcmos_strerror(err));
            return err;
        }
    }

    /* ToDo: implement free flow_id assignment */
    flow_key.flow_id = (tc_flow->flow_id != BCM_FLOW_ID_INVALID) ? tc_flow->flow_id : ++global_flow_id;
    BCMOLT_CFG_INIT(&flow_cfg, flow, flow_key);
    BCMOLT_MSG_FIELD_SET(&flow_cfg, statistics, BCMOS_TRUE);
    if (type == BCMOLT_FLOW_TYPE_DOWNSTREAM || type == BCMOLT_FLOW_TYPE_MULTICAST)
    {
        BCMOLT_MSG_FIELD_SET(&flow_cfg, ingress_intf.intf_type, BCMOLT_FLOW_INTERFACE_TYPE_NNI);
        BCMOLT_MSG_FIELD_SET(&flow_cfg, ingress_intf.intf_id, nni->intf_id);

        if (rule->group_id == BCM_GROUP_ID_INVALID)
        {
            BCMOLT_MSG_FIELD_SET(&flow_cfg, egress_intf.intf_type, BCMOLT_FLOW_INTERFACE_TYPE_PON);
            BCMOLT_MSG_FIELD_SET(&flow_cfg, egress_intf.intf_id, v_ani->pon_ni);
            sched_id =  xpon_tm_sched_id(BCMOLT_INTERFACE_TYPE_PON, v_ani->pon_ni);
        }
    }
    else
    {
        BCMOLT_MSG_FIELD_SET(&flow_cfg, ingress_intf.intf_type, BCMOLT_FLOW_INTERFACE_TYPE_PON);
        BCMOLT_MSG_FIELD_SET(&flow_cfg, ingress_intf.intf_id, v_ani->pon_ni);

        BCMOLT_MSG_FIELD_SET(&flow_cfg, egress_intf.intf_type, BCMOLT_FLOW_INTERFACE_TYPE_NNI);
        BCMOLT_MSG_FIELD_SET(&flow_cfg, egress_intf.intf_id, nni->intf_id);
        sched_id =  xpon_tm_sched_id(BCMOLT_INTERFACE_TYPE_NNI, 0);
    }

    if (rule->group_id != BCM_GROUP_ID_INVALID)
    {
        BCMOLT_MSG_FIELD_SET(&flow_cfg, group_id, rule->group_id);
    }

    /* Attach to per-PON TM_SCHED, queue per traffic class, except when dealing with downstream N:1 or mcast */
    if (!bcmolt_is_per_flow_mode())
    {
        if (rule->group_id == BCM_GROUP_ID_INVALID || type == BCMOLT_FLOW_TYPE_UPSTREAM)
        {
            BCMOLT_MSG_FIELD_SET(&flow_cfg, egress_qos.type,
                (type == BCMOLT_FLOW_TYPE_UPSTREAM) ?
                    BCMOLT_EGRESS_QOS_TYPE_PRIORITY_TO_QUEUE :
                    BCMOLT_EGRESS_QOS_TYPE_FIXED_QUEUE);
            BCMOLT_MSG_FIELD_SET(&flow_cfg, egress_qos.tm_sched.id, sched_id);
            if (type == BCMOLT_FLOW_TYPE_UPSTREAM)
            {
                BCMOLT_MSG_FIELD_SET(&flow_cfg, egress_qos.u.priority_to_queue.tm_q_set_id, 0);
                BCMOLT_MSG_FIELD_SET(&flow_cfg, egress_qos.u.priority_to_queue.tm_qmp_id, nni->intf_id);
            }
            else
            {
                BCMOLT_MSG_FIELD_SET(&flow_cfg, egress_qos.u.fixed_queue.queue_id, traffic_class);
            }
            BCMOLT_MSG_FIELD_SET(&flow_cfg, onu_id, v_ani->onu_id);
            BCMOLT_MSG_FIELD_SET(&flow_cfg, svc_port_id, tc_flow->gem->gemport_id);
        }
    }

    /* Map classifier */
    err = xpon_map_bal_flow_classifier(rule, tc_flow->qos_class, &flow_cfg);
    if (err != BCM_ERR_OK)
    {
        NC_ERROR_REPLY(srs, NULL,
            "Failed to map rule+qos classdifier to BAL flow. Failed to create %s OLT flow %u. Error %s\n",
            bcmolt_enum_stringval(bcmolt_flow_type_string_table, type), flow_key.flow_id,
            bcmos_strerror(err));
        return err;
    }

    /* ToDo: add support for IP protocol and MAC address match */

    /* Map actions */

    if (actions != NULL && actions->num_pop_tags > actions->num_push_tags)
    {
        int num_pop_tags = actions->num_pop_tags - actions->num_push_tags;
        cmd_id |= BCMOLT_ACTION_CMD_ID_REMOVE_OUTER_TAG;
        if (num_pop_tags > 1)
            cmd_id |= BCMOLT_ACTION_CMD_ID_REMOVE_INNER_TAG;
    }
    if (actions != NULL && actions->num_push_tags)
    {
        const bbf_dot1q_tag *tag;
        tag = &actions->push_tags[BBF_TAG_INDEX_TYPE_OUTER];
        if (actions->num_pop_tags == actions->num_push_tags)
        {
            cmd_id |= BCMOLT_ACTION_CMD_ID_REMARK_OUTER_PBITS | BCMOLT_ACTION_CMD_ID_XLATE_OUTER_TAG;
        }
        else
        {
            cmd_id |= BCMOLT_ACTION_CMD_ID_ADD_OUTER_TAG;
        }
        if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, vlan_id))
            BCMOLT_MSG_FIELD_SET(&flow_cfg, action.o_vid, tag->vlan_id);
        if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, pbit))
            BCMOLT_MSG_FIELD_SET(&flow_cfg, action.o_pbits, tag->pbit);

        if (actions->num_push_tags > 1)
        {
            tag = &actions->push_tags[BBF_TAG_INDEX_TYPE_INNER];
            if (actions->num_pop_tags)
            {
                cmd_id |= BCMOLT_ACTION_CMD_ID_REMARK_OUTER_PBITS | BCMOLT_ACTION_CMD_ID_XLATE_OUTER_TAG;
            }
            else
            {
                cmd_id |= BCMOLT_ACTION_CMD_ID_ADD_INNER_TAG;
            }
            if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, vlan_id))
                BCMOLT_MSG_FIELD_SET(&flow_cfg, action.i_vid, tag->vlan_id);
            if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, pbit))
                BCMOLT_MSG_FIELD_SET(&flow_cfg, action.i_pbits, tag->pbit);
        }
    }
    BCMOLT_MSG_FIELD_SET(&flow_cfg, action.cmds_bitmask, cmd_id);
    BCMOLT_MSG_FIELD_SET(&flow_cfg, state, BCMOLT_FLOW_STATE_ENABLE);

    /* Finally create BAL flow */
    err = bcmolt_cfg_set(netconf_agent_olt_id(), &flow_cfg.hdr);
    if (err != BCM_ERR_OK)
    {
        NC_ERROR_REPLY(srs, NULL, "failed to create %s OLT flow %u. Error %s (%s)\n",
            bcmolt_enum_stringval(bcmolt_flow_type_string_table, type), flow_key.flow_id,
            bcmos_strerror(err), flow_cfg.hdr.hdr.err_text);
        return err;
    }

    tc_flow->flow_id = flow_cfg.key.flow_id;
    tc_flow->flow_dir |= ((type == BCMOLT_FLOW_TYPE_DOWNSTREAM) ? XPON_FLOW_DIR_DOWNSTREAM : XPON_FLOW_DIR_UPSTREAM);

    NC_LOG_DBG("Created %s BAL flow %u\n",
        bcmolt_enum_stringval(bcmolt_flow_type_string_table, type), flow_cfg.key.flow_id);

    return BCM_ERR_OK;
}

/* Delete US/DS BAL flows for all TCs */
static void delete_bal_flows(bbf_subif_ingress_rule *rule, bcmolt_flow_type type)
{
    for(int i = 0; i < BCM_SIZEOFARRAY(rule->flows); i++)
    {
        if (rule->flows[i].flow_id != BCM_FLOW_ID_INVALID)
        {
            delete_bal_flow(rule->flows[i].flow_id, type);
            rule->flows[i].flow_id = BCM_FLOW_ID_INVALID;
            rule->flows[i].gem = NULL;
            rule->flows[i].qos_class = NULL;
        }
    }
}

/* Create US/DS BAL flows for all TCs */
static bcmos_errno xpon_create_bal_flows(sr_session_ctx_t *srs, bcmolt_flow_type type,
    bbf_subif_ingress_rule *rule, const bbf_flexible_rewrite *actions,
    const xpon_enet *nni, const xpon_v_ani *v_ani, bcmolt_group_id group_id)
{
    bcmos_errno err = BCM_ERR_OK;
    int i;

    for(i = 0; i < BCM_SIZEOFARRAY(rule->flows) && err == BCM_ERR_OK; i++)
    {
        if (rule->flows[i].gem != NULL && rule->flows[i].qos_class != NULL)
        {
            err = xpon_create_bal_flow(srs, type, rule, actions, nni, v_ani, i);
        }
    }
    if (err != BCM_ERR_OK)
    {
        delete_bal_flows(rule, type);
        return err;
    }

    return BCM_ERR_OK;
}

/* Create a DHCP relay interface */
static bcmos_errno xpon_create_dhcpr_interface(sr_session_ctx_t *srs,
    const xpon_vlan_subif *subif,
    bbf_subif_ingress_rule *ds_rule,
    bbf_subif_ingress_rule *us_rule,
    const xpon_enet *nni,
    const xpon_v_ani *v_ani)
{
    bcmolt_flow_id flow_id = BCM_FLOW_ID_INVALID;
    dhcp_relay_interface_info info = {};
    /* Find any flow in the ds_rule */
    for (int i = 0; i < BCM_SIZEOFARRAY(ds_rule->flows); i++)
    {
        if (ds_rule->flows[i].flow_id != BCM_FLOW_ID_INVALID)
        {
            flow_id = ds_rule->flows[i].flow_id;
            break;
        }
    }
    if (flow_id == BCM_FLOW_ID_INVALID)
    {
        NC_ERROR_REPLY(srs, NULL, "Couldn't find an inject flow for subif %s\n",
            subif->hdr.name);
        return BCM_ERR_INTERNAL;
    }
    info.name = subif->hdr.name;
    info.is_trusted = subif->dhcpr.trusted;
    info.owner = ds_rule;
    info.profile = subif->dhcpr.profile;
    info.pon_ni = v_ani->pon_ni;
    info.nni = nni->intf_id;
    info.ds_filter = ds_rule->match;
    info.us_filter = us_rule->match;
    info.bal_flow = flow_id;
    return dhcp_relay_interface_add(&info, &ds_rule->dhcpr_iface);
}

/* Create upstream or downstream ONU flow */
static bcmos_errno xpon_create_onu_flow(sr_session_ctx_t *srs, xpon_v_ani *v_ani,
    xpon_vlan_subif *subif, bbf_subif_ingress_rule *rule, uint8_t traffic_class, bcmonu_mgmt_flow_dir_id dir)
{
    bbf_subif_ingress_rule_flow *tc_flow;
    bcmonu_mgmt_flow_cfg cfg; /* declare main API struct */
    bcmonu_mgmt_flow_key key = {};
    bbf_match_criteria match = {};
    bbf_match_criteria match_with_qos;
    bbf_flexible_rewrite actions = {};
    const xpon_gem *gem;
    bcmonu_mgmt_flow_action_type_id cmd_id = 0;
    bcmos_errno err = BCM_ERR_OK;

    /* Sanity checks */
    if (traffic_class >= BCM_SIZEOFARRAY(rule->flows))
        return BCM_ERR_INTERNAL;
    tc_flow = &rule->flows[traffic_class];
    gem = tc_flow->gem;
    if (gem == NULL)
        return BCM_ERR_INTERNAL;

    if (tc_flow->flow_id != BCM_FLOW_ID_INVALID)
        return BCM_ERR_OK;

    key.id = tc_flow->flow_id;
    key.dir = dir;
    if (key.id == BCM_FLOW_ID_INVALID)
        key.id = ++global_onu_flow_id;
    BCMONU_MGMT_CFG_INIT(&cfg, flow, key);

    /* In the upstream subif classifier and actions are fine. In the downstream need to invert */
    match = rule->match;
    match_with_qos = match;
    if (tc_flow->qos_class != NULL)
    {
        /* Extended match with QoS classification */
        err = xpon_merge_match(&match_with_qos, &tc_flow->qos_class->match);
    }
    if (dir == BCMONU_MGMT_FLOW_DIR_ID_DOWNSTREAM)
    {
        actions = subif->egress_rewrite;
        xpon_apply_actions_to_match(&match_with_qos, &actions);
        err = (err != BCM_ERR_OK) ? err : xpon_match_diff(&match_with_qos, &rule->match, &actions);
        match = match_with_qos;
    }
    else
    {
        bbf_flexible_rewrite extra_actions = {};
        actions = rule->rewrite;
        err = (err != BCM_ERR_OK) ? err : xpon_match_diff(&rule->match, &match_with_qos, &extra_actions);
        err = (err != BCM_ERR_OK) ? err : xpon_merge_actions(&actions, &extra_actions);
    }
    if (err != BCM_ERR_OK)
        return err;

    /* No to ONU configuration */
    BCMONU_MGMT_FIELD_SET(&cfg.data.onu_key, onu_key, pon_ni, v_ani->pon_ni);
    BCMONU_MGMT_FIELD_SET(&cfg.data.onu_key, onu_key, onu_id, v_ani->onu_id);
    BCMONU_MGMT_FIELD_SET_PRESENT(&cfg.data, flow_cfg_data, onu_key);
    BCMONU_MGMT_FIELD_SET(&cfg.data, flow_cfg_data, admin_state, BCMONU_MGMT_ADMIN_STATE_UP);
    BCMONU_MGMT_FIELD_SET(&cfg.data, flow_cfg_data, flow_type, BCMONU_MGMT_FLOW_TYPE_UNICAST);
    BCMONU_MGMT_FIELD_SET(&cfg.data, flow_cfg_data, svc_port_id, gem->gemport_id);
    if (dir == BCMONU_MGMT_FLOW_DIR_ID_UPSTREAM)
        BCMONU_MGMT_FIELD_SET(&cfg.data, flow_cfg_data, agg_port_id, gem->tcont->alloc_id);

    /* Map classifier */
    if (match.vlan_tag_match.tag_match_types[BBF_TAG_INDEX_TYPE_OUTER] != BBF_VLAN_TAG_MATCH_TYPE_ALL)
    {
        const bbf_dot1q_tag *tag;
        if (match.vlan_tag_match.tag_match_types[BBF_TAG_INDEX_TYPE_OUTER] == BBF_VLAN_TAG_MATCH_TYPE_UNTAGGED)
        {
            BCMONU_MGMT_FIELD_SET(&cfg.data.match, flow_match, o_untagged, BCMOS_TRUE);
        }
        if (match.vlan_tag_match.num_tags)
        {
            tag = &match.vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_OUTER];
            if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, vlan_id))
                BCMONU_MGMT_FIELD_SET(&cfg.data.match, flow_match, o_vid, tag->vlan_id);
            if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, pbit))
                BCMONU_MGMT_FIELD_SET(&cfg.data.match, flow_match, o_pcp, tag->pbit);
        }
        if (match.vlan_tag_match.num_tags > 1)
        {
            tag = &match.vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_INNER];
            if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, vlan_id))
                BCMONU_MGMT_FIELD_SET(&cfg.data.match, flow_match, o_vid, tag->vlan_id);
            if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, pbit))
                BCMONU_MGMT_FIELD_SET(&cfg.data.match, flow_match, o_pcp, tag->pbit);
        }
        BCMONU_MGMT_FIELD_SET_PRESENT(&cfg.data, flow_cfg_data, match);
    }
    if (match.protocol_match.match_type != BBF_PROTOCOL_MATCH_ANY)
    {
        BCMONU_MGMT_FIELD_SET(&cfg.data.match, flow_match, ether_type,
            xpon_map_protocol_match_to_ether_type(&match.protocol_match));
        BCMONU_MGMT_FIELD_SET_PRESENT(&cfg.data, flow_cfg_data, match);
    }

    /* Map actions */
    if (actions.num_pop_tags)
    {
        cmd_id |= BCMONU_MGMT_FLOW_ACTION_TYPE_ID_POP;
        if (actions.num_pop_tags > 1)
            cmd_id |= BCMONU_MGMT_FLOW_ACTION_TYPE_ID_POP_INNER_TAG;
    }
    if (actions.num_push_tags)
    {
        const bbf_dot1q_tag *tag;
        if (actions.num_push_tags > actions.num_pop_tags)
            cmd_id |= BCMONU_MGMT_FLOW_ACTION_TYPE_ID_PUSH;

        cmd_id &= ~BCMONU_MGMT_FLOW_ACTION_TYPE_ID_POP_INNER_TAG;
        if (actions.num_push_tags == actions.num_pop_tags)
            cmd_id &= ~BCMONU_MGMT_FLOW_ACTION_TYPE_ID_POP;

        tag = &actions.push_tags[BBF_TAG_INDEX_TYPE_OUTER];
        if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, vlan_id))
        {
            BCMONU_MGMT_FIELD_SET(&cfg.data.action, flow_action, o_vid, tag->vlan_id);
            if (actions.num_pop_tags)
                cmd_id |= BCMONU_MGMT_FLOW_ACTION_TYPE_ID_TRANSLATE_VID;
        }
        if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, pbit))
        {
            BCMONU_MGMT_FIELD_SET(&cfg.data.action, flow_action, o_pcp, tag->pbit);
            if (actions.num_pop_tags)
                cmd_id |= BCMONU_MGMT_FLOW_ACTION_TYPE_ID_TRANSLATE_PCP;
        }

        if (actions.num_push_tags > 1)
        {
            if (!actions.num_pop_tags)
                cmd_id |= BCMONU_MGMT_FLOW_ACTION_TYPE_ID_PUSH_INNER_TAG;

            tag = &actions.push_tags[BBF_TAG_INDEX_TYPE_INNER];
            if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, vlan_id))
            {
                BCMONU_MGMT_FIELD_SET(&cfg.data.action, flow_action, o_vid, tag->vlan_id);
                if (actions.num_pop_tags == 2)
                    cmd_id |= BCMONU_MGMT_FLOW_ACTION_TYPE_ID_TRANSLATE_INNER_VID;
            }
            if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, pbit))
            {
                BCMONU_MGMT_FIELD_SET(&cfg.data.action, flow_action, o_pcp, tag->pbit);
                if (actions.num_pop_tags == 2)
                    cmd_id |= BCMONU_MGMT_FLOW_ACTION_TYPE_ID_TRANSLATE_INNER_PCP;
            }
        }
    }
    BCMONU_MGMT_FIELD_SET(&cfg.data.action, flow_action, type, cmd_id);
    BCMONU_MGMT_FIELD_SET_PRESENT(&cfg.data, flow_cfg_data, action);

    if (!bcm_tr451_onu_management_is_enabled())
    {
        err = bcmonu_mgmt_cfg_set(netconf_agent_olt_id(), &cfg.hdr);
        if (err != BCM_ERR_OK)
        {
            NC_ERROR_REPLY(srs, NULL, "failed to create %s ONU flow. Error %s\n",
                (dir == BCMONU_MGMT_FLOW_DIR_ID_DOWNSTREAM) ? "DS" : "US",
                bcmos_strerror(err));
            return err;
        }
    }

    tc_flow->flow_id = cfg.key.id;
    tc_flow->flow_dir |= ((dir == BCMONU_MGMT_FLOW_DIR_ID_DOWNSTREAM) ? XPON_FLOW_DIR_DOWNSTREAM : XPON_FLOW_DIR_UPSTREAM);
    tc_flow->gem = gem;

    return BCM_ERR_OK;
}

/* Create BAL group */
static bcmos_errno xpon_create_bal_group(sr_session_ctx_t *srs,
    xpon_vlan_subif *net_if, bbf_subif_ingress_rule *netif_rule,
    const bbf_flexible_rewrite *egress_actions)
{
    bcmolt_group_key key = { .id = global_group_id };
    bcmolt_group_cfg group_cfg;
    bbf_flexible_rewrite actions = {};
    bcmolt_action_cmd_id cmd_id = 0;
    bcmos_errno err;

    BCMOLT_CFG_INIT(&group_cfg, group, key);

    /* Map actions */
    if (netif_rule != NULL)
        actions = netif_rule->rewrite;
    if (egress_actions != NULL)
        xpon_merge_actions(&actions, egress_actions);
    /* Map actions */
    if (actions.num_pop_tags)
    {
        cmd_id |= BCMOLT_ACTION_CMD_ID_REMOVE_OUTER_TAG;
        if (actions.num_pop_tags > 1)
            cmd_id |= BCMOLT_ACTION_CMD_ID_REMOVE_INNER_TAG;
    }
    if (actions.num_push_tags)
    {
        const bbf_dot1q_tag *tag;
        cmd_id |= BCMOLT_ACTION_CMD_ID_ADD_OUTER_TAG;
        tag = &actions.push_tags[BBF_TAG_INDEX_TYPE_OUTER];
        if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, vlan_id))
            BCMOLT_MSG_FIELD_SET(&group_cfg, action.o_vid, tag->vlan_id);
        if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, pbit))
            BCMOLT_MSG_FIELD_SET(&group_cfg, action.o_pbits, tag->pbit);

        if (actions.num_push_tags > 1)
        {
            cmd_id |= BCMOLT_ACTION_CMD_ID_ADD_INNER_TAG;
            tag = &actions.push_tags[BBF_TAG_INDEX_TYPE_INNER];
            if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, vlan_id))
                BCMOLT_MSG_FIELD_SET(&group_cfg, action.i_vid, tag->vlan_id);
            if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, pbit))
                BCMOLT_MSG_FIELD_SET(&group_cfg, action.i_pbits, tag->pbit);
        }
    }
    BCMOLT_MSG_FIELD_SET(&group_cfg, action.cmds_bitmask, cmd_id);

    /* Create group */
    /* Finally create BAL flow */
    err = bcmolt_cfg_set(netconf_agent_olt_id(), &group_cfg.hdr);
    if (err != BCM_ERR_OK)
    {
        NC_ERROR_REPLY(srs, NULL, "failed to create a group. Error %s (%s)\n",
            bcmos_strerror(err), group_cfg.hdr.hdr.err_text);
        return err;
    }

    netif_rule->group_id = key.id;
    ++global_group_id;

    return BCM_ERR_OK;
}

static bcmos_errno xpon_create_bal_group_member(sr_session_ctx_t *srs,
    const xpon_vlan_subif *net_if, const xpon_vlan_subif *acc_if,
    bbf_subif_ingress_rule *netif_rule, bbf_subif_ingress_rule *acc_rule,
    uint8_t traffic_class)
{
    const xpon_v_ani_v_enet *v_ani_v_enet = (xpon_v_ani_v_enet *)acc_if->subif_lower_layer;
    const xpon_v_ani *v_ani = v_ani_v_enet->v_ani;
    bcmolt_group_members_update op;
    bcmolt_group_key key = { .id = netif_rule->group_id };
    bcmolt_group_member_info memb = {};
    bcmolt_group_member_info_list_u8 memb_list = { .len = 1, .arr = &memb };
    bcmolt_intf_ref intf_ref = {
        .intf_type = BCMOLT_INTERFACE_TYPE_PON,
        .intf_id = v_ani->pon_ni
    };
    /* TODO: use tm_qmp mapper derived from qos classifier instead of default */
    bcmolt_egress_qos egress_qos = {
        .type = BCMOLT_EGRESS_QOS_TYPE_FIXED_QUEUE,/*BCMOLT_EGRESS_QOS_TYPE_PRIORITY_TO_QUEUE,*/
        .tm_sched.id = xpon_tm_sched_id(BCMOLT_INTERFACE_TYPE_PON, v_ani->pon_ni),
        .u.fixed_queue = {
            .queue_id = 0,
            // .tm_qmp_id = BCM_DEFAULT_TM_QMP_ID,
            // .tm_q_set_id = BCMOLT_TM_QUEUE_SET_ID_QSET_NOT_USE,

        }
    };
    const xpon_gem *gem = NULL;
    bcmos_errno err;

    gem = (netif_rule->flows[traffic_class].gem != NULL) ?
        netif_rule->flows[traffic_class].gem :
        acc_rule->flows[traffic_class].gem;
    BCMOLT_OPER_INIT(&op, group, members_update, key);
    if (gem != NULL)
        BCMOLT_FIELD_SET(&memb, group_member_info, svc_port_id, gem->gemport_id);
    BCMOLT_FIELD_SET(&memb, group_member_info, intf, intf_ref);
    BCMOLT_FIELD_SET(&memb, group_member_info, egress_qos, egress_qos);
    BCMOLT_MSG_FIELD_SET(&op, members_cmd.command, BCMOLT_MEMBERS_UPDATE_COMMAND_ADD);
    BCMOLT_MSG_FIELD_SET(&op, members_cmd.members, memb_list);

    err = bcmolt_oper_submit(netconf_agent_olt_id(), &op.hdr);
    if (err != BCM_ERR_OK)
    {
        NC_ERROR_REPLY(srs, NULL, "failed to add group member. Error %s (%s)\n",
            bcmos_strerror(err), op.hdr.hdr.err_text);
        return err;
    }

    return BCM_ERR_OK;
}


/* Create US and DS ONU flows */
static bcmos_errno xpon_create_onu_flows(sr_session_ctx_t *srs, xpon_v_ani *v_ani,
    xpon_v_ani_v_enet *v_ani_v_enet, xpon_vlan_subif *subif, bbf_subif_ingress_rule *rule)
{
    bbf_match_criteria onu_match = rule->match;
    bbf_subif_ingress_rule *olt_rule = NULL, *rule_tmp;
    xpon_vlan_subif *olt_subif, *subif_tmp;
    bcmos_errno err;

    if (v_ani == NULL || !v_ani->registered || v_ani_v_enet == NULL)
        return BCM_ERR_STATE;

    /* Find matching OLT rule */
    xpon_apply_actions_to_match(&onu_match, &rule->rewrite);
    STAILQ_FOREACH_SAFE(olt_subif, &v_ani_v_enet->subifs, next, subif_tmp)
    {
        STAILQ_FOREACH_SAFE(olt_rule, &olt_subif->ingress, next, rule_tmp)
        {
            if (xpon_is_match(&onu_match, &olt_rule->match))
            {
                break;
            }
        }
        if (olt_rule != NULL)
            break;
    }
    if (olt_rule == NULL)
    {
        NC_LOG_ERR("Can't find matching OLT rule for %s\n", subif->hdr.name);
        return BCM_ERR_NOENT;
    }

    /* Assign TCs and GEMs based on the qos_profile */
    err = xpon_find_rule_gem(srs, subif, rule, v_ani_v_enet, BCMOS_FALSE);
    if (err != BCM_ERR_OK)
    {
        /* We couldn't identify GEM based on the qos_profile associated with ani-side vsi.
           Try to check what GEM(s) are assigned to the linked vani-side vsi
        */
        int num_assigned_gems = 0;
        for (int i = 0; i < BCM_SIZEOFARRAY(olt_rule->flows); i++)
        {
            bbf_match_criteria match_with_qos = rule->match;
            bbf_subif_ingress_rule_flow *tc_flow = &rule->flows[i];
            if (olt_rule->flows[i].gem == NULL)
                continue;
            if (tc_flow->gem != NULL)
            {
                ++num_assigned_gems;
                continue; /* already exists */
            }
            if (tc_flow->qos_class != NULL)
            {
                /* Extended match with QoS classification */
                err = xpon_merge_match(&match_with_qos, &tc_flow->qos_class->match);
                if (err != BCM_ERR_OK)
                    continue;
            }
            tc_flow->gem = olt_rule->flows[i].gem;
            tc_flow->qos_class = olt_rule->flows[i].qos_class;
            ++num_assigned_gems;
        }
        if (!num_assigned_gems)
        {
            NC_ERROR_REPLY(srs, NULL, "rule %s: can't find matching GEM port needed to create an ONU flow for VSI %s.\n",
                rule->name, subif->hdr.name);
            return BCM_ERR_PARM;
        }
    }

    /* Now go over all traffic classes and create ONU flows */
    for (int i = 0; i < BCM_SIZEOFARRAY(rule->flows); i++)
    {
        bbf_subif_ingress_rule_flow *tc_flow = &rule->flows[i];
        if (tc_flow->flow_id != BCM_FLOW_ID_INVALID)
            continue;
        if (tc_flow->gem == NULL)
            continue;
        err = xpon_create_onu_flow(srs, v_ani, subif, rule, i, BCMONU_MGMT_FLOW_DIR_ID_UPSTREAM);
        if (err != BCM_ERR_OK)
        {
            tc_flow->gem = NULL;
            tc_flow->qos_class = NULL;
            return err;
        }
#ifdef CREATE_DOWNSTREAM_ONU_FLOWS
        err = xpon_create_onu_flow(srs, v_ani, subif, rule, i, BCMONU_MGMT_FLOW_DIR_ID_DOWNSTREAM);
        if (err != BCM_ERR_OK)
        {
            delete_onu_flow(tc_flow->flow_id, BCMONU_MGMT_FLOW_DIR_ID_UPSTREAM);
            tc_flow->flow_id = BCM_FLOW_ID_INVALID;
            tc_flow->gem = NULL;
            tc_flow->qos_class = NULL;
            return err;
        }
#endif
    }

    return BCM_ERR_OK;
}

/* Create ONU flows on subif */
bcmos_errno xpon_create_onu_flows_on_subif(sr_session_ctx_t *srs, xpon_obj_hdr *uni, xpon_vlan_subif *subif)
{
    xpon_v_ani_v_enet *v_ani_v_enet;
    xpon_ani *ani;
    xpon_v_ani *v_ani;
    bbf_subif_ingress_rule *rule, *rule_tmp;

    if (uni->obj_type == XPON_OBJ_TYPE_ANI_V_ENET)
    {
        v_ani_v_enet = (xpon_v_ani_v_enet *)((xpon_ani_v_enet *)uni)->linked_if;
        ani = (xpon_ani *)((xpon_ani_v_enet *)uni)->lower_layer;
    }
    else if (uni->obj_type == XPON_OBJ_TYPE_ENET)
    {
        v_ani_v_enet = (xpon_v_ani_v_enet *)((xpon_enet *)uni)->linked_if;
        ani = (xpon_ani *)((xpon_enet *)uni)->lower_layer;
    }
    else
    {
        NC_LOG_ERR("Unexpected object %s\n", uni->name);
        return BCM_ERR_PARM;
    }
    v_ani = (ani == NULL) ? NULL : ani->linked_v_ani;
    if (v_ani_v_enet == NULL || v_ani == NULL || ani->hdr.obj_type != XPON_OBJ_TYPE_ANI)
    {
        NC_LOG_ERR("Couldn't create ONU flows: v_ani_v_enet:%s v_ani:%s ani:%s ani_obj_type:%d\n",
            v_ani_v_enet ? v_ani_v_enet->hdr.name : "none",
            v_ani ? v_ani->hdr.name : "none",
            ani ? ani->hdr.name : "none",
            ani ? ani->hdr.obj_type : -1);
        return BCM_ERR_PARM;
    }

    STAILQ_FOREACH_SAFE(rule, &subif->ingress, next, rule_tmp)
    {
        /* Tru to create flows. Ignore errors */
        xpon_create_onu_flows(srs, v_ani, v_ani_v_enet, subif, rule);
    }

    return BCM_ERR_OK;
}

/* Create ONU flows on uni */
bcmos_errno xpon_create_onu_flows_on_uni(sr_session_ctx_t *srs, xpon_obj_hdr *uni)
{
    xpon_v_ani_v_enet *v_ani_v_enet;
    xpon_vlan_subif *subif, *subif_tmp;
    const xpon_subif_list *subifs;

    if (uni->obj_type == XPON_OBJ_TYPE_ANI_V_ENET)
    {
        v_ani_v_enet = (xpon_v_ani_v_enet *)((xpon_ani_v_enet *)uni)->linked_if;
        subifs = &(((xpon_ani_v_enet *)uni)->subifs);
    }
    else if (uni->obj_type == XPON_OBJ_TYPE_ENET)
    {
        v_ani_v_enet = (xpon_v_ani_v_enet *)((xpon_enet *)uni)->linked_if;
        subifs = &(((const xpon_enet *)uni)->subifs);
    }
    else
    {
        NC_LOG_ERR("Unexpected object %s\n", uni->name);
        return BCM_ERR_PARM;
    }

    if (v_ani_v_enet == NULL || v_ani_v_enet->hdr.obj_type != XPON_OBJ_TYPE_V_ANI_V_ENET)
        return BCM_ERR_PARM;

    STAILQ_FOREACH_SAFE(subif, subifs, next, subif_tmp)
    {
        /* Tru to create flows. Ignore errors */
        xpon_create_onu_flows_on_subif(srs, uni, subif);
    }

    return BCM_ERR_OK;
}

static bcmos_errno xpon_find_rule_gem(
    sr_session_ctx_t *srs,
    xpon_vlan_subif *subif, bbf_subif_ingress_rule *rule,
    const xpon_v_ani_v_enet *v_ani_v_enet,
    bcmos_bool stop_on_error)
{
    const xpon_qos_policy_profile *prof;
    const xpon_qos_classifier *qos_class = NULL;
    int num_assigned = 0;

    /* Assign GEM for all traffic classes. Return error if non is found */
    prof = subif->qos_policy_profile;
    if (prof == NULL)
    {
        NC_ERROR_REPLY(srs, NULL, "qos-policy-profile is missing for vlan-subif %s\n", subif->hdr.name);
        return BCM_ERR_NOENT;
    }

    /* Iterate over qos classifiers and classifiers for which there is a provisioned GEM port. */
    qos_class = xpon_qos_classifier_get_next(prof, rule, NULL);
    while (qos_class != NULL)
    {
        if (xpon_is_match(&rule->match, &qos_class->match))
        {
            const xpon_gem *gem = xpon_gem_get_by_traffic_class(v_ani_v_enet, qos_class->traffic_class);
            if (gem != NULL)
            {
                rule->flows[qos_class->traffic_class].gem = gem;
                rule->flows[qos_class->traffic_class].qos_class = qos_class;
                ++num_assigned;

                /* Populate priority_to_tc and base_gem for per-flow mode */
                if (qos_class->match.vlan_tag_match.num_tags)
                {
                    const bbf_dot1q_tag *tag = &qos_class->match.vlan_tag_match.tags[0];
                    if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, pbit))
                        rule->priority_to_tc[tag->pbit] = qos_class->traffic_class;
                }
                else
                {
                    for (int i = 0; i < 8; i++)
                    {
                        if (rule->priority_to_tc[i] < 0)
                            rule->priority_to_tc[i] = qos_class->traffic_class;
                    }
                }
            }
        }
        qos_class = xpon_qos_classifier_get_next(prof, rule, qos_class);
    }

    if (!num_assigned)
    {
        if (stop_on_error)
        {
            NC_ERROR_REPLY(srs, NULL, "rule %s: can't find matching GEM port needed to create an OLT or ONU flow.\n",
                rule->name);
        }
        else
        {
            NC_LOG_DBG("rule %s: can't find matching GEM port needed to create an OLT or ONU flow.\n",
                rule->name)
        }
        return BCM_ERR_NOENT;
    }

    return BCM_ERR_OK;
}

static bcmos_errno xpon_apply_n_1_flow_create(sr_session_ctx_t *srs, xpon_forwarder *fwd)
{
    xpon_vlan_subif *net_if = NULL;
    bbf_subif_ingress_rule *netif_rule;
    xpon_vlan_subif *acc_if;
    struct xpon_forwarder_port *port, *tmp_port;
    xpon_vlan_subif *subif;
    xpon_v_ani_v_enet *v_ani_v_enet;
    const xpon_enet *nni;
    xpon_v_ani *v_ani = NULL;
    bbf_subif_ingress_rule *rule, *rule_tmp;
    bbf_flexible_rewrite *actions = NULL;
    bcmos_errno err = BCM_ERR_OK;
    bcmos_bool is_multicast = BCMOS_FALSE; /* TODO */

    /* Find network side interface */
    STAILQ_FOREACH_SAFE(port, &fwd->ports, next, tmp_port)
    {
        subif = port->subif;
        if (subif->usage == BBF_INTERFACE_USAGE_NETWORK_PORT)
        {
            if (net_if != NULL)
            {
                NC_ERROR_REPLY(srs, NULL, "forwarder %s: N:1 forwarder can't include more than 1 network port\n", fwd->hdr.name);
                return BCM_ERR_NOT_SUPPORTED;
            }
            net_if = subif;
        }
    }
    if (net_if == NULL)
    {
        NC_ERROR_REPLY(srs, NULL, "forwarder %s: N:1 forwarder must include a network port\n", fwd->hdr.name);
        return BCM_ERR_NOT_SUPPORTED;
    }

    /* paranoya check */
    if (net_if->subif_lower_layer == NULL)
    {
        NC_ERROR_REPLY(srs, NULL, "forwarder %s: something is wrong. subif-lower-layer is not set in interface %s\n",
            fwd->hdr.name, net_if->hdr.name);
        return BCM_ERR_INTERNAL;
    }
    if (net_if->subif_lower_layer->obj_type != XPON_OBJ_TYPE_ENET)
    {
        NC_ERROR_REPLY(srs, NULL, "forwarder %s: subif %s belong to interface %s of wrong type. Expected enet\n",
            fwd->hdr.name, net_if->hdr.name, net_if->subif_lower_layer->name);
        return BCM_ERR_PARM;
    }
    nni = (const xpon_enet *)net_if->subif_lower_layer;

    /* net_if must contain exactly 1 rule */
    netif_rule = STAILQ_FIRST(&net_if->ingress);
    if (netif_rule == NULL || STAILQ_NEXT(netif_rule, next) != NULL)
    {
        NC_ERROR_REPLY(srs, NULL, "forwarder %s: N:1: network interface %s must have exactly 1 ingress rule\n",
            fwd->hdr.name, net_if->hdr.name);
        return BCM_ERR_NOT_SUPPORTED;
    }

    /* Go over access side ports and make sure that we can identify GEM ports */
    STAILQ_FOREACH_SAFE(port, &fwd->ports, next, tmp_port)
    {
        acc_if = port->subif;
        if (acc_if->usage == BBF_INTERFACE_USAGE_NETWORK_PORT)
            continue;

        /* It is expected that acc_if->subif_lower_layer is olt-v-enet */
        if (acc_if->subif_lower_layer->obj_type != XPON_OBJ_TYPE_V_ANI_V_ENET)
        {
            NC_ERROR_REPLY(srs, NULL, "forwarder %s: subif %s belong to interface %s of wrong type. Expected v-olt-v-enet\n",
                fwd->hdr.name, acc_if->hdr.name, acc_if->subif_lower_layer->name);
            return BCM_ERR_PARM;
        }

        v_ani_v_enet = (xpon_v_ani_v_enet *)acc_if->subif_lower_layer;
        v_ani = v_ani_v_enet->v_ani;
        if (v_ani == NULL)
        {
            NC_ERROR_REPLY(srs, NULL, "forwarder %s: v-ani reference is not set on %s\n",
                fwd->hdr.name, v_ani_v_enet->hdr.name);
            return BCM_ERR_PARM;
        }

        /* Find GEM for each upstream rule
        */
        STAILQ_FOREACH_SAFE(rule, &acc_if->ingress, next, rule_tmp)
        {
            err = xpon_find_rule_gem(srs, acc_if, rule, v_ani_v_enet, BCMOS_TRUE);
            if (err != BCM_ERR_OK)
                break;
        }
        if (err != BCM_ERR_OK)
            return err;

        /* Make sure that all egress packet modification rules are the same */
        if (actions == NULL)
        {
            actions = &acc_if->egress_rewrite;
        }
        else
        {
            if (!xpon_is_actions_match(actions, &acc_if->egress_rewrite))
            {
                NC_ERROR_REPLY(srs, NULL, "forwarder %s: all DS flows must have the same egress action\n",
                    fwd->hdr.name);
                return BCM_ERR_NOT_SUPPORTED;
            }
        }
    }

    /* Done with validation. Now start actrual configuration.
       - create group
       - create DS flow referencing the group with classifier and action taken from NNI
       - for each acc subif create an upstream flow
       - for each acc subif add group member
    */
    err = xpon_create_bal_group(srs, net_if, netif_rule, actions);

    /* Create DS flow. At this pooint group type will be set */
    if (err == BCM_ERR_OK)
    {
        err = xpon_create_bal_flows(srs,
            is_multicast ? BCMOLT_FLOW_TYPE_MULTICAST : BCMOLT_FLOW_TYPE_DOWNSTREAM,
            netif_rule,
            NULL, nni, NULL, netif_rule->group_id);
    }

    /* Create group members */
    if (err == BCM_ERR_OK)
    {
        STAILQ_FOREACH_SAFE(port, &fwd->ports, next, tmp_port)
        {
            acc_if = port->subif;
            if (acc_if->usage == BBF_INTERFACE_USAGE_NETWORK_PORT)
                continue;
            STAILQ_FOREACH_SAFE(rule, &acc_if->ingress, next, rule_tmp)
            {
                for (int i = 0; i < BCM_SIZEOFARRAY(rule->flows); i++)
                {
                    if (rule->flows[i].gem == NULL && netif_rule->flows[i].gem == NULL)
                        continue;
                    err = xpon_create_bal_group_member(srs, net_if, acc_if, netif_rule, rule, i);
                    if (err != BCM_ERR_OK)
                        break;
                }
            }
        }
    }

    /* Create US flows */
    if (!is_multicast && err == BCM_ERR_OK)
    {
        STAILQ_FOREACH_SAFE(port, &fwd->ports, next, tmp_port)
        {
            acc_if = port->subif;
            if (acc_if->usage == BBF_INTERFACE_USAGE_NETWORK_PORT)
                continue;
            v_ani_v_enet = (xpon_v_ani_v_enet *)acc_if->subif_lower_layer;
            v_ani = v_ani_v_enet->v_ani;
            STAILQ_FOREACH_SAFE(rule, &acc_if->ingress, next, rule_tmp)
            {
                err = xpon_create_bal_flows(srs, BCMOLT_FLOW_TYPE_UPSTREAM, rule,
                    &rule->rewrite, nni, v_ani, netif_rule->group_id);
                if (err != BCM_ERR_OK)
                    break;
            }
        }
    }

    /* Roll-back in case of error */
    if (err != BCM_ERR_OK)
    {
        for (int i = 0; i < BCM_SIZEOFARRAY(netif_rule->flows); i++)
        {
            if (netif_rule->flows[i].flow_id != BCM_FLOW_ID_INVALID)
            {
                delete_bal_flow(netif_rule->flows[i].flow_id,
                    is_multicast ? BCMOLT_FLOW_TYPE_MULTICAST : BCMOLT_FLOW_TYPE_DOWNSTREAM);
                netif_rule->flows[i].flow_id = BCM_FLOW_ID_INVALID;
            }
        }
        if (netif_rule->group_id != BCM_GROUP_ID_INVALID)
        {
            delete_bal_group(netif_rule->group_id);
            netif_rule->group_id = BCM_GROUP_ID_INVALID;
        }
        if (!is_multicast)
        {
            STAILQ_FOREACH_SAFE(port, &fwd->ports, next, tmp_port)
            {
                acc_if = port->subif;
                if (acc_if->usage == BBF_INTERFACE_USAGE_NETWORK_PORT)
                    continue;
                STAILQ_FOREACH_SAFE(rule, &acc_if->ingress, next, rule_tmp)
                {
                    for (int i = 0; i < BCM_SIZEOFARRAY(rule->flows); i++)
                    {
                        if (rule->flows[i].flow_id != BCM_FLOW_ID_INVALID)
                        {
                            delete_bal_flow(rule->flows[i].flow_id, BCMOLT_FLOW_TYPE_UPSTREAM);
                            rule->flows[i].flow_id = BCM_FLOW_ID_INVALID;
                        }
                    }
                }
            }
        }
    }

    return err;
}


bcmos_errno xpon_apply_flow_create(sr_session_ctx_t *srs, xpon_forwarder *fwd)
{
    xpon_vlan_subif *net_if, *acc_if;
    xpon_v_ani_v_enet *v_ani_v_enet;
    xpon_v_ani *v_ani;
    xpon_obj_hdr *ani_if;
    const xpon_enet *nni;
    bbf_subif_ingress_rule *rule, *rule_tmp;
    uint32_t num_ports;
    bcmos_errno err = BCM_ERR_OK;

    num_ports = xpon_fwd_port_num_of(fwd);
    if (num_ports > 2)
    {
        /* N:1 is not supported for now */
        if (fwd->mac_learning_db == NULL)
        {
            NC_ERROR_REPLY(srs, NULL, "forwarder %s: mac-learning-db must be set for N:1\n", fwd->hdr.name);
            return BCM_ERR_PARM;
        }
    }

    /* if not all ports are configured - stop here */
    if (num_ports < 2)
        return BCM_ERR_OK;

    if (fwd->mac_learning_db != NULL)
    {
        return xpon_apply_n_1_flow_create(srs, fwd);
    }

    /* forwarding between access and network sides */
    net_if = STAILQ_FIRST(&fwd->ports)->subif;
    acc_if = STAILQ_NEXT(STAILQ_FIRST(&fwd->ports), next)->subif;
    if ((net_if->usage == BBF_INTERFACE_USAGE_NETWORK_PORT && acc_if->usage == BBF_INTERFACE_USAGE_NETWORK_PORT) ||
        (net_if->usage != BBF_INTERFACE_USAGE_NETWORK_PORT && acc_if->usage != BBF_INTERFACE_USAGE_NETWORK_PORT))
    {
        NC_ERROR_REPLY(srs, NULL, "forwarder %s: 1 port must be on network and 1 on access side\n", fwd->hdr.name);
        return BCM_ERR_PARM;
    }
    if (net_if->usage != BBF_INTERFACE_USAGE_NETWORK_PORT)
    {
        xpon_vlan_subif *tmp_if = net_if;
        net_if = acc_if;
        acc_if = tmp_if;
    }

    /* paranoya check */
    if (net_if->subif_lower_layer == NULL || acc_if->subif_lower_layer == NULL)
    {
        NC_ERROR_REPLY(srs, NULL, "forwarder %s: something is wrong. subif-lower-layer is not set\n", fwd->hdr.name);
        return BCM_ERR_INTERNAL;
    }

    /* It is expected that acc_if->subif_lower_layer is olt-v-enet */
    if (acc_if->subif_lower_layer->obj_type != XPON_OBJ_TYPE_V_ANI_V_ENET)
    {
        NC_ERROR_REPLY(srs, NULL, "forwarder %s: subif %s belong to interface %s of wrong type. Expected v-olt-v-enet\n",
            fwd->hdr.name, acc_if->hdr.name, acc_if->subif_lower_layer->name);
        return BCM_ERR_PARM;
    }

    if (net_if->subif_lower_layer->obj_type != XPON_OBJ_TYPE_ENET)
    {
        NC_ERROR_REPLY(srs, NULL, "forwarder %s: subif %s belong to interface %s of wrong type. Expected enet\n",
            fwd->hdr.name, net_if->hdr.name, net_if->subif_lower_layer->name);
        return BCM_ERR_PARM;
    }
    nni = (const xpon_enet *)net_if->subif_lower_layer;

    v_ani_v_enet = (xpon_v_ani_v_enet *)acc_if->subif_lower_layer;
    v_ani = v_ani_v_enet->v_ani;
    if (v_ani == NULL)
    {
        NC_ERROR_REPLY(srs, NULL, "forwarder %s: v-ani reference is not set on %s\n",
            fwd->hdr.name, acc_if->subif_lower_layer->name);
        return BCM_ERR_PARM;
    }
    ani_if = v_ani_v_enet->linked_if;

    /* Find GEM for each upstream rule. Each upstream rule will then be paired
       with downstream rule for BAL flow creation
    */
    STAILQ_FOREACH_SAFE(rule, &acc_if->ingress, next, rule_tmp)
    {
        err = xpon_find_rule_gem(srs, acc_if, rule, v_ani_v_enet, BCMOS_TRUE);
        if (err != BCM_ERR_OK)
            break;
    }
    if (err != BCM_ERR_OK)
        return err;

    /* Finally create US and DS BAL flows.
       It is a bit fuzzy.
       Go over upstream rules and find matching downstream rule. After that,
       create BAL bi-directional flow
    */
    STAILQ_FOREACH_SAFE(rule, &acc_if->ingress, next, rule_tmp)
    {
        bbf_subif_ingress_rule *ds_rule;
        bbf_flexible_rewrite actions;
        bbf_flexible_rewrite ds_actions;
        bbf_match_criteria to_match_plus_actions;
        xpon_vlan_subif *onu_subif = NULL;
        bbf_subif_ingress_rule *onu_rule = NULL;

        /* Find matching downstream rule */
        ds_rule = xpon_vlan_subif_ingress_rule_get_match(rule, net_if);
        if (ds_rule == NULL)
        {
            NC_ERROR_REPLY(srs, NULL, "forwarder %s: upstream and downstream don't match\n", fwd->hdr.name);
            err = BCM_ERR_PARM;
            break;
        }

        /* Find matching ONU rule. At least 1 rule must exist */
        if (ani_if != NULL)
        {
            err = xpon_vlan_subif_subif_rule_get_next_match(rule, ani_if,
                &onu_subif, &onu_rule);
            if (err != BCM_ERR_OK)
            {
                NC_ERROR_REPLY(srs, NULL, "forwarder %s: can't find ONU subif matching OLT rule %s\n",
                    fwd->hdr.name, rule->name);
                break;
            }
        }

        /* Now prepare downstream actions */
        ds_rule->ds_rule = BCMOS_TRUE;

        /* Copy GEM assignment from US rules to the DS */
        for(int i = 0; i < BCM_SIZEOFARRAY(ds_rule->flows); i++)
        {
            ds_rule->flows[i].gem = rule->flows[i].gem;
            ds_rule->flows[i].qos_class = rule->flows[i].qos_class;
        }

        /* Downstream actions */
        ds_actions = ds_rule->rewrite;
        err = xpon_merge_actions(&ds_actions, &acc_if->egress_rewrite);
        if (err != BCM_ERR_OK)
            break;

        /* Make sure that actions and classification criteria match. That is,
           Once downstream actions are applied to the downstream classification criteria, the result
           should match the upstream classification criteria */
        to_match_plus_actions = ds_rule->match;
        xpon_apply_actions_to_match(&to_match_plus_actions, &ds_actions);
        if (!xpon_is_match(&to_match_plus_actions, &rule->match))
        {
            NC_ERROR_REPLY(srs, NULL,
                "DS classification rule '%s.%s' + actions doesn't match the US classification rule '%s.%s'\n",
                net_if->hdr.name, ds_rule->name, acc_if->hdr.name, rule->name);
            err = BCM_ERR_PARM;
            break;
        }

        /*
         * Upstream
         */

        /* Upstream actions */
        actions = rule->rewrite;
        err = xpon_merge_actions(&actions, &net_if->egress_rewrite);
        if (err != BCM_ERR_OK)
            break;

        /* Make sure that actions and classification criteria match. That is,
           Once upstream actions are applied to the upstream classification criteria, the result
           should match the downstream classification criteria */
        to_match_plus_actions = rule->match;
        xpon_apply_actions_to_match(&to_match_plus_actions, &actions);
        if (!xpon_is_match(&to_match_plus_actions, &ds_rule->match))
        {
            NC_ERROR_REPLY(srs, NULL,
                "US classification rule '%s.%s' + actions doesn't match the DS classification rule '%s.%s'\n",
                acc_if->hdr.name, rule->name, net_if->hdr.name, ds_rule->name);
            err = BCM_ERR_PARM;
            break;
        }

#ifndef BCM_OPEN_SOURCE
        if (bcmolt_is_per_flow_mode())
        {
            /* Additional validations for per-flow mode */
            err = xpon_iwf_validate_and_find_base_gem(srs, rule, ds_rule, &actions, v_ani);
            if (err != BCM_ERR_OK)
                break;

            /* Create upstream IWF flows and a single upstream BAL flow if in per-flow mode. */
            err = xpon_iwf_create_us_flows(srs, rule, &actions, v_ani, BCMOLT_VLAN_TO_FLOW_MAPPING_METHOD_VID);
            if (err != BCM_ERR_OK)
                break;

            /* Create a single BAL flow without actions. Header manipulation is done by the IWF,
             * hence we use ds_rule in both US and DS directions */
            err = xpon_create_bal_flow(srs, BCMOLT_FLOW_TYPE_UPSTREAM, ds_rule, NULL, nni, v_ani, 0);
            if (err != BCM_ERR_OK)
                break;
        }
        else
#endif /* #ifndef BCM_OPEN_SOURCE */
        {
            /* Create a BAL flow per traffic class */
            err = xpon_create_bal_flows(srs, BCMOLT_FLOW_TYPE_UPSTREAM, rule, &actions,
                nni, v_ani, BCM_GROUP_ID_INVALID);
            if (err != BCM_ERR_OK)
                break;
        }

        /*
         * Downstream
         */

        /* Copy flow assignment from US rules to the DS */
        ds_rule->base_gemport_id = rule->base_gemport_id;
        for(int i = 0; i < BCM_SIZEOFARRAY(ds_rule->flows); i++)
        {
            ds_rule->flows[i].flow_id = rule->flows[i].flow_id;
        }

#ifndef BCM_OPEN_SOURCE
        /* Create downstream IWF flows and a single BAL flow if in per-flow mode */
        if (bcmolt_is_per_flow_mode())
        {
            err = xpon_iwf_create_ds_flows(srs, ds_rule, &ds_actions, v_ani, BCMOLT_VLAN_TO_FLOW_MAPPING_METHOD_VID);
            if (err != BCM_ERR_OK)
                break;

            /* Create a single BAL flow without actions. Packet header manipulation is done by the IWF */
            err = xpon_create_bal_flow(srs, BCMOLT_FLOW_TYPE_DOWNSTREAM, ds_rule, NULL, nni, v_ani, 0);
            if (err != BCM_ERR_OK)
                break;
        }
        else
#endif /* #ifndef BCM_OPEN_SOURCE */
        {
            /* Create BAL downstream flows, 1 per traffic class */
            err = xpon_create_bal_flows(srs, BCMOLT_FLOW_TYPE_DOWNSTREAM, ds_rule, &ds_actions,
                nni, v_ani, BCM_GROUP_ID_INVALID);
            if (err != BCM_ERR_OK)
                break;
        }


        /* If DS flow contains a DHCP relay profile reference - create a DHCP relay flow */
        if (acc_if->dhcpr.enabled && acc_if->dhcpr.profile != NULL)
        {
            err = xpon_create_dhcpr_interface(srs, acc_if, ds_rule, rule, nni, v_ani);
            if (err != BCM_ERR_OK)
                break;
        }

        /* Create ONU flows if not done yet */
        if (ani_if != NULL && v_ani->registered)
        {
            /* Go over all matching ONU subifs and rules and create flows */
            onu_subif = NULL;
            onu_rule = NULL;
            xpon_vlan_subif_subif_rule_get_next_match(rule, ani_if, &onu_subif, &onu_rule);
            while (onu_rule != NULL)
            {
                err = xpon_create_onu_flows(srs, v_ani, v_ani_v_enet, onu_subif, onu_rule);
                if (err != BCM_ERR_OK)
                    break;
                xpon_vlan_subif_subif_rule_get_next_match(rule, ani_if, &onu_subif, &onu_rule);
            }
        }
    }

    return err;
}
