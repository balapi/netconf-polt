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
 * bbf-xpon.c
 */
#include <bcmos_system.h>
#include <bcmolt_netconf_module_utils.h>
#include "bbf-xpon-internal.h"
#include <bcmos_hash_table.h>

static bcmos_mutex xpon_lock;
static hash_table *object_hash;
static hash_table *vlan_hash;

#define MAX_INTERFACE_NAME_LENGTH   32
#define XPON_OBJ_HASH_KEY_LENGTH    MAX_INTERFACE_NAME_LENGTH

typedef struct xpon_vlan_key
{
    bcmolt_interface pon_ni;
    uint16_t vlan;
} xpon_vlan_key;

typedef struct xpon_vlan_entry
{
    bcmolt_flow_id flow_id;
} xpon_vlan_entry;

/* TODO: ideally would be to expose BAL's max_num_of_flows and a few other limits through
   OLT object. Using a constant for now.
*/
#define XPON_MAX_FLOWS              4096


static uint16_t number_of_pons;
static bcmolt_topology_map olt_topology_maps[BCM_MAX_PONS_PER_OLT];

typedef struct xpon_scheduled_request xpon_scheduled_request;
struct xpon_scheduled_request
{
    bcmolt_msg *msg;
    bbf_xpon_request_type type;
    bcmos_timer timer;
    TAILQ_ENTRY(xpon_scheduled_request) next;
};

static TAILQ_HEAD(, xpon_scheduled_request) scheduled_request_list;
static bcmos_mutex scheduled_request_lock;

/*
 * Protection lock
 */
void bbf_xpon_lock(void)
{
    bcmos_mutex_lock(&xpon_lock);
}

void bbf_xpon_unlock(void)
{
    bcmos_mutex_unlock(&xpon_lock);
}


/*
 * Interface lookup service
 */

static uint8_t *xpon_interface_hash_key(const char *name, uint8_t *key)
{
    memset(key, 0, XPON_OBJ_HASH_KEY_LENGTH);
    strncpy((char *)key, name, MAX_INTERFACE_NAME_LENGTH);
    return key;
}

static bcmos_errno xpon_object_alloc(const char *name, xpon_obj_type obj_type, uint32_t size, xpon_obj_hdr **p_obj)
{
    char *p_name;
    *p_obj = bcmos_calloc(size + strlen(name) + 1);
    if (*p_obj == NULL)
        return BCM_ERR_NOMEM;
    p_name = (char *)(*p_obj) + size;
    strcpy(p_name, name);
    (*p_obj)->name = p_name;
    (*p_obj)->obj_type = obj_type;
    return BCM_ERR_OK;
}

static void xpon_object_free(xpon_obj_hdr *obj)
{
    bcmos_free(obj);
}

/* Map TR-385 if-type to the internal xpon_obj_type */
xpon_obj_type xpon_iftype_to_obj_type(const char *iftype)
{
    xpon_obj_type obj_type;
    if (!strcmp(iftype, BBF_XPON_IFTYPE_CHANNEL_GROUP))
        obj_type = XPON_OBJ_TYPE_CGROUP;
    else if (!strcmp(iftype, BBF_XPON_IFTYPE_CHANNEL_PARTITION))
        obj_type = XPON_OBJ_TYPE_CPART;
    else if (!strcmp(iftype, BBF_XPON_IFTYPE_CHANNEL_PAIR))
        obj_type = XPON_OBJ_TYPE_CPAIR;
    else if (!strcmp(iftype, BBF_XPON_IFTYPE_CHANNEL_TERMINATION))
        obj_type = XPON_OBJ_TYPE_CTERM;
    else if (!strcmp(iftype, BBF_XPON_IFTYPE_V_ANI))
        obj_type = XPON_OBJ_TYPE_V_ANI;
    else if (!strcmp(iftype, BBF_XPON_IFTYPE_ANI))
        obj_type = XPON_OBJ_TYPE_ANI;
    else if (!strcmp(iftype, BBF_XPON_IFTYPE_OLT_V_ENET))
        obj_type = XPON_OBJ_TYPE_V_ANI_V_ENET;
    else if (!strcmp(iftype, BBF_XPON_IFTYPE_ONU_V_ENET))
        obj_type = XPON_OBJ_TYPE_ANI_V_ENET;
    else if (!strcmp(iftype, IANA_IFTYPE_ENET))
        obj_type = XPON_OBJ_TYPE_ENET;
    else if (!strcmp(iftype, BBF_IFTYPE_VLAN_SUBIF))
        obj_type = XPON_OBJ_TYPE_VLAN_SUBIF;
    else
        obj_type = XPON_OBJ_TYPE_INVALID;
    return obj_type;
}

const char *xpon_obj_type_to_str(xpon_obj_type obj_type)
{
    static const char *obj_type_name[] = {
        [XPON_OBJ_TYPE_ENET]                    = "ENET",
        [XPON_OBJ_TYPE_CGROUP]                  = "CGROUP",
        [XPON_OBJ_TYPE_CPART]                   = "CPART",
        [XPON_OBJ_TYPE_CPAIR]                   = "CPAIR",
        [XPON_OBJ_TYPE_CTERM]                   = "CTERM",
        [XPON_OBJ_TYPE_V_ANI]                   = "V-ANI",
        [XPON_OBJ_TYPE_ANI]                     = "ANI",
        [XPON_OBJ_TYPE_V_ANI_V_ENET]            = "V-ANI-V-ENET",
        [XPON_OBJ_TYPE_ANI_V_ENET]              = "ANI_V_ENET",
        [XPON_OBJ_TYPE_VLAN_SUBIF]              = "VLAN-SUBIF",
        [XPON_OBJ_TYPE_TCONT]                   = "TCONT",
        [XPON_OBJ_TYPE_GEM]                     = "GEM",
        [XPON_OBJ_TYPE_WAVELENGTH_PROFILE]      = "WAVELENGTH-PROFILE",
        [XPON_OBJ_TYPE_TRAFFIC_DESCR_PROFILE]   = "TRAFFIC_DESCR_PROFILE",
        [XPON_OBJ_TYPE_QOS_CLASSIFIER]          = "QOS_CLASSIFIER",
        [XPON_OBJ_TYPE_QOS_POLICY]              = "QOS_POLICY",
        [XPON_OBJ_TYPE_QOS_POLICY_PROFILE]      = "QOS_POLICY_PROFILE",
        [XPON_OBJ_TYPE_FORWARDER_PORT]          = "FORWARDER_PORT",
        [XPON_OBJ_TYPE_FORWARDER]               = "FORWARDER",
        [XPON_OBJ_TYPE_FWD_SPLIT_HORIZON_PROFILE] = "FWD_SPLIT_HORIZON_PROFILE",
        [XPON_OBJ_TYPE_FWD_DB]                  = "FWD_DB",
        [XPON_OBJ_TYPE_HARDWARE]                = "HARDWARE",
        [XPON_OBJ_TYPE_DHCPR_PROFILE]           = "DHCP-PROFILE",
    };
    static const char *obj_type_invalid = "INVALID";
    if (obj_type >= XPON_OBJ_TYPE__FIRST && obj_type <= XPON_OBJ_TYPE__LAST)
        return obj_type_name[obj_type];
    else
        return obj_type_invalid;
}

bbf_interface_usage xpon_map_iface_usage(const char *usage_str)
{
    bbf_interface_usage usage = BBF_INTERFACE_USAGE_UNDEFINED;
    if (usage_str != NULL)
    {
        if (!strcmp(usage_str, "network-port"))
            usage = BBF_INTERFACE_USAGE_NETWORK_PORT;
        else if (!strcmp(usage_str, "subtended-node-port"))
            usage = BBF_INTERFACE_USAGE_SUBTENDED_NODE_PORT;
        else if (!strcmp(usage_str, "inherit"))
            usage = BBF_INTERFACE_USAGE_INHERIT;
    }
    return usage;
}

/* Add interface to hash */
bcmos_errno xpon_object_add(xpon_obj_hdr *hdr)
{
    uint8_t keybuf[XPON_OBJ_HASH_KEY_LENGTH];
    uint8_t *key = xpon_interface_hash_key(hdr->name, keybuf);
    bcmos_errno err;

    bbf_xpon_lock();
    if (hash_table_get(object_hash, key) != NULL)
    {
        err = BCM_ERR_ALREADY;
    }
    else
    {
        if (hash_table_put(object_hash, key, &hdr) != NULL)
            err = BCM_ERR_OK;
        else
            err = BCM_ERR_NOMEM;
    }
    bbf_xpon_unlock();
    NC_LOG_DBG("Added object %s, type %d. %s\n", hdr->name, hdr->obj_type, bcmos_strerror(err));
    return err;
}

/* Find interface object by name */
bcmos_errno xpon_object_get(const char *name, xpon_obj_hdr **p_hdr)
{
    uint8_t keybuf[XPON_OBJ_HASH_KEY_LENGTH];
    uint8_t *key = xpon_interface_hash_key(name, keybuf);
    xpon_obj_hdr **p_stored_hdr;

    p_stored_hdr = (xpon_obj_hdr **)hash_table_get(object_hash, key);
    NC_LOG_DBG("Looking up object %s. %s\n", name, p_stored_hdr ? "FOUND" : "NOT FOUND");

    if (p_stored_hdr == NULL)
        return BCM_ERR_NOENT;
    *p_hdr = *p_stored_hdr;
    return BCM_ERR_OK;
}

/* Remove interface from the hash */
bcmos_errno xpon_object_delete(xpon_obj_hdr *hdr)
{
    uint8_t keybuf[XPON_OBJ_HASH_KEY_LENGTH];
    uint8_t *key = xpon_interface_hash_key(hdr->name, keybuf);
    bcmos_bool removed;
    bbf_xpon_lock();
    removed = hash_table_remove(object_hash, key);
    bbf_xpon_unlock();
    NC_LOG_DBG("Deleted object %s. found=%d\n", hdr->name, removed);
    if (removed)
        xpon_object_free(hdr);
    return removed ? BCM_ERR_OK : BCM_ERR_NOENT;
}

bcmos_errno xpon_object_get_or_add(const char *name, xpon_obj_type obj_type, uint32_t obj_size,
    xpon_obj_hdr **p_hdr, bcmos_bool *is_added)
{
    bcmos_errno err;

    if (name==NULL || p_hdr==NULL)
        return BCM_ERR_PARM;

    bbf_xpon_lock();

    err = xpon_object_get(name, p_hdr);
    if (err == BCM_ERR_OK)
    {
        if ((*p_hdr)->obj_type != obj_type)
        {
            BCMOS_TRACE_ERR("Found object of wrong type. Name %s\n", name);
            err = BCM_ERR_INTERNAL;
        }
        if (is_added)
            *is_added = BCMOS_FALSE;
        bbf_xpon_unlock();
        return BCM_ERR_OK;
    }

    /* Not found. Add */
    if (is_added != NULL)
    {
        xpon_obj_hdr *obj;
        err = xpon_object_alloc(name, obj_type, obj_size, &obj);
        if (err == BCM_ERR_OK)
        {
            err = xpon_object_add(obj);
            if (err == BCM_ERR_OK)
            {
                *is_added = BCMOS_TRUE;
                *p_hdr = obj;
            }
            else
            {
                bcmos_free(obj);
            }
        }
    }

    bbf_xpon_unlock();

    return err;
}

/* merge match criteria */
bcmos_errno xpon_merge_match(bbf_match_criteria *match, const bbf_match_criteria *with_match)
{
    int i;

    /* Merge common tags */
    for (i = 0; i < match->vlan_tag_match.num_tags; i++)
    {
        bbf_dot1q_tag *tag = &match->vlan_tag_match.tags[i];
        const bbf_dot1q_tag *with_tag = &with_match->vlan_tag_match.tags[i];

        if (i >= with_match->vlan_tag_match.num_tags)
            break;
        if (with_match->vlan_tag_match.tag_match_types[i] == BBF_VLAN_TAG_MATCH_TYPE_ALL)
            continue;
        if (BBF_DOT1Q_TAG_PROP_IS_SET(with_tag, vlan_id))
        {
            /* Make sure that match and with_match are compatible */
            if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, vlan_id) && tag->vlan_id != with_tag->vlan_id)
                goto error;
            BBF_DOT1Q_TAG_PROP_SET(tag, vlan_id, with_tag->vlan_id);
        }
        if (BBF_DOT1Q_TAG_PROP_IS_SET(with_tag, pbit))
        {
            /* Make sure that match and with_match are compatible */
            if (BBF_DOT1Q_TAG_PROP_IS_SET(tag, pbit) && tag->pbit != with_tag->pbit)
                goto error;
            BBF_DOT1Q_TAG_PROP_SET(tag, pbit, with_tag->pbit);
        }
        if (BBF_DOT1Q_TAG_PROP_IS_SET(with_tag, dei))
        {
            BBF_DOT1Q_TAG_PROP_SET(tag, dei, with_tag->dei);
        }
    }

    /* Copy the renaming tags */
    for ( ;  i < with_match->vlan_tag_match.num_tags; i++)
    {
        match->vlan_tag_match.tags[i] = with_match->vlan_tag_match.tags[i];
        match->vlan_tag_match.tag_match_types[i] = with_match->vlan_tag_match.tag_match_types[i];
        ++match->vlan_tag_match.num_tags;
    }

    return BCM_ERR_OK;

error:
    NC_LOG_ERR("Internal error. Can't merge incompatible match criteria\n");
    return BCM_ERR_INTERNAL;
}

/* merge VLAN actions */
bcmos_errno xpon_merge_actions(bbf_flexible_rewrite *actions, const bbf_flexible_rewrite *with_actions)
{
    bcmos_errno err = BCM_ERR_OK;
    actions->num_pop_tags += with_actions->num_pop_tags;
    if (with_actions->num_push_tags)
    {
        for (int i = 0; i < with_actions->num_push_tags; i++)
        {
            const bbf_dot1q_tag *with_tag = &with_actions->push_tags[i];
            if (BBF_DOT1Q_TAG_PROP_IS_SET(with_tag, tag_type))
            {
                /* Really adding a tag */
                if (actions->num_push_tags >= 2)
                {
                    err = BCM_ERR_PARM;
                    break;
                }
                actions->push_tags[actions->num_push_tags++] = with_actions->push_tags[i];
            }
            else
            {
                /* Merge push tag */
                if (BBF_DOT1Q_TAG_PROP_IS_SET(with_tag, vlan_id))
                    BBF_DOT1Q_TAG_PROP_SET(&actions->push_tags[i], vlan_id, with_tag->vlan_id);
                if (BBF_DOT1Q_TAG_PROP_IS_SET(with_tag, pbit))
                    BBF_DOT1Q_TAG_PROP_SET(&actions->push_tags[i], pbit, with_tag->pbit);
                if (BBF_DOT1Q_TAG_PROP_IS_SET(with_tag, dei))
                    BBF_DOT1Q_TAG_PROP_SET(&actions->push_tags[i], dei, with_tag->dei);
            }
        }
    }
    return err;
}

/* Compare actions */
bcmos_bool xpon_is_actions_match(const bbf_flexible_rewrite *actions1, const bbf_flexible_rewrite *actions2)
{
    int i;
    if (actions1->num_pop_tags != actions2->num_pop_tags ||
        actions1->num_push_tags != actions2->num_push_tags)
    {
        return BCMOS_FALSE;
    }
    for (i = 0; i < actions1->num_push_tags; i++)
    {
        if (actions1->push_tags[i].tag_type != actions2->push_tags[i].tag_type  ||
            actions1->push_tags[i].vlan_id != actions2->push_tags[i].vlan_id    ||
            actions1->push_tags[i].pbit != actions2->push_tags[i].pbit          ||
            actions1->push_tags[i].dei != actions2->push_tags[i].dei)
        {
            return BCMOS_FALSE;
        }
    }
    return BCMOS_TRUE;
}

/* pop tags */
static void xpon_pop_tags_from_match(bbf_match_criteria *match, uint8_t num_pop_tags)
{
    int i;
    if (!num_pop_tags)
        return;
    if (num_pop_tags > match->vlan_tag_match.num_tags)
        num_pop_tags = match->vlan_tag_match.num_tags;
    for (i = 0; i < num_pop_tags; i++)
    {
        match->vlan_tag_match.tags[i] = match->vlan_tag_match.tags[i + 1];
        match->vlan_tag_match.tag_match_types[i] = match->vlan_tag_match.tag_match_types[i + 1];
    }
    for ( ; i < 2; i++)
    {
        match->vlan_tag_match.tag_match_types[i] = BBF_VLAN_TAG_MATCH_TYPE_ALL;
    }
    match->vlan_tag_match.num_tags -= num_pop_tags;
}

/* push tags */
static void xpon_push_tags_to_match(bbf_match_criteria *match, uint8_t num_push_tags, const bbf_dot1q_tag *tags)
{
    int i;
    if (num_push_tags + match->vlan_tag_match.num_tags > 2)
        num_push_tags = 2 - match->vlan_tag_match.num_tags;
    if (!num_push_tags)
        return;
    /* We push OUTER tag, so need to shift all existing tags */
    if (match->vlan_tag_match.num_tags)
    {
        for (i = match->vlan_tag_match.num_tags - 1; i >= 0; i--)
        {
            match->vlan_tag_match.tags[i + num_push_tags] = match->vlan_tag_match.tags[i];
            match->vlan_tag_match.tag_match_types[i + num_push_tags] = match->vlan_tag_match.tag_match_types[i];
        }
    }
    for (i = 0; i < num_push_tags; i++)
    {
        match->vlan_tag_match.tags[i] = tags[i];
        match->vlan_tag_match.tag_match_types[i] = BBF_VLAN_TAG_MATCH_TYPE_VLAN_TAGGED;
    }
    match->vlan_tag_match.num_tags += num_push_tags;
}

/* apply actions to match */
void xpon_apply_actions_to_match(bbf_match_criteria *match, const bbf_flexible_rewrite *actions)
{
    xpon_pop_tags_from_match(match, actions->num_pop_tags);
    xpon_push_tags_to_match(match, actions->num_push_tags, actions->push_tags);
}

/* check that packet matching "from" also matches "to" */
bcmos_bool xpon_is_match(const bbf_match_criteria *from, const bbf_match_criteria *to)
{
    int i;

    /* TODO: add more match types */
    if (to->vlan_tag_match.num_tags > from->vlan_tag_match.num_tags)
        return BCMOS_FALSE;
    for (i = 0; i < to->vlan_tag_match.num_tags; i++)
    {
        const bbf_dot1q_tag *from_tag = &from->vlan_tag_match.tags[i];
        const bbf_dot1q_tag *to_tag = &to->vlan_tag_match.tags[i];
        if (to->vlan_tag_match.tag_match_types[i] == BBF_VLAN_TAG_MATCH_TYPE_ALL)
            continue;
        if (to->vlan_tag_match.tag_match_types[i] != from->vlan_tag_match.tag_match_types[i])
            return BCMOS_FALSE;
        /* Compare tags */
        if (BBF_DOT1Q_TAG_PROP_IS_SET(to_tag, tag_type) &&
            (!BBF_DOT1Q_TAG_PROP_IS_SET(from_tag, tag_type) || to_tag->tag_type != from_tag->tag_type))
        {
            return BCMOS_FALSE;
        }
        if (BBF_DOT1Q_TAG_PROP_IS_SET(to_tag, vlan_id) &&
            (!BBF_DOT1Q_TAG_PROP_IS_SET(from_tag, vlan_id) || to_tag->vlan_id != from_tag->vlan_id))
        {
            return BCMOS_FALSE;
        }
        /* Note that pbit and dei are checked differently. if not set in "from" - it is considered a match */
        if (BBF_DOT1Q_TAG_PROP_IS_SET(to_tag, pbit) && BBF_DOT1Q_TAG_PROP_IS_SET(from_tag, pbit) &&
            to_tag->pbit != from_tag->pbit)
        {
            return BCMOS_FALSE;
        }
        if (BBF_DOT1Q_TAG_PROP_IS_SET(to_tag, dei) && BBF_DOT1Q_TAG_PROP_IS_SET(from_tag, dei) &&
            to_tag->dei != from_tag->dei)
        {
            return BCMOS_FALSE;
        }
    }
    return BCMOS_TRUE;
}

/* Parse & add flexible match attribute */
bcmos_errno xpon_add_flexible_match(sr_session_ctx_t *srs, bbf_match_criteria *match, const char *xpath,
    sr_val_t *old_val, sr_val_t *new_val)
{
    sr_val_t *val = (new_val != NULL) ? new_val : old_val;
    char leafbuf[BCM_MAX_LEAF_LENGTH];
    const char *leaf = nc_xpath_leaf_get(xpath, leafbuf, sizeof(leafbuf));
    bcmos_errno err = BCM_ERR_OK;

    do
    {
        if (strstr(xpath, "untagged") != NULL)
        {
            match->vlan_tag_match.tag_match_types[0] = BBF_VLAN_TAG_MATCH_TYPE_UNTAGGED;
            match->vlan_tag_match.num_tags = 0;
        }
        else if (strstr(xpath, "tag[index") != NULL)
        {
            char index_str[16] = "";
            bbf_tag_index_type tag_index;
            bbf_dot1q_tag *tag;

            nc_xpath_key_get(xpath, "index", index_str, sizeof(index_str));
            /* Only indexes 0 and 1 are supported */
            if (!strcmp(index_str, "0"))
                tag_index = BBF_TAG_INDEX_TYPE_OUTER;
            else if (!strcmp(index_str, "1"))
                tag_index = BBF_TAG_INDEX_TYPE_INNER;
            else
            {
                NC_ERROR_REPLY(srs, xpath, "tag index %s is invalid\n", index_str);
                err = BCM_ERR_PARM;
                break;
            }
            tag = &match->vlan_tag_match.tags[tag_index];

            /* No go over supported leafs */
            if (!strcmp(leaf, "vlan-id"))
            {
                match->vlan_tag_match.tag_match_types[tag_index] = BBF_VLAN_TAG_MATCH_TYPE_VLAN_TAGGED;
                if (!strcmp(xpath, "/priority-tagged"))
                    BBF_DOT1Q_TAG_PROP_SET(tag, vlan_id, 0);
                else if (strcmp(xpath, "/any"))
                {
                    BUG_ON(val->type != SR_STRING_T);
                    BUG_ON(val->data.string_val == NULL);
                    if (strchr(val->data.string_val, ',') || strchr(val->data.string_val, '-'))
                    {
                        NC_ERROR_REPLY(srs, xpath, "vlan-id groups are not supported: %s\n", val->data.string_val);
                        err = BCM_ERR_NOT_SUPPORTED;
                        break;
                    }
                    BBF_DOT1Q_TAG_PROP_SET(tag, vlan_id, (uint16_t)strtoul(val->data.string_val, NULL, 0));
                }
            }
            else if (!strcmp(leaf, "tag-type"))
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
            else if (!strcmp(leaf, "pbit") || !strcmp(leaf, "dei"))
            {
                if (val->type == SR_ENUM_T)
                {
                    if (strcmp(val->data.enum_val, "any"))
                    {
                        NC_ERROR_REPLY(srs, xpath, "classification by %s=%s is not supported\n",
                            leaf, val->data.enum_val);
                        err = BCM_ERR_NOT_SUPPORTED;
                    }
                    break;
                }
                else if (val->type == SR_STRING_T)
                {
                    char *p_end = NULL;
                    long num_val;

                    num_val = strtol(val->data.string_val, &p_end, 0);
                    if (p_end != NULL && *p_end)
                    {
                        NC_ERROR_REPLY(srs, xpath, "classification by %s=%s is not supported\n",
                            leaf, val->data.string_val);
                        err = BCM_ERR_NOT_SUPPORTED;
                    }
                    if (num_val > 7)
                    {
                        NC_ERROR_REPLY(srs, xpath, "classification by %s=%s: pbit is out of range\n",
                            leaf, val->data.string_val);
                        err = BCM_ERR_PARM;
                    }
                    BBF_DOT1Q_TAG_PROP_SET(tag, pbit, num_val);
                }
            }
            if (match->vlan_tag_match.num_tags < tag_index + 1)
                match->vlan_tag_match.num_tags = tag_index + 1;
        }
        else if (strstr(xpath, "ethernet-frame-type") != NULL)
        {
            if (val->type == SR_ENUM_T)
            {
                if (!strcmp(val->data.enum_val, "pppoe"))
                    match->protocol_match.match_type |= BBF_PROTOCOL_MATCH_PPPOE_DATA | BBF_PROTOCOL_MATCH_PPPOE_DISCOVERY;
                else if (!strcmp(val->data.enum_val, "ipv4"))
                    match->protocol_match.match_type |= BBF_PROTOCOL_MATCH_IPV4;
                else if (!strcmp(val->data.enum_val, "ipv6"))
                    match->protocol_match.match_type |= BBF_PROTOCOL_MATCH_IPV6;
                else if (strcmp(val->data.enum_val, "any"))
                {
                    NC_ERROR_REPLY(srs, xpath, "classification by ethernet-frame-type '%s' is not supported\n",
                        val->data.enum_val);
                    err = BCM_ERR_NOT_SUPPORTED;
                    break;
                }
            }
            else if (val->type == SR_UINT16_T)
            {
                match->protocol_match.match_type |= BBF_PROTOCOL_MATCH_SPECIFIC;
                match->protocol_match.ether_type = val->data.uint16_val;
            }
        }
        else if (strstr(xpath, "protocol-match") != NULL)
        {
            if (val->type == SR_ENUM_T)
            {
                if (!strcmp(val->data.enum_val, "arp"))
                    match->protocol_match.match_type |= BBF_PROTOCOL_MATCH_ARP;
                else if (!strcmp(val->data.enum_val, "igmp"))
                    match->protocol_match.match_type |= BBF_PROTOCOL_MATCH_IGMP;
                else if (!strcmp(val->data.enum_val, "mld"))
                    match->protocol_match.match_type |= BBF_PROTOCOL_MATCH_MLD;
                else if (!strcmp(val->data.enum_val, "dhcpv4"))
                    match->protocol_match.match_type |= BBF_PROTOCOL_MATCH_DHCPV4;
                else if (!strcmp(val->data.enum_val, "dhcpv6"))
                    match->protocol_match.match_type |= BBF_PROTOCOL_MATCH_DHCPV6;
                else if (!strcmp(val->data.enum_val, "pppoe-discovery"))
                    match->protocol_match.match_type |= BBF_PROTOCOL_MATCH_PPPOE_DISCOVERY;
                else if (!strcmp(val->data.enum_val, "dot1x"))
                    match->protocol_match.match_type |= BBF_PROTOCOL_MATCH_DOT1X;
                else if (!strcmp(val->data.enum_val, "lacp"))
                    match->protocol_match.match_type |= BBF_PROTOCOL_MATCH_LACP;
                else if (strcmp(val->data.enum_val, "any-protocol"))
                {
                    NC_ERROR_REPLY(srs, xpath, "classification by protocol-match '%s' is not supported\n",
                        val->data.enum_val);
                    err = BCM_ERR_NOT_SUPPORTED;
                    break;
                }
            }
            if ((match->protocol_match.match_type & (match->protocol_match.match_type - 1)) != 0)
            {
                NC_ERROR_REPLY(srs, xpath, "Matching by multiple protocols and/or ethernet-frame-types is not supported\n");
                err = BCM_ERR_NOT_SUPPORTED;
            }
        }
    } while (0);
    return err;
}

/* Check symmetric tag match */
static bcmos_bool xpon_tags_is_match(const bbf_dot1q_tag *tag1, const bbf_dot1q_tag *tag2)
{
    /* Compare tags */
    if (BBF_DOT1Q_TAG_PROP_IS_SET(tag1, tag_type) != BBF_DOT1Q_TAG_PROP_IS_SET(tag2, tag_type) ||
        tag1->tag_type != tag2->tag_type)
    {
        return BCMOS_FALSE;
    }
    if (BBF_DOT1Q_TAG_PROP_IS_SET(tag1, vlan_id) != BBF_DOT1Q_TAG_PROP_IS_SET(tag2, vlan_id)    ||
        tag1->vlan_id != tag2->vlan_id)
    {
        return BCMOS_FALSE;
    }
    /* Note that PROP_IS_SET is not checked for to_tag's pbit and dei intentionally.
        pbit and dei can be set by action leading to false negative.
        The below checks will find if default value of 0 was changed
    */
    if (tag1->pbit != tag2->pbit)
        return BCMOS_FALSE;
    if (tag1->dei != tag2->dei)
        return BCMOS_FALSE;
    return BCMOS_TRUE;
}

static void xpon_add_pop_tags_to_actions(bbf_flexible_rewrite *action, uint8_t num_pop_tags)
{
    action->num_pop_tags += num_pop_tags;
}

static void xpon_add_push_tags_to_actions(bbf_flexible_rewrite *action, uint8_t num_push_tags, const bbf_dot1q_tag *tags)
{
    int i;
    if (!num_push_tags)
        return;
    if (num_push_tags + action->num_push_tags > 2)
        num_push_tags = 2 - action->num_push_tags;
    for (i = 0; i < num_push_tags; i++)
        action->push_tags[action->num_push_tags++] = tags[i];
}

/* Calculate action that translates from_match into to_match */
bcmos_errno xpon_match_diff(const bbf_match_criteria *from_match, const bbf_match_criteria *to_match,
    bbf_flexible_rewrite *actions)
{
    memset(actions, 0, sizeof(*actions));
    if (to_match->vlan_tag_match.num_tags > from_match->vlan_tag_match.num_tags)
    {
        /* we need to push some tags */
        if (from_match->vlan_tag_match.num_tags)
        {
            /* if from_tag matches inner to tag, we just need to push 1 tag.
               Otherwise, we need to pop the old tag and push 2 */
            if (xpon_tags_is_match(
                    &to_match->vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_INNER],
                    &from_match->vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_OUTER]))
            {
                xpon_add_push_tags_to_actions(actions, 1, &to_match->vlan_tag_match.tags[0]);
            }
            else
            {
                xpon_add_pop_tags_to_actions(actions, 1);
                xpon_add_push_tags_to_actions(actions, to_match->vlan_tag_match.num_tags,
                    &to_match->vlan_tag_match.tags[0]);
            }
        }
        else
        {
            /* just push all tags */
            xpon_add_push_tags_to_actions(actions, to_match->vlan_tag_match.num_tags,
                &to_match->vlan_tag_match.tags[0]);
        }
    }
    else if (to_match->vlan_tag_match.num_tags == from_match->vlan_tag_match.num_tags)
    {
        if (to_match->vlan_tag_match.num_tags)
        {
            /* If inner tag doesn't match - strip and replace all
                otherwise, strip and replace only outer */
            if (!xpon_tags_is_match(
                    &to_match->vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_INNER],
                    &from_match->vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_INNER]))
            {
                xpon_add_pop_tags_to_actions(actions, to_match->vlan_tag_match.num_tags);
                xpon_add_push_tags_to_actions(actions, to_match->vlan_tag_match.num_tags,
                    &to_match->vlan_tag_match.tags[0]);
            }
            else if (!xpon_tags_is_match(
                &to_match->vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_OUTER],
                &from_match->vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_OUTER]))
            {
                xpon_add_pop_tags_to_actions(actions, 1);
                xpon_add_push_tags_to_actions(actions, 1, &to_match->vlan_tag_match.tags[0]);
            }
        }
    }
    else
    {
        /* to_tags < from_tags */
        xpon_add_pop_tags_to_actions(actions, 1);
        if (to_match->vlan_tag_match.num_tags)
        {
            /* if inner from_tag matches outer to tag, we just need to pop 1 tag (already done).
                Otherwise, we need to pop the old tag and push the replacementcd */
            if (!xpon_tags_is_match(
                    &to_match->vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_OUTER],
                    &from_match->vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_INNER]))
            {
                xpon_add_pop_tags_to_actions(actions, 1);
                xpon_add_push_tags_to_actions(actions, to_match->vlan_tag_match.num_tags,
                    &to_match->vlan_tag_match.tags[0]);
            }
        }
        else
        {
            /* just pop all tags */
            xpon_add_pop_tags_to_actions(actions, from_match->vlan_tag_match.num_tags);
        }
    }

    return BCM_ERR_OK;
}


/* Get OLT topology */
bcmos_errno xpon_get_olt_topology(bcmolt_topology *topo)
{
    bcmolt_olt_cfg olt_cfg;
    bcmolt_olt_key key = {};
    uint8_t buf[1024];
    bcmos_errno err;
    int i;

    BCMOLT_CFG_INIT(&olt_cfg, olt, key);
    BCMOLT_FIELD_SET_PRESENT(&olt_cfg.data, olt_cfg_data, topology);
    BCMOLT_CFG_LIST_BUF_SET(&olt_cfg, olt, buf, sizeof(buf));
    err = bcmolt_cfg_get(netconf_agent_olt_id(), &olt_cfg.hdr);
    if (err != BCM_ERR_OK)
    {
        NC_LOG_ERR("Failed to read OLT topology. Error %s\n", bcmos_strerror(err));
        return err;
    }
    if (olt_cfg.data.topology.topology_maps.len > BCM_MAX_PONS_PER_OLT)
    {
        NC_LOG_ERR("OLT topology map length %u is insane\n", olt_cfg.data.topology.topology_maps.len);
        return BCM_ERR_INTERNAL;
    }
    for (i = 0; i < olt_cfg.data.topology.topology_maps.len; i++)
        olt_topology_maps[i] = olt_cfg.data.topology.topology_maps.arr[i];

    topo->num_switch_ports = olt_cfg.data.topology.num_switch_ports;
    topo->topology_maps.arr = olt_topology_maps;
    topo->topology_maps.len = olt_cfg.data.topology.topology_maps.len;
    return BCM_ERR_OK;
}

/* Get total number of PONs in the system */
uint16_t xpon_get_number_of_pons(void)
{
    bcmolt_topology topo;
    bcmos_errno err;

    if (number_of_pons)
    {
        return number_of_pons;
    }

    err = xpon_get_olt_topology(&topo);
    if (err != BCM_ERR_OK)
        return 0;

    number_of_pons = topo.topology_maps.len;

    return number_of_pons;
}

/* Get tm_sched ID for an interface */
bcmolt_tm_sched_id xpon_tm_sched_id(bcmolt_interface_type type, bcmolt_interface ni)
{
    if (type == BCMOLT_INTERFACE_TYPE_NNI)
        return ni;
    return ni + 16;
}

/* Create tm_sched for PON or NNI interface with queue per traffic class */
bcmos_errno xpon_tm_sched_create(bcmolt_interface_type type, bcmolt_interface ni)
{
    bcmolt_tm_sched_cfg tm_sched_cfg;
    bcmolt_tm_sched_key tm_sched_key = {.id = xpon_tm_sched_id(type, ni)};
    int tc;
    bcmos_errno err;

    BCMOLT_CFG_INIT(&tm_sched_cfg, tm_sched, tm_sched_key);

    BCMOLT_MSG_FIELD_SET(&tm_sched_cfg, attachment_point.type, BCMOLT_TM_SCHED_OUTPUT_TYPE_INTERFACE);
    BCMOLT_MSG_FIELD_SET(&tm_sched_cfg, attachment_point.u.interface.interface_ref.intf_type, type);
    BCMOLT_MSG_FIELD_SET(&tm_sched_cfg, attachment_point.u.interface.interface_ref.intf_id, ni);
    BCMOLT_MSG_FIELD_SET(&tm_sched_cfg, sched_type, BCMOLT_TM_SCHED_TYPE_SP);
    BCMOLT_MSG_FIELD_SET(&tm_sched_cfg, num_priorities, 8);
    err = bcmolt_cfg_set(netconf_agent_olt_id(), &tm_sched_cfg.hdr);
    if(err != BCM_ERR_OK)
    {
        NC_LOG_ERR("Failed to create tm_sched for %s %u. Error %s\n",
            (type == BCMOLT_INTERFACE_TYPE_NNI) ? "nni" : "pon_ni", ni, bcmos_strerror(err));
        return err;
    }

    /* Create a default qmp for NNI interface */
    if (type == BCMOLT_INTERFACE_TYPE_NNI)
    {
        bcmolt_tm_qmp_key key = {
            .id = ni
        };
        bcmolt_tm_qmp_cfg qmp_cfg;
        bcmolt_arr_u8_8 pbits_to_tmq = {};
        for (tc = 0; tc < 8; tc++)
            pbits_to_tmq.arr[tc] = tc;

        BCMOLT_CFG_INIT(&qmp_cfg, tm_qmp, key);
        BCMOLT_MSG_FIELD_SET(&qmp_cfg, pbits_to_tmq_id, pbits_to_tmq);
        BCMOLT_MSG_FIELD_SET(&qmp_cfg, type, BCMOLT_TM_QMP_TYPE_PBITS);
        err = bcmolt_cfg_set(netconf_agent_olt_id(), &qmp_cfg.hdr);
        if (err != BCM_ERR_OK)
        {
            NC_LOG_ERR("Failed to create tm_qmp %u. Error %s (%s)\n",
                ni, bcmos_strerror(err), qmp_cfg.hdr.hdr.err_text);
            return err;
        }
    }

    for (tc = 0; tc < 8; tc++)
    {
        bcmolt_tm_queue_key tm_queue_key = {
            .sched_id = tm_sched_key.id,
            .id = tc,
            .tm_q_set_id = (type == BCMOLT_INTERFACE_TYPE_NNI) ? 0 : 32768
        };
        bcmolt_tm_queue_cfg tm_queue_cfg;

        BCMOLT_CFG_INIT(&tm_queue_cfg, tm_queue, tm_queue_key);
        BCMOLT_MSG_FIELD_SET(&tm_queue_cfg, tm_sched_param.type, BCMOLT_TM_SCHED_PARAM_TYPE_PRIORITY);
        BCMOLT_MSG_FIELD_SET(&tm_queue_cfg, tm_sched_param.u.priority.priority, tc);
        err = bcmolt_cfg_set(netconf_agent_olt_id(), &tm_queue_cfg.hdr);
        if(err != BCM_ERR_OK)
        {
            NC_LOG_ERR("Failed to create tm_queue %u.%u. Error %s\n", tm_queue_key.sched_id, tc, bcmos_strerror(err));
            break;
        }
    }

    return err;
}

bcmos_errno xpon_tm_qmp_create(bcmolt_tm_qmp_id id, bcmolt_tm_queue_set_id tmq_set_id, uint8_t pbit_to_queue_map[])
{
    bcmolt_tm_qmp_key key = { .id = id };
    bcmolt_tm_qmp_cfg cfg;
    bcmolt_arr_u8_8 pbits_to_tmq_arr;
    bcmos_errno err;

    BCMOLT_CFG_INIT(&cfg, tm_qmp, key);
    BCMOLT_MSG_FIELD_SET(&cfg, type, BCMOLT_TM_QMP_TYPE_PBITS);
    memcpy(pbits_to_tmq_arr.arr, pbit_to_queue_map, sizeof(pbits_to_tmq_arr.arr));
    BCMOLT_MSG_FIELD_SET(&cfg, pbits_to_tmq_id, pbits_to_tmq_arr);
    err = bcmolt_cfg_set(netconf_agent_olt_id(), &cfg.hdr);
    if (err != BCM_ERR_OK)
    {
        NC_LOG_ERR("Failed to create tm_qmp %u. Error %s (%s)\n",
            id, bcmos_strerror(err), cfg.hdr.hdr.err_text);
        return err;
    }
    return BCM_ERR_OK;
}

bcmos_errno xpon_default_tm_qmp_create(bcmolt_tm_qmp_id id)
{
    uint8_t pbit_to_queue_map[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
    return xpon_tm_qmp_create(BCM_DEFAULT_TM_QMP_ID, BCMOLT_TM_QUEUE_SET_ID_QSET_NOT_USE, pbit_to_queue_map);
}

/*
 * Scheduled request support
 */

/* Free scheduled request */
static void xpon_scheduled_request_free(xpon_scheduled_request *req)
{
    bcmolt_msg_free(req->msg);
    bcmos_free(req);
}

static bcmos_timer_rc xpon_sched_req_handler(bcmos_timer *timer, long data)
{
    xpon_scheduled_request *req = (xpon_scheduled_request *)data;
    bcmos_errno err;

    bcmos_mutex_lock(&scheduled_request_lock);
    TAILQ_REMOVE(&scheduled_request_list, req, next);
    bcmos_mutex_unlock(&scheduled_request_lock);

    switch(req->type)
    {
        case BBF_XPON_REQUEST_TYPE_CFG:
            err = bcmolt_cfg_set(netconf_agent_olt_id(), (bcmolt_cfg *)req->msg);
            break;

        case BBF_XPON_REQUEST_TYPE_OPER:
            err = bcmolt_oper_submit(netconf_agent_olt_id(), (bcmolt_oper *)req->msg);
            break;

        default:
            NC_LOG_ERR("Scheduled request type %d is insane\n", req->type);
            err = BCM_ERR_INTERNAL;
    }
    if (err != BCM_ERR_OK)
    {
        NC_LOG_ERR("Scheduled request failed, error '%s'\n", bcmos_strerror(err));
    }
    else
    {
        NC_LOG_DBG("Scheduled request executed successfully\n");
    }
    xpon_scheduled_request_free(req);

    return BCMOS_TIMER_OK;
}

/* Scheduled request support */
static bcmos_errno xpon_scheduled_request_submit(bcmolt_msg *msg, bbf_xpon_request_type type, uint32_t delay)
{
    xpon_scheduled_request *req;
    bcmolt_msg *copy = NULL;
    bcmos_timer_parm tp = {
        .name = "sched_req",
        .handler = xpon_sched_req_handler,
        .owner = BCMOS_MODULE_ID_NETCONF_SERVER
    };
    bcmos_errno err;

    err = bcmolt_msg_clone(&copy, msg);
    if (err != BCM_ERR_OK)
    {
        NC_LOG_ERR("bcmolt_msg_clone() failed. '%s'\n", bcmos_strerror(err));
        return err;
    }
    req = bcmos_calloc(sizeof(*req));
    if (req == NULL)
    {
        bcmolt_msg_free(copy);
        return BCM_ERR_NOMEM;
    }
    req->msg = copy;
    req->type = type;

    tp.data = (long)req;
    err = bcmos_timer_create(&req->timer, &tp);
    if (err != BCM_ERR_OK)
    {
        NC_LOG_ERR("bcmos_timer_create() failed. err='%s'\n", bcmos_strerror(err));
        bcmolt_msg_free(copy);
        bcmos_free(req);
        return err;
    }
    bcmos_mutex_lock(&scheduled_request_lock);
    TAILQ_INSERT_TAIL(&scheduled_request_list, req, next);
    bcmos_mutex_unlock(&scheduled_request_lock);
    bcmos_timer_start(&req->timer, delay);

    return BCM_ERR_OK;
}

bcmos_errno xpon_cfg_set_and_schedule_if_failed(sr_session_ctx_t *srs, bcmolt_cfg *cfg, uint32_t delay,
    bcmos_errno test_err, const char *test_text)
{
    bcmos_errno err;

    err = bcmolt_cfg_set(netconf_agent_olt_id(), cfg);
    if (err != BCM_ERR_OK)
    {
        if (err == test_err &&
            (test_text == NULL || strstr(cfg->hdr.err_text, test_text) != NULL))
        {
            err = xpon_scheduled_request_submit(&cfg->hdr, BBF_XPON_REQUEST_TYPE_CFG, delay);
            if (err != BCM_ERR_OK)
            {
                NC_ERROR_REPLY(srs, NULL, "bcmolt_cfg_set() failed. Error '%s'-'%s'\n",
                    bcmos_strerror(cfg->hdr.err), cfg->hdr.err_text);
            }
            else
            {
                NC_LOG_DBG("bcmolt_cfg_set() failed. Error '%s'-'%s'. Scheduled to be retried in %u ms\n",
                    bcmos_strerror(cfg->hdr.err), cfg->hdr.err_text, delay / 1000);
            }
        }
    }
    return err;
}

bcmos_errno xpon_oper_submit_and_schedule_if_failed(sr_session_ctx_t *srs, bcmolt_oper *oper, uint32_t delay,
    bcmos_errno test_err, const char *test_text)
{
    bcmos_errno err;

    err = bcmolt_oper_submit(netconf_agent_olt_id(), oper);
    if (err != BCM_ERR_OK)
    {
        if (err == test_err &&
            (test_text == NULL || strstr(oper->hdr.err_text, test_text) != NULL))
        {
            err = xpon_scheduled_request_submit(&oper->hdr, BBF_XPON_REQUEST_TYPE_OPER, delay);
            if (err != BCM_ERR_OK)
            {
                NC_ERROR_REPLY(srs, NULL, "bcmolt_oper_submit() failed. Error '%s'-'%s'\n",
                    bcmos_strerror(oper->hdr.err), oper->hdr.err_text);
            }
            else
            {
                NC_LOG_DBG("bcmolt_oper_submit() failed. Error '%s'-'%s'. Scheduled to be retried in %u ms\n",
                    bcmos_strerror(oper->hdr.err), oper->hdr.err_text, delay / 1000);
            }
        }
    }
    return err;
}

bcmos_errno xpon_vlan_add(bcmolt_interface pon_ni, uint16_t vlan, bcmolt_flow_id flow_id)
{
    xpon_vlan_key key_str = {
        .pon_ni = pon_ni,
        .vlan = vlan
    };
    xpon_vlan_entry entry = {
        .flow_id = flow_id
    };
    uint8_t *key = (uint8_t *)&key_str;
    bcmos_errno err;

    bbf_xpon_lock();
    if (hash_table_get(vlan_hash, key) != NULL)
    {
        err = BCM_ERR_ALREADY;
    }
    else
    {
        if (hash_table_put(vlan_hash, key, &entry) != NULL)
            err = BCM_ERR_OK;
        else
            err = BCM_ERR_NOMEM;
    }
    bbf_xpon_unlock();
    NC_LOG_DBG("Added vlan [%u:%u]=%u. Result '%s'\n", pon_ni, vlan, flow_id, bcmos_strerror(err));
    return err;

}

bcmos_errno xpon_vlan_delete(bcmolt_interface pon_ni, uint16_t vlan)
{
    xpon_vlan_key key_str = {
        .pon_ni = pon_ni,
        .vlan = vlan
    };
    uint8_t *key = (uint8_t *)&key_str;
    bcmos_bool removed;

    bbf_xpon_lock();
    removed = hash_table_remove(vlan_hash, key);
    bbf_xpon_unlock();
    NC_LOG_DBG("Deleted vlan %u:%u. found=%d\n", pon_ni, vlan, removed);

    return removed ? BCM_ERR_OK : BCM_ERR_NOENT;
}

bcmos_errno bcmolt_xpon_utils_init(void)
{
    bcmos_errno err;
    err = bcmos_mutex_create(&xpon_lock, 0, "xpon_lock");
    if (err != BCM_ERR_OK)
        return err;
    err = bcmos_mutex_create(&scheduled_request_lock, 0, "xpon_sched_req_lock");
    if (err != BCM_ERR_OK)
        return err;

    /* Initialize object hash */
    object_hash = hash_table_create(BCM_MAX_PONS_PER_OLT * (4 + XPON_MAX_ONUS_PER_PON),
        sizeof(void *), XPON_OBJ_HASH_KEY_LENGTH, "bbf-xpon");
    if (object_hash == NULL)
        return BCM_ERR_NOMEM;

    vlan_hash = hash_table_create(XPON_MAX_FLOWS,
        sizeof(xpon_vlan_entry), sizeof(xpon_vlan_key), "xpon-vlan");
    if (vlan_hash == NULL)
    {
        hash_table_delete(object_hash);
        return BCM_ERR_NOMEM;
    }

    TAILQ_INIT(&scheduled_request_list);

    return err;
}


void bcmolt_xpon_utils_exit(void)
{
    xpon_scheduled_request *req, *req_tmp;

    TAILQ_FOREACH_SAFE(req, &scheduled_request_list, next, req_tmp)
    {
        bcmos_timer_stop(&req->timer);
    }

    bcmos_mutex_lock(&scheduled_request_lock);
    while (!TAILQ_EMPTY(&scheduled_request_list))
    {
        req = TAILQ_FIRST(&scheduled_request_list);
        TAILQ_REMOVE(&scheduled_request_list, req, next);
        xpon_scheduled_request_free(req);
    }
    bcmos_mutex_destroy(&scheduled_request_lock);

    if (object_hash)
    {
        hash_table_clear(object_hash);
        hash_table_delete(object_hash);
        object_hash = NULL;
    }
    if (vlan_hash)
    {
        hash_table_clear(vlan_hash);
        hash_table_delete(vlan_hash);
        vlan_hash = NULL;
    }

    bcmos_mutex_destroy(&xpon_lock);
}