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
 * bbf-xpon-enet.c
 */
#include "bbf-xpon-internal.h"

static xpon_obj_list enet_list;

bcmos_errno xpon_enet_init(sr_session_ctx_t *srs)
{
    STAILQ_INIT(&enet_list);
    return BCM_ERR_OK;
}

bcmos_errno xpon_enet_start(sr_session_ctx_t *srs)
{
    return BCM_ERR_OK;
}

void xpon_enet_exit(sr_session_ctx_t *srs)
{

}

int xpon_enet_state_get_cb(sr_session_ctx_t *session, const char *xpath, struct lyd_node **parent)
{
    return 0;
}

/* Find or add enet object */
bcmos_errno xpon_enet_get_by_name(const char *name, xpon_enet **p_enet, bcmos_bool *is_added)
{
    xpon_obj_hdr *obj = NULL;
    bcmos_errno err;

    err = xpon_object_get_or_add(name, XPON_OBJ_TYPE_ENET,
        sizeof(xpon_enet), &obj, is_added);
    if (err != BCM_ERR_OK)
        return err;
    *p_enet = (xpon_enet *)obj;
    if (is_added != NULL && *is_added)
    {
        STAILQ_INIT(&(*p_enet)->subifs);
        STAILQ_INSERT_TAIL(&enet_list, obj, next);
        NC_LOG_INFO("enet %s added\n", name);
    }
    return BCM_ERR_OK;
}

/* Remove enet object */
void xpon_enet_delete(xpon_enet *enet)
{
    xpon_vlan_subif *subif, *subif_tmp;
    STAILQ_FOREACH_SAFE(subif, &enet->subifs, next, subif_tmp)
    {
        xpon_vlan_subif_delete(subif);
    }
    xpon_unlink(&enet->linked_if);
    if (enet->lower_layer && enet->lower_layer->created_by_forward_reference)
        xpon_interface_delete(enet->lower_layer);
    if (enet->port_layer_if && enet->port_layer_if->hdr.created_by_forward_reference)
        xpon_hardware_delete(enet->port_layer_if);
    STAILQ_REMOVE_SAFE(&enet_list, &enet->hdr, xpon_obj_hdr, next);
    NC_LOG_INFO("enet %s deleted\n", enet->hdr.name);
    xpon_object_delete(&enet->hdr);
}

bcmos_errno xpon_enet_transaction(sr_session_ctx_t *srs, nc_transact *tr)
{
    xpon_enet *enet = NULL;
    xpon_enet changes = {};
    char keyname[32]={};
    nc_transact_elem *elem;
    bcmos_errno err = BCM_ERR_OK;
    const char *iter_xpath;
    bcmos_bool was_added = BCMOS_FALSE;

    /* See if there is an existing enet object */
    elem = STAILQ_FIRST(&tr->elems);
    if (elem == NULL)
        return BCM_ERR_OK;
    iter_xpath = elem->old_val ? elem->old_val->xpath : elem->new_val->xpath;
    nc_xpath_key_get(iter_xpath, "name", keyname, sizeof(keyname));
    NC_LOG_DBG("Handling enet %s transaction\n", keyname);
    err = xpon_enet_get_by_name(keyname, &enet, &was_added);
    if (err != BCM_ERR_OK)
        return err;
    /* If the interface has already been created by forward reference - stop here */
    if (enet->hdr.created_by_forward_reference)
    {
        enet->hdr.created_by_forward_reference = BCMOS_FALSE;
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
            changes.hdr.being_deleted = (elem->new_val == NULL);
        }
        else if (!strcmp(leaf, "lower-layer-interface"))
        {
            xpon_obj_hdr *hdr = NULL;
            if (elem->new_val != NULL)
            {
                const char *if_name = val->data.string_val;
                err = xpon_interface_get_populate(srs, if_name, XPON_OBJ_TYPE_ANY, &hdr);
                if (err != BCM_ERR_OK)
                {
                    NC_ERROR_REPLY(srs, iter_xpath, "enet %s references lower-layer-interface %s which doesn't exist\n",
                        keyname, if_name);
                    break;
                }
            }
            XPON_PROP_SET(&changes, enet, lower_layer, hdr);
        }
        else if (!strcmp(leaf, "interface-usage"))
        {
            XPON_PROP_SET(&changes, enet, usage,
                xpon_map_iface_usage(elem->new_val ? elem->new_val->data.identityref_val : NULL));
        }
        else if (strstr(leaf, "port-layer-if") != NULL)
        {
            xpon_hardware *port = NULL;
            if (elem->new_val != NULL)
            {
                const char *_name = elem->new_val ? elem->new_val->data.string_val : elem->old_val->data.string_val;
                err = xpon_hardware_get_populate(srs, _name, &port);
                if (err != BCM_ERR_OK)
                {
                    NC_ERROR_REPLY(srs, iter_xpath, "interface %s references hardware component %s which doesn't exist\n",
                        keyname, _name);
                    err = BCM_ERR_PARM;
                    break;
                }
                XPON_PROP_SET(&changes, enet, port_layer_if, port);
                if (port != NULL)
                {
#ifdef OB_BAA
                    /* OB-BAA derives PON interface id from the port name */
                    if (!memcmp(_name, "PORT", 4) || !memcmp(_name, "port", 4))
                    {
                        const char *_port_id = _name + 4;
                        if (_port_id[0] == '_' || _port_id[0] == '-')
                            ++_port_id;
                        changes.intf_id = atoi(_port_id) - 1;
                    }
                    else
#endif
                    /* Note that parent-rel-pos numbering normally starts from 1 (RFC 6933) */
                    if (XPON_PROP_IS_SET(port, hardware, parent_rel_pos))
                        changes.intf_id = enet->intf_id = port->parent_rel_pos - 1;
                    else if (port->parent != NULL && XPON_PROP_IS_SET(port->parent, hardware, parent_rel_pos))
                        changes.intf_id = enet->intf_id = port->parent->parent_rel_pos - 1;
                }
            }
        }
    }

    if (err == BCM_ERR_OK && !changes.hdr.being_deleted)
    {
        /* Copy properties as more are added */
        XPON_PROP_COPY(&changes, enet, enet, lower_layer);
        changes.lower_layer = NULL;
        XPON_PROP_COPY(&changes, enet, enet, usage);
    }

    if ((err != BCM_ERR_OK && was_added) || changes.hdr.being_deleted)
        xpon_enet_delete(enet);

    if (changes.lower_layer && changes.lower_layer->created_by_forward_reference)
        xpon_interface_delete(changes.lower_layer);

    if (changes.hdr.being_deleted)
        err = BCM_ERR_OK;

    NC_LOG_DBG("enet transaction completed: %s\n", bcmos_strerror(err));

    return err;
}


