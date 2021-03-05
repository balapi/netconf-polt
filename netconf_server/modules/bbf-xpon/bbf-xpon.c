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

sr_subscription_ctx_t *sr_ctx;
static sr_subscription_ctx_t *sr_ctx_intf;

static const char* ietf_interfaces_features[] = {
    "arbitrary-names",
    "pre-provisioning",
    "if-mib",
    NULL
};

static const char* xponvani_features[] = {
    "configurable-v-ani-onu-id",
    "configurable-v-ani-management-gem-port-id",
    NULL
};

static const char* xpongemtcont_features[] = {
    "configurable-gemport-id",
    "configurable-alloc-id",
    NULL
};

static const char* l2_forwarding_features[] = {
    "forwarding-databases",
    "shared-forwarding-databases",
    "mac-learning",
    "split-horizon-profiles",
    NULL
};

static const char* ietf_hardware_features[] = {
    "entity-mib",
    "hardware-state",
    NULL
};

static const char* bbf_hardware_features[] = {
    "additional-hardware-configuration",
    "model-name-configuration",
    "interface-hardware-reference",
    "hardware-component-reset",
    NULL
};

static sr_session_ctx_t *sr_session;

static bcmos_bool device_connection_status[BCM_MAX_DEVS_PER_OLT];

static int num_connected_devices(void)
{
    int num_connected = 0;
    int i;
    for (i = 0; i < BCM_MAX_DEVS_PER_OLT; i++)
    {
        if (device_connection_status[i])
            ++num_connected;
    }
    return num_connected;
}

static int xpon_interface_state_get_cb(sr_session_ctx_t *session, const char *module_name,
    const char *xpath, const char *request_path, uint32_t request_id,
    struct lyd_node **parent, void *private_data)
{
    NC_LOG_INFO("module=%s xpath=%s request=%s\n", module_name, xpath, request_path);

    if (strcmp(module_name, IETF_INTERFACES_MODULE_NAME))
        return SR_ERR_OK;

    xpon_cpair_state_get_cb(session, xpath, parent);
    xpon_cterm_state_get_cb(session, xpath, parent);
    xpon_v_ani_state_get_cb(session, xpath, parent);
    xpon_ani_state_get_cb(session, xpath, parent);
    xpon_v_ani_v_enet_state_get_cb(session, xpath, parent);
    xpon_ani_v_enet_state_get_cb(session, xpath, parent);
    xpon_enet_state_get_cb(session, xpath, parent);
    xpon_vlan_subif_state_get_cb(session, xpath, parent);
    return SR_ERR_OK;
}

static bcmos_errno bbf_xpon_apply_transaction(sr_session_ctx_t *srs, nc_transact *transact, const char *keyname)
{
    bcmos_errno err = BCM_ERR_OK;
    if (transact->plugin_elem_type == NC_TRANSACT_PLUGIN_ELEM_TYPE_INVALID)
    {
        /* Try to identify by name */
        xpon_obj_hdr *obj = NULL;
        if (xpon_object_get(keyname, &obj) == BCM_ERR_OK)
            transact->plugin_elem_type = (int)obj->obj_type;
    }

    switch(transact->plugin_elem_type)
    {
        case (int)XPON_OBJ_TYPE_CGROUP:
            err = xpon_cgroup_transaction(srs, transact);
            break;
        case (int)XPON_OBJ_TYPE_CPART:
            err = xpon_cpart_transaction(srs, transact);
            break;
        case (int)XPON_OBJ_TYPE_CPAIR:
            err = xpon_cpair_transaction(srs, transact);
            break;
        case (int)XPON_OBJ_TYPE_CTERM:
            err = xpon_cterm_transaction(srs, transact);
            break;
        case (int)XPON_OBJ_TYPE_V_ANI:
            err = xpon_v_ani_transaction(srs, transact);
            break;
        case (int)XPON_OBJ_TYPE_ANI:
            err = xpon_ani_transaction(srs, transact);
            break;
        case (int)XPON_OBJ_TYPE_V_ANI_V_ENET:
            err = xpon_v_ani_v_enet_transaction(srs, transact);
            break;
        case (int)XPON_OBJ_TYPE_ANI_V_ENET:
            err = xpon_ani_v_enet_transaction(srs, transact);
            break;
        case (int)XPON_OBJ_TYPE_ENET:
            err = xpon_enet_transaction(srs, transact);
            break;
        case (int)XPON_OBJ_TYPE_VLAN_SUBIF:
            err = xpon_vlan_subif_transaction(srs, transact);
            break;
        default:
            err = BCM_ERR_INTERNAL;
            break;
    }
    nc_transact_free(transact);
    return err;
}

/* Data store change indication callback */
static int bbf_xpon_interface_change_cb(sr_session_ctx_t *srs, const char *module_name,
    const char *xpath, sr_event_t event, uint32_t request_id, void *private_ctx)
{
    sr_change_iter_t *sr_iter = NULL;
    sr_change_oper_t sr_oper;
    sr_val_t *sr_old_val = NULL, *sr_new_val = NULL;
    char keyname[32];
    char prev_keyname[32] = "";
    nc_transact transact;
    int sr_rc;
    bcmos_errno err = BCM_ERR_OK;

    nc_config_lock();

    NC_LOG_INFO("module=%s xpath=%s event=%d\n", module_name, xpath, event);

    /* We only handle CHANGE and ABORT events.
     * Since there is no way to reserve resources in advance and no way to fail the APPLY event,
     * configuration is applied in VERIFY event.
     * There are no other verifiers, but if there are and they fail,
     * ABORT event will roll-back the changes.
     */
    if (event == SR_EV_DONE)
    {
        nc_config_unlock();
        return SR_ERR_OK;
    }

    nc_transact_init(&transact, event);

    for (sr_rc = sr_get_changes_iter(srs, BBF_XPON_INTERFACE_PATH_BASE "//.", &sr_iter);
        (err == BCM_ERR_OK) && (sr_rc == SR_ERR_OK) &&
            (sr_rc = sr_get_change_next(srs, sr_iter, &sr_oper, &sr_old_val, &sr_new_val)) == SR_ERR_OK;
        nc_sr_free_value_pair(&sr_old_val, &sr_new_val))
    {
        const char *iter_xpath;
        char leafbuf[BCM_MAX_LEAF_LENGTH];
        const char *leaf;
        sr_val_t *sr_val;

        NC_LOG_DBG("old_val=%s new_val=%s. Leaf type %d\n",
            sr_old_val ? sr_old_val->xpath : "none",
            sr_new_val ? sr_new_val->xpath : "none",
            sr_old_val ? sr_old_val->type : sr_new_val->type);

        if ((sr_old_val && ((sr_old_val->type == SR_LIST_T) && (sr_oper != SR_OP_MOVED))) ||
            (sr_new_val && ((sr_new_val->type == SR_LIST_T) && (sr_oper != SR_OP_MOVED))) ||
            (sr_old_val && (sr_old_val->type == SR_CONTAINER_T)) ||
            (sr_new_val && (sr_new_val->type == SR_CONTAINER_T)))
        {
            /* no semantic meaning */
            continue;
        }

        sr_val = sr_new_val ? sr_new_val : sr_old_val;
        iter_xpath = sr_val->xpath;
        if (nc_xpath_key_get(iter_xpath, "name", keyname, sizeof(keyname)) != BCM_ERR_OK)
        {
            continue;
        }

        /* Handle transaction if key changed */
        if (strcmp(keyname, prev_keyname) && *prev_keyname)
        {
            err = bbf_xpon_apply_transaction(srs, &transact, prev_keyname);
            nc_transact_init(&transact, event);
            strcpy(prev_keyname, keyname);
            *keyname = 0;
            if (err != BCM_ERR_OK)
                break;
        }
        else
        {
            strcpy(prev_keyname, keyname);
        }

        /* Special handling of interface type */
        leaf = nc_xpath_leaf_get(iter_xpath, leafbuf, sizeof(leafbuf));
        if (transact.plugin_elem_type == NC_TRANSACT_PLUGIN_ELEM_TYPE_INVALID &&
            sr_val->data.identityref_val != NULL &&
            leaf != NULL && !strcmp(leaf, "type"))
        {
            transact.plugin_elem_type = xpon_iftype_to_obj_type(sr_val->data.identityref_val);
        }
        else
        {
            /* code */
            err = nc_transact_add(&transact, &sr_old_val, &sr_new_val);
        }
    }
    if (*keyname)
        err = bbf_xpon_apply_transaction(srs, &transact, keyname);

    nc_sr_free_value_pair(&sr_old_val, &sr_new_val);
    sr_free_change_iter(sr_iter);

    nc_config_unlock();

    return nc_bcmos_errno_to_sr_errno(err);
}

/* Get interface from the local DB. If not found, try to create and populate info from operational data */
bcmos_errno xpon_interface_get_populate(sr_session_ctx_t *srs, const char *name,
    xpon_obj_type expected_obj_type, xpon_obj_hdr **p_obj)
{
    bcmos_errno err;

    *p_obj = NULL;
    err = xpon_object_get(name, p_obj);

    if (err != BCM_ERR_OK)
    {
        sr_val_t *values = NULL;
        size_t value_cnt = 0;
        int i;
        int sr_rc;
        char query_xpath[256];
        nc_transact transact;

        /* Try to create & populate object from the operational data */
        snprintf(query_xpath, sizeof(query_xpath)-1,
            BBF_XPON_INTERFACE_PATH_BASE "/interface[name='%s']//.", name);
        sr_rc = sr_get_items(srs, query_xpath, 0, SR_OPER_DEFAULT, &values, &value_cnt);
        if (sr_rc)
        {
            NC_LOG_ERR("sr_get_items(%s) -> %s\n", query_xpath, sr_strerror(sr_rc));
            return BCM_ERR_PARM;
        }

        NC_LOG_DBG("Populating %s from operational data\n", query_xpath);

        /* Create amd populate transaction */
        nc_transact_init(&transact, SR_EV_CHANGE);
        transact.do_not_free_values = BCMOS_TRUE;
        err = BCM_ERR_OK;

        for (i = 0; i < value_cnt && err == BCM_ERR_OK; i++)
        {
            char leafbuf[BCM_MAX_LEAF_LENGTH];
            const char *leaf;
            sr_val_t *sr_old_val = NULL;
            sr_val_t *sr_new_val = &values[i];

            NC_LOG_DBG("value=%s. Leaf type %d\n",
                values[i].xpath, values[i].type);

            if (values[i].type == SR_LIST_T || values[i].type == SR_CONTAINER_T)
            {
                /* no semantic meaning (for now) */
                continue;
            }

            /* Special handling of interface type */
            leaf = nc_xpath_leaf_get(values[i].xpath, leafbuf, sizeof(leafbuf));
            if (transact.plugin_elem_type == NC_TRANSACT_PLUGIN_ELEM_TYPE_INVALID &&
                values[i].data.identityref_val != NULL && leaf != NULL && !strcmp(leaf, "type"))
            {
                transact.plugin_elem_type = xpon_iftype_to_obj_type(values[i].data.identityref_val);
            }
            else
            {
                /* code */
                err = nc_transact_add(&transact, &sr_old_val, &sr_new_val);
            }
        }
        if (transact.plugin_elem_type != NC_TRANSACT_PLUGIN_ELEM_TYPE_INVALID)
        {
            if (expected_obj_type != XPON_OBJ_TYPE_ANY &&
                expected_obj_type != transact.plugin_elem_type)
            {
                NC_LOG_ERR("interface %s is of unexpected type. Expected %s got %s\n",
                    name, xpon_obj_type_to_str(expected_obj_type),
                    xpon_obj_type_to_str(transact.plugin_elem_type));
                return BCM_ERR_NOENT;
            }
            err = bbf_xpon_apply_transaction(srs, &transact, name);
            if (err == BCM_ERR_OK)
            {
                err = xpon_object_get(name, p_obj);
                if (*p_obj != NULL)
                    (*p_obj)->created_by_forward_reference = BCMOS_TRUE;
            }
        }
        nc_transact_free(&transact);
        sr_free_values(values, value_cnt);
    }
    return err;
}

/* Delete any interface */
void xpon_interface_delete(xpon_obj_hdr *obj)
{
    switch(obj->obj_type)
    {
        case XPON_OBJ_TYPE_CGROUP:
            xpon_cgroup_delete((xpon_channel_group *)obj);
            break;
        case XPON_OBJ_TYPE_CPART:
            xpon_cpart_delete((xpon_channel_partition *)obj);
            break;
        case XPON_OBJ_TYPE_CPAIR:
            xpon_cpair_delete((xpon_channel_pair *)obj);
            break;
        case XPON_OBJ_TYPE_CTERM:
            xpon_cterm_delete((xpon_channel_termination *)obj);
            break;
        case XPON_OBJ_TYPE_V_ANI:
            xpon_v_ani_delete((xpon_v_ani *)obj);
            break;
        case XPON_OBJ_TYPE_ANI:
            xpon_ani_delete((xpon_ani *)obj);
            break;
        case XPON_OBJ_TYPE_V_ANI_V_ENET:
            xpon_v_ani_v_enet_delete((xpon_v_ani_v_enet *)obj);
            break;
        case XPON_OBJ_TYPE_ANI_V_ENET:
            xpon_ani_v_enet_delete((xpon_ani_v_enet *)obj);
            break;
        case XPON_OBJ_TYPE_ENET:
            xpon_enet_delete((xpon_enet *)obj);
            break;
        case XPON_OBJ_TYPE_VLAN_SUBIF:
            xpon_vlan_subif_delete((xpon_vlan_subif *)obj);
            break;
        default:
            break;
    }
}

/* Subscribe to configuration change events */
static bcmos_errno bbf_xpon_unsubscribe(sr_session_ctx_t *srs)
{
    int sr_rc = SR_ERR_OK;
    if (sr_ctx_intf != NULL)
    {
        sr_rc = sr_unsubscribe(sr_ctx_intf);
        if (SR_ERR_OK == sr_rc)
        {
            NC_LOG_INFO("Unsubscribed from %s subtree change indications\n", BBF_XPON_INTERFACE_PATH_BASE);
        }
        else
        {
            NC_LOG_ERR("Failed to unsubscribe from %s subtree changes (%s).\n",
                BBF_XPON_INTERFACE_PATH_BASE, sr_strerror(sr_rc));
        }
        sr_ctx_intf = NULL;
    }
    return (sr_rc == SR_ERR_OK) ? BCM_ERR_OK : BCM_ERR_INTERNAL;
}

/* Subscribe to configuration change events */
static bcmos_errno bbf_xpon_subscribe(sr_session_ctx_t *srs)
{
    int sr_rc;

#if 0
    /* Apply pending configuration if any */
    nc_cfg_copy(srs, IETF_INTERFACES_MODULE_NAME, NC_DATASTORE_PENDING, NC_DATASTORE_STARTUP);
    nc_cfg_reset(srs, IETF_INTERFACES_MODULE_NAME, NC_DATASTORE_PENDING);
#endif

    /* subscribe to events */
    sr_rc = sr_module_change_subscribe(srs, IETF_INTERFACES_MODULE_NAME, NULL,
            bbf_xpon_interface_change_cb, NULL, 0, BCM_SR_MODULE_CHANGE_SUBSCR_FLAGS,
            &sr_ctx_intf);
    if (SR_ERR_OK == sr_rc)
    {
        NC_LOG_INFO("Subscribed to %s subtree changes.\n", BBF_XPON_INTERFACE_PATH_BASE);
    }
    else
    {
        NC_LOG_ERR("Failed to subscribe to %s subtree changes (%s).\n",
            BBF_XPON_INTERFACE_PATH_BASE, sr_strerror(sr_rc));
    }

    return (sr_rc == SR_ERR_OK) ? BCM_ERR_OK : BCM_ERR_INTERNAL;
}

/* Interface indication handler */
static void _pon_interface_indication_cb(bcmolt_oltid olt, bcmolt_msg *msg)
{
    xpon_channel_termination *cterm;
    sr_val_t *values = NULL;
    size_t values_cnt = 0;

    switch(msg->subgroup)
    {
        case BCMOLT_PON_INTERFACE_AUTO_SUBGROUP_STATE_CHANGE_COMPLETED:
        {
            bcmolt_pon_interface_state_change_completed *sc = (bcmolt_pon_interface_state_change_completed *)msg;
            NC_LOG_INFO("%u.%u: pon_interface.state_change_completed %s\n",
                olt, sc->key.pon_ni,
                (sc->data.result == BCMOLT_RESULT_SUCCESS) ? "SUCCESS" : "FAILURE");
            cterm = xpon_cterm_get_by_id(olt, sc->key.pon_ni);
            if (cterm == NULL)
            {
                NC_LOG_INFO("%u.%u: channel termination is not found\n",
                    olt, sc->key.pon_ni);
                break;
            }
            cterm->interface_up = (sc->data.new_state == BCMOLT_INTERFACE_STATE_ACTIVE_WORKING);
        }
        break;

        case BCMOLT_PON_INTERFACE_AUTO_SUBGROUP_ONU_DISCOVERED:
            bbf_xpon_onu_discovered(olt, msg);
            break;

        default:
            break;
    }

    if (values_cnt)
        sr_free_values(values, values_cnt);

    bcmolt_msg_free(msg);
}

/* Check if device is connected */
static bcmos_bool _device_is_connected(bcmolt_oltid olt, bcmolt_devid device)
{
    bcmolt_device_cfg cfg;
    bcmolt_device_key key = { .device_id = device };
    bcmos_errno err;

    BCMOLT_CFG_INIT(&cfg, device, key);
    BCMOLT_FIELD_SET_PRESENT(&cfg.data, device_cfg_data, system_mode);
    err = bcmolt_cfg_get(olt, &cfg.hdr);
    return (err == BCM_ERR_OK);
}

static bcmos_errno _create_pon_tm_scheds(bcmolt_devid dev)
{
    bcmolt_topology topo;
    bcmos_errno err;
    int i;

    err = xpon_get_olt_topology(&topo);
    /* Create TM_SCHED objects for all PONs on the device */
    for (i = 0; i < topo.topology_maps.len && err == BCM_ERR_OK; i++)
    {
        if (topo.topology_maps.arr[i].olt_device_id == dev)
            err = xpon_tm_sched_create(BCMOLT_INTERFACE_TYPE_PON, i);
    }
    return err;
}

/* Access terminal status change indication handler */
static void _device_indication_cb(bcmolt_oltid olt, bcmolt_msg *msg)
{
    switch(msg->subgroup)
    {
        case BCMOLT_DEVICE_AUTO_SUBGROUP_CONNECTION_COMPLETE:
            {
                bcmolt_device_connection_complete *cc = (bcmolt_device_connection_complete *)msg;
                NC_LOG_INFO("Got device.connection_complete(%u) indication\n", cc->key.device_id);
                _create_pon_tm_scheds(cc->key.device_id);
                if (!num_connected_devices())
                    bbf_xpon_subscribe(sr_session);
                device_connection_status[cc->key.device_id] = BCMOS_TRUE;
            }
            break;

        case BCMOLT_DEVICE_AUTO_SUBGROUP_DISCONNECTION_COMPLETE:
        case BCMOLT_DEVICE_AUTO_SUBGROUP_CONNECTION_FAILURE:
            {
                bcmolt_device_disconnection_complete *dc = (bcmolt_device_disconnection_complete *)msg;
                NC_LOG_INFO("Got device.disconnection_complete/device.connection_failure indication\n");
                device_connection_status[dc->key.device_id] = BCMOS_TRUE;
                if (!num_connected_devices())
                    bbf_xpon_unsubscribe(sr_session);
            }
            break;

        default:
            break;
    }
    bcmolt_msg_free(msg);
}

/* Register/unregister for BAL interface indications */
static bcmos_errno bcm_interfaces_ind_register_unregister(bcmos_bool is_register)
{
    bcmolt_rx_cfg cb_cfg = {
        .module = BCMOS_MODULE_ID_NETCONF_SERVER,
        .flags = BCMOLT_AUTO_FLAGS_DISPATCH
    };
    bcmolt_oltid olt = netconf_agent_olt_id();
    bcmos_errno err;

    do
    {
        cb_cfg.obj_type = BCMOLT_OBJ_ID_PON_INTERFACE;
        cb_cfg.rx_cb = _pon_interface_indication_cb;
        if (is_register)
            err = bcmolt_ind_subscribe(olt, &cb_cfg);
        else
            err = bcmolt_ind_unsubscribe(olt, &cb_cfg);
        if(BCM_ERR_OK != err)
        {
            NC_LOG_ERR("Failed to %ssubscribe to/from pon_interface indications. Error %s\n",
                is_register ? "":"un-", bcmos_strerror(err));
            break;
        }

        cb_cfg.obj_type = BCMOLT_OBJ_ID_DEVICE;
        cb_cfg.rx_cb = _device_indication_cb;
        if (is_register)
            err = bcmolt_ind_subscribe(olt, &cb_cfg);
        else
            err = bcmolt_ind_unsubscribe(olt, &cb_cfg);
        if(BCM_ERR_OK != err)
        {
            NC_LOG_ERR("Failed to %ssubscribe to/from device indications. Error %s\n",
                is_register ? "":"un-", bcmos_strerror(err));
            break;
        }
    } while (0);

    return err;
}

bcmos_errno bbf_xpon_module_init(sr_session_ctx_t *srs, struct ly_ctx *ly_ctx)
{
    bcmos_errno err = BCM_ERR_INTERNAL;
    const struct lys_module *ietf_intf_mod;
    const struct lys_module *xponvani_mod;
    const struct lys_module *xpongemtcont_mod;
    const struct lys_module *l2_forwarding_mod;
    const struct lys_module *ietf_hardware_mod;
    const struct lys_module *bbf_hardware_types_mod;
    const struct lys_module *bbf_hardware_mod;
    const struct lys_module *onu_states_mod;
    const struct lys_module *dhcpr_mod;
    const struct lys_module *bbf_interface_pon_ref_mod;
    int i;

    do  {
        /* make sure that ietf-interfaces module is loaded */
        ietf_intf_mod = ly_ctx_get_module(ly_ctx, IETF_INTERFACES_MODULE_NAME, NULL, 1);
        if (ietf_intf_mod == NULL)
        {
            ietf_intf_mod = ly_ctx_load_module(ly_ctx, IETF_INTERFACES_MODULE_NAME, NULL);
            if (ietf_intf_mod == NULL)
            {
                NC_LOG_ERR(IETF_INTERFACES_MODULE_NAME ": can't find the schema in sysrepo\n");
                break;
            }
        }

        /* make sure that bbf-xponvani module is loaded */
        xponvani_mod = ly_ctx_get_module(ly_ctx, BBF_XPONVANI_MODULE_NAME, NULL, 1);
        if (xponvani_mod == NULL)
        {
            xponvani_mod = ly_ctx_load_module(ly_ctx, BBF_XPONVANI_MODULE_NAME, NULL);
            if (xponvani_mod == NULL)
            {
                NC_LOG_ERR(BBF_XPONVANI_MODULE_NAME ": can't find the schema in sysrepo\n");
                break;
            }
        }

        /* make sure that bbf-xpongemtcont module is loaded */
        xpongemtcont_mod = ly_ctx_get_module(ly_ctx, BBF_XPONGEMTCONT_MODULE_NAME, NULL, 1);
        if (xpongemtcont_mod == NULL)
        {
            xpongemtcont_mod = ly_ctx_load_module(ly_ctx, BBF_XPONGEMTCONT_MODULE_NAME, NULL);
            if (xpongemtcont_mod == NULL)
            {
                NC_LOG_ERR(BBF_XPONGEMTCONT_MODULE_NAME ": can't find the schema in sysrepo\n");
                break;
            }
        }

        /* make sure that bbf-xpongemtcont module is loaded */
        l2_forwarding_mod = ly_ctx_get_module(ly_ctx, BBF_L2_FORWARDING_MODULE_NAME, NULL, 1);
        if (l2_forwarding_mod == NULL)
        {
            l2_forwarding_mod = ly_ctx_load_module(ly_ctx, BBF_L2_FORWARDING_MODULE_NAME, NULL);
            if (l2_forwarding_mod == NULL)
            {
                NC_LOG_ERR(BBF_L2_FORWARDING_MODULE_NAME ": can't find the schema in sysrepo\n");
                break;
            }
        }

        /* make sure that ietf-hardware module is loaded */
        ietf_hardware_mod = ly_ctx_get_module(ly_ctx, IETF_HARDWARE_MODULE_NAME, NULL, 1);
        if (ietf_hardware_mod == NULL)
        {
            ietf_hardware_mod = ly_ctx_load_module(ly_ctx, IETF_HARDWARE_MODULE_NAME, NULL);
            if (ietf_hardware_mod == NULL)
            {
                NC_LOG_ERR(IETF_HARDWARE_MODULE_NAME ": can't find the schema in sysrepo\n");
                break;
            }
        }

        /* make sure that bbf-hardware-types module is loaded */
        bbf_hardware_types_mod = ly_ctx_get_module(ly_ctx, BBF_HARDWARE_TYPES_MODULE_NAME, NULL, 1);
        if (bbf_hardware_types_mod == NULL)
        {
            bbf_hardware_types_mod = ly_ctx_load_module(ly_ctx, BBF_HARDWARE_TYPES_MODULE_NAME, NULL);
            if (bbf_hardware_types_mod == NULL)
            {
                NC_LOG_ERR(BBF_HARDWARE_TYPES_MODULE_NAME ": can't find the schema in sysrepo\n");
                break;
            }
        }

        /* make sure that bbf-hardware module is loaded */
        bbf_hardware_mod = ly_ctx_get_module(ly_ctx, BBF_HARDWARE_MODULE_NAME, NULL, 1);
        if (bbf_hardware_mod == NULL)
        {
            bbf_hardware_mod = ly_ctx_load_module(ly_ctx, BBF_HARDWARE_MODULE_NAME, NULL);
        }

        /* make sure that bbf-interface-pon-reference module is loaded */
        bbf_interface_pon_ref_mod = ly_ctx_get_module(ly_ctx, BBF_INTERFACE_PON_REFERENCE, NULL, 1);
        if (bbf_interface_pon_ref_mod == NULL)
        {
            bbf_interface_pon_ref_mod = ly_ctx_load_module(ly_ctx, BBF_INTERFACE_PON_REFERENCE, NULL);
        }

        /* AT least one of bbf-hardware.yang or bbf-interface-pon-refference.yang must be loaded */
        if (bbf_hardware_mod == NULL && bbf_interface_pon_ref_mod == NULL)
        {
            NC_LOG_ERR("can't find schemas %s and %s in sysrepo. At least one of them must be loaded.\n",
                BBF_HARDWARE_MODULE_NAME, BBF_INTERFACE_PON_REFERENCE);
            break;
        }

        /* make sure that bbf-xpon-onu-states module is loaded */
        onu_states_mod = ly_ctx_get_module(ly_ctx, BBF_XPON_ONU_STATES_MODULE_NAME, NULL, 1);
        if (onu_states_mod == NULL)
        {
            onu_states_mod = ly_ctx_load_module(ly_ctx, BBF_XPON_ONU_STATES_MODULE_NAME, NULL);
            if (onu_states_mod == NULL)
            {
                NC_LOG_ERR(BBF_XPON_ONU_STATES_MODULE_NAME ": can't find the schema in sysrepo\n");
                break;
            }
        }

        /* make sure that bbf-l2-dhcpv4-relay module is loaded */
        dhcpr_mod = ly_ctx_get_module(ly_ctx, BBF_L2_DHCPV4_RELAY_MODULE_NAME, NULL, 1);
        if (dhcpr_mod == NULL)
        {
            dhcpr_mod = ly_ctx_load_module(ly_ctx, BBF_L2_DHCPV4_RELAY_MODULE_NAME, NULL);
            if (dhcpr_mod == NULL)
            {
                NC_LOG_ERR(BBF_L2_DHCPV4_RELAY_MODULE_NAME ": can't find the schema in sysrepo\n");
                break;
            }
        }

        /* Enable all relevant features are enabled in sysrepo */
        for (i = 0; ietf_interfaces_features[i]; i++)
        {
            if (lys_features_enable(ietf_intf_mod, ietf_interfaces_features[i]))
            {
                NC_LOG_ERR("%s: can't enable feature %s\n", IETF_INTERFACES_MODULE_NAME, ietf_interfaces_features[i]);
                break;
            }
        }
        if (ietf_interfaces_features[i])
            break;

        for (i = 0; xponvani_features[i]; i++)
        {
            if (lys_features_enable(xponvani_mod, xponvani_features[i]))
            {
                NC_LOG_ERR("%s: can't enable feature %s\n", BBF_XPONVANI_MODULE_NAME, xponvani_features[i]);
                break;
            }
        }
        if (xponvani_features[i])
            break;

        for (i = 0; xpongemtcont_features[i]; i++)
        {
            if (lys_features_enable(xpongemtcont_mod, xpongemtcont_features[i]))
            {
                NC_LOG_ERR("%s: can't enable feature %s\n", BBF_XPONGEMTCONT_MODULE_NAME, xpongemtcont_features[i]);
                break;
            }
        }
        if (xpongemtcont_features[i])
            break;

        for (i = 0; l2_forwarding_features[i]; i++)
        {
            if (lys_features_enable(l2_forwarding_mod, l2_forwarding_features[i]))
            {
                NC_LOG_ERR("%s: can't enable feature %s\n", BBF_L2_FORWARDING_MODULE_NAME, l2_forwarding_features[i]);
                break;
            }
        }
        if (l2_forwarding_features[i])
            break;

        for (i = 0; ietf_hardware_features[i]; i++)
        {
            if (lys_features_enable(ietf_hardware_mod, ietf_hardware_features[i]))
            {
                NC_LOG_ERR("%s: can't enable feature %s\n", IETF_HARDWARE_MODULE_NAME, ietf_hardware_features[i]);
                break;
            }
        }
        if (ietf_hardware_features[i])
            break;

        if (bbf_hardware_mod != NULL)
        {
            for (i = 0; bbf_hardware_features[i]; i++)
            {
                if (lys_features_enable(bbf_hardware_mod, bbf_hardware_features[i]))
                {
                    NC_LOG_ERR("%s: can't enable feature %s\n", BBF_HARDWARE_MODULE_NAME, bbf_hardware_features[i]);
                    break;
                }
            }
            if (bbf_hardware_features[i])
                break;
        }

#if 0
        /* Reset stored configuration if requested */
        if (!netconf_agent_startup_options_get()->reset_cfg)
        {
            /* Copy saved running configuration to startup if required */
            if (netconf_agent_startup_options_get()->restore_running)
            {
                nc_cfg_copy(srs, IETF_INTERFACES_MODULE_NAME, NC_DATASTORE_RUNNING, NC_DATASTORE_PENDING);
            }
            else
            {
                nc_cfg_copy(srs, IETF_INTERFACES_MODULE_NAME, NC_DATASTORE_STARTUP, NC_DATASTORE_PENDING);
            }
        }
        nc_cfg_reset_startup(srs, IETF_INTERFACES_MODULE_NAME);
#endif

        sr_session = srs;

        err = bcmolt_xpon_utils_init();
        if (err != BCM_ERR_OK)
            break;

        /* Register for access terminal indications */
        err = bcm_interfaces_ind_register_unregister(BCMOS_TRUE);
        if (err != BCM_ERR_OK)
            break;

        /*
         * Initialize sub-components
         */
        err = (err != BCM_ERR_OK) ? err : xpon_wavelen_prof_init(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_cgroup_init(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_cpart_init(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_cpair_init(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_cterm_init(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_v_ani_init(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_ani_init(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_v_ani_v_enet_init(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_ani_v_enet_init(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_enet_init(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_vlan_subif_init(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_tcont_init(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_gem_init(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_link_init(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_forwarder_init(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_qos_classifier_init(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_qos_policy_init(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_qos_policy_profile_init(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_hardware_init(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_dhcpr_init(srs);

    } while (0);

    return err;
}

bcmos_errno bbf_xpon_module_start(sr_session_ctx_t *srs, struct ly_ctx *ly_ctx)
{
    bcmos_errno err = BCM_ERR_OK;
    bcmolt_devid dev;
    bcmolt_oltid olt = 0;

    do  {
        int sr_rc;
        /* Subscribe for operational data retrieval */
        sr_rc = sr_oper_get_items_subscribe(srs, IETF_INTERFACES_MODULE_NAME, BBF_XPON_INTERFACE_STATE_PATH_BASE,
            xpon_interface_state_get_cb, NULL, SR_SUBSCR_CTX_REUSE, &sr_ctx);
        if (SR_ERR_OK != sr_rc) {
            NC_LOG_ERR("Failed to subscribe to %s subtree operation data retrieval (%s).",
                BBF_XPON_INTERFACE_STATE_PATH_BASE, sr_strerror(sr_rc));
            err = nc_sr_errno_to_bcmos_errno(sr_rc);
            break;
        }

        //_reset_bal();

        /* Create NNI tm_sched */
        err = xpon_tm_sched_create(BCMOLT_INTERFACE_TYPE_NNI, 0);
        if (err != BCM_ERR_OK)
            break;

        /* Subscribe to changes if device is already active */
        for (dev = 0; dev < BCM_MAX_DEVS_PER_OLT && err == BCM_ERR_OK; dev++)
        {
            if (_device_is_connected(olt, dev))
            {
                device_connection_status[dev] = BCMOS_TRUE;
                err = _create_pon_tm_scheds(dev);
            }
        }

        /* Create default pbit to queue mapper */
        err = (err != BCM_ERR_OK) ? err : xpon_default_tm_qmp_create(BCM_DEFAULT_TM_QMP_ID);

        if (num_connected_devices())
            err = (err != BCM_ERR_OK) ? err : bbf_xpon_subscribe(srs);

        /*
         * Start sub-components
         */
        err = (err != BCM_ERR_OK) ? err : xpon_wavelen_prof_start(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_cgroup_start(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_cpart_start(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_cpair_start(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_cterm_start(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_v_ani_start(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_ani_start(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_v_ani_v_enet_start(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_ani_v_enet_start(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_enet_start(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_vlan_subif_start(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_tcont_start(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_gem_start(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_link_start(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_forwarder_start(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_qos_classifier_start(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_qos_policy_start(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_qos_policy_profile_start(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_hardware_start(srs);
        err = (err != BCM_ERR_OK) ? err : xpon_dhcpr_start(srs);

    } while (0);

    return err;
}

void bbf_xpon_module_exit(sr_session_ctx_t *srs, struct ly_ctx *ly_ctx)
{
    bbf_xpon_unsubscribe(srs);
    bcm_interfaces_ind_register_unregister(BCMOS_FALSE);
    xpon_cgroup_exit(srs);
    xpon_cpart_exit(srs);
    xpon_cpair_exit(srs);
    xpon_cterm_exit(srs);
    xpon_v_ani_exit(srs);
    xpon_ani_exit(srs);
    xpon_v_ani_v_enet_exit(srs);
    xpon_ani_v_enet_exit(srs);
    xpon_enet_exit(srs);
    xpon_vlan_subif_exit(srs);
    xpon_tcont_exit(srs);
    xpon_gem_exit(srs);
    xpon_wavelen_prof_exit(srs);
    xpon_link_exit(srs);
    xpon_forwarder_exit(srs);
    bcmolt_xpon_utils_exit();
    xpon_qos_classifier_exit(srs);
    xpon_qos_policy_exit(srs);
    xpon_qos_policy_profile_exit(srs);
    xpon_hardware_exit(srs);
    xpon_dhcpr_exit(srs);
}
