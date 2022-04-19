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

#include <bcmos_system.h>
#include <bcmolt_netconf_module_utils.h>
#include <bcmolt_netconf_constants.h>
#include <bbf-mfc.h>
#include <mfc_relay.h>

#define BCM_MAX_YANG_NAME_LENGTH    32

static sr_subscription_ctx_t *sr_ctx;
static sr_subscription_ctx_t *sr_ctx_state;

static const char* bbf_polt_mfc_features[] = {
    "*",
    NULL
};

/* Data store change indication callback */
static int bbf_polt_mfc_client_change_cb(sr_session_ctx_t *srs,
#ifdef SYSREPO_LIBYANG_V2
    uint32_t sub_id,
#endif
    const char *module_name, const char *xpath, sr_event_t event,
    uint32_t request_id, void *private_ctx)
{
    sr_change_iter_t *sr_iter = NULL;
    sr_change_oper_t sr_oper;
    const struct lyd_node *node;
    const char *prev_val, *prev_list;
    NC_SR_GET_CHANGE_TREE_NEXT_PREF_DFLT_TYPE prev_dflt;
    mfc_relay_client_parms mfc_client_parms = {};
    char qualified_xpath[BCM_MAX_XPATH_LENGTH];

    int sr_rc;
    bcmos_errno err = BCM_ERR_OK;

    NC_LOG_INFO("xpath=%s event=%d\n", xpath, event);

    /* We only handle CHANGE and ABORT events.
     * Since there is no way to reserve resources in advance and no way to fail the APPLY event,
     * configuration is applied in VERIFY event.
     * There are no other verifiers, but if there are and they fail,
     * ABORT event will roll-back the changes.
     */
    if (event == SR_EV_DONE)
        return SR_ERR_OK;

    snprintf(qualified_xpath, sizeof(qualified_xpath)-1, "%s//.", xpath);
    qualified_xpath[sizeof(qualified_xpath)-1] = 0;

    sr_rc = sr_get_changes_iter(srs, qualified_xpath, &sr_iter);
    while ((err == BCM_ERR_OK) && (sr_rc == SR_ERR_OK) &&
           ((sr_rc = sr_get_change_tree_next(srs, sr_iter, &sr_oper,
                &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK))
    {
        const char *node_name = node->schema->name;

        NC_LOG_DBG("op=%s node=%s\n", sr_op_name(sr_oper), node_name);

        /* Handle attributes */
        if (!strcmp(node_name, "enabled"))
        {
            /* SIVA CALL WRAPPER */
            err = bcm_mfc_relay_client_enable_disable(
                (sr_oper != SR_OP_DELETED) && NC_LYD_DATA_NODE_BOOL_VAL(node));
            continue;
        }

        if (sr_oper != SR_OP_DELETED)
        {
            if (!strcmp(node_name, "remote-port") || !strcmp(node_name, "remote-address"))
            {
                /* access points */
                const struct lyd_node *access_name_node;
                const struct lyd_node *endpoint_name_node;

                access_name_node = nc_ly_get_sibling_or_parent_node(node, "name");
                NC_LOG_DBG("access-node %s\n", access_name_node ? access_name_node->schema->name : "*undefined*");
                if (access_name_node == NULL)
                {
                    NC_LOG_ERR("can't find access-node\n");
                    continue;
                }
                endpoint_name_node = nc_ly_get_sibling_or_parent_node(access_name_node, "name");
                if (endpoint_name_node == NULL)
                {
                    NC_LOG_ERR("can't find remote-endpoint node\n");
                    continue;
                }
                NC_LOG_DBG("Handling remote-endpoint[%s]/access-points[%s]\n",
                    endpoint_name_node->schema->name, access_name_node->schema->name);
                mfc_client_parms.access_point_name = NC_LYD_DATA_NODE_STRING_VAL(access_name_node);
                mfc_client_parms.endpoint_name = NC_LYD_DATA_NODE_STRING_VAL(endpoint_name_node);
                mfc_client_parms.access_point_name = NC_LYD_DATA_NODE_STRING_VAL(access_name_node);

                if (!strcmp(node_name, "remote-port"))
                    mfc_client_parms.port = NC_LYD_DATA_NODE_VAL(node)->uint16;
                else if (!strcmp(node_name, "remote-address"))
                    mfc_client_parms.server_address = NC_LYD_DATA_NODE_STRING_VAL(node);
                else if (!strcmp(node_name, "local-endpoint-name"))
                    mfc_client_parms.local_endpoint_name = NC_LYD_DATA_NODE_STRING_VAL(node);

                if ((mfc_client_parms.port != 0) &&
                    (mfc_client_parms.server_address != NULL) &&
                    (mfc_client_parms.local_endpoint_name != NULL))
                {
                    /* SIVA CALL WRAPPER */
                    err = bcm_mfc_relay_client_create(&mfc_client_parms);
                    memset(&mfc_client_parms, 0, sizeof(mfc_client_parms));
                }
            }
        }
        else
        {
            const struct lyd_node *endpoint_node;
            const struct lyd_node *access_node;
            const char *entity_name = NC_LYD_DATA_NODE_STRING_VAL(node);

            /* Deleted */
            if (!strcmp(node_name, "name"))
            {
                access_node = nc_ly_get_sibling_or_parent_node(node, "access-points");
                endpoint_node = nc_ly_get_sibling_or_parent_node(node, "remote-endpoints");

                if (access_node)
                {
                    /* SIVA CALL WRAPPER */
                    NC_LOG_DBG("Deleting access-points [%s] is not supported. Request ignored\n",
                        entity_name);
                }
                else if (endpoint_node != NULL)
                {
                    /* SIVA CALL WRAPPER */
                    err = bcm_mfc_relay_client_delete(NC_LYD_DATA_NODE_STRING_VAL(endpoint_node));
                }
            }
        }
    }
    sr_free_change_iter(sr_iter);

    return nc_bcmos_errno_to_sr_errno(err);
}

bcmos_errno bbf_polt_mfc_module_init(sr_session_ctx_t *srs, struct ly_ctx *ly_ctx)
{
    const struct lys_module *bbf_polt_mod;

    bbf_polt_mod = nc_ly_ctx_load_module(ly_ctx, BBF_POLT_MFC_MODULE_NAME, NULL,
        bbf_polt_mfc_features, BCMOS_TRUE);
    if (bbf_polt_mod == NULL)
    {
        NC_LOG_ERR("%s: can't find the schema in sysrepo\n", BBF_POLT_MFC_MODULE_NAME);
        return BCM_ERR_INTERNAL;
    }

    return BCM_ERR_OK;
}

static char *_get_date_time_string(char *buf, uint32_t buf_size)
{
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    snprintf(buf, buf_size,
        "%.4d-%.2d-%.2dT%.2d:%.2d:%.2dZ",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

/* Client endpoint connected/disconnected notification */
static void _client_connect_disconnect_cb(void *data, const char *remote_endpoint_name,
    const char *access_point_name, bcmos_bool is_connected)
{
    sr_session_ctx_t *session = (sr_session_ctx_t *)data;
    const struct ly_ctx *ctx = sr_get_context(sr_session_get_connection(session));
    struct lyd_node *notif = NULL;
    char notif_xpath[200];
    char date_time_string[64];

    do
    {
        snprintf(notif_xpath, sizeof(notif_xpath)-1,
            "%s/remote-endpoint[name='%s']/remote-endpoint-status-change",
            BBF_POLT_MFC_CLIENT_REMOTE_ENDPOINTS_PATH, remote_endpoint_name);
        notif = nc_ly_sub_value_add(ctx, NULL, notif_xpath, NULL, NULL);
        if (notif == NULL)
        {
            NC_LOG_ERR("Failed to create notification %s.\n", notif_xpath);
            break;
        }

        if (nc_ly_sub_value_add(ctx, notif, notif_xpath, "access-point", access_point_name) == NULL)
        {
            NC_LOG_ERR("Failed to add 'access-point' node to notification %s.\n", notif_xpath);
            break;
        }

        if (nc_ly_sub_value_add(ctx, notif, notif_xpath, "connected", is_connected ? "true" : "false") == NULL)
        {
            NC_LOG_ERR("Failed to add 'connected' node to notification %s.\n", notif_xpath);
            break;
        }

        if (nc_ly_sub_value_add(ctx, notif, notif_xpath, "remote-endpoint-state-last-change",
                _get_date_time_string(date_time_string, sizeof(date_time_string))) == NULL)
        {
            NC_LOG_ERR("Failed to add 'remote-endpoint-state-last-change' node to notification %s.\n", notif_xpath);
            break;
        }

        if (nc_sr_event_notif_send(session, notif, notif_xpath) != BCM_ERR_OK)
            break;

        NC_LOG_DBG("Sent %s notification: remote_endpoint %s, access_point %s: %sconnected\n",
            notif_xpath, remote_endpoint_name, access_point_name, is_connected ? "" : "dis");

    } while (0);

    nc_sr_event_notif_free(notif);
}

bcmos_errno bbf_polt_mfc_module_start(sr_session_ctx_t *srs, struct ly_ctx *ly_ctx)
{
    int sr_rc;
    bcmos_errno err;

    /* Register for gRPC connect/disconnect notifications */
    err = bcm_mfc_connect_disconnect_cb_register(_client_connect_disconnect_cb, srs);
    if (err != BCM_ERR_OK)
    {
        NC_LOG_ERR("Failed to subscribe to pOLT connect/disconnect notifications (%s).\n",
            bcmos_strerror(err));
        return err;
    }

    /* subscribe to events */
    sr_rc = sr_module_change_subscribe(srs, BBF_POLT_MFC_MODULE_NAME, BBF_POLT_MFC_CLIENT_PATH,
            bbf_polt_mfc_client_change_cb, NULL, 0, SR_SUBSCR_ENABLED | SR_SUBSCR_CTX_REUSE,
            &sr_ctx);
    if (SR_ERR_OK != sr_rc)
    {
        NC_LOG_ERR("Failed to subscribe to %s subtree changes (%s).\n",
            BBF_POLT_MFC_CLIENT_PATH, sr_strerror(sr_rc));
        bbf_polt_mfc_module_exit(srs, ly_ctx);
        return nc_sr_errno_to_bcmos_errno(sr_rc);
    }
    NC_LOG_INFO("Subscribed to %s subtree changes.\n", BBF_POLT_MFC_CLIENT_PATH);

    return BCM_ERR_OK;
}

void bbf_polt_mfc_module_exit(sr_session_ctx_t *srs, struct ly_ctx *ly_ctx)
{
    if (sr_ctx != NULL)
    {
        sr_unsubscribe(sr_ctx);
        sr_ctx = NULL;
    }
    if (sr_ctx_state != NULL)
    {
        sr_unsubscribe(sr_ctx_state);
        sr_ctx_state = NULL;
    }
    bcm_mfc_connect_disconnect_cb_register(NULL, srs);
}
