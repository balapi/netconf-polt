/*
<:copyright-BRCM:2016-2020:Apache:standard

 Copyright (c) 2016-2020 Broadcom. All Rights Reserved

 The term “Broadcom” refers to Broadcom Inc. and/or its subsidiaries

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

:>
 */
#include <bcm_tr451_polt.h>
#include <bcm_tr451_polt_internal.h>

/* Print OMCI send/receive statistics */
static bcmos_errno polt_cli_stats(bcmcli_session *session, const bcmcli_cmd_parm parm[], uint16_t nparms)
{
    VomciConnectionStats stats = {};
    const char *ep_name = nullptr;
    const char *peer_name = nullptr;
    do
    {
        bcm_tr451_stats_get(&ep_name, &peer_name, &stats);
        if (ep_name == nullptr)
            break;
        bcmcli_print(session,
            "Endpoint %s peer=%s: to-ONU: gRPC=%u OMCI=%u discarded=%u  from-ONU: OMCI=%u gRPC=%u discarded=%u\n",
            ep_name, peer_name,
            stats.packets_vomci_to_onu_recv, stats.packets_vomci_to_onu_sent, stats.packets_vomci_to_onu_disc,
            stats.packets_onu_to_vomci_recv, stats.packets_onu_to_vomci_sent, stats.packets_onu_to_vomci_disc);
    } while (BCMOS_TRUE);
    return BCM_ERR_OK;
}

/* Create client/server endpoint */
static bcmos_errno polt_cli_endpoint_create(bcmcli_session *session, const bcmcli_cmd_parm parm[], uint16_t nparms)
{
    bcmos_bool is_server = (bcmos_bool)parm[0].value.number;
    tr451_endpoint ep = {
        .name = (const char *)parm[1].value.string,
        .host_name = bcmcli_parm_is_set(session, &parm[3]) ? (const char *)parm[3].value.string : NULL,
        .port = (uint16_t)parm[2].value.number
    };
    bcmos_errno rc;

    if (is_server)
    {
        tr451_server_endpoint server_ep = { .endpoint = ep };
        rc = bcm_tr451_polt_grpc_server_create(&server_ep);
    }
    else
    {
        tr451_client_endpoint *client_ep;
        if (ep.host_name == NULL)
        {
            bcmcli_print(session, "Hostname is required for client endpoint\n");
            return BCM_ERR_PARM;
        }
        client_ep = bcm_tr451_client_endpoint_alloc(ep.name);
        rc = bcm_tr451_client_endpoint_add_entry(client_ep, &ep);
        rc = rc ? rc : bcm_tr451_polt_grpc_client_create(client_ep);
        bcm_tr451_client_endpoint_free(client_ep);
    }
    return rc;
}

/* Delete client/server endpoint */
static bcmos_errno polt_cli_endpoint_delete(bcmcli_session *session, const bcmcli_cmd_parm parm[], uint16_t nparms)
{
    bcmos_bool is_server = (bcmos_bool)parm[0].value.number;
    const char *name = (const char *)parm[1].value.string;
    bcmos_errno rc;

    if (is_server)
    {
        rc = bcm_tr451_polt_grpc_server_delete(name);
    }
    else
    {
        rc = bcm_tr451_polt_grpc_client_delete(name);
    }
    return rc;
}

/* Create client/server filter */
static bcmos_errno polt_cli_create_filter(bcmcli_session *session, const bcmcli_cmd_parm parm[], uint16_t nparms)
{
    tr451_polt_filter filter = {
        .name = (const char *)parm[0].value.string,
        .type = (tr451_polt_filter_type)parm[3].value.number,
        .priority = (uint16_t)parm[1].value.number,
    };
    const char *ep_name = (const char *)parm[2].value.string;
    uint16_t vendor_id = (uint16_t)parm[4].value.number;
    uint16_t vendor_specific = (uint16_t)parm[5].value.number;
    bcmos_errno rc;

    if (filter.type == TR451_FILTER_TYPE_ANY)
    {
        if (bcmcli_parm_is_set(session, &parm[4]) || bcmcli_parm_is_set(session, &parm[5]))
        {
            bcmcli_print(session, "vendor_id and/or vendor_specific parameters are incompatible with filter mode ANY\n");
            return BCM_ERR_PARM;
        }
    }
    else if (filter.type == TR451_FILTER_TYPE_VENDOR_ID)
    {
        if (!bcmcli_parm_is_set(session, &parm[4]))
        {
            bcmcli_print(session, "vendor_id is required for filter mode vendor_id\n");
            return BCM_ERR_PARM;
        }
        if (bcmcli_parm_is_set(session, &parm[5]))
        {
            bcmcli_print(session, "vendor_specific is incompatible with filter mode vendor_id\n");
            return BCM_ERR_PARM;
        }
        filter.serial_number[0] = (vendor_id >> 24) & 0xff;
        filter.serial_number[1] = (vendor_id >> 16) & 0xff;
        filter.serial_number[2] = (vendor_id >> 8) & 0xff;
        filter.serial_number[3] = vendor_id & 0xff;
    }
    else if (filter.type == TR451_FILTER_TYPE_SERIAL_NUMBER)
    {
        if (!bcmcli_parm_is_set(session, &parm[4]) || !bcmcli_parm_is_set(session, &parm[5]))
        {
            bcmcli_print(session, "vendor_id and vendor_specific are required for filter mode vendor_id\n");
            return BCM_ERR_PARM;
        }
        filter.serial_number[0] = (vendor_id >> 24) & 0xff;
        filter.serial_number[1] = (vendor_id >> 16) & 0xff;
        filter.serial_number[2] = (vendor_id >> 8) & 0xff;
        filter.serial_number[3] = vendor_id & 0xff;
        filter.serial_number[4] = (vendor_specific >> 24) & 0xff;
        filter.serial_number[5] = (vendor_specific >> 16) & 0xff;
        filter.serial_number[6] = (vendor_specific >> 8) & 0xff;
        filter.serial_number[7] = vendor_specific & 0xff;
    }
    rc = bcm_tr451_polt_filter_set(&filter, ep_name);
    return rc;
}

/* Enable/disable client/server subsystem */
static bcmos_errno polt_cli_set_state(bcmcli_session *session, const bcmcli_cmd_parm parm[], uint16_t nparms)
{
    bcmos_bool is_server = (bcmos_bool)parm[0].value.number;
    bcmos_bool is_enable = (bcmos_bool)parm[1].value.number;
    bcmos_errno rc;

    if (is_server)
        rc = bcm_tr451_polt_grpc_server_enable_disable(is_enable);
    else
        rc = bcm_tr451_polt_grpc_client_enable_disable(is_enable);
    return rc;
}

/* Set authentication names */
static bcmos_errno polt_cli_set_auth_keys(bcmcli_session *session, const bcmcli_cmd_parm parm[], uint16_t nparms)
{
    return bcm_tr451_auth_set(parm[0].value.string, parm[1].value.string, parm[2].value.string);
}

void bcm_tr451_polt_cli_init(void)
{
    bcmcli_entry *dir;
    static bcmcli_enum_val client_server_enum_table[] = {
        { .name = "client", .val = (long)BCMOS_FALSE },
        { .name = "server", .val = (long)BCMOS_TRUE },
        BCMCLI_ENUM_LAST
    };
    static bcmcli_enum_val filter_enum_table[] = {
        { .name = "any", .val = (long)TR451_FILTER_TYPE_ANY },
        { .name = "vendor_id", .val = (long)TR451_FILTER_TYPE_VENDOR_ID },
        { .name = "serial_number", .val = (long)TR451_FILTER_TYPE_SERIAL_NUMBER },
        BCMCLI_ENUM_LAST
    };

    dir = bcmcli_dir_add(NULL, "polt", "pOLT Debug", BCMCLI_ACCESS_ADMIN, NULL);

    /* Enable/disable client/server subsystem */
    {
        static bcmcli_cmd_parm cmd_parms[] = {
            BCMCLI_MAKE_PARM("client_server", "Client/Server", BCMCLI_PARM_ENUM, 0),
            BCMCLI_MAKE_PARM("enable", "Enable", BCMCLI_PARM_ENUM, 0),
            { 0 }
        } ;
        cmd_parms[0].enum_table = client_server_enum_table;
        cmd_parms[1].enum_table = bcmcli_enum_bool_table;
        bcmcli_cmd_add(dir, "set_state", polt_cli_set_state, "Enable/disable client/server subsystem",
            BCMCLI_ACCESS_ADMIN, NULL, cmd_parms);
    }

    /* Create an endpoint */
    {
        static bcmcli_cmd_parm cmd_parms[] = {
            BCMCLI_MAKE_PARM("client_server", "Client/Server", BCMCLI_PARM_ENUM, 0),
            BCMCLI_MAKE_PARM("name", "Endpoint name", BCMCLI_PARM_STRING, 0),
            BCMCLI_MAKE_PARM("port", "port to listen at/connect to", BCMCLI_PARM_NUMBER, 0),
            BCMCLI_MAKE_PARM("host", "host to listen at/connect to", BCMCLI_PARM_STRING, BCMCLI_PARM_FLAG_OPTIONAL),
            { 0 }
        } ;
        cmd_parms[0].enum_table = client_server_enum_table;
        bcmcli_cmd_add(dir, "endpoint_create", polt_cli_endpoint_create, "Create a client/server endpoint",
            BCMCLI_ACCESS_ADMIN, NULL, cmd_parms);
    }

    /* Delete an endpoint */
    {
        static bcmcli_cmd_parm cmd_parms[] = {
            BCMCLI_MAKE_PARM("client_server", "Client/Server", BCMCLI_PARM_ENUM, 0),
            BCMCLI_MAKE_PARM("name", "Endpoint name", BCMCLI_PARM_STRING, 0),
            { 0 }
        } ;
        cmd_parms[0].enum_table = client_server_enum_table;
        bcmcli_cmd_add(dir, "endpoint_Delete", polt_cli_endpoint_delete, "Delete a client/server endpoint",
            BCMCLI_ACCESS_ADMIN, NULL, cmd_parms);
    }

    /* Create a filter */
    {
        static bcmcli_cmd_parm cmd_parms[] = {
            BCMCLI_MAKE_PARM("name", "Filter name", BCMCLI_PARM_STRING, 0),
            BCMCLI_MAKE_PARM("priority", "Filter priority", BCMCLI_PARM_NUMBER, 0),
            BCMCLI_MAKE_PARM("ep_name", "Endpoint name", BCMCLI_PARM_STRING, 0),
            BCMCLI_MAKE_PARM("type", "Filter mode", BCMCLI_PARM_ENUM, 0),
            BCMCLI_MAKE_PARM("vendor_id", "Vendor id", BCMCLI_PARM_HEX, BCMCLI_PARM_FLAG_OPTIONAL),
            BCMCLI_MAKE_PARM("vendor_specific", "Vendor specific id", BCMCLI_PARM_HEX, BCMCLI_PARM_FLAG_OPTIONAL),
            { 0 }
        };
        cmd_parms[3].enum_table = filter_enum_table;
        bcmcli_cmd_add(dir, "filter", polt_cli_create_filter, "Create a client/server filter",
            BCMCLI_ACCESS_ADMIN, NULL, cmd_parms);
    }

    /* Authentication keys */
    {
        static bcmcli_cmd_parm cmd_parms[] = {
            BCMCLI_MAKE_PARM("priv_key", "Private key file name", BCMCLI_PARM_STRING, 0),
            BCMCLI_MAKE_PARM("local_cert", "Local certificate file name", BCMCLI_PARM_STRING, 0),
            BCMCLI_MAKE_PARM("peer_cert", "Peer certificate file name", BCMCLI_PARM_STRING, 0),
            { 0 }
        } ;
        bcmcli_cmd_add(dir, "auth", polt_cli_set_auth_keys, "Set authentication keys",
            BCMCLI_ACCESS_ADMIN, NULL, cmd_parms);
    }

    /* Display statistics */
    BCMCLI_MAKE_CMD_NOPARM(dir, "stats", "Print statistics", polt_cli_stats);

#ifdef TR451_POLT_ENABLE_VENDOR_CLI
    /* Initialize vendor CLI */
    tr451_vendor_cli_init(dir);
#endif
}
