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

#include <tr451_polt_vendor.h>
#include <tr451_polt_for_vendor.h>
#include <tr451_polt_vendor_specific.h>
#include <sim_tr451_polt_vendor_internal.h>

#define TR451_POLT_DEFAULT_LISTEN_FROM_ONU_SIM_PORT 50500
static uint8_t inject_buffer[44];
static uint8_t registration_id_buffer[36];

/* Inject OMCI_RX packet */
static bcmos_errno polt_cli_inject_omci_rx(bcmcli_session *session, const bcmcli_cmd_parm parm[], uint16_t nparms)
{
    const char *cterm_name = (const char *)parm[0].value.string;
    uint16_t onu_id = (uint16_t)parm[1].value.unumber;
    sim_tr451_vendor_packet_received_from_onu(cterm_name, onu_id,
        inject_buffer,
        bcmolt_buf_get_used(&parm[2].value.buffer));
    /* Clear buffer for the next iteration */
    memset(inject_buffer, 0, sizeof(inject_buffer));
    return BCM_ERR_OK;
}

/*Inject OMCI_TX packet to ONU*/
static bcmos_errno polt_cli_inject_omci_tx(bcmcli_session *session, const bcmcli_cmd_parm parm[], uint16_t nparms)
{
    bcmos_errno err;

    OnuHeader *header = new OnuHeader();
    header->set_chnl_term_name(parm[0].value.string);
    header->set_onu_id(parm[1].value.unumber);
    OmciPacket *grpc_omci_packet = new OmciPacket();
    grpc_omci_packet->set_allocated_header(header);
    grpc_omci_packet->set_payload(inject_buffer, sizeof(inject_buffer));

    err = tr451_vendor_omci_send_to_onu(*grpc_omci_packet);
    if (err != BCM_ERR_OK)
    {
        grpc::Status status = tr451_bcm_errno_grpc_status(err,
            "Failed to send OMCI message to ONU %s:%u. Error '%s'",
            grpc_omci_packet->header().chnl_term_name().c_str(), grpc_omci_packet->header().onu_id(),
            bcmos_strerror(err));
        BCM_POLT_LOG(ERROR, "%s:\n", status.error_message().c_str());
        return BCM_ERR_IO;
    }
    BCM_POLT_LOG(DEBUG, "Sent OMCI message to ONU %s:%u. %lu bytes\n",
        grpc_omci_packet->header().chnl_term_name().c_str(), grpc_omci_packet->header().onu_id(),
        grpc_omci_packet->payload().length());

    return BCM_ERR_OK;
}

/* Add ONU */
static bcmos_errno polt_cli_onu_add(bcmcli_session *session, const bcmcli_cmd_parm parm[], uint16_t nparms)
{
    const char *cterm_name = (const char *)parm[0].value.string;
    uint16_t onu_id = (uint16_t)parm[1].value.unumber;
    const char *vendor_id = (const char *)parm[2].value.string;
    uint32_t vendor_specific = (uint32_t)parm[3].value.unumber;
    xpon_onu_presence_flags flags = (xpon_onu_presence_flags)parm[4].value.unumber;
    uint8_t *registration_id = bcmcli_parm_is_set(session, &parm[5]) ? registration_id_buffer : NULL;
    bcmos_errno rc;

    tr451_polt_onu_serial_number serial_number = {};
    strncpy((char *)&serial_number.data[0], vendor_id, sizeof(serial_number));
    serial_number.data[4] = (vendor_specific >> 24) & 0xff;
    serial_number.data[5] = (vendor_specific >> 16) & 0xff;
    serial_number.data[6] = (vendor_specific >> 8) & 0xff;
    serial_number.data[7] = vendor_specific & 0xff;

    rc = sim_tr451_vendor_onu_added(cterm_name, onu_id, &serial_number, registration_id, flags);
    memset(registration_id_buffer, 0, sizeof(registration_id_buffer));
    return rc;
}

/* Delete ONU */
static bcmos_errno polt_cli_onu_delete(bcmcli_session *session, const bcmcli_cmd_parm parm[], uint16_t nparms)
{
    const char *cterm_name = (const char *)parm[0].value.string;
    uint16_t onu_id = (uint16_t)parm[1].value.unumber;
    const char *vendor_id = (const char *)parm[2].value.string;
    uint32_t vendor_specific = (uint32_t)parm[3].value.unumber;
    xpon_onu_presence_flags flags = (xpon_onu_presence_flags)parm[4].value.unumber;

    tr451_polt_onu_serial_number serial_number = {};
    strncpy((char *)&serial_number.data[0], vendor_id, sizeof(serial_number));
    serial_number.data[4] = (vendor_specific >> 24) & 0xff;
    serial_number.data[5] = (vendor_specific >> 16) & 0xff;
    serial_number.data[6] = (vendor_specific >> 8) & 0xff;
    serial_number.data[7] = vendor_specific & 0xff;

    return sim_tr451_vendor_onu_removed(cterm_name, onu_id, &serial_number, flags);
}

/* Set Rx handling mode */
static bcmos_errno polt_cli_set_rx_mode(bcmcli_session *session, const bcmcli_cmd_parm parm[], uint16_t nparms)
{
    tr451_polt_sim_rx_cfg rx_cfg = {};
    rx_cfg.mode = (tr451_polt_sim_rx_mode)parm[0].value.number;
    switch (rx_cfg.mode)
    {
        case TR451_POLT_SIM_RX_MODE_DISCARD:
            break;
        case TR451_POLT_SIM_RX_MODE_LOOPBACK:
            rx_cfg.loopback.skip = (uint32_t)parm[1].value.unumber;
            break;
        case TR451_POLT_SIM_RX_MODE_ONU_SIM:
            rx_cfg.onu_sim.remote_address = (uint32_t)parm[1].value.unumber;
            rx_cfg.onu_sim.remote_port = (uint16_t)parm[2].value.unumber;
            rx_cfg.onu_sim.local_port = (uint16_t)parm[3].value.unumber;
            break;
    }
    return sim_tr451_vendor_rx_cfg_set(&rx_cfg);
}

bcmos_errno tr451_vendor_cli_init(bcmcli_entry *dir)
{
    static bcmcli_enum_val onu_flags_table[] = {
        { .name = "expected",           .val=XPON_ONU_PRESENCE_FLAG_V_ANI },
        { .name = "present",            .val=XPON_ONU_PRESENCE_FLAG_ONU },
        { .name = "in_o5",              .val=XPON_ONU_PRESENCE_FLAG_ONU_IN_O5 },
        { .name = "activation_failed",  .val=XPON_ONU_PRESENCE_FLAG_ONU_ACTIVATION_FAILED },
        BCMCLI_ENUM_LAST
    };

    /* Add ONU */
    {
        static bcmcli_cmd_parm cmd_parms[] = {
            BCMCLI_MAKE_PARM("channel_term", "Channel termination name", BCMCLI_PARM_STRING, 0),
            BCMCLI_MAKE_PARM("onu_id", "onu_id", BCMCLI_PARM_NUMBER, 0),
            BCMCLI_MAKE_PARM("serial_vendor_id", "serial_number: 4 bytes ASCII vendor id", BCMCLI_PARM_STRING, 0),
            BCMCLI_MAKE_PARM("serial_vendor_specific", "serial_number: vendor-specific id", BCMCLI_PARM_HEX, 0),
            BCMCLI_MAKE_PARM_ENUM_MASK_DEFVAL("flags", "notification flags", onu_flags_table, 0, "expected+present+in_o5"),
            BCMCLI_MAKE_PARM("registration_id", "Optional registration id", BCMCLI_PARM_BUFFER, BCMCLI_PARM_FLAG_OPTIONAL),
            { 0 }
        } ;
        cmd_parms[5].value.buffer.len = sizeof(registration_id_buffer);
        cmd_parms[5].value.buffer.start = cmd_parms[5].value.buffer.curr = registration_id_buffer;
        bcmcli_cmd_add(dir, "onu_add", polt_cli_onu_add, "Add ONU",
            BCMCLI_ACCESS_ADMIN, NULL, cmd_parms);
    }

    /* Delete ONU */
    {
        static bcmcli_cmd_parm cmd_parms[] = {
            BCMCLI_MAKE_PARM("channel_term", "Channel termination name", BCMCLI_PARM_STRING, 0),
            BCMCLI_MAKE_PARM("onu_id", "onu_id", BCMCLI_PARM_NUMBER, 0),
            BCMCLI_MAKE_PARM("serial_vendor_id", "serial_number: 4 bytes ASCII vendor id", BCMCLI_PARM_STRING, 0),
            BCMCLI_MAKE_PARM("serial_vendor_specific", "serial_number: vendor-specific id", BCMCLI_PARM_HEX, 0),
            BCMCLI_MAKE_PARM_ENUM_MASK_DEFVAL("flags", "notification flags", onu_flags_table, 0, "expected"),
            { 0 }
        } ;
        bcmcli_cmd_add(dir, "onu_delete", polt_cli_onu_delete, "Delete ONU",
            BCMCLI_ACCESS_ADMIN, NULL, cmd_parms);
    }

    /* Inject proxy_rx */
    {
        static bcmcli_cmd_parm inject_parms[] = {
            BCMCLI_MAKE_PARM("channel_term", "Channel termination name", BCMCLI_PARM_STRING, 0),
            BCMCLI_MAKE_PARM("onu", "ONU", BCMCLI_PARM_NUMBER, 0),
            BCMCLI_MAKE_PARM("data", "OMCI packet without MIC", BCMCLI_PARM_BUFFER, 0),
            { 0 } } ;
        inject_parms[2].value.buffer.len = sizeof(inject_buffer);
        inject_parms[2].value.buffer.start = inject_parms[2].value.buffer.curr = inject_buffer;
        bcmcli_cmd_add(dir, "inject", polt_cli_inject_omci_rx,
            "Inject OMCI packet received from ONU", BCMCLI_ACCESS_ADMIN, NULL, inject_parms);
    }

    /* Inject proxy_tx */
    {
        static bcmcli_cmd_parm inject_parms[] = {
            BCMCLI_MAKE_PARM("channel_term", "Channel termination name", BCMCLI_PARM_STRING, 0),
            BCMCLI_MAKE_PARM("onu", "ONU", BCMCLI_PARM_NUMBER, 0),
            BCMCLI_MAKE_PARM("data", "OMCI packet without MIC", BCMCLI_PARM_BUFFER, 0),
            { 0 } } ;
        inject_parms[2].value.buffer.len = sizeof(inject_buffer);
        inject_parms[2].value.buffer.start = inject_parms[2].value.buffer.curr = inject_buffer;
        bcmcli_cmd_add(dir, "inject_onu", polt_cli_inject_omci_tx,
            "Inject OMCI packet received from vOMCI", BCMCLI_ACCESS_ADMIN, NULL, inject_parms);
    }


    /* Set Rx handling mode */
    {
        static bcmcli_cmd_parm loopback_parms[] = {
            BCMCLI_MAKE_PARM("skip", "Acknowledge 1 packet per skip+1 requests with AR=1", BCMCLI_PARM_NUMBER, 0),
            { 0 } } ;
        static bcmcli_cmd_parm onu_sim_parms[] = {
            BCMCLI_MAKE_PARM("onu_sim_ip", "ONU simulator IP address", BCMCLI_PARM_IP, 0),
            BCMCLI_MAKE_PARM("onu_sim_port", "ONU simulator UDP port", BCMCLI_PARM_NUMBER, 0),
            BCMCLI_MAKE_PARM("local_udp_port", "Optional local UDP port", BCMCLI_PARM_NUMBER, BCMCLI_PARM_FLAG_DEFVAL),
            { 0 } } ;
        onu_sim_parms[2].value.number = TR451_POLT_DEFAULT_LISTEN_FROM_ONU_SIM_PORT;
        static bcmcli_enum_val rx_mode_enum_table[] = {
            { .name = "discard", .val = (long)TR451_POLT_SIM_RX_MODE_DISCARD },
            { .name = "loopback", .val = (long)TR451_POLT_SIM_RX_MODE_LOOPBACK, .parms = loopback_parms },
            { .name = "onu_sim", .val = (long)TR451_POLT_SIM_RX_MODE_ONU_SIM , .parms = onu_sim_parms },
            BCMCLI_ENUM_LAST
        };
        static bcmcli_cmd_parm cmd_parms[] = {
            BCMCLI_MAKE_PARM("mode", "RX handling mode", BCMCLI_PARM_ENUM, BCMCLI_PARM_FLAG_SELECTOR),
            { 0 }
        } ;
        cmd_parms[0].enum_table = rx_mode_enum_table;
        bcmcli_cmd_add(dir, "rx_mode", polt_cli_set_rx_mode, "Set Receive handling mode",
            BCMCLI_ACCESS_ADMIN, NULL, cmd_parms);

    }

    return BCM_ERR_OK;
}
