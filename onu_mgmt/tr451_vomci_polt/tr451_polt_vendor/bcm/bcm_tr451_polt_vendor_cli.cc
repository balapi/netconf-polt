/*
<:copyright-BRCM:2016-2020:proprietary:standard

 Copyright (c) 2016-2020 Broadcom. All Rights Reserved

 This program is the proprietary software of Broadcom and/or its
 licensors, and may only be used, duplicated, modified or distributed pursuant
 to the terms and conditions of a separate, written license agreement executed
 between you and Broadcom (an "Authorized License").  Except as set forth in
 an Authorized License, Broadcom grants no license (express or implied), right
 to use, or waiver of any kind with respect to the Software, and Broadcom
 expressly reserves all rights in and to the Software and all intellectual
 property rights therein.  IF YOU HAVE NO AUTHORIZED LICENSE, THEN YOU HAVE
 NO RIGHT TO USE THIS SOFTWARE IN ANY WAY, AND SHOULD IMMEDIATELY NOTIFY
 BROADCOM AND DISCONTINUE ALL USE OF THE SOFTWARE.

 Except as expressly set forth in the Authorized License,

 1. This program, including its structure, sequence and organization,
    constitutes the valuable trade secrets of Broadcom, and you shall use
    all reasonable efforts to protect the confidentiality thereof, and to
    use this information only in connection with your use of Broadcom
    integrated circuit products.

 2. TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
    AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES, REPRESENTATIONS OR
    WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH
    RESPECT TO THE SOFTWARE.  BROADCOM SPECIFICALLY DISCLAIMS ANY AND
    ALL IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY, NONINFRINGEMENT,
    FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES, ACCURACY OR
    COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE
    TO DESCRIPTION. YOU ASSUME THE ENTIRE RISK ARISING OUT OF USE OR
    PERFORMANCE OF THE SOFTWARE.

 3. TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL BROADCOM OR
    ITS LICENSORS BE LIABLE FOR (i) CONSEQUENTIAL, INCIDENTAL, SPECIAL,
    INDIRECT, OR EXEMPLARY DAMAGES WHATSOEVER ARISING OUT OF OR IN ANY
    WAY RELATING TO YOUR USE OF OR INABILITY TO USE THE SOFTWARE EVEN
    IF BROADCOM HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES;
    OR (ii) ANY AMOUNT IN EXCESS OF THE AMOUNT ACTUALLY PAID FOR THE
    SOFTWARE ITSELF OR U.S. $1, WHICHEVER IS GREATER. THESE LIMITATIONS
    SHALL APPLY NOTWITHSTANDING ANY FAILURE OF ESSENTIAL PURPOSE OF ANY
    LIMITED REMEDY.
:>
 */

#include <tr451_polt_vendor.h>
#include <tr451_polt_for_vendor.h>
#include <tr451_polt_vendor_specific.h>
#include <bcm_tr451_polt_vendor_internal.h>

static uint8_t inject_buffer[44];

/* Inject OMCI_RX packet */
static bcmos_errno polt_cli_inject_omci_rx(bcmcli_session *session, const bcmcli_cmd_parm parm[], uint16_t nparms)
{
    bcmolt_onu_omci_packet *msg;
    msg = (bcmolt_onu_omci_packet *)bcmos_calloc(sizeof(*msg));
    bcmolt_onu_key key = {
        .pon_ni = (bcmolt_interface)parm[0].value.unumber,
        .onu_id = (bcmolt_onu_id)parm[1].value.unumber
    };
    if (msg == NULL)
        return BCM_ERR_NOMEM;
    msg->hdr.hdr.subgroup = BCMOLT_ONU_AUTO_SUBGROUP_OMCI_PACKET;
    msg->key = key;
    msg->data.buffer.len = bcmolt_buf_get_used(&parm[2].value.buffer);
    msg->data.buffer.arr = inject_buffer;
    bcm_tr451_vendor_packet_received_from_onu(msg);
    /* Clear buffer for the next iteration */
    memset(inject_buffer, 0, sizeof(inject_buffer));
    return BCM_ERR_OK;
}

/* Create channel-termination - pon-interface-id map */
static bcmos_errno polt_cli_create_chnl_term_map(bcmcli_session *session, const bcmcli_cmd_parm parm[], uint16_t nparms)
{
    return bcm_tr451_channel_termination_mapper_add((const char *)parm[0].value.string, parm[1].value.number);
}

/* Add ONU */
static bcmos_errno polt_cli_onu_add(bcmcli_session *session, const bcmcli_cmd_parm parm[], uint16_t nparms)
{
    bcmolt_interface pon_ni = (bcmolt_interface)parm[0].value.number;
    bcmolt_onu_id onu_id = (bcmolt_onu_id)parm[1].value.number;
    const char *vendor_id = (const char *)parm[2].value.string;
    uint32_t vendor_specific = (uint32_t)parm[3].value.unumber;

    bcmolt_serial_number serial_number = {};
    strncpy((char *)&serial_number.vendor_id.arr[0], vendor_id, sizeof(serial_number.vendor_id.arr));
    serial_number.vendor_specific.arr[0] = (vendor_specific >> 24) & 0xff;
    serial_number.vendor_specific.arr[1] = (vendor_specific >> 16) & 0xff;
    serial_number.vendor_specific.arr[2] = (vendor_specific >> 8) & 0xff;
    serial_number.vendor_specific.arr[3] = vendor_specific & 0xff;

    return bcm_tr451_vendor_onu_added(pon_ni, onu_id, &serial_number);
}

/* Delete ONU */
static bcmos_errno polt_cli_onu_delete(bcmcli_session *session, const bcmcli_cmd_parm parm[], uint16_t nparms)
{
    bcmolt_interface pon_ni = (bcmolt_interface)parm[0].value.number;
    bcmolt_onu_id onu_id = (bcmolt_onu_id)parm[1].value.number;
    return bcm_tr451_vendor_onu_removed(pon_ni, onu_id);
}

bcmos_errno tr451_vendor_cli_init(bcmcli_entry *dir)
{
    /* Create channel-term -- pon_ni mapping */
    {
        static bcmcli_cmd_parm cmd_parms[] = {
            BCMCLI_MAKE_PARM("channel_term", "Channel termination name", BCMCLI_PARM_STRING, 0),
            BCMCLI_MAKE_PARM_RANGE("pon_ni", "pon_ni", BCMCLI_PARM_NUMBER, 0, 0, BCM_MAX_PONS_PER_OLT - 1),
            { 0 }
        } ;
        bcmcli_cmd_add(dir, "chnl_term_map", polt_cli_create_chnl_term_map,
            "Create channel-termination -- pon_ni mapping", BCMCLI_ACCESS_ADMIN, NULL, cmd_parms);
    }

    /* Add ONU */
    {
        static bcmcli_cmd_parm cmd_parms[] = {
            BCMCLI_MAKE_PARM("pon_ni", "pon_ni", BCMCLI_PARM_NUMBER, 0),
            BCMCLI_MAKE_PARM("onu_id", "onu_id", BCMCLI_PARM_NUMBER, 0),
            BCMCLI_MAKE_PARM("serial_vendor_id", "serial_number: 4 bytes ASCII vendor id", BCMCLI_PARM_STRING, 0),
            BCMCLI_MAKE_PARM("serial_vendor_specific", "serial_number: vendor-specific id", BCMCLI_PARM_HEX, 0),
            { 0 }
        } ;
        bcmcli_cmd_add(dir, "onu_add", polt_cli_onu_add, "Add ONU",
            BCMCLI_ACCESS_ADMIN, NULL, cmd_parms);
    }

    /* Delete ONU */
    {
        static bcmcli_cmd_parm cmd_parms[] = {
            BCMCLI_MAKE_PARM("pon_ni", "pon_ni", BCMCLI_PARM_NUMBER, 0),
            BCMCLI_MAKE_PARM("onu_id", "onu_id", BCMCLI_PARM_NUMBER, 0),
            { 0 }
        } ;
        bcmcli_cmd_add(dir, "onu_delete", polt_cli_onu_delete, "Delete ONU",
            BCMCLI_ACCESS_ADMIN, NULL, cmd_parms);
    }

    /* Inject proxy_rx */
    {
        static bcmcli_cmd_parm inject_parms[] = {
            BCMCLI_MAKE_PARM("pon", "PON", BCMCLI_PARM_NUMBER, 0),
            BCMCLI_MAKE_PARM("onu", "ONU", BCMCLI_PARM_NUMBER, 0),
            BCMCLI_MAKE_PARM("data", "OMCI data", BCMCLI_PARM_BUFFER, 0),
            { 0 } } ;
        inject_parms[2].value.buffer.len = sizeof(inject_buffer);
        inject_parms[2].value.buffer.start = inject_parms[2].value.buffer.curr = inject_buffer;
        bcmcli_cmd_add(dir, "inject", polt_cli_inject_omci_rx,
            "Inject OMCI packet received from ONU", BCMCLI_ACCESS_ADMIN, NULL, inject_parms);
    }

    return BCM_ERR_OK;
}