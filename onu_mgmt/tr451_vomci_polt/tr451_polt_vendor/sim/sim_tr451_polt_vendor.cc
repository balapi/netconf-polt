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
#include <fstream>

#include <tr451_polt_vendor.h>
#include <tr451_polt_for_vendor.h>
#include <tr451_polt_vendor_specific.h>
#include <sim_tr451_polt_vendor_internal.h>

#define OMCI_MAX_MTU        2048

static tr451_vendor_event_cfg vendor_event_cfg;
static tr451_polt_sim_rx_cfg vendor_rx_cfg;
static uint32_t vendor_rx_skipped;
static int tr451_onu_sim_socket;
static bcmos_bool tr451_onu_sim_rx_task_created;
static bcmos_task tr451_onu_sim_rx_task;
static char tr451_onu_sim_rx_buf[OMCI_MAX_MTU + sizeof(tr451_onu_sim_packet_header)];
static char tr451_onu_sim_tx_buf[OMCI_MAX_MTU + sizeof(tr451_onu_sim_packet_header)];

//
// Helper functions
//

/* Prepare onu_info */
static bcmos_errno tr451_prepare_onu_info(const char *cterm_name, uint16_t onu_id,
    const tr451_polt_onu_serial_number *serial_number, tr451_polt_onu_info *onu_info)
{
    if (vendor_event_cfg.tr451_onu_state_change_cb == nullptr)
    {
        BCM_POLT_LOG(ERROR, "No tr451_onu_state_change_cb registration\n");
        return BCM_ERR_NOT_SUPPORTED;;
    }
    memset(onu_info, 0, sizeof(*onu_info));
    onu_info->cterm_name = cterm_name;
    onu_info->pon_interface_id = POLT_PON_ID_UNDEFINED;
    onu_info->onu_id = onu_id;
    if (onu_info->onu_id >= TR451_POLT_MAX_ONUS_PER_PON)
    {
        BCM_POLT_LOG(ERROR, "onu_id out of range\n");
        return BCM_ERR_PARM;
    }

    memcpy(&onu_info->serial_number, serial_number, 8);

    return BCM_ERR_OK;
}

/* Report ONU discovered */
bcmos_errno sim_tr451_vendor_onu_added(const char *cterm_name, uint16_t onu_id,
   const tr451_polt_onu_serial_number *serial, xpon_onu_presence_flags flags)
{
    tr451_polt_onu_info onu_info;
    bcmos_errno err;

    err = tr451_prepare_onu_info(cterm_name, onu_id, serial, &onu_info);
    if (err != BCM_ERR_OK)
        return err;
    onu_info.presence_flags = flags ? flags : XPON_ONU_PRESENCE_FLAG_ONU;
    vendor_event_cfg.tr451_onu_state_change_cb(vendor_event_cfg.user_handle, &onu_info);
    if (vendor_event_cfg.tr451_onu_state_change_notify_cb != nullptr)
    {
        err = vendor_event_cfg.tr451_onu_state_change_notify_cb(vendor_event_cfg.user_handle, &onu_info);
    }

    return err;
}

/* Report ONU removed */
bcmos_errno sim_tr451_vendor_onu_removed(const char *cterm_name, uint16_t onu_id,
   const tr451_polt_onu_serial_number *serial, xpon_onu_presence_flags flags)
{
    tr451_polt_onu_info onu_info;
    bcmos_errno err;

    err = tr451_prepare_onu_info(cterm_name, onu_id, serial, &onu_info);
    if (err != BCM_ERR_OK)
        return err;
    onu_info.presence_flags = flags ? flags : XPON_ONU_PRESENCE_FLAG_V_ANI;
    vendor_event_cfg.tr451_onu_state_change_cb(vendor_event_cfg.user_handle, &onu_info);

    if (vendor_event_cfg.tr451_onu_state_change_notify_cb != nullptr)
    {
        err = vendor_event_cfg.tr451_onu_state_change_notify_cb(vendor_event_cfg.user_handle, &onu_info);
    }

    return err;
}

/* Report packet received from ONU */
bcmos_errno sim_tr451_vendor_packet_received_from_onu(const char *cterm_name, uint16_t onu_id, const uint8_t *data, uint32_t length)
{
    if (vendor_event_cfg.tr451_omci_rx_cb == nullptr)
        return BCM_ERR_NOT_SUPPORTED;
    if (cterm_name == nullptr || data == nullptr || length <= 4)
        return BCM_ERR_PARM;
    BCM_POLT_LOG(DEBUG, "RX from ONU: cterm=%s onu_id=%u length=%u OMCI_HDR=%02x%02x%02x%02x %02x%02x%02x%02x\n",
        cterm_name, onu_id, length,
        data[0], data[1], data[2], data[3],
        data[4], data[5], data[6], data[7]);
    OnuHeader* header = new OnuHeader();
    header->set_chnl_term_name(cterm_name);
    header->set_onu_id(onu_id);
    OmciPacketEntry *grpc_packet = new OmciPacketEntry();
    grpc_packet->set_allocated_header(header);
    grpc_packet->set_payload(data, length);
    vendor_event_cfg.tr451_omci_rx_cb(vendor_event_cfg.user_handle, grpc_packet);
    return BCM_ERR_OK;
}

/* Send packet to ONU simulator */
static bcmos_errno tr451_vendor_omci_send_to_onu_sim(const OmciPacket &packet)
{
    uint32_t length = packet.payload().length();
    if (length > OMCI_MAX_MTU)
    {
        BCM_POLT_LOG(DEBUG, "TX to ONU: OMCI packet is too long %u. Discarded\n", length);
        return BCM_ERR_OVERFLOW;
    }

    tr451_onu_sim_packet_header *hdr = (tr451_onu_sim_packet_header *)tr451_onu_sim_tx_buf;
    strncpy(hdr->cterm_name, packet.header().chnl_term_name().c_str(), sizeof(hdr->cterm_name));
    hdr->onu_id = htons(packet.header().onu_id());
    memcpy((uint8_t *)(hdr + 1), packet.payload().c_str(), length);

    int rc;
    rc = send(tr451_onu_sim_socket, tr451_onu_sim_tx_buf, length + sizeof(tr451_onu_sim_packet_header), 0);
    if (rc < 0)
    {
        BCM_POLT_LOG(DEBUG, "TX to ONU: failed to send. Error '%s'\n", strerror(errno));
        return BCM_ERR_IO;
    }
    return BCM_ERR_OK;
}


/*
 * External interface
 */

/**
 * @brief  Initialize TR-451 vendor library
 * @returns BCM_ERR_OK(0) or error code <0
 */
bcmos_errno tr451_vendor_init(void)
{
    // Set loopback RX handling mode by default
    tr451_polt_sim_rx_cfg rx_cfg = {};
    rx_cfg.mode = TR451_POLT_SIM_RX_MODE_LOOPBACK;
    return sim_tr451_vendor_rx_cfg_set(&rx_cfg);
}

/**
 * @brief  Terminate TR-451 vendor library
 * @returns BCM_ERR_OK(0) or error code <0
 */
bcmos_errno tr451_vendor_exit(void);

/**
 * @brief  Send packet to ONU
 * @note The function can be called for multiple ONUs simultaneously
 *      from different execution context. It is the responsibility of the
 *      implementer to make it thread-safe.
 * @param[in]  &packet:     OMCI packet received from vOMCI peer
 * @returns BCM_ERR_OK(0) or error code <0
 */
bcmos_errno tr451_vendor_omci_send_to_onu(const OmciPacket &packet)
{
    bcmos_errno err = BCM_ERR_OK;
    const string *p_payload = &packet.payload();
    const uint8_t *data = (const uint8_t *)p_payload->c_str();

    BCM_POLT_LOG(DEBUG, "TX to ONU: cterm=%s onu_id=%u length=%lu OMCI_HDR=%02x%02x%02x%02x %02x%02x%02x%02x\n",
        packet.header().chnl_term_name().c_str(), packet.header().onu_id(), p_payload->length(),
        data[0], data[1], data[2], data[3],
        data[4], data[5], data[6], data[7]);

    switch(vendor_rx_cfg.mode)
    {
        case TR451_POLT_SIM_RX_MODE_DISCARD:
        break;

        case TR451_POLT_SIM_RX_MODE_LOOPBACK:
        {
            string payload = packet.payload();
            uint8_t msg_type = payload[2];
            // If AR is not set - just return
            if ((msg_type & 0x40) == 0)
                break;
            if (vendor_rx_skipped < vendor_rx_cfg.loopback.skip)
            {
                ++vendor_rx_skipped;
                break;
            }
            // Toggle AR/AK bit
            msg_type &= ~0x40;
            msg_type |= 0x20;
            payload[2] = msg_type;
            for (int i=8; i<48; i++)
                payload[i] = 0;
            err = sim_tr451_vendor_packet_received_from_onu(
                packet.header().chnl_term_name().c_str(),
                (uint16_t)packet.header().onu_id(),
                (const uint8_t *)payload.c_str(),
                payload.length());
            vendor_rx_skipped = 0;
        }
        break;

        case TR451_POLT_SIM_RX_MODE_ONU_SIM:
            err = tr451_vendor_omci_send_to_onu_sim(packet);
        break;
    }
    return err;
}

/* Receive task handler */
static int _onu_sim_rx_task_handler(long data)
{
    bcmos_task *this_task = bcmos_task_current();
    tr451_onu_sim_packet_header *hdr = (tr451_onu_sim_packet_header *)tr451_onu_sim_rx_buf;
    fd_set read_fds;
    struct timeval tv = {};
    int rc;

    // Poll with 100ms interval
    tv.tv_usec = 100000;

    while (!this_task->destroy_request)
    {
        FD_ZERO(&read_fds);
        FD_SET(tr451_onu_sim_socket, &read_fds);

        rc = select(tr451_onu_sim_socket + 1, &read_fds, NULL, NULL, &tv);
        if (!rc)
            continue;
        if (rc < 0)
            break;

        /* Check for receive. The function waits for a short while and the times out */
        rc = recv(tr451_onu_sim_socket, tr451_onu_sim_rx_buf, sizeof(tr451_onu_sim_rx_buf), 0);
        if (rc < sizeof(tr451_onu_sim_packet_header))
            break;

        sim_tr451_vendor_packet_received_from_onu(hdr->cterm_name, ntohs(hdr->onu_id),
            (uint8_t *)(hdr + 1), rc - sizeof(tr451_onu_sim_packet_header));
    }
    BCM_POLT_LOG(INFO, "ONU-SIM rx task terminated\n");

    return 0;
}


/* Set receive handling mode */
bcmos_errno sim_tr451_vendor_rx_cfg_set(const tr451_polt_sim_rx_cfg *cfg)
{
    if (cfg->mode == TR451_POLT_SIM_RX_MODE_ONU_SIM)
    {
        struct sockaddr_in addr = {};
        bcmos_errno err;

        tr451_onu_sim_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (tr451_onu_sim_socket < 0)
        {
            BCM_POLT_LOG(ERROR, "Can't create UDP socket\n");
            return BCM_ERR_IO;
        }

        // bind
        addr.sin_family = AF_INET;
        addr.sin_port = htons(cfg->onu_sim.local_port);
        if (bind(tr451_onu_sim_socket, (struct sockaddr *)&addr, sizeof(addr)) == -1)
        {
            BCM_POLT_LOG(ERROR, "Can't bind ONU-SIM socket to port %u. Error %s\n",
                cfg->onu_sim.local_port, strerror(errno));
            close(tr451_onu_sim_socket);
            return BCM_ERR_IO;
        }

        // connect
        addr.sin_family = AF_INET;
        addr.sin_port = htons(cfg->onu_sim.remote_port);
        addr.sin_addr.s_addr = htonl(cfg->onu_sim.remote_address);
        if (connect(tr451_onu_sim_socket, (struct sockaddr *)&addr, sizeof(addr)) == -1)
        {
            BCM_POLT_LOG(ERROR, "Can't connect ONU-SIM socket to %d.%d.%d.%d:%u. Error %s\n",
                (cfg->onu_sim.remote_address >> 24) & 0xff,
                (cfg->onu_sim.remote_address >> 16) & 0xff,
                (cfg->onu_sim.remote_address >> 8) & 0xff,
                cfg->onu_sim.remote_address & 0xff,
                cfg->onu_sim.remote_port, strerror(errno));
            close(tr451_onu_sim_socket);
            return BCM_ERR_IO;
        }

        // create RX task
        bcmos_task_parm tp = {};
        tp.name = "cm_rx",
        tp.priority = TASK_PRIORITY_TRANSPORT_RX,
        tp.handler = _onu_sim_rx_task_handler,
        err = bcmos_task_create(&tr451_onu_sim_rx_task, &tp);
        if (err != BCM_ERR_OK)
        {
            BCM_POLT_LOG(ERROR, "ONU-SIM RX task create failed: %s\n", bcmos_strerror(err));
            close(tr451_onu_sim_socket);
            return err;
        }
        tr451_onu_sim_rx_task_created = BCMOS_TRUE;
    }
    else
    {
        if (vendor_rx_cfg.mode == TR451_POLT_SIM_RX_MODE_ONU_SIM && tr451_onu_sim_rx_task_created)
        {
            close(tr451_onu_sim_socket);
            bcmos_task_destroy(&tr451_onu_sim_rx_task);
            tr451_onu_sim_rx_task_created = BCMOS_FALSE;
        }
    }

    vendor_rx_skipped = 0;
    vendor_rx_cfg = *cfg;

    return BCM_ERR_OK;
}

/**
 * @brief  Register to receive OMCI packets
 * @note
 * @param[in]  rx_cb:           Receive callback function to be called when OMCI packet is received
 * @param[in]  *rx_cb_handle:   Handle to pass to rx_cb
 * @returns BCM_ERR_OK(0) or error code <0
 */
bcmos_errno tr451_vendor_event_register(const tr451_vendor_event_cfg *cb_cfg)
{
    if (cb_cfg != nullptr)
    {
        vendor_event_cfg = *cb_cfg;
    }
    else
    {
        memset(&vendor_event_cfg, 0, sizeof(vendor_event_cfg));
    }
    return BCM_ERR_OK;
}
