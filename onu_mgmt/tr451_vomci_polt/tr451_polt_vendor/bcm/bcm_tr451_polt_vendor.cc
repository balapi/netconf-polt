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
#include <fstream>

#include <tr451_polt_vendor.h>
#include <tr451_polt_for_vendor.h>
#include <tr451_polt_vendor_specific.h>
#include <bcm_tr451_polt_vendor_internal.h>

static bcmos_errno bcm_packet_grpc_to_bcmolt(const OmciPacket *grpc_packet, bcmolt_onu_cpu_packets *bcm_packet);
static bcmos_errno bcm_packet_bcmolt_to_grpc(const bcmolt_onu_omci_packet *bcm_packet, OmciPacket *grpc_packet);

static tr451_vendor_event_cfg vendor_event_cfg;

static bcmolt_serial_number onu_serial_number[TR451_POLT_MAX_PONS_PER_OLT][TR451_POLT_MAX_ONUS_PER_PON];

//
// Helper functions
//

/* Prepare onu_info */
static bcmos_errno tr451_prepare_onu_info(bcmolt_interface pon_ni, bcmolt_onu_id onu_id,
    const bcmolt_serial_number *serial_number, tr451_polt_onu_info *onu_info)
{
    if (vendor_event_cfg.tr451_onu_state_change_cb == nullptr)
    {
        BCM_POLT_LOG(ERROR, "No tr451_onu_state_change_cb registration\n");
        return BCM_ERR_NOT_SUPPORTED;;
    }
    memset(onu_info, 0, sizeof(*onu_info));
    onu_info->pon_interface_id = pon_ni;
    onu_info->onu_id = onu_id;

    if (onu_info->pon_interface_id >= TR451_POLT_MAX_PONS_PER_OLT ||
        onu_info->onu_id >= TR451_POLT_MAX_ONUS_PER_PON)
    {
        BCM_POLT_LOG(ERROR, "pon_ni or onu_id out of range\n");
        return BCM_ERR_PARM;
    }

    // Find channel-term mapping
    onu_info->cterm_name = bcm_tr451_channel_termination_mapper_get_name_by_id(onu_info->pon_interface_id);
    if (onu_info->cterm_name == nullptr)
    {
        BCM_POLT_LOG(ERROR, "Can't find PON interface %u mapping to channel-termination.\n",
            onu_info->pon_interface_id);
        return BCM_ERR_NOENT;
    }

    if (serial_number != nullptr)
    {
        memcpy(&onu_info->serial_number.data[0], &serial_number->vendor_id.arr[0], 4);
        memcpy(&onu_info->serial_number.data[4], &serial_number->vendor_specific.arr[0], 4);
        memcpy(&onu_serial_number[onu_info->pon_interface_id][onu_info->onu_id], &onu_info->serial_number, 8);
    }
    else
    {
        memcpy(&onu_info->serial_number, &onu_serial_number[onu_info->pon_interface_id][onu_info->onu_id], 8);
    }

    return BCM_ERR_OK;
}

/* Report ONU discovered */
bcmos_errno bcm_tr451_vendor_onu_added(bcmolt_interface pon_ni, bcmolt_onu_id onu_id,
    const bcmolt_serial_number *serial)
{
    tr451_polt_onu_info onu_info;
    bcmos_errno err = tr451_prepare_onu_info(pon_ni, onu_id, serial, &onu_info);
    if (err != BCM_ERR_OK)
        return err;
    onu_info.present = BCMOS_TRUE;
    onu_info.active = BCMOS_TRUE;
    vendor_event_cfg.tr451_onu_state_change_cb(vendor_event_cfg.user_handle, &onu_info);
    return BCM_ERR_OK;
}

/* Report ONU removed */
bcmos_errno bcm_tr451_vendor_onu_removed(bcmolt_interface pon_ni, bcmolt_onu_id onu_id)
{
    tr451_polt_onu_info onu_info;
    bcmos_errno err = tr451_prepare_onu_info(pon_ni, onu_id, nullptr, &onu_info);
    if (err != BCM_ERR_OK)
        return err;
    vendor_event_cfg.tr451_onu_state_change_cb(vendor_event_cfg.user_handle, &onu_info);
    return BCM_ERR_OK;
}

/* Report packet received from ONU */
bcmos_errno bcm_tr451_vendor_packet_received_from_onu(bcmolt_onu_omci_packet *bcm_packet)
{
    OmciPacketEntry *grpc_packet = new OmciPacketEntry();
    bcmos_errno err;

    err = bcm_packet_bcmolt_to_grpc(bcm_packet, grpc_packet);
    if (err == BCM_ERR_OK && vendor_event_cfg.tr451_omci_rx_cb != nullptr)
    {
        uint8_t *data=bcm_packet->data.buffer.arr;
        BCM_POLT_LOG(DEBUG,
            "omci_packet: %u.%u->vomci: [%u] %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
            bcm_packet->key.pon_ni, bcm_packet->key.onu_id, bcm_packet->data.buffer.len,
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]);
        vendor_event_cfg.tr451_omci_rx_cb(vendor_event_cfg.user_handle, grpc_packet);
    }
    else
    {
        delete grpc_packet;
    }
    bcmolt_msg_free(&bcm_packet->hdr.hdr);
    return err;
}

//
// Maple/Aspen indication handling
//

// OMCI packet from ONU indication
static void bcm_tr451_omci_rx_cb(bcmolt_oltid olt_id, bcmolt_msg *msg)
{
    bcmolt_onu_omci_packet *bcm_packet = (bcmolt_onu_omci_packet *)msg;
    bcm_tr451_vendor_packet_received_from_onu(bcm_packet);
}

// Register for OMCI indications
static bcmos_errno bcm_tr451_subscribe_omci_rx(void)
{
    struct bcmolt_rx_cfg rx_cfg = {};
    bcmos_errno err;

    /* Register a callback for handling received OMCI packets. */
    rx_cfg.obj_type = BCMOLT_OBJ_ID_ONU;
    rx_cfg.rx_cb = bcm_tr451_omci_rx_cb;
    rx_cfg.subgroup = BCMOLT_ONU_AUTO_SUBGROUP_OMCI_PACKET;
    err = bcmolt_ind_subscribe(BCM_DEFAULT_OLT_ID, &rx_cfg);
    if (err != BCM_ERR_OK)
    {
        BCM_POLT_LOG(ERROR, "Failed to register for OMCI indications\n");
        return err;
    }
    BCM_POLT_LOG(INFO, "Subscribed to OMCI messages from ONUs\n");
    return BCM_ERR_OK;
}

// ONU activation completed message handler
static void bcm_tr451_onu_status_change_cb(bcmolt_devid device_id, bcmolt_msg *msg)
{
    // Keys in all ONU indications are the same
    bcmolt_onu_key key = ((bcmolt_onu_onu_activation_completed *)msg)->key;
    BCM_POLT_LOG(INFO, "Received '%s' indication from ONU %u:%u.\n",
        BCMOLT_ENUM_STRING_VAL(bcmolt_onu_auto_subgroup, msg->subgroup),
        key.pon_ni, key.onu_id);

    do {
        switch(msg->subgroup)
        {
            case BCMOLT_ONU_AUTO_SUBGROUP_ONU_ACTIVATION_COMPLETED:
                {
                    bcmolt_onu_cfg cfg;
                    bcmolt_onu_onu_activation_completed *ac = (bcmolt_onu_onu_activation_completed *)msg;
                    bcmos_errno err;

                    if (ac->data.status != BCMOLT_RESULT_SUCCESS)
                    {
                        BCM_POLT_LOG(INFO, "ONU %u:%u: activation failed. Ignored..\n",
                            key.pon_ni, key.onu_id);
                        break;
                    }
                    // Read serial number in order to apply filters
                    BCMOLT_CFG_INIT(&cfg, onu, key);
                    BCMOLT_MSG_FIELD_GET(&cfg, itu.serial_number);
                    err = bcmolt_cfg_get(BCM_DEFAULT_OLT_ID, &cfg.hdr);
                    if (err != BCM_ERR_OK)
                    {
                        BCM_POLT_LOG(ERROR, "Couldn't read serial number for ONU %u:%u\n",
                            key.pon_ni, key.onu_id);
                        break;
                    }
                    bcm_tr451_vendor_onu_added(key.pon_ni, key.onu_id, &cfg.data.itu.serial_number);
                }
                break;

            case BCMOLT_ONU_AUTO_SUBGROUP_ONU_DEACTIVATION_COMPLETED:
            case BCMOLT_ONU_AUTO_SUBGROUP_ONU_DISABLE_COMPLETED:
                {
                    bcm_tr451_vendor_onu_removed(key.pon_ni, key.onu_id);
                }
                break;

            default:
                break;
        }
    } while (0);

    bcmolt_msg_free(msg);
}

// Register for ONU status change indications
static bcmos_errno bcm_tr451_subscribe_onu_status_change(void)
{
    struct bcmolt_rx_cfg rx_cfg = {};
    bcmos_errno err;

    /* Register a callback for handling received OMCI packets. */
    rx_cfg.obj_type = BCMOLT_OBJ_ID_ONU;
    rx_cfg.rx_cb = bcm_tr451_onu_status_change_cb;
    rx_cfg.subgroup = BCMOLT_ONU_AUTO_SUBGROUP_ONU_ACTIVATION_COMPLETED;
    err = bcmolt_ind_subscribe(BCM_DEFAULT_OLT_ID, &rx_cfg);
    rx_cfg.subgroup = BCMOLT_ONU_AUTO_SUBGROUP_ONU_DEACTIVATION_COMPLETED;
    err = err ? err : bcmolt_ind_subscribe(BCM_DEFAULT_OLT_ID, &rx_cfg);
    rx_cfg.subgroup = BCMOLT_ONU_AUTO_SUBGROUP_ONU_DISABLE_COMPLETED;
    err = err ? err : bcmolt_ind_subscribe(BCM_DEFAULT_OLT_ID, &rx_cfg);
    if (err != BCM_ERR_OK)
    {
        BCM_POLT_LOG(ERROR, "Failed to register for ONU status change indications\n");
        return err;
    }
    BCM_POLT_LOG(INFO, "Subscribed to ONU status change indications\n");
    return BCM_ERR_OK;
}

//
// grpc - bcmolt OMCI packet translation
//

bcmos_errno bcm_packet_grpc_to_bcmolt(const OmciPacket *grpc_packet, bcmolt_onu_cpu_packets *bcm_packet)
{
    const std::string &pkt = grpc_packet->payload();
    bcmolt_onu_key key = {};
    bcmos_errno err;
    char *endptr = NULL;

    // Map channel termination name to pon_ni
    err = bcm_tr451_channel_termination_mapper_get_id_by_name(
        grpc_packet->chnl_term_name().c_str(), &key.pon_ni);
    if (err != BCM_ERR_OK)
    {
        BCM_POLT_LOG(ERROR, "Can't translate channel-term \"%s\" to pon_ni\n",
            grpc_packet->chnl_term_name().c_str());
        return err;
    }
    key.onu_id = (uint16_t)strtoul(grpc_packet->onu_id().c_str(), &endptr, 0);
    if ((endptr && *endptr) || key.onu_id >= TR451_POLT_MAX_ONUS_PER_PON)
    {
        BCM_POLT_LOG(ERROR, "onu_id %s is insane\n",
            grpc_packet->onu_id().c_str());
        return BCM_ERR_PARM;
    }

    BCMOLT_OPER_INIT(bcm_packet, onu, cpu_packets, key);
    BCMOLT_FIELD_SET(&bcm_packet->data, onu_cpu_packets_data, packet_type, BCMOLT_PACKET_TYPE_OMCI);
    BCMOLT_FIELD_SET(&bcm_packet->data, onu_cpu_packets_data, calc_crc, BCMOS_TRUE);
    BCMOLT_FIELD_SET(&bcm_packet->data, onu_cpu_packets_data, packet_size, pkt.length());
    BCMOLT_FIELD_SET(&bcm_packet->data, onu_cpu_packets_data, number_of_packets, 1);
    bcm_packet->data.buffer.len = pkt.length();
    bcm_packet->data.buffer.arr = (uint8_t *)pkt.data();
    BCMOLT_FIELD_SET_PRESENT(&bcm_packet->data, onu_cpu_packets_data, buffer);
    return BCM_ERR_OK;
}

bcmos_errno bcm_packet_bcmolt_to_grpc(const bcmolt_onu_omci_packet *bcm_packet, OmciPacket *grpc_packet)
{
    const char *cterm_name = bcm_tr451_channel_termination_mapper_get_name_by_id(bcm_packet->key.pon_ni);
    if (cterm_name == NULL)
    {
        BCM_POLT_LOG(ERROR, "Can't translate pon_ni %u to channel-termination name. OMCI packet discarded\n",
            bcm_packet->key.pon_ni);
        return BCM_ERR_NOENT;
    }
    if (bcm_packet->data.buffer.len <= 4)
    {
        // paranoya
        BCM_POLT_LOG(ERROR, "OMCI packet received from OLT is insane. length = %u. OMCI packet discarded\n",
            bcm_packet->data.buffer.len);
        return BCM_ERR_PARM;
    }
    grpc_packet->set_chnl_term_name(cterm_name);
    grpc_packet->set_onu_id(std::to_string(bcm_packet->key.onu_id));
    grpc_packet->set_payload(bcm_packet->data.buffer.arr, bcm_packet->data.buffer.len - 4); // Strip CRC/MIC
    return BCM_ERR_OK;
}

//
// channel-term - pon_ni mapper
//
#define MAX_INTERFACE_NAME_LENGTH   32

static hash_table *channel_term_hash;
static char channel_term_name_array[BCM_MAX_PONS_PER_OLT][MAX_INTERFACE_NAME_LENGTH];

typedef struct channel_term_record
{
    bcmolt_interface pon_ni;
} channel_term_record;

bcmos_errno bcm_tr451_channel_termination_mapper_init(void)
{
    channel_term_hash = hash_table_create(BCM_MAX_PONS_PER_OLT,
        sizeof(channel_term_record), MAX_INTERFACE_NAME_LENGTH, (char *)"channel-term");
    return BCM_ERR_OK;
}

/* channel-termination -> pon_id mapping */
bcmos_errno bcm_tr451_channel_termination_mapper_add(const char *channel_termination_name, bcmolt_interface pon_ni)
{
    uint8_t hash_key[MAX_INTERFACE_NAME_LENGTH]={};
    const channel_term_record rec = {
        .pon_ni = pon_ni
    };
    const channel_term_record *p_rec;

    strncpy((char *)hash_key, channel_termination_name, sizeof(hash_key));
    p_rec = (channel_term_record *)hash_table_get(channel_term_hash, hash_key);
    if (p_rec != NULL)
    {
        return (p_rec->pon_ni == pon_ni) ? BCM_ERR_OK : BCM_ERR_ALREADY;
    }

    if (hash_table_put(channel_term_hash, hash_key, &rec) == NULL)
        return BCM_ERR_NOMEM;

    strncpy(channel_term_name_array[pon_ni], channel_termination_name, sizeof(channel_term_name_array[pon_ni]) - 1);

    BCM_POLT_LOG(INFO, "channel-termination %s corresponds to PON %u\n",
        channel_termination_name, pon_ni);

    return BCM_ERR_OK;
}

const char *bcm_tr451_channel_termination_mapper_get_name_by_id(bcmolt_interface pon_ni)
{
    if (pon_ni >= BCM_MAX_PONS_PER_OLT)
        return NULL;
    if (!channel_term_name_array[pon_ni][0])
        return NULL;
    return channel_term_name_array[pon_ni];
}

bcmos_errno bcm_tr451_channel_termination_mapper_get_id_by_name(const char *name, bcmolt_interface *pon_ni)
{
    uint8_t hash_key[MAX_INTERFACE_NAME_LENGTH]={};
    const channel_term_record *p_rec;

    if (name == NULL)
        return BCM_ERR_PARM;
    strncpy((char *)hash_key, name, sizeof(hash_key));
    p_rec = (channel_term_record *)hash_table_get(channel_term_hash, hash_key);
    if (p_rec == NULL)
        return BCM_ERR_NOENT;
    if (pon_ni != NULL)
        *pon_ni = p_rec->pon_ni;
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
    bcmos_errno err = BCM_ERR_OK;

    // Initialize cterm - pon_ni mapper
    err = err ? err : bcm_tr451_channel_termination_mapper_init();

    // Register for ONU status change indications
    err = err ? err : bcm_tr451_subscribe_onu_status_change();

    // Register for OMCI indications
    err = err ? err : bcm_tr451_subscribe_omci_rx();

    return err;
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
    bcmolt_onu_cpu_packets bcm_omci_msg;
    uint8_t *data;
    bcmos_errno err;

    // Convert to BCM message
    err = bcm_packet_grpc_to_bcmolt(&packet, &bcm_omci_msg);
    if (err != BCM_ERR_OK)
        return err;

    data=bcm_omci_msg.data.buffer.arr;
    BCM_POLT_LOG(DEBUG,
        "omci_packet: vomci->%u.%u: [%u] %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
        bcm_omci_msg.key.pon_ni, bcm_omci_msg.key.onu_id, bcm_omci_msg.data.buffer.len,
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]);

    // Send OMCI packet to ONU
    err = bcmolt_oper_submit(BCM_DEFAULT_OLT_ID, &bcm_omci_msg.hdr);
    if (err != BCM_ERR_OK)
    {
        BCM_POLT_LOG(ERROR, "Failed to send OMCI message to ONU %u:%u. %u bytes. Error '%s' - '%s'\n",
            bcm_omci_msg.key.pon_ni, bcm_omci_msg.key.onu_id,
            bcm_omci_msg.data.packet_size, bcmos_strerror(err), bcm_omci_msg.hdr.hdr.err_text);
        return err;
    }

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
