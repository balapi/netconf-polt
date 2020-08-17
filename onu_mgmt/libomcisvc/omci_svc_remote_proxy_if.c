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

#include <bcmolt_api.h>
#include <bcm_dev_log.h>
#include "onu_mgmt_test.h"
#include "omci_svc_adapter_common.h"
#include "omci_svc_common.h"
#include "omci_svc_flow.h"
#include "omci_svc_onu.h"
#include "omci_svc.h"

/* ONU:omci_packet indication handler */
static void omci_svc_onu_auto_omci_packet_rx_cb(bcmolt_oltid olt_id, bcmolt_msg *msg);


static bcmos_errno _omci_proxy_send(bcmolt_oltid olt_id, uint32_t logical_pon, bcmolt_pon_onu_id onu_id, bcmolt_u8_list_u32_max_2048 *buf)
{
    bcmolt_onu_cpu_packets omci_cpu_packets = {};
    bcmolt_onu_key key = {.pon_ni=logical_pon, .onu_id=onu_id};
    bcmolt_bin_str cpu_buf = {.len = buf->len, .arr = buf->val};

    BCMOLT_OPER_INIT(&omci_cpu_packets, onu, cpu_packets, key);
    BCMOLT_FIELD_SET(&omci_cpu_packets.data, onu_cpu_packets_data, packet_type, BCMOLT_PACKET_TYPE_OMCI);
    BCMOLT_FIELD_SET(&omci_cpu_packets.data, onu_cpu_packets_data, calc_crc, omci_svc_omci_is_olt_calc_crc(buf));
    BCMOLT_FIELD_SET(&omci_cpu_packets.data, onu_cpu_packets_data, number_of_packets, 1); /* 1 pkt at a time */
    BCMOLT_FIELD_SET(&omci_cpu_packets.data, onu_cpu_packets_data, packet_size, buf->len); 
    BCMOLT_FIELD_SET(&omci_cpu_packets.data, onu_cpu_packets_data, buffer, cpu_buf); 

    /** Test utility: use the actual topo olt id instead of test olt id to call aspen api */
    olt_id = ONU_MGMT_TEST_SET_DEFAULT_OLT_ID(olt_id);

    bcmos_errno rc = bcmolt_oper_submit(olt_id, &omci_cpu_packets.hdr);
    if (BCM_ERR_OK != rc)
    {
        BCM_LOG(ERROR, omci_svc_log_id, "OMCI message send Failed for (PON=%u, ONU=%u)\n", logical_pon, onu_id);
    }

    return rc;
}

/**
 * @brief this function is called by transport layer, thru adapter,
 * to send out omci msg through Maple.
 *
 * @note msg_len is an array with lengths of the messages being sent out
 */
bcmos_errno omci_svc_omci_data_req(bcmolt_oltid olt_id, uint32_t pon_ni, uint16_t onu_id, uint8_t msg_count, void *msg_buf[], uint16_t msg_len[])
{
    bcmos_errno rc;
    uint32_t logical_pon = pon_ni;
    bcmolt_pon_onu_id _onu_id = onu_id;
    uint8_t i;


    if (!msg_count)
    {
        BCM_LOG(ERROR, omci_svc_log_id, "No message to be sent to device (PON=%u, ONU=%u)\n", logical_pon, _onu_id);
        return BCM_ERR_PARM;
    }

    for (i = 0; i < msg_count; i++)
    {
        bcmolt_u8_list_u32_max_2048 buf = {};

        if (msg_len[i] > OMCI_SVC_OMCI_MSG_LEN_MAX)
        {
            BCM_LOG(ERROR, omci_svc_log_id, "Message size=%u is too big (PON=%u, ONU=%u)\n", msg_len[i], logical_pon, _onu_id);
            continue;
        }

        buf.val = msg_buf[i];
        buf.len = msg_len[i];

       /** Workaround until the OCS OMCI stack calculates the CRC correctly for XG-PON1.
        *  For broadcom stack, it is a no-op.
        */
        /** @todo aspen : not needed for broadcom omci stack */
//        if ((omci_svc_topo_pon_get_sub_family(olt_id, logical_pon) == BCMBAL_PON_SUB_FAMILY_XGPON) ||
//            (omci_svc_topo_pon_get_sub_family(olt_id, logical_pon) == BCMBAL_PON_SUB_FAMILY_XGS))
//        {
//            omci_svc_omci_update_xgpon_omci_buf_len(&buf);
//        }
//

        rc = _omci_proxy_send(olt_id, logical_pon, _onu_id, &buf);

        if (rc != BCM_ERR_OK)
        {
            BCM_LOG(ERROR, omci_svc_log_id, "%s failed: PON=%u, ONU=%u, rc=%s\n", __FUNCTION__, logical_pon, _onu_id, bcmos_strerror(rc));
            return BCM_ERR_PARM;
        }
    }

    return BCM_ERR_OK;
}


/** @brief subscribe IND */
bcmos_errno omci_svc_subscribe_omci_proxy_ind(bcmolt_oltid olt_id)
{
    bcmos_errno rc;
    bcmolt_rx_cfg rx_cfg = {};

    rx_cfg.obj_type = BCMOLT_OBJ_ID_ONU;
    rx_cfg.flags = BCMOLT_AUTO_FLAGS_NONE;
    rx_cfg.subgroup = BCMOLT_ONU_AUTO_SUBGROUP_OMCI_PACKET;
    rx_cfg.rx_cb = omci_svc_onu_auto_omci_packet_rx_cb;

    /** Test utility: use the actual topo olt id instead of test olt id to call aspen api */
    olt_id = ONU_MGMT_TEST_SET_DEFAULT_OLT_ID(olt_id);

    rc = bcmolt_ind_subscribe(olt_id, &rx_cfg);
    if (rc != BCM_ERR_OK)
    {
        BCM_LOG(ERROR, omci_svc_log_id, "Failed to subscribe to Aspen ONU indications for OMCI Packets. Error %s\n", bcmos_strerror(rc));
    }

    return rc;
}

/** @brief unsubscribe IND */
bcmos_errno omci_svc_unsubscribe_omci_proxy_ind(bcmolt_oltid olt_id)
{
    bcmos_errno rc;
    bcmolt_rx_cfg rx_cfg = {};

    rx_cfg.obj_type = BCMOLT_OBJ_ID_ONU;
    rx_cfg.flags = BCMOLT_AUTO_FLAGS_NONE;
    rx_cfg.subgroup = BCMOLT_ONU_AUTO_SUBGROUP_OMCI_PACKET;
    rx_cfg.rx_cb = omci_svc_onu_auto_omci_packet_rx_cb;

    /** Test utility: use the actual topo olt id instead of test olt id to call aspen api */
    olt_id = ONU_MGMT_TEST_SET_DEFAULT_OLT_ID(olt_id);

    rc = bcmolt_ind_unsubscribe(olt_id, &rx_cfg);
    if (rc != BCM_ERR_OK)
    {
        BCM_LOG(ERROR, omci_svc_log_id, "Failed to Unsubscribe from Aspen ONU indications for OMCI Packets. Error %s\n", bcmos_strerror(rc));
    }

    return rc;
}

/* ONU:omci_packet indication handler */
static void omci_svc_onu_auto_omci_packet_rx_cb(bcmolt_oltid olt_id, bcmolt_msg *msg)
{
    bcmolt_onu_omci_packet *omci_pkt = (bcmolt_onu_omci_packet *)msg;

    if (!omci_pkt->data.crc_ok)
    {
        BCM_LOG(ERROR, omci_svc_log_id, "CRC Error in OMCI Packet\n");
    }
    else
    {
        /** Test utility: map the actual topo olt id to the test olt id on omci pkt receive */
        olt_id = ONU_MGMT_TEST_SET_TEST_OLT_ID(olt_id);

        omci_svc_omci_data_ind_itu_pon(olt_id, omci_pkt->key.pon_ni, omci_pkt->key.onu_id, omci_pkt->data.packet_size, omci_pkt->data.buffer);
    }

    /* Free the indication since we're done processing it */
    bcmolt_msg_free(msg);
}
