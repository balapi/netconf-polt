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

/**
 * @file omci_stack_api.c
 * @brief This file has the api interface to the broadcom omci stack. These apis will be called
 * by service layer for sending out OMCI Managed Entity messages to ONU. The APIs for receiving indications
 * will also be part of this file.
 */
#include "bcmos_system.h"
#include "bcm_dev_log.h"
#include "omci_stack_buf.h"
#include "omci_stack_api.h"
#include "omci_stack_internal.h"
#include "omci_stack_common.h"
#include "omci_stack_protocol_prop.h"
#include "omci_stack_enc_dec.h"
#include "omci_stack_me_tl_intf.h"
#ifdef ENABLE_LOG
#include <bcmolt_host_dev_log.h>
#endif

#ifdef ENABLE_LOG
/* The logging device id for the OMCI Stack ME Layer */
dev_log_id log_id_bcm_omci_stack_me_layer = DEV_LOG_INVALID_ID;
bcm_dev_log_level log_level_bcm_omci_stack_me_layer = DEV_LOG_LEVEL_DEBUG;
#endif

bcm_omci_stack_init_parms omci_init_parms;
static bcmos_bool omci_stack_initialized;

/*
 * Default dummy callbacks
 */
static void default_swdl_response_cb(bcm_omci_me_hdr *me_hdr, bcm_omci_swdl_response *data)
{
    BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "Software download is not supported\n");
    bcm_omci_me_free(me_hdr);
}

static void default_alarm_cb(bcm_omci_me_key *key, bcm_omci_alarm *alarm)
{
    BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "Alarms handling is not supported\n");
}

static void default_avc_cb(bcm_omci_me_key *key, bcm_omci_avc *avc)
{
    BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "AVC handling is not supported\n");
}

/* API Initialization to be called once by the omci service layer */
bcmos_errno bcm_omci_stack_init(const bcm_omci_stack_init_parms *init_parms)
{
    bcmos_errno rc;

    if (omci_stack_initialized)
        return BCM_ERR_ALREADY;
    if (init_parms == NULL ||
        init_parms->transmit_cb == NULL ||
        init_parms->response_cb == NULL ||
        init_parms->mib_upload_response_cb == NULL ||
        !init_parms->max_olts)

    {
        return BCM_ERR_PARM;
    }


#ifdef ENABLE_LOG
    if (DEV_LOG_INVALID_ID == log_id_bcm_omci_stack_me_layer)
    {
        log_id_bcm_omci_stack_me_layer = bcm_dev_log_id_register("OMCI_ME_LAYER", DEV_LOG_LEVEL_INFO, DEV_LOG_ID_TYPE_BOTH);
        bcm_dev_log_group_add_log_id(log_group_onu_mgmt, log_id_bcm_omci_stack_me_layer);
    }
#endif
    BCM_LOG(INFO, log_id_bcm_omci_stack_me_layer, "Using Broadcom OMCI Stack\n");

    rc = omci_transport_init(init_parms);
    if (rc != BCM_ERR_OK)
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "omci_transport_init() failed. %s\n", bcmos_strerror(rc));
        return rc;
    }

    omci_init_parms = *init_parms;
    if (omci_init_parms.swdl_response_cb == NULL)
        omci_init_parms.swdl_response_cb = default_swdl_response_cb;
    if (omci_init_parms.alarm_cb == NULL)
        omci_init_parms.alarm_cb = default_alarm_cb;
    if (omci_init_parms.avc_cb == NULL)
        omci_init_parms.avc_cb = default_avc_cb;
    omci_stack_initialized = BCMOS_TRUE;

    return BCM_ERR_OK;
}

/* @brief API to de-initialize omci stack, called by the omci service layer */
bcmos_errno bcm_omci_stack_deinit(void)
{
    if (!omci_stack_initialized)
        return BCM_ERR_OK;
    omci_transport_deinit();
    return BCM_ERR_OK;
}

/**
 * @brief OLT-level initialization
 */
bcmos_errno bcm_omci_olt_init(bcmolt_oltid oltid, const bcm_omci_olt_init_parms *init_parms)
{
    bcmos_errno rc;
    if (init_parms == NULL)
        return BCM_ERR_PARM;
    if (!omci_stack_initialized)
        return BCM_ERR_STATE;
    rc = omci_transport_olt_init(oltid, init_parms->max_pons, init_parms->max_onus_per_pon);
    if (rc != BCM_ERR_OK)
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "omci_transport_olt_init() for OLT=%d Failed. %s\n",
                oltid, bcmos_strerror(rc));
        return rc;
    }
    BCM_LOG(INFO, log_id_bcm_omci_stack_me_layer, "BCM OMCI Stack: OLT %u initialized\n", oltid);
    return BCM_ERR_OK;
}

/**
 * @brief OLT-level de-initialization
 */
bcmos_errno bcm_omci_olt_deinit(bcmolt_oltid oltid)
{
    if (!omci_stack_initialized)
        return BCM_ERR_STATE;
    omci_transport_olt_deinit(oltid);
    return BCM_ERR_OK;
}

/**
 * @brief  ONU level initialization
 */
bcmos_errno bcm_omci_onu_init(bcmolt_oltid oltid, bcmolt_interface logical_pon,
    bcmolt_onu_id onu_id, const bcm_omci_onu_init_parms *init_parms)
{
    return omci_transport_onu_init(oltid, logical_pon, onu_id, init_parms);
}

/**
 * @brief  ONU level de-initialization
 */
bcmos_errno bcm_omci_onu_deinit(bcmolt_oltid oltid, bcmolt_interface logical_pon, bcmolt_onu_id onu_id)
{
    omci_transport_onu_deinit(oltid, logical_pon, onu_id);
    return BCM_ERR_OK;
}


/* Helper function.
 * Encode and send header
 */
static bcmos_errno bcm_omci_encode_and_send(bcm_omci_me_hdr *me_hdr, bcm_omci_msg_type msg_type)
{
    bcmos_errno  rc;
    uint8_t     *encode_buf = NULL;
    uint32_t    encode_len = 0;

    /* set the omci msg type (ME action) */
    me_hdr->omci_msg_type =  msg_type;

#ifdef ENABLE_LOG
    /** dump the ME fields */
    bcm_omci_me_log(me_hdr, log_id_bcm_omci_stack_me_layer, log_level_bcm_omci_stack_me_layer);
#endif

    /* call encode callback to get encoded byte stream for omci msg */
    rc = bcm_omci_me_encode(me_hdr, &encode_buf, &encode_len, msg_type);

#ifdef ENABLE_LOG
    /** dump the encoded buffer */
    bcm_omci_stack_util_dump_raw_buf(&me_hdr->key, encode_buf, encode_len, log_id_bcm_omci_stack_me_layer);
#endif

    /** call stack protocol layer to send the msg out onto omci channel to onu */
    rc = (rc != BCM_ERR_OK) ? rc : bcm_omci_tl_send_msg(me_hdr, encode_buf, encode_len);

    return rc;
}


/* @brief API to be called by omci service layer to set a ME with action Create */
bcmos_errno bcm_omci_create_req(bcm_omci_me_hdr *me_hdr)
{
    return bcm_omci_encode_and_send(me_hdr, BCM_OMCI_MSG_TYPE_CREATE);
}

/* @brief API to be called by omci service layer to set a ME with action Set */
bcmos_errno bcm_omci_set_req(bcm_omci_me_hdr *me_hdr)
{
    return bcm_omci_encode_and_send(me_hdr, BCM_OMCI_MSG_TYPE_SET);
}

/* @brief API to be called by omci service layer to set an ME with action Reboot */
bcmos_errno bcm_omci_reboot_req(bcm_omci_me_key *me_key)
{
    bcm_omci_me_hdr me_hdr;
    BCM_OMCI_HDR_INIT(&me_hdr, onu_g, *me_key);
    return bcm_omci_encode_and_send(&me_hdr, BCM_OMCI_MSG_TYPE_REBOOT);
}

/* @brief API to be called by omci service layer to get a ME from ONU side */
bcmos_errno bcm_omci_get_req(bcm_omci_me_hdr *me_hdr)
{
    return bcm_omci_encode_and_send(me_hdr, BCM_OMCI_MSG_TYPE_GET);
}

/* @brief API to be called by omci service layer to Delete a ME on ONU */
bcmos_errno bcm_omci_delete_req(bcm_omci_me_key *me_key)
{
    bcm_omci_me_hdr me_hdr;
    _BCM_OMCI_HDR_INIT(&me_hdr, *me_key);
    return bcm_omci_encode_and_send(&me_hdr, BCM_OMCI_MSG_TYPE_DELETE);
}

/* @brief API to be called by omci service layer for MIB Reset Req */
bcmos_errno bcm_omci_mib_reset_req(bcm_omci_me_key *me_key)
{
    bcm_omci_me_hdr me_hdr;
    bcmos_errno  rc;

    /* init hdr & set the omci msg type (ME action) */
    BCM_OMCI_HDR_INIT(&me_hdr, onu_data, *me_key);
    me_hdr.key.entity_instance = 0;
    me_hdr.omci_msg_type = BCM_OMCI_MSG_TYPE_MIB_RESET;

#ifdef ENABLE_LOG
    /** dump the ME fields */
    bcm_omci_me_log(&me_hdr, log_id_bcm_omci_stack_me_layer, log_level_bcm_omci_stack_me_layer);
#endif

    /** call stack protocol layer to send the msg out onto omci channel to onu */
    rc = bcm_omci_tl_send_msg_operation (&me_hdr);

    return rc;
}

/* @brief API to be called by omci service layer for MIB Upload Req */
bcmos_errno bcm_omci_mib_upload_req(bcm_omci_me_key *me_key)
{
    bcm_omci_me_hdr me_hdr;
    bcmos_errno  rc;

    /* init hdr & set the omci msg type (ME action) */
    BCM_OMCI_HDR_INIT(&me_hdr, onu_data, *me_key);
    me_hdr.key.entity_instance = 0;
    me_hdr.omci_msg_type = BCM_OMCI_MSG_TYPE_MIB_UPLOAD;

#ifdef ENABLE_LOG
    /** dump the ME fields */
    bcm_omci_me_log(&me_hdr, log_id_bcm_omci_stack_me_layer, log_level_bcm_omci_stack_me_layer);
#endif

    /** call stack protocol layer to send the msg out onto omci channel to onu */
    rc = bcm_omci_tl_send_msg_operation (&me_hdr);

    return rc;
}

/* @brief API to be called by omci service layer for MIB Upload Next Req */
bcmos_errno bcm_omci_mib_upload_next_req(bcm_omci_me_key *me_key)
{
    bcm_omci_me_hdr me_hdr;
    bcmos_errno  rc;

    /* init hdr & set the omci msg type (ME action) */
    BCM_OMCI_HDR_INIT(&me_hdr, onu_data, *me_key);
    me_hdr.key.entity_instance = 0;
    me_hdr.omci_msg_type = BCM_OMCI_MSG_TYPE_MIB_UPLOAD_NEXT;

    /** call transport layer to send the msg out onto omci channel to onu */
    rc = omci_transport_send_mib_upload_next_request(&me_hdr);

    return rc;
}

/*
 * Software download support
 */

/* Helper function:
   Allocate encode buffer
*/
static bcmos_errno bcm_omci_req_buffer_alloc(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len)
{
    bcm_omci_buf bcm_buf; /* this is actually bcmolt_buf; bcm_omci_buf should be auto-generated as a typedef of bcmolt_buf */
    bcmos_errno rc;

    if (BCM_ERR_OK != (rc = bcm_omci_encode_buf_alloc(&bcm_buf, me_hdr->omci_format)))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer: %s(%d)\n",
            __FUNCTION__, bcmos_strerror(rc), rc);
        return BCM_ERR_NOMEM;
    }
    *encode_len = bcmolt_buf_get_used(&bcm_buf);
    *encode_buf = bcm_buf.start;

    return BCM_ERR_OK;
}

/* @brief API to be called by omci service layer to start software download */
bcmos_errno bcm_omci_swdl_start_req(bcm_omci_me_key *me_key, bcm_omci_swdl_start *data)
{
    bcmos_errno  rc = BCM_ERR_OK;
    bcm_omci_sw_image_cfg sw_image;
    uint8_t *encode_buf;
    uint32_t encode_len;
    int i;

    if (data->num_inst > 9 || !data->image_size)
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : invalid parameters. num_inst must be 1..9 and image_size > 0. Got %u %u\n",
            __FUNCTION__, data->num_inst, data->image_size);
        return BCM_ERR_PARM;
    }
    BCM_OMCI_HDR_INIT(&sw_image.hdr, sw_image, *me_key);
    sw_image.hdr.omci_msg_type = BCM_OMCI_MSG_TYPE_START_SW_DOWNLOAD;

    /* Allocate encode buffer */
    rc = bcm_omci_req_buffer_alloc(&sw_image.hdr, &encode_buf, &encode_len);
    if (rc != BCM_ERR_OK)
        return rc;

    /* Encode content */
    BCM_OMCI_ENCODE_UINT8(encode_buf, encode_len, data->win_size);
    BCM_OMCI_ENCODE_UINT32(encode_buf, encode_len, data->image_size);
    BCM_OMCI_ENCODE_UINT8(encode_buf, encode_len, data->num_inst);
    for (i = 0; i < data->num_inst; i++)
        BCM_OMCI_ENCODE_UINT16(encode_buf, encode_len, data->slot_me[i]);

#ifdef ENABLE_LOG
    /** dump the encoded buffer */
    bcm_omci_stack_util_dump_raw_buf(me_key, encode_buf, encode_len, log_id_bcm_omci_stack_me_layer);
#endif

    /* Send */
    rc = omci_transport_send_msg(&sw_image.hdr, encode_buf, encode_len, BCMOS_TRUE);

    return rc;
}

/* @brief API to be called by omci service layer to send software download section */
bcmos_errno bcm_omci_swdl_section_req(bcm_omci_me_key *me_key,
    uint8_t section_num, uint16_t data_length, uint8_t *data,
    bcmos_bool ack_required, bcmos_bool extended_omci)
{
    bcmos_errno  rc = BCM_ERR_OK;
    bcm_omci_sw_image_cfg sw_image;
    uint8_t *encode_buf;
    uint32_t encode_len;

    BCM_OMCI_HDR_INIT(&sw_image.hdr, sw_image, *me_key);
    sw_image.hdr.omci_msg_type = BCM_OMCI_MSG_TYPE_DOWNLOAD_SECTION;

    if ((extended_omci && data_length > BCM_OMCI_SWDL_EXTENDED_SECTION_SIZE) ||
        (!extended_omci && data_length > BCM_OMCI_SWDL_BASELINE_SECTION_SIZE))
        return BCM_ERR_RANGE;

    /* init hdr & set the omci msg type (ME action) */
    if (extended_omci)
        sw_image.hdr.omci_format = BCM_OMCI_MSG_FORMAT_EXTENDED;

    /* Allocate encode buffer */
    rc = bcm_omci_req_buffer_alloc(&sw_image.hdr, &encode_buf, &encode_len);
    if (rc != BCM_ERR_OK)
        return rc;

    /* Encode content */
    if (extended_omci)
    {
        BCM_OMCI_ENCODE_UINT16(encode_buf, encode_len, data_length + 1);
    }
    BCM_OMCI_ENCODE_UINT8(encode_buf, encode_len, section_num);
    BCM_OMCI_ENCODE_BUF(encode_buf, encode_len, data, data_length);

#ifdef ENABLE_LOG
    /** dump the encoded buffer */
    bcm_omci_stack_util_dump_raw_buf(me_key, encode_buf, encode_len, log_id_bcm_omci_stack_me_layer);
#endif

    /* Send */
    rc = omci_transport_send_msg (&sw_image.hdr, encode_buf, encode_len, ack_required);

    return rc;
}

/* @brief API to be called by omci service layer to end software download */
bcmos_errno bcm_omci_swdl_end_req(bcm_omci_me_key *me_key, bcm_omci_swdl_end *data)
{
    bcmos_errno  rc;
    bcm_omci_sw_image_cfg sw_image;
    uint8_t *encode_buf;
    uint32_t encode_len;
    int i;

    BCM_OMCI_HDR_INIT(&sw_image.hdr, sw_image, *me_key);
    sw_image.hdr.omci_msg_type = BCM_OMCI_MSG_TYPE_END_SW_DOWNLOAD;

    /* Allocate encode buffer */
    rc = bcm_omci_req_buffer_alloc(&sw_image.hdr, &encode_buf, &encode_len);
    if (rc != BCM_ERR_OK)
        return rc;

    /* Encode content */
    BCM_OMCI_ENCODE_UINT32(encode_buf, encode_len, data->crc32);
    BCM_OMCI_ENCODE_UINT32(encode_buf, encode_len, data->image_size);
    BCM_OMCI_ENCODE_UINT8(encode_buf, encode_len, data->num_inst);
    for (i = 0; i < data->num_inst; i++)
        BCM_OMCI_ENCODE_UINT16(encode_buf, encode_len, data->slot_me[i]);

#ifdef ENABLE_LOG
    /** dump the encoded buffer */
    bcm_omci_stack_util_dump_raw_buf(me_key, encode_buf, encode_len, log_id_bcm_omci_stack_me_layer);
#endif

    /* Send */
    rc = omci_transport_send_msg(&sw_image.hdr, encode_buf, encode_len, BCMOS_TRUE);

    return rc;
}

/* @brief API to be called by omci service layer to activate s/w image */
bcmos_errno bcm_omci_swdl_activate_req(bcm_omci_me_key *me_key, bcm_omci_swdl_activate_mode mode)
{
    bcmos_errno  rc;
    bcm_omci_sw_image_cfg sw_image;
    uint8_t *encode_buf;
    uint32_t encode_len;

    BCM_OMCI_HDR_INIT(&sw_image.hdr, sw_image, *me_key);
    sw_image.hdr.omci_msg_type = BCM_OMCI_MSG_TYPE_ACTIVATE_SW;

    /* Allocate encode buffer */
    rc = bcm_omci_req_buffer_alloc(&sw_image.hdr, &encode_buf, &encode_len);
    if (rc != BCM_ERR_OK)
        return rc;

    /* Encode content */
    BCM_OMCI_ENCODE_UINT8(encode_buf, encode_len, mode);

#ifdef ENABLE_LOG
    /** dump the encoded buffer */
    bcm_omci_stack_util_dump_raw_buf(me_key, encode_buf, encode_len, log_id_bcm_omci_stack_me_layer);
#endif

    /* Send */
    rc = omci_transport_send_msg (&sw_image.hdr, encode_buf, encode_len, BCMOS_TRUE);

    return rc;
}

/* @brief API to be called by omci service layer to commit s/w image */
bcmos_errno bcm_omci_swdl_commit_req(bcm_omci_me_key *me_key)
{
    bcmos_errno  rc = BCM_ERR_OK;
    bcm_omci_me_hdr me_hdr;

    BCM_OMCI_HDR_INIT(&me_hdr, sw_image, *me_key);
    me_hdr.omci_msg_type = BCM_OMCI_MSG_TYPE_COMMIT_SW;

#ifdef ENABLE_LOG
    /** dump the ME fields */
    bcm_omci_me_log(&me_hdr, log_id_bcm_omci_stack_me_layer, log_level_bcm_omci_stack_me_layer);
#endif

    /** call stack protocol layer to send the msg out onto omci channel to onu */
    rc = bcm_omci_tl_send_msg_operation (&me_hdr);

    return rc;
}

/* @brief API to be called by omci service layer to synchronize time on onu-g */
bcmos_errno bcm_omci_sync_time_req(bcm_omci_me_key *me_key)
{
    bcm_omci_me_hdr me_hdr;
    BCM_OMCI_HDR_INIT(&me_hdr, onu_g, *me_key);
    return bcm_omci_encode_and_send(&me_hdr, BCM_OMCI_MSG_TYPE_SYNC_TIME);
}

/* @brief  Free me_hdr block */
void bcm_omci_me_free(bcm_omci_me_hdr *me_hdr)
{
    if (me_hdr->me_free != NULL)
        me_hdr->me_free(me_hdr);
}
