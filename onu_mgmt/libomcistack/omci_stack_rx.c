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
 * @file omci_stack_rx.c
 * @brief This file contains receive handlers that validate & decode data portion of
 *       received OMCI messages and call the relevant service layer/application callback
 */
#include "bcmos_system.h"
#include "bcmos_errno.h"
#include "bcm_dev_log.h"
#include "omci_stack_buf.h"
#include "omci_stack_api.h"
#include "omci_stack_internal.h"
#include "omci_stack_common.h"
#include "omci_stack_protocol_prop.h"
#include "omci_stack_enc_dec.h"
#include "omci_stack_me_tl_intf.h"
#ifdef ENABLE_LOG
#include <bcm_dev_log.h>
#endif

#ifdef ENABLE_LOG
/* The logging device id for the OMCI Stack ME Layer */
extern dev_log_id log_id_bcm_omci_stack_me_layer;
extern bcm_dev_log_level log_level_bcm_omci_stack_me_layer;
#endif

/** @brief enum for check ME reassembly conditions and notify ME to service layer */
typedef enum
{
    NO_ACTION,
    COPY_STORED_ME_SEGMENT,
    COPY_STORED_ME_SEGMENT_AND_NOTIFY_STORED_ME,
    NOTIFY_STORED_ME_AND_SET_NEW_ME_SEGMENT,
    SET_NEW_ME_SEGMENT,
    NOTIFY_NEW_ME,
    NOTIFY_STORED_ME_AND_NOTIFY_NEW_ME
} bcm_omci_check_me_reassembly_and_notify;

#ifdef ENABLE_LOG
static char *check_reassembly_and_notify_str[] =
{
    "NO_ACTION",
    "COPY_STORED_ME_SEGMENT",
    "COPY_STORED_ME_SEGMENT_AND_NOTIFY_STORED_ME",
    "NOTIFY_STORED_ME_AND_SET_NEW_ME_SEGMENT",
    "SET_NEW_ME_SEGMENT",
    "NOTIFY_NEW_ME",
    "NOTIFY_STORED_ME_AND_NOTIFY_NEW_ME"
};
#endif

/** @brief ONU context stored for ME reassembly for multiple segments received in MIB Upload Next responses from ONU */
typedef struct
{
    bcm_omci_me_hdr *stored_me_segments;
    bcm_omci_result stored_me_segments_omci_result;
} bcm_omci_me_reassembly_context;

static void bcm_omci_me_decode_rsp_result(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len);
static bcmos_errno bcm_omci_check_reassembly_and_notification (bcm_omci_me_hdr *me_mib_upload, bcm_omci_me_hdr *me_cfg_reassemble,
                                                              bcm_omci_result result, bcm_omci_check_me_reassembly_and_notify *me_notify_check);
static void bcm_omci_me_reassembly_set_new_me_segment (bcm_omci_me_hdr *me_mib_upload, bcm_omci_result result);
static void bcm_omci_me_reassembly_clear_me_segments_and_context(bcm_omci_me_key *me_key);
static void bcm_omci_me_reassembly_copy_me_segment (bcm_omci_me_hdr *me_mib_upload, bcm_omci_me_reassembly_context *reassembly_context, bcm_omci_result result);
static void bcm_omci_get_rsp(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len);
static void bcm_omci_mib_reset_rsp(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len);
static void bcm_omci_mib_upload_rsp(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len);
static void bcm_omci_mib_upload_next_rsp(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len);
static void bcm_omci_swdl_start_rsp(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len);
static void bcm_omci_swdl_end_rsp(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len);
static void bcm_omci_swdl_section_rsp(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len);

/* @brief API to be called by omci service layer to decode raw OMCI message */
static bcmos_errno bcm_omci_me_decode_and_log(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len)
{
    bcmos_errno rc;

    /* decode */
    rc = bcm_omci_me_decode(me_hdr, decode_buf, decode_len, me_hdr->omci_msg_type);
    if (BCM_ERR_OK != rc)
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "Can't decode auto msg. entity_class %u\n", me_hdr->key.entity_class);
        return rc;
    }

#ifdef ENABLE_LOG
    /** dump the ME (segment) fields */
    bcm_omci_me_log(me_hdr, log_id_bcm_omci_stack_me_layer, log_level_bcm_omci_stack_me_layer);
#endif

    return BCM_ERR_OK;
}

static void bcm_omci_rsp_result_only(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf,
    uint32_t decode_len, bcmos_bool is_update_mib_sync)
{
    bcm_omci_me_decode_rsp_result(me_hdr, decode_buf, decode_len);
    if (BCM_OMCI_RESULT_CMD_PROC_SUCCESS == me_hdr->rsp.result && is_update_mib_sync)
    	omci_transport_increment_mib_data_sync(me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id);

    /* finally call omci svc layer / application callback */
    omci_init_parms.response_cb(me_hdr);
}

/* @brief API called by transport layer on a Create Rsp from ONU */
void bcm_omci_rsp(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len)
{
    switch(me_hdr->omci_msg_type)
    {
        case BCM_OMCI_MSG_TYPE_CREATE:
        case BCM_OMCI_MSG_TYPE_DELETE:
        case BCM_OMCI_MSG_TYPE_SET:
        case BCM_OMCI_MSG_TYPE_COMMIT_SW:
            bcm_omci_rsp_result_only(me_hdr, decode_buf, decode_len, BCMOS_TRUE);
            break;

        case BCM_OMCI_MSG_TYPE_REBOOT:
        case BCM_OMCI_MSG_TYPE_ACTIVATE_SW:
        case BCM_OMCI_MSG_TYPE_SYNC_TIME:
            bcm_omci_rsp_result_only(me_hdr, decode_buf, decode_len, BCMOS_FALSE);
            break;

        case BCM_OMCI_MSG_TYPE_GET:
            bcm_omci_get_rsp(me_hdr, decode_buf, decode_len);
            break;

        case BCM_OMCI_MSG_TYPE_MIB_RESET:
            bcm_omci_mib_reset_rsp(me_hdr, decode_buf, decode_len);
            break;

        case BCM_OMCI_MSG_TYPE_MIB_UPLOAD:
            bcm_omci_mib_upload_rsp(me_hdr, decode_buf, decode_len);
            break;

        case BCM_OMCI_MSG_TYPE_MIB_UPLOAD_NEXT:
            bcm_omci_mib_upload_next_rsp(me_hdr, decode_buf, decode_len);
            break;

        case BCM_OMCI_MSG_TYPE_START_SW_DOWNLOAD:
            bcm_omci_swdl_start_rsp(me_hdr, decode_buf, decode_len);
            break;

        case BCM_OMCI_MSG_TYPE_END_SW_DOWNLOAD:
            bcm_omci_swdl_end_rsp(me_hdr, decode_buf, decode_len);
            break;

        case BCM_OMCI_MSG_TYPE_DOWNLOAD_SECTION:
            bcm_omci_swdl_section_rsp(me_hdr, decode_buf, decode_len);
            break;

        case BCM_OMCI_MSG_TYPE_GET_ALL_ALARMS:
        case BCM_OMCI_MSG_TYPE_GET_ALL_ALARMS_NEXT:
        case BCM_OMCI_MSG_TYPE_ALARM:
        case BCM_OMCI_MSG_TYPE_AVC:
        case BCM_OMCI_MSG_TYPE_TEST:
        case BCM_OMCI_MSG_TYPE_GET_NEXT:
        case BCM_OMCI_MSG_TYPE_TEST_RESULT:
        case BCM_OMCI_MSG_TYPE_GET_CURRENT_DATA:
        case BCM_OMCI_MSG_TYPE_SET_TABLE:
        default:
            BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "Message type %s is currently not supported\n",
                BCM_OMCI_MSG_TYPE_STR(me_hdr->omci_msg_type));
            break;
    }
}

/* @brief API called by transport layer on a Get Rsp from ONU */
static void bcm_omci_get_rsp(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len)
{
    bcmos_errno  rc = BCM_ERR_OK;
    bcm_omci_me_hdr *me_rsp = NULL;

    me_hdr->omci_msg_type = BCM_OMCI_MSG_TYPE_GET;
    do
    {
        if (BCM_OMCI_OBJ_ID__BEGIN == me_hdr->obj_type)
        {
            me_hdr->rsp.result = BCM_OMCI_RESULT_CMD_NOT_SUPPORTED;
            break;
        }

        BCM_OMCI_DECODE_MSG_CONTENT_RSP_RESULT(decode_buf, decode_len, me_hdr->rsp.result);
        if (me_hdr->rsp.result != BCM_OMCI_RESULT_CMD_PROC_SUCCESS)
        {
            break;
        }

        me_rsp = bcmos_calloc(bcm_omci_me_cfg_get_struct_length(me_hdr->obj_type));
        if (me_rsp == NULL)
        {
            me_hdr->rsp.result = BCM_OMCI_RESULT_CMD_PROC_ERROR;
            break;
        }
        *me_rsp = *me_hdr;
        me_rsp->me_free = bcm_omci_dyn_me_free_cb;

        /* Decode */
        rc = bcm_omci_me_decode_and_log(me_rsp, decode_buf, decode_len);

    } while (0);

    if (rc != BCM_ERR_OK || me_hdr->rsp.result != BCM_OMCI_RESULT_CMD_PROC_SUCCESS)
    {
        if (me_hdr->rsp.result == BCM_OMCI_RESULT_CMD_PROC_SUCCESS)
            me_hdr->rsp.result = BCM_OMCI_RESULT_CMD_PROC_ERROR;
        if (me_rsp != NULL)
        {
            bcmos_free(me_rsp);
            me_rsp = NULL;
        }
    }

    /* finally call omci svc layer */
    omci_init_parms.response_cb(me_rsp ? me_rsp : me_hdr);
}

/* @brief API to be called by transport layer to notify autonomous message */
void bcm_omci_auto(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len)
{
    switch (me_hdr->omci_msg_type)
    {
        case BCM_OMCI_MSG_TYPE_ALARM:
        {
            bcm_omci_alarm alarm = {};
            BCM_OMCI_DECODE_BUF(decode_buf, decode_len, &alarm.alarm_bitmap[0], sizeof(alarm.alarm_bitmap));
            /* Skip padding */
            BCM_OMCI_DECODE_SKIP(decode_buf, decode_len, 3);
            /* Alarm sequence number */
            BCM_OMCI_DECODE_UINT8(decode_buf, decode_len, alarm.alarm_seq_number);

            /* Report to OMCI SVC layer */
            omci_init_parms.alarm_cb(&me_hdr->key, &alarm);
            break;
        }

        default:
            break;
    }
}

/* @brief API to be called by transport layer to notify request timeout */
void bcm_omci_req_error(bcm_omci_me_hdr *me_hdr, bcmos_errno err)
{
    me_hdr->status = err;
    omci_init_parms.response_cb(me_hdr);
}

/* @brief API called by transport layer on a MIB Reset Rsp from ONU */
static void bcm_omci_mib_reset_rsp(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len)
{
    bcm_omci_me_decode_rsp_result(me_hdr, decode_buf, decode_len);

    /* Reset the MIB data sync*/
    if (BCM_OMCI_RESULT_CMD_PROC_SUCCESS == me_hdr->rsp.result)
       	omci_transport_reset_mib_data_sync(me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id);

    /* finally call omci svc layer / application callback */
    omci_init_parms.response_cb(me_hdr);
}

/* @brief API called by transport layer to on receiving a MIB Upload Initiation Rsp from ONU */
static void bcm_omci_mib_upload_rsp(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len)
{
    bcm_omci_mib_upload_response data = {};

    if (decode_buf == NULL || decode_len < sizeof(uint16_t))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "Malformed %s response ignored\n",
            BCM_OMCI_MSG_TYPE_STR(me_hdr->omci_msg_type));
        return;
    }

    /** decode me count in message content */
    BCM_OMCI_DECODE_MSG_CONTENT_NUM_NEXT_CMDS(decode_buf, decode_len, data.mib_upload.me_count);

    BCM_LOG(INFO, log_id_bcm_omci_stack_me_layer, "%s: num_next_cmds = %d\n", __FUNCTION__, data.mib_upload.me_count);

    omci_transport_mib_upload_num_cmds_set(&me_hdr->key, data.mib_upload.me_count);

    /* clear the onu context for me reassembly */
    bcm_omci_me_reassembly_clear_me_segments_and_context(&me_hdr->key);

    /* finally call omci svc layer / application callback */
    omci_init_parms.mib_upload_response_cb(me_hdr, &data);
}


/* @brief API called by transport layer to decode MEs on MIB Upload Next Rsp from ONU */
static void bcm_omci_mib_upload_next_rsp(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len)
{
    bcmos_errno  rc = BCM_ERR_INTERNAL;  /* by default it is an error */
    uint8_t *decode_buf_msg_content = decode_buf;
    uint16_t decode_len_msg_content = decode_len;
    bcm_omci_me_hdr  *me_mib_upload = NULL;
    bcm_omci_me_key me_mib_upload_key = me_hdr->key;
    /* me reassembly data */
    bcm_omci_me_reassembly_context *me_reassembly_context = NULL;
    bcm_omci_me_hdr  *stored_me_segments = NULL;
    bcm_omci_result  stored_me_segments_result = BCM_OMCI_RESULT_CMD_PROC_SUCCESS;
    bcm_omci_check_me_reassembly_and_notify check_me_reassembly_and_notify = NO_ACTION;
    bcm_omci_result curr_me_segment_result = omci_transport_mib_upload_next(&me_hdr->key);
    bcmos_bool is_free_me_mib_upload = BCMOS_TRUE;
    bcm_omci_mib_upload_response data = {};
    bcm_omci_obj_id obj_type;

    if (decode_buf == NULL || decode_len < sizeof(uint16_t))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "Malformed %s response ignored\n",
            BCM_OMCI_MSG_TYPE_STR(me_hdr->omci_msg_type));
        return;
    }

    /** decode entity class & instance from message content */
    BCM_OMCI_DECODE_MSG_CONTENT_ME_ENTITY_CLASS(decode_buf_msg_content, decode_len_msg_content,  me_mib_upload_key.entity_class);
    BCM_OMCI_DECODE_MSG_CONTENT_ME_ENTITY_INSTANCE(decode_buf_msg_content, decode_len_msg_content, me_mib_upload_key.entity_instance);

    BCM_LOG(DEBUG, log_id_bcm_omci_stack_me_layer, "%s: MIB Upload Next Rsp: entity_class = %s(%u), entity_instance = %d(0x%X)\n",
            __FUNCTION__,
            BCM_OMCI_ME_CLASS_VAL_STR(me_mib_upload_key.entity_class), me_mib_upload_key.entity_class,
            me_mib_upload_key.entity_instance,
			me_mib_upload_key.entity_instance);

    /** @note if a ME is not handled then just call service layer with the key */
    obj_type = bcm_omci_me_class_val2bcm_omci_obj_id_conv(me_mib_upload_key.entity_class);
    if (BCM_OMCI_OBJ_ID__BEGIN == obj_type)
    {
        /* ME not supported in stack data model (i.e. not decoded), just send the key */
        /* allocate memory for the uploaded me */
        me_mib_upload = bcmos_calloc (sizeof(bcm_omci_me_hdr));
        if (NULL == me_mib_upload)
            goto exit;

        /* initialize a generic me structure */
        _BCM_OMCI_HDR_INIT(me_mib_upload, me_mib_upload_key);
        me_mib_upload->omci_msg_type = BCM_OMCI_MSG_TYPE_MIB_UPLOAD_NEXT;
    }
    else
    {
        /* allocate memory for the uploaded me (segment)*/
        me_mib_upload = bcmos_calloc (bcm_omci_me_cfg_get_struct_length(obj_type));
        if (NULL == me_mib_upload)
            goto exit;

        _BCM_OMCI_HDR_INIT(me_mib_upload, me_mib_upload_key);
        me_mib_upload->omci_msg_type = BCM_OMCI_MSG_TYPE_MIB_UPLOAD_NEXT;
        me_mib_upload->dir = BCM_OMCI_OBJ_MSG_DIR_RESPONSE;

        /* call decode callback to decode omci msg */
        rc = bcm_omci_me_decode(me_mib_upload, decode_buf_msg_content, decode_len_msg_content, BCM_OMCI_MSG_TYPE_MIB_UPLOAD_NEXT);
        if (BCM_ERR_OK != rc)
            goto exit;

#ifdef ENABLE_LOG
        /** dump the ME (segment) fields */
        bcm_omci_me_log(me_mib_upload, log_id_bcm_omci_stack_me_layer, log_level_bcm_omci_stack_me_layer);
#endif
    }

    /* Do some validation here */
    if ((BCM_OMCI_ME_CLASS_VAL__BEGIN >= me_mib_upload_key.entity_class) ||
        (BCM_OMCI_ME_CLASS_VAL__END   <= me_mib_upload_key.entity_class))
    {
#ifdef FLAG_ERROR_FOR_UNKNOWN_ME
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s: Failed: invalid entity_class = %s (%u), entity_instance = %d\n",
                __FUNCTION__,
                BCM_OMCI_ME_CLASS_VAL_STR(me_mib_upload_key.entity_class),
                me_mib_upload_key.entity_class,
                me_mib_upload_key.entity_instance);

        rc = BCM_ERR_PARM;
        goto exit;
#else
        BCM_LOG(WARNING, log_id_bcm_omci_stack_me_layer, "%s: Ignoring invalid entity_class = %s (%u), entity_instance = %d\n",
                __FUNCTION__,
                BCM_OMCI_ME_CLASS_VAL_STR(me_mib_upload_key.entity_class),
                me_mib_upload_key.entity_class,
                me_mib_upload_key.entity_instance);
#endif
    }

    /* check ME reassembly and notification to svc layer */
    me_reassembly_context = BCM_OMCI_TL_ONU_DB_ME_CONTEXT_GET(me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id);
    if (NULL != me_reassembly_context)
    {
        stored_me_segments = me_reassembly_context->stored_me_segments;
        stored_me_segments_result = me_reassembly_context->stored_me_segments_omci_result;
    }
    rc  = bcm_omci_check_reassembly_and_notification (me_mib_upload, stored_me_segments, curr_me_segment_result, &check_me_reassembly_and_notify);

    /** Notify and/or Store ME  segment(s) */
    data.mib_upload_next.is_last = (curr_me_segment_result == BCM_OMCI_RESULT_IND_LAST);
    switch (check_me_reassembly_and_notify)
    {
        case COPY_STORED_ME_SEGMENT:
            bcm_omci_me_reassembly_copy_me_segment (me_mib_upload, me_reassembly_context, curr_me_segment_result);
            /* trigger mib upload next req from here, since we are not calling svc layer */
            if (BCM_OMCI_RESULT_IND_MORE == curr_me_segment_result)
            {
                bcm_omci_mib_upload_next_req(&me_hdr->key);
            }
            break;

        case COPY_STORED_ME_SEGMENT_AND_NOTIFY_STORED_ME:
            bcm_omci_me_reassembly_copy_me_segment (me_mib_upload, me_reassembly_context, curr_me_segment_result);
            if (stored_me_segments->rsp.result == BCM_OMCI_RESULT_CMD_PROC_SUCCESS)
                 stored_me_segments->rsp.result = curr_me_segment_result;
            omci_init_parms.mib_upload_response_cb(stored_me_segments, &data);
            bcm_omci_me_reassembly_clear_me_segments_and_context(&me_mib_upload_key);
            break;

        case NOTIFY_STORED_ME_AND_SET_NEW_ME_SEGMENT:
            /* notify omci svc layer / application callback */
            if (stored_me_segments->rsp.result == BCM_OMCI_RESULT_CMD_PROC_SUCCESS)
                 stored_me_segments->rsp.result = stored_me_segments_result;
            omci_init_parms.mib_upload_response_cb(stored_me_segments, &data);
            bcm_omci_me_reassembly_clear_me_segments_and_context(&me_mib_upload_key);
            bcm_omci_me_reassembly_set_new_me_segment(me_mib_upload, curr_me_segment_result);
            is_free_me_mib_upload = BCMOS_FALSE;
            break;

        case SET_NEW_ME_SEGMENT:
            bcm_omci_me_reassembly_set_new_me_segment (me_mib_upload, curr_me_segment_result);
            is_free_me_mib_upload = BCMOS_FALSE;

            /* trigger mib upload next req from here, since we are not calling svc layer */
            if (BCM_OMCI_RESULT_IND_MORE == curr_me_segment_result)
            {
                bcm_omci_mib_upload_next_req(&me_hdr->key);
            }
            break;

        case NOTIFY_NEW_ME:
            if (me_mib_upload->rsp.result == BCM_OMCI_RESULT_CMD_PROC_SUCCESS)
                 me_mib_upload->rsp.result = curr_me_segment_result;
            omci_init_parms.mib_upload_response_cb(me_mib_upload, &data);
            break;

        case NOTIFY_STORED_ME_AND_NOTIFY_NEW_ME:
            /* notify svc layer of the stored ME */
            if (stored_me_segments->rsp.result == BCM_OMCI_RESULT_CMD_PROC_SUCCESS)
                 stored_me_segments->rsp.result = stored_me_segments_result;
            omci_init_parms.mib_upload_response_cb(stored_me_segments, &data);
            /* ... since it would be immediately followed by the last mib upload response to svc layer */
            bcm_omci_me_reassembly_clear_me_segments_and_context(&me_mib_upload_key);

            /* notify svc layer of the new ME */
            if (me_mib_upload->rsp.result == BCM_OMCI_RESULT_CMD_PROC_SUCCESS)
                 me_mib_upload->rsp.result = curr_me_segment_result;
            omci_init_parms.mib_upload_response_cb(me_mib_upload, &data);
            break;

        case NO_ACTION:
        default:
            goto exit;
            break;
    }

exit:

    if (BCM_ERR_OK != rc)
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s: Failed: entity_class = %s (%u), entity_instance = %d\n",
                __FUNCTION__, BCM_OMCI_ME_CLASS_VAL_STR(me_mib_upload_key.entity_class), me_mib_upload_key.entity_class,
                me_mib_upload_key.entity_instance);
    }

    /** free the memory */
    if ((NULL != me_mib_upload) && (BCMOS_TRUE == is_free_me_mib_upload))
    {
        bcmos_free (me_mib_upload);
    }
}

/* Helper function that decodes swdl header for all requests */
#define BCM_OMCI_SWDL_ANY_RESP(_hdr, _buf, _len, _res) \
    do { \
        if (BCM_OMCI_SW_IMAGE_OBJ_ID != (_hdr)->obj_type) \
        { \
            BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s: unexpected object id %d\n",\
                __FUNCTION__, (_hdr)->obj_type ); \
            return;\
        } \
        BCM_OMCI_DECODE_MSG_CONTENT_RSP_RESULT(_buf, _len, _res);\
    } while (0)


/* @brief API called by transport layer to notify Download Start response */
static void bcm_omci_swdl_start_rsp(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len)
{
    bcm_omci_swdl_response swdl_rsp = {};
    int i;

    BCM_OMCI_SWDL_ANY_RESP(me_hdr, decode_buf, decode_len, me_hdr->rsp.result);

    // Decode message
    BCM_OMCI_DECODE_UINT8(decode_buf, decode_len, swdl_rsp.swdl_start.win_size);
    BCM_OMCI_DECODE_UINT8(decode_buf, decode_len, swdl_rsp.swdl_start.num_inst);
    BCM_OMCI_DECODE_UINT8(decode_buf, decode_len, swdl_rsp.swdl_start.me_id);
    if (swdl_rsp.swdl_start.num_inst > BCM_SIZEOFARRAY(swdl_rsp.swdl_start.result))
        swdl_rsp.swdl_start.num_inst = BCM_SIZEOFARRAY(swdl_rsp.swdl_start.result);
    for (i = 0; i < swdl_rsp.swdl_start.num_inst; i++)
    {
        if (!decode_len)
            break;
        BCM_OMCI_DECODE_UINT8(decode_buf, decode_len, swdl_rsp.swdl_start.result[i]);
    }

    /* finally call omci svc layer */
    omci_init_parms.swdl_response_cb(me_hdr, &swdl_rsp);
}

/* @brief API called by transport layer to notify Download Start response */
static void bcm_omci_swdl_end_rsp(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len)
{
    bcm_omci_swdl_response swdl_rsp = {};
    int i;

    BCM_OMCI_SWDL_ANY_RESP(me_hdr, decode_buf, decode_len, me_hdr->rsp.result);

    // Decode message
    BCM_OMCI_DECODE_UINT8(decode_buf, decode_len, swdl_rsp.swdl_end.num_inst);
    if (swdl_rsp.swdl_end.num_inst > BCM_SIZEOFARRAY(swdl_rsp.swdl_end.slot))
        swdl_rsp.swdl_end.num_inst = BCM_SIZEOFARRAY(swdl_rsp.swdl_end.slot);
    for (i = 0; i < swdl_rsp.swdl_end.num_inst; i++)
    {
        if (decode_len < 3)
            break;
        BCM_OMCI_DECODE_UINT16(decode_buf, decode_len, swdl_rsp.swdl_end.slot[i].slot_me);
        BCM_OMCI_DECODE_UINT8(decode_buf, decode_len, swdl_rsp.swdl_end.slot[i].result);
    }

    /* finally call omci svc layer */
    omci_init_parms.swdl_response_cb(me_hdr, &swdl_rsp);
}

/* @brief API called by transport layer to notify Download Section response */
static void bcm_omci_swdl_section_rsp(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len)
{
    bcm_omci_swdl_response swdl_rsp = {};

    if (me_hdr->omci_format == BCM_OMCI_MSG_FORMAT_EXTENDED)
    {
        uint16_t content_length;
        BCM_OMCI_DECODE_UINT16(decode_buf, decode_len, content_length);
        (void)content_length;
    }

    BCM_OMCI_SWDL_ANY_RESP(me_hdr, decode_buf, decode_len, me_hdr->rsp.result);

    // Decode message
    BCM_OMCI_DECODE_UINT8(decode_buf, decode_len, swdl_rsp.swdl_section.section_num);

    /* finally call omci svc layer */
    omci_init_parms.swdl_response_cb(me_hdr, &swdl_rsp);
}

/*
 * Helper routines
 */

#define  BCM_OMCI_STACK_DUMP_ROW_LENGTH     16      /*hex bytes in a row */


/* @brief Helper routine to decode the Result field in message content in rsp msgs */
static void bcm_omci_me_decode_rsp_result(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len)
{
    uint8_t *decode_buf_msg_content = decode_buf;
    int decode_len_msg_content = decode_len;

    /** decode me count in message content */
    if (me_hdr->omci_format == BCM_OMCI_MSG_FORMAT_EXTENDED)
    {
        decode_buf_msg_content += OMCI_EXTENDED_MSG_RESPONSE_RESULT_OFFSET;
        decode_len_msg_content -= OMCI_EXTENDED_MSG_RESPONSE_RESULT_OFFSET;
    }

    me_hdr->rsp.result = BCM_OMCI_RESULT_TL_ERROR;
    if (decode_buf == NULL || decode_len_msg_content <= 0)
        return;
    BCM_OMCI_DECODE_MSG_CONTENT_RSP_RESULT(decode_buf_msg_content, decode_len_msg_content, me_hdr->rsp.result);
}


/**
 * @brief helper routine which reassembles ME segments and checks if svc layer is to be notified of the ME.
 * This routine will be used for MIB Upload Next Rsp, AVC, Get Rsp.
 */
static bcmos_errno bcm_omci_check_reassembly_and_notification(
    bcm_omci_me_hdr *me_mib_upload, bcm_omci_me_hdr *me_cfg_reassemble,
    bcm_omci_result result, bcm_omci_check_me_reassembly_and_notify *me_notify_check)
{
    *me_notify_check = NO_ACTION; /* by default */

    /** Check if it is another segment of the last ME & instance */
    if (NULL != me_cfg_reassemble)
    {
        if (BCM_OMCI_IS_SAME_ME_AND_INSTANCE(&me_mib_upload->key, &me_cfg_reassemble->key))
        {
            /* add to current ME */
            *me_notify_check = COPY_STORED_ME_SEGMENT;

            if (BCM_OMCI_RESULT_IND_LAST == result)
            {
                *me_notify_check = COPY_STORED_ME_SEGMENT_AND_NOTIFY_STORED_ME;
            }
            else if ((BCM_OMCI_RESULT_CMD_PROC_SUCCESS != result) && (BCM_OMCI_RESULT_IND_MORE != result))
            {
                /** result is error, so notify svc layer */
                *me_notify_check = COPY_STORED_ME_SEGMENT_AND_NOTIFY_STORED_ME;
            }
        }
        else if (!BCM_OMCI_IS_SAME_ME_AND_INSTANCE(&me_mib_upload->key, &me_cfg_reassemble->key))
        {
            /* curr me & instance complete; send up to svc layer */
            *me_notify_check = NOTIFY_STORED_ME_AND_SET_NEW_ME_SEGMENT;
            /* however also check if this new ME should be notified up too */
            if (BCM_OMCI_RESULT_IND_LAST == result)
            {
                *me_notify_check = NOTIFY_STORED_ME_AND_NOTIFY_NEW_ME;
            }
            else if ((BCM_OMCI_RESULT_CMD_PROC_SUCCESS != result) && (BCM_OMCI_RESULT_IND_MORE != result))
            {
                /** result is error, so notify svc layer */
                *me_notify_check = NOTIFY_STORED_ME_AND_NOTIFY_NEW_ME;
            }
        }

        BCM_LOG(DEBUG, log_id_bcm_omci_stack_me_layer, "Reassembly & Notification check: %s; stored entity class = %s(%u), stored entity_instance = %d\n",
            check_reassembly_and_notify_str[*me_notify_check],
            BCM_OMCI_ME_CLASS_VAL_STR(me_cfg_reassemble->key.entity_class),
            me_cfg_reassemble->key.entity_class,
            me_cfg_reassemble->key.entity_instance);

        BCM_LOG(DEBUG, log_id_bcm_omci_stack_me_layer, "new entity class = %s(%u), new entity instance = %d, omci result = %s (%u) \n",
            BCM_OMCI_ME_CLASS_VAL_STR(me_mib_upload->key.entity_class),
            me_mib_upload->key.entity_class,
            me_mib_upload->key.entity_instance,
            bcm_omci_result2str_conv(result), result);
    }
    else /* a new ME segment or a total ME  */
    {
        /* set current ME */
        *me_notify_check = SET_NEW_ME_SEGMENT;

        if (BCM_OMCI_RESULT_IND_LAST == result)
        {
            *me_notify_check = NOTIFY_NEW_ME;
        }
        else if ((BCM_OMCI_RESULT_CMD_PROC_SUCCESS != result) && (BCM_OMCI_RESULT_IND_MORE != result))
        {
            /** result is error, so notify svc layer */
            *me_notify_check = NOTIFY_NEW_ME;
        }

        BCM_LOG(DEBUG, log_id_bcm_omci_stack_me_layer,
            "Reassembly & Notification check: %s; curr ME stored is NULL, new entity class = %s(%u), new entity instance = %d, omci result = %s (%u)\n",
            check_reassembly_and_notify_str[*me_notify_check],
            BCM_OMCI_ME_CLASS_VAL_STR(me_mib_upload->key.entity_class),
            me_mib_upload->key.entity_class,
            me_mib_upload->key.entity_instance,
            bcm_omci_result2str_conv(result), result);
    }

    return BCM_ERR_OK;
}

/** @brief stores a new me segment in onu db for reassembly */
static void bcm_omci_me_reassembly_set_new_me_segment (bcm_omci_me_hdr *me_mib_upload, bcm_omci_result result)
{
    /* free current context if there is still a non-NULL context */
    bcm_omci_me_reassembly_clear_me_segments_and_context(&me_mib_upload->key);

    /* set new context */
    bcm_omci_me_reassembly_context *me_reassembly_context = NULL;
    me_reassembly_context = bcmos_calloc(sizeof(bcm_omci_me_reassembly_context));
    me_reassembly_context->stored_me_segments = me_mib_upload;
    me_reassembly_context->stored_me_segments_omci_result = result;
    BCM_OMCI_TL_ONU_DB_ME_CONTEXT_SET(me_mib_upload->key.olt_id, me_mib_upload->key.logical_pon, me_mib_upload->key.onu_id, me_reassembly_context);
}

/** @brief clears stored me segments pointer from onu db, and also clears the context */
static void bcm_omci_me_reassembly_clear_me_segments_and_context(bcm_omci_me_key *me_key)
{
    bcm_omci_me_reassembly_context *me_reassembly_context = BCM_OMCI_TL_ONU_DB_ME_CONTEXT_GET(me_key->olt_id, me_key->logical_pon, me_key->onu_id);
    if (NULL != me_reassembly_context)
    {
        if (NULL != me_reassembly_context->stored_me_segments)
        {
            /* else if some me segment was stored then free the memory and clear */
            bcmos_free(me_reassembly_context->stored_me_segments);
            me_reassembly_context->stored_me_segments = NULL;
        }

        /* free current context */
        BCM_OMCI_TL_ONU_DB_ME_CONTEXT_CLEAR(me_key->olt_id, me_key->logical_pon, me_key->onu_id);
    }
}

/** @brief copy ME segment from received msg to reassembly ME */
static void bcm_omci_me_reassembly_copy_me_segment(bcm_omci_me_hdr *me_mib_upload, bcm_omci_me_reassembly_context *reassembly_context, bcm_omci_result result)
{
    if (BCM_OMCI_OBJ_ID__BEGIN == me_mib_upload->obj_type)
        return;

    reassembly_context->stored_me_segments_omci_result = result;
    bcm_omci_me_cfg_copy_partial(me_mib_upload, reassembly_context->stored_me_segments, me_mib_upload->obj_type);
}

/* @brief Function that frees dynamically allocated me_hdr */
void bcm_omci_dyn_me_free_cb(bcm_omci_me_hdr *me_hdr)
{
    if (me_hdr != NULL)
        bcmos_free(me_hdr);
}

#ifdef ENABLE_LOG
/**
 * @brief helper routine to dump omci byte stream.
 *
 * @note this assumes that the logger task is already initialized and running:
 */
void bcm_omci_stack_util_dump_raw_buf(const bcm_omci_me_key *me_key, const uint8_t *buf, uint32_t buf_len,
    dev_log_id log_id)
{
    char buf_string[64] = {}; /* space for 16 Hex bytes + white space after each + \n + '\0' */
    char *buf_write_ptr = buf_string;
    int i = 0;
    int total_len = 0;

    if (log_id == log_id_bcm_omci_stack_me_layer)
    {
        return; /* for now do not log if called from ME layer */
    }

    if ((NULL == buf) || (0 >= buf_len))
    {
        BCM_LOG(INFO, log_id, "NULL omci raw buf, or len is 0 \n");
        return;
    }

    if (me_key->logical_pon & me_key->onu_id)
    {
        /* init the write pointer */
    	buf_write_ptr = buf_string;
        buf_write_ptr += sprintf (buf_write_ptr, "{olt_id=%u pon_if=%u, onu_id=%u, cookie=%lu}: \n",
            me_key->olt_id, me_key->logical_pon, me_key->onu_id, me_key->cookie);
        *buf_write_ptr = '\0';

        BCM_LOG_CALLER_FMT(DEBUG, log_id, "%s", buf_string);
    }

    while (total_len < buf_len)
    {
        /* init the write pointer */
    	buf_write_ptr = buf_string;
        for (i=0; (i < BCM_OMCI_STACK_DUMP_ROW_LENGTH && total_len < buf_len); i++, total_len++)
        {
            buf_write_ptr += sprintf (buf_write_ptr, "%02X ", *(buf+total_len));
        }
        buf_write_ptr += sprintf (buf_write_ptr, "\n");
        *buf_write_ptr = '\0';

        BCM_LOG_CALLER_FMT(DEBUG, log_id, "%s", buf_string);
    }

    return;
}
#endif


