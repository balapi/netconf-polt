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

#ifndef _OMCI_STACK_COMMON_H_
#define _OMCI_STACK_COMMON_H_
/**
 * @file omci_stack_common.h
 * @brief has common definitions in ME layer used by all MEs
 */

#include <bcmolt_conv.h>
#include "omci_stack_buf.h"
#include "omci_stack_model_ids.h"


/** @brief me class val to obj id conversion */
BCMOLT_TYPE2TYPE(bcm_omci_me_class_val, bcm_omci_obj_id, extern);
BCMOLT_TYPE2TYPE(bcm_omci_obj_id, bcm_omci_me_class_val, extern);

#define BCM_OMCI_IS_SAME_ME_AND_INSTANCE(_me_key, _me_reassemble_key) \
    ((_me_key)->entity_class == (_me_reassemble_key)->entity_class &&\
     (_me_key)->entity_instance == (_me_reassemble_key)->entity_instance)

/** @brief decode 1 byte from omci msg content */
#define BCM_OMCI_DECODE_UINT8(_msg_content_buf, _msg_content_len, _val) \
    do \
    { \
        uint8_t _tmp_val;  \
        memcpy(&(_tmp_val), (_msg_content_buf), sizeof(uint8_t)); \
        _val = _tmp_val; \
        (_msg_content_buf) += 1; \
        (_msg_content_len) -= 1; \
    } while (0);

/** @brief decode 2 byte from omci msg content */
#define BCM_OMCI_DECODE_UINT16(_msg_content_buf, _msg_content_len, _val) \
    do \
    { \
        uint16_t _tmp_val;  \
        memcpy(&(_tmp_val), (_msg_content_buf), sizeof(uint16_t)); \
        (_val) = BCMOS_ENDIAN_BIG_TO_CPU_U16(_tmp_val); \
        (_msg_content_buf) += 2; \
        (_msg_content_len) -= 2; \
    } while (0);

/** @brief decode 4 byte from omci msg content */
#define BCM_OMCI_DECODE_UINT32(_msg_content_buf, _msg_content_len, _val) \
    do \
    { \
        uint32_t _tmp_val;  \
        memcpy(&(_tmp_val), (_msg_content_buf), sizeof(uint32_t)); \
        (_val) = BCMOS_ENDIAN_BIG_TO_CPU_U32(_tmp_val); \
        (_msg_content_buf) += 4; \
        (_msg_content_len) -= 4; \
    } while (0);

/** @brief decode buffer from omci msg content */
#define BCM_OMCI_DECODE_BUF(_msg_content_buf, _msg_content_len, _val, _len) \
    do \
    { \
        memcpy((char *)_val, (char *)(_msg_content_buf), _len); \
        (_msg_content_buf) += _len; \
        (_msg_content_len) -= _len; \
    } while (0);

/** @brief skip bytes in decode buffer */
#define BCM_OMCI_DECODE_SKIP(_msg_content_buf, _msg_content_len, _len) \
    do \
    { \
        (_msg_content_buf) += _len; \
        (_msg_content_len) -= _len; \
    } while (0);

/** @brief decode 1 byte from omci msg content */
#define BCM_OMCI_ENCODE_UINT8(_msg_content_buf, _msg_content_len, _val) \
    do \
    { \
        uint8_t _tmp_val = _val;  \
        memcpy(((char *)(_msg_content_buf)) + (_msg_content_len), &(_tmp_val), sizeof(uint8_t)); \
        (_msg_content_len) += 1; \
    } while (0);

/** @brief decode 2 byte from omci msg content */
#define BCM_OMCI_ENCODE_UINT16(_msg_content_buf, _msg_content_len, _val) \
    do \
    { \
        uint16_t _tmp_val = BCMOS_ENDIAN_CPU_TO_BIG_U16(_val); \
        memcpy(((char *)(_msg_content_buf)) + (_msg_content_len), &(_tmp_val), sizeof(uint16_t)); \
        (_msg_content_len) += 2; \
    } while (0);

/** @brief encode 4 byte from omci msg content */
#define BCM_OMCI_ENCODE_UINT32(_msg_content_buf, _msg_content_len, _val) \
    do \
    { \
        uint32_t _tmp_val = BCMOS_ENDIAN_CPU_TO_BIG_U32(_val); \
        memcpy(((char *)(_msg_content_buf)) + (_msg_content_len), &(_tmp_val), sizeof(uint32_t)); \
        (_msg_content_len) += 4; \
    } while (0);

/** @brief encode buffer from omci msg content */
#define BCM_OMCI_ENCODE_BUF(_msg_content_buf, _msg_content_len, _val, _len) \
    do \
    { \
        memcpy(((char *)(_msg_content_buf)) + (_msg_content_len), _val, _len); \
        (_msg_content_len) += _len; \
    } while (0);

/** @brief decode 2 bytes from omci msg content for entity class (used for MIB upload, AVC, Get Rsp etc) */
#define BCM_OMCI_DECODE_MSG_CONTENT_ME_ENTITY_CLASS(_msg_content_buf, _msg_content_len, _me_entity_class) \
    BCM_OMCI_DECODE_UINT16(_msg_content_buf, _msg_content_len, _me_entity_class)

/** @brief decode 2 bytes from omci msg content for entity instance (used for MIB upload, AVC, Get Rsp etc) */
#define BCM_OMCI_DECODE_MSG_CONTENT_ME_ENTITY_INSTANCE(_msg_content_buf, _msg_content_len, _me_entity_inst) \
    BCM_OMCI_DECODE_UINT16(_msg_content_buf, _msg_content_len, _me_entity_inst)

/** @brief decode 1 byte from omci msg content for rsp result */
#define BCM_OMCI_DECODE_MSG_CONTENT_RSP_RESULT(_msg_content_buf, _msg_content_len, _result) \
    BCM_OMCI_DECODE_UINT8(_msg_content_buf, _msg_content_len, _result)

/** @brief decode 2 bytes from omci msg content for num next cmds */
#define BCM_OMCI_DECODE_MSG_CONTENT_NUM_NEXT_CMDS(_msg_content_buf, _msg_content_len, _num_next_cmds) \
    BCM_OMCI_DECODE_UINT16(_msg_content_buf, _msg_content_len, _num_next_cmds)


/** common routines used for all ME objects */
bcmos_bool _bcm_omci_common_attribute_mask_encode (bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
bcmos_bool _bcm_omci_common_attribute_recv_mask_decode (bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask *fields_present, bcm_omci_msg_type omci_msg_type);
bcmos_bool _bcm_omci_common_attribute_send_mask_decode (bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask *fields_present, bcm_omci_msg_type omci_msg_type);
bcmos_bool _bcm_omci_common_me_cfg_to_attr_mask (bcm_omci_presence_mask fields_present, uint16_t *attribute_mask);
bcmos_bool _bcm_omci_common_attr_mask_to_me_cfg (uint16_t attribute_mask, bcm_omci_presence_mask *fields_present);
bcmos_errno bcm_omci_encode_buf_alloc (bcm_omci_buf *bcm_buf, int omci_msg_format);
bcmos_bool bcm_omci_presence_mask_check(const bcm_omci_me_hdr *me_hdr, bcm_omci_msg_type omci_msg_type, uint32_t *err_attr_id);
bcmos_bool bcm_omci_is_onu_to_olt(const bcm_omci_me_hdr *me_hdr);

/** check ifan attribute is present based on presence mask */
#define BCM_OMCI_IS_ATTRIB_PRESENT_IN_MSG(_me_class_val, _attrid, _attr_present_mask) ((_attr_present_mask) & (1ULL << (_attrid)))

#endif //_OMCI_STACK_COMMON_H_
