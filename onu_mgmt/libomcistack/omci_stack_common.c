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
 * @file omci_stack_common.c
 * @brief This file has routines which are not ME specific
 */

#include <bcmos_system.h>
#include <bcmos_errno.h>
#ifdef ENABLE_LOG
#include "bcm_dev_log.h"
#endif
#include "omci_stack_buf.h"
#include "omci_stack_me_hdr.h"
#include "omci_stack_common.h"
#include "omci_stack_protocol_prop.h"
#include "omci_stack_model_types.h"
#include "omci_stack_me_tl_intf.h"


/** Prototype declarations */
/** common routines used for all ME objects */
bcmos_bool _bcm_omci_common_attribute_mask_encode (bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type);
bcmos_bool _bcm_omci_common_attribute_mask_decode (bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask *fields_present, bcm_omci_msg_type omci_msg_type);
bcmos_bool _bcm_omci_common_me_cfg_to_attr_mask (bcm_omci_presence_mask fields_present, uint16_t *attribute_mask);
bcmos_bool _bcm_omci_common_attr_mask_to_me_cfg (uint16_t attribute_mask, bcm_omci_presence_mask *fields_present);
bcmos_errno bcm_omci_encode_buf_alloc (bcm_omci_buf *bcm_buf, int omci_msg_format);



/**
 * @brief encodes attribute mask into omci msg.
 *      This is a common routine to be used for all objects.
 *
 * @note Encode in the Attribute Mask - encoded for Set, Get etc . Not encoded for Create, Delete etc
 */
bcmos_bool _bcm_omci_common_attribute_mask_encode (bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask fields_present, bcm_omci_msg_type omci_msg_type)
{
    uint16_t attribute_mask = 0;

    if (BCM_OMCI_MSG_TYPE_IS_ATTRIB_MASK_PRESENT_IN_SEND_MSG(omci_msg_type))
    {
        /* first convert the presence mask to attribute mask where attribute 1 bit is in MSB */
        if (!_bcm_omci_common_me_cfg_to_attr_mask (fields_present, &attribute_mask))
        {
            return BCMOS_FALSE;
        }
        /* encode in attribute mask */
        if (!bcm_omci_buf_write_u16(p_bcm_buf, attribute_mask))
        {
            return BCMOS_FALSE;
        }
    }

    return BCMOS_TRUE;
}

/**
 * @brief decodes attribute mask from received omci msg.
 *      This is a common routine to be used for all objects.
 *
 * @note Decode Attribute Mask - decoded for Set, Get etc . Not decoded for Create, Delete etc
 */
bcmos_bool _bcm_omci_common_attribute_recv_mask_decode (bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask *fields_present, bcm_omci_msg_type omci_msg_type)
{
    /* first convert the presence mask to attribute mask where attribute 1 bit is in MSB */
    uint16_t attribute_mask = 0;

    if (BCM_OMCI_MSG_TYPE_IS_ATTRIB_MASK_PRESENT_IN_RECV_MSG(omci_msg_type))
    {
        /* first decode attribute mask bytes: 9-10  */
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &attribute_mask))
        {
            return BCMOS_FALSE;
        }

        if (!_bcm_omci_common_attr_mask_to_me_cfg (attribute_mask, fields_present))
        {
            return BCMOS_FALSE;
        }
    }

    return BCMOS_TRUE;
}

/**
 * @brief decodes attribute mask from omci msg being sent.
 *      This is a common routine to be used for all objects.
 *
 * @note Decode Attribute Mask - decoded for Set, Get etc . Not decoded for Create, Delete etc
 */
bcmos_bool _bcm_omci_common_attribute_send_mask_decode (bcm_omci_buf *p_bcm_buf, bcm_omci_presence_mask *fields_present, bcm_omci_msg_type omci_msg_type)
{
    /* first convert the presence mask to attribute mask where attribute 1 bit is in MSB */
    uint16_t attribute_mask = 0;

    if (BCM_OMCI_MSG_TYPE_IS_ATTRIB_MASK_PRESENT_IN_SEND_MSG(omci_msg_type))
    {
        /* first decode attribute mask bytes: 9-10  */
        if (!bcm_omci_buf_read_u16(p_bcm_buf, &attribute_mask))
        {
            return BCMOS_FALSE;
        }

        if (!_bcm_omci_common_attr_mask_to_me_cfg (attribute_mask, fields_present))
        {
            return BCMOS_FALSE;
        }
    }

    return BCMOS_TRUE;
}

/**
 * @brief swaps the bits in field present mask to the omci attribute mask.
 *          This is a common routine to be used for all objects
 *
 * @param[ in ]      fields_present  ME attribute present mask
 * @param[ in,out ]  attribute_mask OMCI msg attribute present mask
 *
 * @returns BCMOS_TRUE, BCMOS_FALSE
 */
bcmos_bool _bcm_omci_common_me_cfg_to_attr_mask (bcm_omci_presence_mask fields_present, uint16_t *attribute_mask)
{
    uint16_t bit_pos = 0x8000;

    *attribute_mask = 0;
    while (bit_pos)
    {
        if (fields_present & 0x01)
        {
            *attribute_mask |= bit_pos;
        }

        fields_present >>= 1;
        bit_pos >>= 1;
    }

    return BCMOS_TRUE;
}


/**
 * @brief swaps the bits in attribute mask to field present mask.
 *          This is a common routine to be used for all objects
 *
 * @param[ in ]         attribute_mask OMCI msg attribute present mask
 * @param[ in,out ]     fields_present  ME attribute present mask
 *
 * @returns BCMOS_TRUE, BCMOS_FALSE
 */
bcmos_bool _bcm_omci_common_attr_mask_to_me_cfg (uint16_t attribute_mask, bcm_omci_presence_mask *fields_present)
{
    uint16_t bit_pos = 0x8000;
    uint16_t bit_mask = 0x0001;

    *fields_present = 0;
    while (bit_pos)
    {
        if (attribute_mask & bit_pos)
        {
            *fields_present |= bit_mask;
        }

        bit_pos >>= 1;
        bit_mask <<= 1;
    }

    return BCMOS_TRUE;
}



bcmos_errno bcm_omci_encode_buf_alloc (bcm_omci_buf *bcm_buf, int omci_msg_format)
{
    uint8_t *buf = NULL;
    uint16_t len = 0;

    if (BCM_ERR_OK != bcm_omci_tl_buf_alloc(&buf, &len, omci_msg_format))
    {
        BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : error allocating memory for encode buffer\n",
                __FUNCTION__);

        return BCM_ERR_PARM;
    }

    bcm_omci_buf_init(bcm_buf, len, buf);

    return BCM_ERR_OK;
}

bcmos_bool bcm_omci_presence_mask_check(const bcm_omci_me_hdr *me_hdr, bcm_omci_msg_type omci_msg_type, uint32_t *err_attr_id)
{
    bcmos_bool ret = BCMOS_TRUE;
    bcm_omci_presence_mask fields_mask = me_hdr->presence_mask;
    switch(omci_msg_type)
    {
        case BCM_OMCI_MSG_TYPE_CREATE:
        {
            /* "Set-by-create" and only "set-by-create" attributes must be present */
            if (fields_mask != BCM_OMCI_OBJ_ATTR_SET_BY_CREATE_MASK(me_hdr->obj_type))
            {
                /* Don't have to set optional attributes */
                if ((fields_mask & ~BCM_OMCI_OBJ_ATTR_SET_BY_CREATE_MASK(me_hdr->obj_type)) == 0 &&
                    (~fields_mask & BCM_OMCI_OBJ_ATTR_MANDATORY_MASK(me_hdr->obj_type)) == 0)
                {
                    break;
                }

                /* Definitly an error */
                if (~fields_mask & BCM_OMCI_OBJ_ATTR_SET_BY_CREATE_MASK(me_hdr->obj_type))
                {
                    *err_attr_id = ffs(~fields_mask & BCM_OMCI_OBJ_ATTR_SET_BY_CREATE_MASK(me_hdr->obj_type)) - 1;
                    BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : SET_BY_CREATE attribute %s (%d) must be set\n",
                            __FUNCTION__, BCM_OMCI_OBJ_ATTR_NAME_GET(me_hdr->obj_type, *err_attr_id), *err_attr_id);
                }
                else
                {
                    BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : attribute %s (%d) must be set for CREATE operation\n",
                            __FUNCTION__, BCM_OMCI_OBJ_ATTR_NAME_GET(me_hdr->obj_type, *err_attr_id), *err_attr_id);
                    *err_attr_id = ffs(fields_mask & ~BCM_OMCI_OBJ_ATTR_SET_BY_CREATE_MASK(me_hdr->obj_type)) - 1;
                }
                ret = BCMOS_FALSE;
            }
        }
        break;

        case BCM_OMCI_MSG_TYPE_SET:
        {
            /* Make sure that only writeable attributes are set */
            if (fields_mask & ~BCM_OMCI_OBJ_ATTR_SET_MASK(me_hdr->obj_type))
            {
                *err_attr_id = ffs(fields_mask & ~BCM_OMCI_OBJ_ATTR_SET_MASK(me_hdr->obj_type)) - 1;
                BCM_LOG(ERROR, log_id_bcm_omci_stack_me_layer, "%s : attribute %s (%d) must not be set for SET operation\n",
                        __FUNCTION__, BCM_OMCI_OBJ_ATTR_NAME_GET(me_hdr->obj_type, *err_attr_id), *err_attr_id);
                ret = BCMOS_FALSE;
            }
        }
        break;

        default:
            break;
    }

    return ret;
}

/**
 * @brief returns TRUE if message is from ONU --> OLT
 */
bcmos_bool bcm_omci_is_onu_to_olt(const bcm_omci_me_hdr *me_hdr)
{
    if (me_hdr->dir == BCM_OMCI_OBJ_MSG_DIR_RESPONSE)
        return BCMOS_TRUE;
    if (me_hdr->omci_msg_type == BCM_OMCI_MSG_TYPE_ALARM    ||
        me_hdr->omci_msg_type == BCM_OMCI_MSG_TYPE_AVC      ||
        me_hdr->omci_msg_type == BCM_OMCI_MSG_TYPE_TEST_RESULT)
    {
        return BCMOS_TRUE;
    }
    return BCMOS_FALSE;
}
