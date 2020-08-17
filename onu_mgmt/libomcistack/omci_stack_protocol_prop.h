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

#ifndef _OMCI_STACK_PROTOCOL_PROP_H_
#define _OMCI_STACK_PROTOCOL_PROP_H_

/**
 * @file omci_stack_protocol_prop.h
 *
 * @brief This file will be manually written code. This has the properties of ME and Attributes defined as per
 * OMCI specifications. These properties will be used for validating an ME api call.
 */
#include "bcmos_system.h"
#include "bcmos_errno.h"
#include "bcmolt_conv.h"


#define BCM_OMCI_MAX_ATTR_COUNT_IN_ME        16          /* max of 16 attributes can be present in a ME */
#define YES BCMOS_TRUE
#define NO  BCMOS_FALSE

/* Message format: Baseline (0x0A) or Extended (0x0B) */
typedef enum bcm_omci_msg_format
{
    BCM_OMCI_MSG_FORMAT_BASE = 0x0A,   /**< Baseline. */
	BCM_OMCI_MSG_FORMAT_EXTENDED = 0x0B,   /**< Extended. */
} bcm_omci_msg_format;


#define BCM_OMCI_FORMAT_BASE_MSG_LEN                     48
#define BCM_OMCI_FORMAT_EXTENDED_MSG_LEN_MAX             1980

/** @brief String mapping of ME CLass val to a readable string */
#define BCM_OMCI_ME_CLASS_VAL_STR(_me_class_val) ((_me_class_val) > BCM_OMCI_ME_CLASS_VAL__END ? \
    "ME_CLASS_VAL_OUT_OF_RNG" : \
        bcm_omci_me_class_val_str[_me_class_val] != NULL ? bcm_omci_me_class_val_str[_me_class_val] : "ME_CLASS_VAL_INVALID")

/** @brief String mapping of object type val to a readable string */
#define BCM_OMCI_OBJ_TYPE_STR(_obj_type) ((_obj_type) > BCM_OMCI_OBJ_ID__NUM_OF ? \
    "ME_OBJ_TYPE_OUT_OF_RNG" : \
        bcm_omci_obj_type_str[_obj_type] != NULL ? bcm_omci_obj_type_str[_obj_type] : "ME_OBJ_TYPE_INVALID")

/**
 * @brief OMCI Message types based on Table  11.2.2-1 in G.988.
 *
 * @note This would be passed in a OMCI message.
 *
 * @note There would be corresponding request apis in southbound to be called
 * by service layer. Also there could be corresponding response or indication APIs
 * in northbound to be called by the transport layer (as callbacks), on receiving
 * a OMCI message from ONU side.
 *
 */

/* Message type */
typedef enum bcm_omci_msg_type
{
    BCM_OMCI_MSG_TYPE__BEGIN = 4,
    BCM_OMCI_MSG_TYPE_CREATE = BCM_OMCI_MSG_TYPE__BEGIN,
    BCM_OMCI_MSG_TYPE_DELETE = 6,
    BCM_OMCI_MSG_TYPE_SET = 8,
    BCM_OMCI_MSG_TYPE_GET = 9,
    BCM_OMCI_MSG_TYPE_GET_ALL_ALARMS = 11,
    BCM_OMCI_MSG_TYPE_GET_ALL_ALARMS_NEXT = 12,
    BCM_OMCI_MSG_TYPE_MIB_UPLOAD = 13,
    BCM_OMCI_MSG_TYPE_MIB_UPLOAD_NEXT = 14,
    BCM_OMCI_MSG_TYPE_MIB_RESET = 15,
    BCM_OMCI_MSG_TYPE_ALARM = 16,
    BCM_OMCI_MSG_TYPE_AVC = 17,
    BCM_OMCI_MSG_TYPE_TEST = 18,
	BCM_OMCI_MSG_TYPE_START_SW_DOWNLOAD = 19,
	BCM_OMCI_MSG_TYPE_DOWNLOAD_SECTION = 20,
	BCM_OMCI_MSG_TYPE_END_SW_DOWNLOAD = 21,
    BCM_OMCI_MSG_TYPE_ACTIVATE_SW = 22,
    BCM_OMCI_MSG_TYPE_COMMIT_SW = 23,
	BCM_OMCI_MSG_TYPE_SYNC_TIME = 24,
    BCM_OMCI_MSG_TYPE_REBOOT = 25,
    BCM_OMCI_MSG_TYPE_GET_NEXT = 26,
    BCM_OMCI_MSG_TYPE_TEST_RESULT = 27,
    BCM_OMCI_MSG_TYPE_GET_CURRENT_DATA = 28,
    BCM_OMCI_MSG_TYPE_SET_TABLE = 29,
    BCM_OMCI_MSG_TYPE__END
} bcm_omci_msg_type;

/**
 * @brief Object message type mask. Can be a combination of flags.
 * @note This has one to one mapping with bcm_omci_msg_type
 * */
typedef enum bcm_omci_obj_action_type
{
    BCM_OMCI_OBJ_ACTION_TYPE_CREATE             = 0x01,
    BCM_OMCI_OBJ_ACTION_TYPE_DELETE             = 0x02,
    BCM_OMCI_OBJ_ACTION_TYPE_SET                = 0x04,
    BCM_OMCI_OBJ_ACTION_TYPE_GET                = 0x08,
    BCM_OMCI_OBJ_ACTION_TYPE_GET_ALL_ALARMS     = 0x10,
    BCM_OMCI_OBJ_ACTION_TYPE_GET_ALL_ALARMS_NEXT= 0x20,
    BCM_OMCI_OBJ_ACTION_TYPE_MIB_UPLOAD         = 0x40,
    BCM_OMCI_OBJ_ACTION_TYPE_MIB_UPLOAD_NEXT    = 0x80,
    BCM_OMCI_OBJ_ACTION_TYPE_MIB_RESET          = 0x100,
    BCM_OMCI_OBJ_ACTION_TYPE_ALARM              = 0x200,
    BCM_OMCI_OBJ_ACTION_TYPE_AVC                = 0x400,
    BCM_OMCI_OBJ_ACTION_TYPE_TEST               = 0x800,
    BCM_OMCI_OBJ_ACTION_TYPE_START_SW_DOWNLOAD  = 0x1000,
    BCM_OMCI_OBJ_ACTION_TYPE_DOWNLOAD_SECTION   = 0x2000,
    BCM_OMCI_OBJ_ACTION_TYPE_END_SW_DOWNLOAD    = 0x4000,
    BCM_OMCI_OBJ_ACTION_TYPE_ACTIVATE_SW        = 0x8000,
    BCM_OMCI_OBJ_ACTION_TYPE_COMMIT_SW          = 0x10000,
    BCM_OMCI_OBJ_ACTION_TYPE_SYNC_TIME          = 0x20000,
    BCM_OMCI_OBJ_ACTION_TYPE_REBOOT             = 0x40000,
    BCM_OMCI_OBJ_ACTION_TYPE_GET_NEXT           = 0x80000,
    BCM_OMCI_OBJ_ACTION_TYPE_TEST_RESULT        = 0x100000,
    BCM_OMCI_OBJ_ACTION_TYPE_GET_CURRENT_DATA   = 0x200000,
    BCM_OMCI_OBJ_ACTION_TYPE_SET_TABLE          = 0x400000
} bcm_omci_obj_action_type;

/** @brief String mapping of OMCI msg type to a readable string */
extern char *bcm_omci_msg_type_str[];
#define BCM_OMCI_MSG_TYPE_STR(_omci_msg_type) bcm_omci_msg_type_str[(_omci_msg_type)]


/**
 *  @brief  OMCI Result, reason in the Response msg from ONU.
 */
typedef enum
{
    BCM_OMCI_RESULT__BEGIN,
    /* The following values are from spec */
    BCM_OMCI_RESULT_CMD_PROC_SUCCESS = BCM_OMCI_RESULT__BEGIN,
    BCM_OMCI_RESULT_CMD_PROC_ERROR,
    BCM_OMCI_RESULT_CMD_NOT_SUPPORTED,
    BCM_OMCI_RESULT_PARAM_ERROR,
    BCM_OMCI_RESULT_UNKNOWN_ME,
    BCM_OMCI_RESULT_UNKNOWN_INSTANCE,
    BCM_OMCI_RESULT_DEVICE_BUSY,
    BCM_OMCI_RESULT_INSTANCE_EXISTS,
    BCM_OMCI_RESULT_RESERVED,                    /* not defined */
    BCM_OMCI_RESULT_ATTR_FAILED_OR_UNKNOWN,

    /* Internal result values reported by Transport layer */
    BCM_OMCI_RESULT_IND_MORE,
    BCM_OMCI_RESULT_IND_LAST,
    BCM_OMCI_RESULT_TL_LINK_ERROR,
    BCM_OMCI_RESULT_TL_ERROR,
    BCM_OMCI_RESULT__NUM_OF
} bcm_omci_result;

/** @brief String mapping of OMCI Result to a readable string */
BCMOLT_TYPE2STR(bcm_omci_result, extern);



/** @brief mcast operations profile ACL set ctrl */
typedef enum
{
    BCM_OMCI_MCAST_ACL_TABLE_SET_CTRL__BEGIN,
    BCM_OMCI_MCAST_ACL_TABLE_SET_CTRL_WRITE_ENTRY,
    BCM_OMCI_MCAST_ACL_TABLE_SET_CTRL_DELETE_ENTRY,
    BCM_OMCI_MCAST_ACL_TABLE_SET_CTRL_CLEAR_ALL,
    BCM_OMCI_MCAST_ACL_TABLE_SET_CTRL__END
} bcm_omci_mcast_acl_set_ctrl;

/** @brief mcast operations profile ACL row part */
typedef enum
{
    BCM_OMCI_MCAST_ACL_ROW_PART__BEGIN,
    BCM_OMCI_MCAST_ACL_ROW_PART0 = BCM_OMCI_MCAST_ACL_ROW_PART__BEGIN,
    BCM_OMCI_MCAST_ACL_ROW_PART1,
    BCM_OMCI_MCAST_ACL_ROW_PART2,
    eOG_MCAST_ACL_ROW_PART__END
} bcm_omci_mcast_acl_row_part;



/** @brief get ME action mask based on omci msg type */
#define BCM_OMCI_ME_ACTION_MASK(_omci_msg_type)  (1ULL << (uint64_t)(_omci_msg_type))


/**
 * @brief Table to define associated properties i.e. AK & Increment Sync Counter,
 * for each OMCI Msg Type. This is also taken from Table 11.2.2-1 in G.988 and is
 * an extension of the above enum.
 *
 * @details this table defines AK (acknowledge) & Increment MIB sync counter flags
 * for each  OMCI Message Type.
 *
 * @note This may be used by stack to wait/check for Ack from ONU , and also
 * to increment MIB sync counter.
 *
 * @note Some of these messages will be sent only from the ONU side e.g. ALARM, AVC etc. OMCI
 *       stack can use this table to validate if a message type is fine to be sent or received along
 *       with the constituent fields, and also take resultant action about send or not send ack ,
 *       wait or not wait for ack etc.
 */

typedef struct bcm_omci_msg_type_flags {
    bcmos_bool olt_to_onu;      /* if TRUE, then Request msg can be sent from OLT -> ONU. Corresponding Response msg will from ONU -> OLT.
                                   if FALSE, then Request msg is from ONU -> OLT.*/
    bcmos_bool is_attrib_mask_present_in_send_msg;  /* if attribute mask is present as a field in the omci msg in send direction */
    bcmos_bool is_attribs_present_in_send_msg;   /* if attributes are present in the omci msg in send direction */
    bcmos_bool is_attrib_mask_present_in_recv_msg;  /* if attribute mask is present as a field in the recv direction */
    bcmos_bool is_attribs_present_in_recv_msg;   /* if attributes are present in the omci msg in recv direction */
} bcm_omci_msg_type_flags;

extern bcm_omci_msg_type_flags bcm_omci_msg_type_flags_arr[];

#define BCM_OMCI_MSG_TYPE_IS_ATTRIB_MASK_PRESENT_IN_SEND_MSG(_type)  (bcm_omci_msg_type_flags_arr[(_type)].is_attrib_mask_present_in_send_msg)
#define BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_SEND_MSG(_type)  (bcm_omci_msg_type_flags_arr[(_type)].is_attribs_present_in_send_msg)

#define BCM_OMCI_MSG_TYPE_IS_ATTRIB_MASK_PRESENT_IN_RECV_MSG(_type)  (bcm_omci_msg_type_flags_arr[(_type)].is_attrib_mask_present_in_recv_msg)
#define BCM_OMCI_MSG_TYPE_IS_ATTRIBS_PRESENT_IN_RECV_MSG(_type)  (bcm_omci_msg_type_flags_arr[(_type)].is_attribs_present_in_recv_msg)

/**
 * @brief attribute presence type: Manadatory or Optional
 */
typedef enum bcm_omci_me_attr_type {
    ATTR_TYPE_MANDATORY = 0,
    ATTR_TYPE_OPTIONAL
} bcm_omci_me_attr_present_type;

/**
 * @brief attribute access type : R, W, RW etc
 */
typedef enum bcm_omci_me_attr_access_type {
    ATTR_ACCESS_TYPE_READ   = 0x0,
    ATTR_ACCESS_TYPE_WRITE  = 0x1,
    ATTR_ACCESS_TYPE_SET_BY_CREATE = 0x2
} bcm_omci_me_attr_access_type;



/** @brief supported action mask for a ME */
typedef uint64_t bcm_omci_me_supported_action_mask;


/**
 * @brief defines attribute properties e.g. R,W,RW access and Mandatory/Optional properties,
 *  based on G.988 spec.
 */
typedef struct bcm_omci_me_attr_prop {
    const char                         *attr_name;
    uint32_t                            attr_access_type;       /** R, W, RW etc taken from bcm_omci_attr_access_type enum, and set as bit mask */
    bcm_omci_me_attr_present_type       attr_present_type;      /** Mandatory or optional attribute */
    uint16_t                            attr_len;               /** encode length for attribute of the ME */
} bcm_omci_me_attr_prop;



/**
 * @brief structure for ME and attribute properties set based on the OMCI spec.
 *
 * @details This structure is initialized in the .c file. It defines the attribute access type properties and the Mandatory / Optional properties for a ME,
 * based on what the standard specifies. It also sets the actions supported for a ME based on the spec. The message length is set based on if the ME
 * is used with Base format (default) or Extended format.
 */
typedef struct bcm_omci_me_proto_props {
    bcm_omci_me_attr_prop  me_attr_properties[BCM_OMCI_MAX_ATTR_COUNT_IN_ME];  /* specifies access type (R, W etc) and presence properties (i.e. Mandatory, Optional) for attributes*/
    uint32_t num_properties;    /* number of entries in me_attr_properties array */
    uint32_t set_by_create_mask;  /* Set-by-create attribute mask */
    uint32_t set_mask;            /* Writeable attribute mask */
    uint32_t mandatory_mask;      /* Mandatory attribute mask */
    bcm_omci_me_supported_action_mask   me_supported_action_mask;      /* Set, Get etc whatever is supported for this ME, in a bit mask format */
} bcm_omci_me_protocol_properties;


/**
 * @brief array to define protocol properties for MEs and attributes based on OMCI spec.
 */
extern bcm_omci_me_protocol_properties  me_and_attr_properties_arr[];



/* Return the me attr_properties[]
 * \param[in]   _me_class_val    ME class value
 */
#define BCM_OMCI_OBJ_ATTR_PROPERTIES_GET(_me_obj_type) (me_and_attr_properties_arr[(_me_obj_type)].me_attr_properties)

/* Return the me attr name
 * \param[in]   _me_class_val    ME class value
 * \param[in]   _me_attr         ME attribute id
 */
#define BCM_OMCI_OBJ_ATTR_NAME_GET(_me_obj_type, _me_attr) (me_and_attr_properties_arr[(_me_obj_type)].me_attr_properties[_me_attr].attr_name)


/* Return the me_me_supported_action_mask from me_and_attr_properties_arr.
 * \param[in]   _me_class_val    ME class value
 */
#define BCM_OMCI_PROTOCOL_ME_SUPPORTED_ACTION_MASK(_me_obj_type) (me_and_attr_properties_arr[(_me_obj_type)].me_supported_action_mask)

/* Return the omci_msg_len from me_and_attr_properties_arr.
 * \param[in]   _me_class_val    ME class value
 */
#define BCM_OMCI_PROTOCOL_OMCI_MSG_LEN_GET(_me_obj_type) (me_and_attr_properties_arr[(_me_obj_type)].omci_msg_len)

/* Return the set_by_create mask
 * \param[in]   _me_class_val    ME class value
 */
#define BCM_OMCI_OBJ_ATTR_SET_BY_CREATE_MASK(_me_obj_type) (me_and_attr_properties_arr[(_me_obj_type)].set_by_create_mask)

/* Return the writeable attribute mask
 * \param[in]   _me_class_val    ME class value
 */
#define BCM_OMCI_OBJ_ATTR_SET_MASK(_me_obj_type) (me_and_attr_properties_arr[(_me_obj_type)].set_mask)

/* Return the mandatory attribute mask
 * \param[in]   _me_class_val    ME class value
 */
#define BCM_OMCI_OBJ_ATTR_MANDATORY_MASK(_me_obj_type) (me_and_attr_properties_arr[(_me_obj_type)].mandatory_mask)

#endif //_OMCI_STACK_PROTOCOL_PROP_H_
