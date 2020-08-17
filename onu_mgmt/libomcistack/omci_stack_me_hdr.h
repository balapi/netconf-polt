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

#ifndef _OMCI_STACK_ME_HDR_H_
#define _OMCI_STACK_ME_HDR_H_

/**
 * @file omci_stack_base_types.h
 * @brief This is manual code to define the basic types for the broadcom omci stack.
 *  This could be used by both the ME layer and the transport layer of the omci stack.
 *  @note This file is similar to bal_obj.h
 */

#include "bcmos_system.h"
#include "bcm_dev_log.h"
#include "omci_stack_model_ids.h"
#include "omci_stack_protocol_prop.h"

/************************************************************************************
  The following typedefs MUST match types with the same names generated from OLT OM.
  The only reason the typedefs are duplicated here is to decouple from OLT OM to
  allow independent OMCI release.
************************************************************************************/
typedef uint16_t bcmolt_oltid;
typedef uint8_t bcmolt_interface;
typedef uint16_t bcmolt_onu_id;
/************************************************************************************/

typedef uint64_t bcm_omci_presence_mask;

/** Presence mask indicating all fields present */
#define BCM_OMCI_PRESENCE_MASK_ALL ((bcm_omci_presence_mask)0xFFFFFFFFFFFFFFFF)

/**
 * OMCI msg direction for the ME object - Request or Response.
 *
 * @note Request or Response does not necessarily fix the direction i.e. olt->onu or onu->olt.
*/
typedef enum bcm_omci_obj_msg_dir {
    BCM_OMCI_OBJ_MSG_DIR_REQUEST,
    BCM_OMCI_OBJ_MSG_DIR_RESPONSE
} bcm_omci_msg_dir;

/** externs */
extern dev_log_id log_id_bcm_omci_stack_me_layer;

/* ME header */
typedef struct bcm_omci_me_hdr bcm_omci_me_hdr;

/**
 * @brief  Free me_hdr block
 */
typedef void (*bcm_omci_me_free_cb)(bcm_omci_me_hdr *me_hdr);

/**
 * @brief Every ME should have an ME key by which to identify a specific ME instance.
 * @note This is used in bcm_omci_me_tcont etc.  ME object structures.
 * @note logical_pon is the logical pon interface (from the SDN side of bal)
 * */
typedef struct
{
    bcmolt_oltid            olt_id;         /**< OLT id */
    bcmolt_interface        logical_pon;    /**< Logical PON interface id on the OLT */
    bcmolt_onu_id           onu_id;         /**< ONU id */
    bcm_omci_me_class_val   entity_class;   /**< Entity class (as per G.988) */
    uint16_t                entity_instance;/**< Entity instance */
    long                    cookie;         /**< Caller's cookie. Returned to the caller in response to
                                                 simplify request-response transaction identification */
} bcm_omci_me_key;

/**
 * @brief Every ME should inherit from this base class.
 * @note This is used in bcm_omci_me_tcont etc.  ME object structures.
 * */
struct bcm_omci_me_hdr
{
    bcm_omci_me_key             key;            /**< OMCI message key */
    bcm_omci_msg_dir            dir;            /**< Direction - request / response */
    bcm_omci_msg_format		    omci_format;    /**< OMCI message format : Baseline or Extended */
    bcm_omci_msg_type           omci_msg_type;  /**< omci msg type Create/Set/Get/Delete etc from Table 11.2.2-1 in G.988 */
    bcm_omci_obj_id             obj_type;       /**< An enumerated ID associated with the object being specified. This is ME Id from the model */
    bcm_omci_presence_mask      presence_mask;  /**< Mask identifying attributes present in OMCI message (request or response) */
    bcmos_errno                 status;         /**< Transaction status code (BCM_ERR_OK, or other error code).
                                                     Error status interpretation depends on the 'dir'.
                                                     if dir==REQUEST, status != BCM_ERR_OK indicates transmit error or timeout.
                                                     if dir==RESPONSE, status != BCM_ERR_OK indicates error or malformed response from ONU.
                                                       In this case rsp.result gives the exact status returned by ONU
                                                */

    /** Response info. Only valid if dir==RESPONSE */
    struct
    {
        bcm_omci_presence_mask      unsupp_presence_mask; /* used for Rsp msg, for unsupported attributes, as reported by ONU */
        bcm_omci_presence_mask      failed_presence_mask; /* used for Rsp msg, for failed attributes, as reported by ONU */
        bcm_omci_result             result;               /* Result returned by ONU */
    } rsp;                                      /**< Common response info */

    bcm_omci_me_free_cb me_free;                /** Optional free callback. Must be set if ME was allocated dynamically */
};

/**
 * ME header access macros
 */

/* This internal macro assumes that obj_type is already set in the key */
#define _BCM_OMCI_HDR_INIT(_hdr, _key) \
    do { \
        memset(_hdr, 0, sizeof(*(_hdr)));\
        (_hdr)->key = (_key);\
        (_hdr)->omci_format = BCM_OMCI_MSG_FORMAT_BASE;\
        (_hdr)->dir = BCM_OMCI_OBJ_MSG_DIR_REQUEST;\
        (_hdr)->obj_type = bcm_omci_me_class_val2bcm_omci_obj_id_conv((_key).entity_class);\
    } while (0)

/* Initialize request
 * \param[in]   _hdr    Message header pointer
 * \param[in]   _obj    Object type name (i.e. tcont)
 * \param[in]   _key    ME key
 */
#define BCM_OMCI_HDR_INIT(_hdr, _obj, _key) \
    do { \
        (_key).entity_class = bcm_omci_me_class_val_ ## _obj; \
        _BCM_OMCI_HDR_INIT(_hdr, _key);\
    } while (0)

/* Internal macro: Get a bitmask given a property ID enum */
#define BCM_OMCI_PROP_MASK_GET(_obj, _p) \
    (bcm_omci_ ## _obj ## _cfg_id_ ## _p == bcm_omci_  ## _obj ## _cfg_id_all_properties ? \
        ((1ULL << (uint64_t)bcm_omci_  ## _obj ## _cfg_id_ ## _p) - 1) : \
        (1ULL << (uint64_t)bcm_omci_  ## _obj ## _cfg_id_ ## _p))

/* Internal macro: Indicate that configuration property is present */
#define _BCM_OMCI_PROP_SET_PRESENT(_hdr, _obj, _p) \
    (_hdr)->presence_mask |= BCM_OMCI_PROP_MASK_GET(_obj, _p)

/** Set configuration property in request structure
 * \param[in]   _m      Configuration structure (me_hdr followed by data)
 * \param[in]   _obj    Object type
 * \param[in]   _p      Property name
 * \param[in]   _v      Property value
 */
#define BCM_OMCI_REQ_PROP_SET(_m, _obj, _p, _v) \
   do { \
       _BCM_OMCI_PROP_SET_PRESENT(&((_m)->hdr), _obj, _p);\
       (_m)->data._p = (_v);\
   } while (0)

/** Set presence bit of configuration property in request structure
 * \param[in]   _m      Configuration structure (me_hdr followed by data)
 * \param[in]   _obj    Object type
 * \param[in]   _p      Property name
 */
#define BCM_OMCI_REQ_PROP_SET_PRESENT(_m, _obj, _p) \
    _BCM_OMCI_PROP_SET_PRESENT(&((_m)->hdr), _obj, _p)

/** Set configuration property for array in message structure
 * \param[in]   _m      Configuration structure
 * \param[in]   _obj    Object type
 * \param[in]   _p      Property name
 * \param[in]   _v      Property value
 * \param[in]   _len    Property sizeof
 */
#define BCM_OMCI_REQ_PROP_SET_ARRAY(_m, _obj, _p, _v, _len) \
   do { \
       _BCM_OMCI_PROP_SET_PRESENT(&(_m)->hdr, _obj, _p);\
       memcpy((_m)->data._p, (_v), (_len));\
   } while (0)

/** Indicate that configuration property should be read
 * \param[in]   _m      Configuration structure
 * \param[in]   _obj    Object type
 * \param[in]   _p      Property name
 */
#define BCM_OMCI_REQ_PROP_GET(_m, _obj, _p) \
    _BCM_OMCI_PROP_SET_PRESENT(&((_m)->hdr), _obj, _p)

/** Check if configuration property is set in response
 * \param[in]   _m      Configuration structure (me_hdr followed by data)
 * \param[in]   _obj    Object type
 * \param[in]   _p      Property name
 */
#define BCM_OMCI_RSP_PROP_IS_SET(_m, _obj, _p) \
    (((_m)->hdr.presence_mask & BCM_OMCI_PROP_MASK_GET(_obj, _p)) ? \
        BCMOS_TRUE : BCMOS_FALSE)

/** Check if configuration property assignment failed (returned by ONU)
 * \param[in]   _hdr    ME header
 * \param[in]   _obj    Object type
 * \param[in]   _p      Property name
 */
#define BCM_OMCI_RSP_PROP_IS_FAILED(_hdr, _obj, _p) \
    ((((_hdr)->dir == BCM_OMCI_OBJ_MSG_DIR_RESPONSE) && \
      (((_hdr)->rsp.failed_presence_mask & BCM_OMCI_PROP_MASK_GET(_obj, _p)))) ? \
        BCMOS_TRUE : BCMOS_FALSE)

/** Check if configuration property is not supported (returned by ONU)
 * \param[in]   _hdr    ME header
 * \param[in]   _obj    Object type
 * \param[in]   _p      Property name
 */
#define BCM_OMCI_RSP_PROP_IS_NOT_SUPPORTED(_hdr, _obj, _p) \
    ((((_hdr)->dir == BCM_OMCI_OBJ_MSG_DIR_RESPONSE) && \
      (((_hdr)->rsp.unsupp_presence_mask & BCM_OMCI_PROP_MASK_GET(_obj, _p)))) ? \
        BCMOS_TRUE : BCMOS_FALSE)

/* Set the object omci_format
 * \param[in]   _s      Object structure
 * \param[in]   _p      New object omci_format
 */
#define BCM_OMCI_OBJ_OMCI_FORMAT_SET(_s, _p) ((_s)->hdr.omci_format = _p )

/* Return the object omci_format
 * \param[in]   _s      Object structure
 */
#define BCM_OMCI_OBJ_OMCI_FORMAT_GET(_s) ((_s)->hdr.omci_format)

/* Set the object omci_msg_type
 * \param[in]   _s      Object structure
 * \param[in]   _p      New object omci_msg_type
 */
#define BCM_OMCI_OBJ_OMCI_MSG_TYPE_SET(_s, _p) ((_s)->hdr.omci_msg_type = _p )

/* Return the object omci_msg_type
 * \param[in]   _s      Object structure
 */
#define BCM_OMCI_OBJ_OMCI_MSG_TYPE_GET(_s) ((_s)->hdr.omci_msg_type)

/* Set the object dir
 * \param[in]   _s      Object structure
 * \param[in]   _p      New object dir
 */
#define BCM_OMCI_OBJ_DIR_SET(_s, _p) ((_s)->hdr.dir = _p )

/* Return the object dir
 * \param[in]   _s      Object structure
 */
#define BCM_OMCI_OBJ_DIR_GET(_s) ((_s)->hdr.dir)


/* Set the object status
 * \param[in]   _s      Object structure
 * \param[in]   _p      New object status
 */
#define BCM_OMCI_OBJ_STATUS_SET(_s, _p) ((_s)->hdr.status = _p )

/* Return the object status
 * \param[in]   _s      Object structure
 */
#define BCM_OMCI_OBJ_STATUS_GET(_s) ((_s)->hdr.status)

#endif  /* _OMCI_STACK_ME_HDR_H_ */

