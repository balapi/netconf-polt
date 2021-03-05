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

#ifndef _OMCI_STACK_ME_TL_INTF_H_
#define _OMCI_STACK_ME_TL_INTF_H_

#include <bcmos_system.h>
#include <bcmos_errno.h>
#include "omci_stack_me_hdr.h"
#include "transport/omci_transport.h"

/**
 * @file omci_stack_me_tl_intf.h
 *
 * @brief interface file between ME layer and Transport layer
 */


/** @brief number of bytes in header of OMCI msg */
#define BCM_OMCI_MSG_NUM_HDR_BYTES 8

/** @brief macros to operate on the me context in Transport layer pon_db */
#define BCM_OMCI_TL_ONU_DB_ME_CONTEXT_SET(_olt, _pon, _onu_id, _context) \
    do { \
        omci_transport_onu_rec *_onu_rec  = omci_db_onu_get(_olt, _pon, _onu_id);\
        if (_onu_rec != NULL) \
            _onu_rec->me_layer_context = (void*)(_context);\
        else \
            bcmos_free(_context); \
    } while (0)

#define BCM_OMCI_TL_ONU_DB_ME_CONTEXT_GET(_olt, _pon, _onu_id) \
    ({ \
        omci_transport_onu_rec *_onu_rec  = omci_db_onu_get(_olt, _pon, _onu_id);\
        void *_context = _onu_rec ? _onu_rec->me_layer_context : NULL;\
        _context;\
    })

#define BCM_OMCI_TL_ONU_DB_ME_CONTEXT_INIT(_olt, _pon, _onu_id) \
    do { \
        omci_transport_onu_rec *_onu_rec  = omci_db_onu_get(_olt, _pon, _onu_id);\
        if (_onu_rec != NULL) \
            _onu_rec->me_layer_context = NULL;\
    } while (0)

#define BCM_OMCI_TL_ONU_DB_ME_CONTEXT_CLEAR(_olt, _pon, _onu_id) \
        do \
        { \
            omci_transport_onu_rec *_onu_rec  = omci_db_onu_get(_olt, _pon, _onu_id);\
            if (_onu_rec != NULL && _onu_rec->me_layer_context != NULL) \
            { \
                bcmos_free(_onu_rec->me_layer_context); \
                _onu_rec->me_layer_context = NULL; \
            } \
        } while (0);

/**
 * bufer alloc to be done by transport layer.
 */
static inline bcmos_errno bcm_omci_tl_buf_alloc(uint8_t **buf, uint16_t *len, int omci_msg_format)
{
    bcmos_errno rc = BCM_ERR_OK;

    rc = omci_transport_buf_alloc (buf, len, omci_msg_format);

    return rc;
}

/**
 * @note used only for unit testing of stack as standalone
 */
static inline bcmos_errno bcm_omci_tl_buf_free (uint8_t *buf)
{
    bcmos_free (buf - BCM_OMCI_MSG_NUM_HDR_BYTES);

    return BCM_ERR_OK;
}


/**
 * @brief wrapper function for interface to omci to send out a msg
 */
static inline bcmos_errno bcm_omci_tl_send_msg( bcm_omci_me_hdr *me_hdr, uint8_t *msg_content, uint16_t msg_content_len)
{
    bcmos_errno rc = BCM_ERR_OK;
    rc = omci_transport_send_msg(me_hdr, msg_content, msg_content_len, BCMOS_TRUE);

    return rc;
}


/**
 * @brief wrapper function for interface to omci to send out a msg for operations e.g. MIB Reset, MIB Upload etc
 */
static inline bcmos_errno bcm_omci_tl_send_msg_operation( bcm_omci_me_hdr *me_hdr)
{
    bcmos_errno rc = BCM_ERR_OK;
    rc = omci_transport_send_msg_operation(me_hdr);

    return rc;
}


#endif //_OMCI_STACK_ME_TL_INTF_H_
