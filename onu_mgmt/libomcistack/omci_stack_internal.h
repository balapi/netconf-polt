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

#ifndef _OMCI_STACK_INTERNAL_H_
#define _OMCI_STACK_INTERNAL_H_

#include "omci_stack_model_types.h"

extern bcm_omci_stack_init_parms omci_init_parms;

/*
 * Internal OMCI stack functions
 */

/**
 * Functions called by OMCI transport layer to finish decoding of received OMCI message
 * and deliver response/auto indication to the registered callback
 */

/**
 * @brief Function called by transport layer on response from ONU
 *
 * @param[in]       me_hdr      ME header. At this point only header has been decoded
 * @param[in]       decode_buf  buffer with raw octet stream for message content
 * @param[in]       decode_len  length of message content
 *
 */
void bcm_omci_rsp(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len);

/**
 * @brief Function to be called by transport layer to notify autonomous message
 *
 * @param[in]       me_hdr      ME header. At this point only header has been decoded
 * @param[in]       decode_buf  buffer with raw octet stream for message content
 * @param[in]       decode_len  length of message content
 */
void bcm_omci_auto(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len);

/**
 * @brief Function to be called by transport layer to timeout or transmit error
 * @param[in]       me_hdr      ME header. At this point only header has been decoded
 * @param[in]       err         Error code
 */
void bcm_omci_req_error(bcm_omci_me_hdr *me_hdr, bcmos_errno err);

/**
 * @brief Function that frees dynamically allocated me_hdr
 * @param[in]       me_hdr      ME header
 */
void bcm_omci_dyn_me_free_cb(bcm_omci_me_hdr *me_hdr);

/** @brief util function to dump raw buffer in 16 hex bytes per line format */
void bcm_omci_stack_util_dump_raw_buf(const bcm_omci_me_key *me_key, const uint8_t *buf, uint32_t buf_len,
    dev_log_id log_id);

#endif /* #ifndef _OMCI_STACK_INTERNAL_H_ */