/*
*  <:copyright-BRCM:2018-2020:Apache:standard
*  
*   Copyright (c) 2018-2020 Broadcom. All Rights Reserved
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
*/

#ifndef _OMCI_STACK_ENC_DEC_H_
#define _OMCI_STACK_ENC_DEC_H_

#include <bcmos_system.h>
#include "omci_stack_me_hdr.h"

uint16_t bcm_omci_me_cfg_get_struct_length(bcm_omci_obj_id me_cfg_obj_id);
bcmos_errno bcm_omci_me_cfg_copy_partial(const void *src_me_cfg, void *dst_me_cfg, bcm_omci_obj_id obj_type);
bcmos_errno bcm_omci_me_encode(const bcm_omci_me_hdr *me_hdr, uint8_t **encode_buf, uint32_t *encode_len, bcm_omci_msg_type omci_msg_type);
bcmos_errno bcm_omci_me_decode(bcm_omci_me_hdr *me_hdr, uint8_t *decode_buf, uint32_t decode_len, bcm_omci_msg_type omci_msg_type);
#ifdef ENABLE_LOG
bcmos_errno bcm_omci_me_log(const bcm_omci_me_hdr *me_hdr, dev_log_id log_id, bcm_dev_log_level log_level);
#endif

#endif
