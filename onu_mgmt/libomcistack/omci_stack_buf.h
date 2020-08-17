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
 
#ifndef _OMCI_STACK_BUF_H_
#define _OMCI_STACK_BUF_H_

#include <bcmolt_buf.h>

/** 
 * @file omci_stack_buf.h
 *
 * fields read & write, to be used for encoding /decoding of the OMCI messages.
 * @note  the bcmolt versions of these read/write take care of endianness also.
 */
typedef bcmolt_buf bcm_omci_buf;

#define bcm_omci_buf_alloc(buf, size)        bcmolt_buf_alloc(buf, size, BCMOLT_BUF_ENDIAN_FIXED)
#define bcm_omci_buf_free                    bcmolt_buf_free
#define bcm_omci_buf_init(buf, size, start)  bcmolt_buf_init(buf, size, start)
#define bcm_omci_buf_skip                    bcmolt_buf_skip
#define bcm_omci_buf_set_pos                 bcmolt_buf_set_pos
#define bcm_omci_buf_get_used                bcmolt_buf_get_used
#define bcm_omci_buf_get_remaining_size      bcmolt_buf_get_remaining_size
#define bcm_omci_buf_write                   bcmolt_buf_write
#define bcm_omci_buf_read                    bcmolt_buf_read
#define bcm_omci_buf_rewind                  bcmolt_buf_rewind
#define bcm_omci_buf_write_u8                bcmolt_buf_write_u8
#define bcm_omci_buf_read_u8                 bcmolt_buf_read_u8
#define bcm_omci_buf_write_u16               bcmolt_buf_write_u16
#define bcm_omci_buf_read_u16                bcmolt_buf_read_u16
#define bcm_omci_buf_write_s16               bcmolt_buf_write_s16
#define bcm_omci_buf_read_s16                bcmolt_buf_read_s16
#define bcm_omci_buf_write_u24               bcmolt_buf_write_u24
#define bcm_omci_buf_read_u24                bcmolt_buf_read_u24
#define bcm_omci_buf_write_u32               bcmolt_buf_write_u32
#define bcm_omci_buf_read_u32                bcmolt_buf_read_u32
#define bcm_omci_buf_write_s32               bcmolt_buf_write_s32
#define bcm_omci_buf_read_s32                bcmolt_buf_read_s32
#define bcm_omci_buf_write_u64               bcmolt_buf_write_u64
#define bcm_omci_buf_read_u64                bcmolt_buf_read_u64
#define bcm_omci_buf_write_bool              bcmolt_buf_write_bool
#define bcm_omci_buf_read_bool               bcmolt_buf_read_bool
#define bcm_omci_buf_write_mac_address       bcmolt_buf_write_mac_address
#define bcm_omci_buf_read_mac_address        bcmolt_buf_read_mac_address
#define bcm_omci_buf_write_ipv4_address      bcmolt_buf_write_ipv4_address
#define bcm_omci_buf_read_ipv4_address       bcmolt_buf_read_ipv4_address
#define bcm_omci_buf_write_ipv6_address      bcmolt_buf_write_ipv6_address
#define bcm_omci_buf_read_ipv6_address       bcmolt_buf_read_ipv6_address
#define bcm_omci_buf_write_vlan_tag          bcmolt_buf_write_vlan_tag
#define bcm_omci_buf_read_vlan_tag           bcmolt_buf_read_vlan_tag





#endif //_OMCI_STACK_BUF_H_
