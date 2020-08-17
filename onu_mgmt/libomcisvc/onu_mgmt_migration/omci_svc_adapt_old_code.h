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

#ifndef _OMCI_SVC_ADAPT_OLD_CODE_H_
#define _OMCI_SVC_ADAPT_OLD_CODE_H_

/**
 * @file omci_svc_adapt_old_code.h
 * @brief Function declarations and all inclusions required for the OMCI Service Layer
 *
 * @defgroup api OMCI Service Layer
 */

#include <bcmolt_api.h>
#include <onu_mgmt_model_types.h>


/************************************************************************************
  Extra adaptations needed to build onu mgmt in Aspen tree, using the old generated code.
************************************************************************************/
typedef uint16_t bcmolt_pon_onu_id;


#define GPON_NUM_OF_ONUS 128
#define XGPON_NUM_OF_ONUS 256

/** Variable-length list of U8. 
    @note this is not defined any more in Aspen tree.
     */
typedef struct bcmolt_u8_list_u16_hex
{
    uint16_t len;   /**< List length. */
    uint8_t *val;   /**< List contents. */
} bcmolt_u8_list_u16_hex;

/** Variable-length list of U8. 
    @note this is not defined any more in Aspen tree.
     */
typedef struct bcmolt_u8_list_u32_max_2048
{
    uint32_t len;   /**< List length. */
    uint8_t *val;   /**< List contents. */
} bcmolt_u8_list_u32_max_2048;


#endif
