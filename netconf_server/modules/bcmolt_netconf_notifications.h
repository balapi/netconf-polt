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

/*
 * bcmolt_netconf_notifications.h
 */

#ifndef BCMOLT_NETCONF_NOTIFICATIONS_H_
#define BCMOLT_NETCONF_NOTIFICATIONS_H_

#include <bcmos_system.h>

#define XPON_ONU_ID_UNDEFINED    0xffff


/* change onu state change event
   serial_number is in 8 byte binary format.
*/
bcmos_errno bcmolt_xpon_v_ani_state_change(const char *cterm_name, uint16_t onu_id,
    const uint8_t *serial_number, bcmos_bool is_present, bcmos_bool is_active);

#endif
