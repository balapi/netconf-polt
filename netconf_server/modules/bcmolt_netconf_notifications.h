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

#ifndef XPON_ONU_PRESENCE_FLAGS_DEFINED
typedef enum
{
    XPON_ONU_PRESENCE_FLAG_NONE                      = 0,
    XPON_ONU_PRESENCE_FLAG_V_ANI                     = 0x01,
    XPON_ONU_PRESENCE_FLAG_ONU                       = 0x02,
    XPON_ONU_PRESENCE_FLAG_ONU_IN_O5                 = 0x04,
    XPON_ONU_PRESENCE_FLAG_ONU_ACTIVATION_FAILED     = 0x08,
    XPON_ONU_PRESENCE_FLAG_UNCLAIMED                 = 0x10,
} xpon_onu_presence_flags;
#define XPON_ONU_PRESENCE_FLAGS_DEFINED
#endif

typedef enum
{
    XPON_ONU_MANAGEMENT_STATE_UNSET                  = 0,
    XPON_ONU_MANAGEMENT_STATE_RELYING_ON_VOMCI,
    XPON_ONU_MANAGEMENT_STATE_EOMCI_BEING_USED,
    XPON_ONU_MANAGEMENT_STATE_VANI_MANAGEMENT_MODE_MISMATCH,
    XPON_ONU_MANAGEMENT_STATE_EOMCI_EXPECTED_BUT_MISSING_ONU_CONFIGURATION,
    XPON_ONU_MANAGEMENT_STATE_UDETERMINED
} xpon_onu_management_state;

typedef struct xpon_v_ani_state_info
{
    const char *cterm_name;
    uint16_t onu_id;
    const uint8_t *serial_number;
    const uint8_t *registration_id;
    xpon_onu_presence_flags presence_flags;
    xpon_onu_management_state management_state;
    const uint8_t *loid;
} xpon_v_ani_state_info;

/* onu-authentication-report action outcome */
typedef enum
{
    XPON_ONU_AUTH_ACTION_STATUS_OK,
    XPON_ONU_AUTH_ACTION_STATUS_MANAGEMENT_MODE_MISMATCH_WITH_V_ANI,
    XPON_ONU_AUTH_ACTION_STATUS_NAME_MISMATCH_WITH_V_ANI,
    XPON_ONU_AUTH_ACTION_STATUS_UNDETERMINED_ERROR,

    XPON_ONU_AUTH_ACTION_STATUS__NUM_OF,
} xpon_onu_auth_action_status;

/* change onu state change event
   serial_number is in 8 byte binary format.
*/
bcmos_errno bcmolt_xpon_v_ani_state_change(const xpon_v_ani_state_info *state_info);

#endif
