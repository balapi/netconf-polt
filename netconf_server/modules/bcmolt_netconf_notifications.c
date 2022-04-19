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
 * bcmolt_netconf_notifications.c
 */

#define _GNU_SOURCE
#include <bcmos_system.h>
#include <sysrepo.h>
#include <libyang/libyang.h>
#include <sysrepo/values.h>
#include <bcmolt_netconf_module_utils.h>
#include <bcmolt_netconf_notifications.h>

extern bcmos_bool xpon_cterm_is_onu_state_notifiable(const char *cterm_name, const char *state);

/* change onu state change event
   serial_number_string is 4 ASCII characters vendor id followed by 8 hex numbers
   representing 4-byte vendor-specific id
*/
bcmos_errno bcmolt_xpon_v_ani_state_change(const xpon_v_ani_state_info *state_info)
{
    sr_session_ctx_t *session = bcm_netconf_session_get();
    const struct ly_ctx *ctx = sr_get_context(sr_session_get_connection(session));
    struct lyd_node *notif = NULL;
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char date_time_string[64];
    char serial_number_string[13];
    const char *presence_state;
    char notif_xpath[200];
    bcmos_errno err = BCM_ERR_INTERNAL;

    /* Don't send notification if ONU was discovered, but not yet activated and v-ani is present.
       In this case NETCONF server will attempt to activate the ONU, so this discovery state is transitional.
    */
    if (state_info->presence_flags == (XPON_ONU_PRESENCE_FLAG_V_ANI | XPON_ONU_PRESENCE_FLAG_ONU) &&
        (state_info->onu_id != XPON_ONU_ID_UNDEFINED))
    {
        NC_LOG_INFO("Transient discovery state for ONU %s:%u. NOT sending a state-change notification\n",
            state_info->cterm_name, state_info->onu_id);
        return BCM_ERR_OK;
    }

    do
    {
#ifdef TR385_ISSUE2
        if ((state_info->presence_flags & XPON_ONU_PRESENCE_FLAG_ONU) != 0)
        {
            if ((state_info->presence_flags & XPON_ONU_PRESENCE_FLAG_V_ANI) != 0)
            {
                presence_state = ((state_info->presence_flags & XPON_ONU_PRESENCE_FLAG_ONU_IN_O5) != 0) ?
                    "bbf-xpon-onu-types:onu-present-and-on-intended-channel-termination" :
                    ((state_info->onu_id != XPON_ONU_ID_UNDEFINED) ?
                       "bbf-xpon-onu-types:onu-present-and-v-ani-known-and-o5-failed" :
                       "bbf-xpon-onu-types:onu-present-and-v-ani-known-and-o5-failed-no-onu-id");

            }
            else
            {
                if ((state_info->presence_flags & XPON_ONU_PRESENCE_FLAG_ONU_ACTIVATION_FAILED) != 0)
                    presence_state = "bbf-xpon-onu-types:onu-present-and-no-v-ani-known-and-o5-failed-undefined";
                else if ((state_info->presence_flags & XPON_ONU_PRESENCE_FLAG_ONU_IN_O5) != 0)
                    presence_state = "bbf-xpon-onu-types:onu-present-and-no-v-ani-known-and-in-o5";
                else if ((state_info->presence_flags & XPON_ONU_PRESENCE_FLAG_UNCLAIMED) != 0)
                    presence_state = "bbf-xpon-onu-types:onu-present-and-no-v-ani-known-and-unclaimed";
                else
                    presence_state = "bbf-xpon-onu-types:onu-present-and-no-v-ani-known-and-o5-failed-no-onu-id";
            }
        }
        else
        {
            presence_state = ((state_info->presence_flags & XPON_ONU_PRESENCE_FLAG_V_ANI) != 0) ?
                "bbf-xpon-onu-types:onu-not-present-with-v-ani" :
                    "bbf-xpon-onu-types:onu-not-present-without-v-ani";
        }

        /* Check if the new state has to be notified */
        if (!xpon_cterm_is_onu_state_notifiable(state_info->cterm_name, presence_state))
        {
            NC_LOG_INFO("cterm %s  onu_id %u: skipping state transition report into presence state %s\n",
                state_info->cterm_name, state_info->onu_id, presence_state);
            return BCM_ERR_OK;
        }

        snprintf(notif_xpath, sizeof(notif_xpath),
            "/ietf-interfaces:interfaces-state/interface[name='%s']/"
            "bbf-xpon:channel-termination/bbf-xpon-onu-state:onu-presence-state-change", state_info->cterm_name);
        notif = nc_ly_sub_value_add(ctx, NULL, notif_xpath, NULL, NULL);
        if (notif == NULL)
            break;

        snprintf(serial_number_string, sizeof(serial_number_string),
            "%c%c%c%c%02X%02X%02X%02X",
            state_info->serial_number[0], state_info->serial_number[1],
            state_info->serial_number[2], state_info->serial_number[3],
            state_info->serial_number[4], state_info->serial_number[5],
            state_info->serial_number[6], state_info->serial_number[7]);
        if (nc_ly_sub_value_add(NULL, notif, notif_xpath, "detected-serial-number", serial_number_string) == NULL)
        {
            break;
        }

        snprintf(date_time_string, sizeof(date_time_string),
            "%.4d-%.2d-%.2dT%.2d:%.2d:%.2dZ",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
        if (nc_ly_sub_value_add(NULL, notif, notif_xpath, "last-change", date_time_string) == NULL)
        {
            break;
        }

        if (nc_ly_sub_value_add(NULL, notif, notif_xpath, "onu-presence-state", presence_state) == NULL)
        {
            break;
        }

        if (state_info->onu_id != XPON_ONU_ID_UNDEFINED)
        {
            char onu_id_str[16];
            snprintf(onu_id_str, sizeof(onu_id_str), "%u", state_info->onu_id);
            if (nc_ly_sub_value_add(NULL, notif, notif_xpath, "onu-id", onu_id_str) == NULL)
            {
                break;
            }
        }

        if (state_info->registration_id != NULL)
        {
            char registration_id_string[73];
            nc_bin_to_hex(state_info->registration_id, 36, registration_id_string);
            if (nc_ly_sub_value_add(NULL, notif, notif_xpath, "detected-registration-id", registration_id_string) == NULL)
            {
                break;
            }
        }

        if (state_info->management_state != XPON_ONU_MANAGEMENT_STATE_UNSET)
        {
            const char *management_state_string = NULL;
            switch(state_info->management_state)
            {
            case XPON_ONU_MANAGEMENT_STATE_RELYING_ON_VOMCI:
                management_state_string = "bbf-obbaa-xpon-onu-types:relying-on-vomci";
                break;
            case XPON_ONU_MANAGEMENT_STATE_EOMCI_BEING_USED:
                management_state_string = "bbf-obbaa-xpon-onu-types:eomci-being-used";
                break;
            case XPON_ONU_MANAGEMENT_STATE_VANI_MANAGEMENT_MODE_MISMATCH:
                management_state_string = "bbf-obbaa-xpon-onu-types:vani-management-mode-mismatch-with-requested-mode";
                break;
            case XPON_ONU_MANAGEMENT_STATE_EOMCI_EXPECTED_BUT_MISSING_ONU_CONFIGURATION:
                management_state_string = "bbf-obbaa-xpon-onu-types:eomci-expected-but-missing-onu-configuration";
                break;
            case XPON_ONU_MANAGEMENT_STATE_UDETERMINED:
                management_state_string = "bbf-obbaa-xpon-onu-types:undetermined";
                break;
            default:
                break;
            }
            if (management_state_string != NULL &&
                (nc_ly_sub_value_add(NULL, notif, notif_xpath,
                    "bbf-obbaa-xpon-onu-authentication:determined-onu-management-mode",
                    management_state_string) == NULL))
            {
                break;
            }
        }

        if (state_info->loid != NULL &&
            (nc_ly_sub_value_add(NULL, notif, notif_xpath,
                "bbf-obbaa-xpon-onu-authentication:detected-loid",
                (const char *)state_info->loid) == NULL))
        {
            break;
        }

#else /* #ifdef TR385_ISSUE2 */
    /* TR-385 issue 1 */
#define BBF_XPON_ONU_STATES_MODULE_NAME             "bbf-xpon-onu-states"
        strncpy(notif_xpath, "/" BBF_XPON_ONU_STATES_MODULE_NAME ":onu-state-change", sizeof(notif_xpath));
        notif = nc_ly_sub_value_add(ctx, NULL, notif_xpath, NULL, NULL);
        if (notif == NULL)
            break;

        snprintf(serial_number_string, sizeof(serial_number_string),
            "%c%c%c%c%02X%02X%02X%02X",
            state_info->serial_number[0], state_info->serial_number[1],
            state_info->serial_number[2], state_info->serial_number[3],
            state_info->serial_number[4], state_info->serial_number[5],
            state_info->serial_number[6], state_info->serial_number[7]);
        if (nc_ly_sub_value_add(NULL, notif, notif_xpath, "detected-serial-number", serial_number_string) == NULL)
        {
            break;
        }

        snprintf(date_time_string, sizeof(date_time_string),
            "%.4d-%.2d-%.2dT%.2d:%.2d:%.2dZ",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
        if (nc_ly_sub_value_add(NULL, notif, notif_xpath, "onu-state-last-change", date_time_string) == NULL)
        {
            break;
        }

        if ((state_info->presence_flags & XPON_ONU_PRESENCE_FLAG_ONU) != 0)
        {
            presence_state = ((state_info->presence_flags & XPON_ONU_PRESENCE_FLAG_V_ANI) != 0) ?
                "bbf-xpon-onu-types:onu-present-and-on-intended-channel-termination" :
                "bbf-xpon-onu-types:onu-present-and-unexpected";
        }
        else
        {
            presence_state = ((state_info->presence_flags & XPON_ONU_PRESENCE_FLAG_V_ANI) != 0) ?
                "bbf-xpon-onu-types:onu-not-present-with-v-ani" :
                "bbf-xpon-onu-types:onu-not-present-without-v-ani";
        }
        if (nc_ly_sub_value_add(NULL, notif, notif_xpath, "onu-state", (void *)(long)presence_state) == NULL)
        {
            break;
        }

        if (state_info->onu_id != XPON_ONU_ID_UNDEFINED)
        {
            char onu_id_str[16];
            snprintf(onu_id_str, sizeof(onu_id_str), "%u", state_info->onu_id);
            if (nc_ly_sub_value_add(NULL, notif, notif_xpath, "onu-id", onu_id_str) == NULL)
            {
                break;
            }
        }

        if (state_info->registration_id != NULL)
        {
            char registration_id_string[73];
            nc_bin_to_hex(state_info->registration_id, 36, registration_id_string);
            if (nc_ly_sub_value_add(NULL, notif, notif_xpath, "detected-registration-id", registration_id_string) == NULL)
            {
                break;
            }
        }

        if (state_info->cterm_name != NULL)
        {
            if (nc_ly_sub_value_add(NULL, notif, notif_xpath, "channel-termination-ref", (void *)(long)state_info->cterm_name) == NULL)
            {
                break;
            }
        }

#endif /* #ifdef TR385_ISSUE2 */

        if (nc_sr_event_notif_send(session, notif, notif_xpath) != BCM_ERR_OK)
            break;

        NC_LOG_INFO("Sent '%s' notification for ONU %s on %s\n", presence_state, serial_number_string, state_info->cterm_name);
        err = BCM_ERR_OK;

    } while (0);

    nc_sr_event_notif_free(notif);

    return err;
}
