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
bcmos_errno bcmolt_xpon_v_ani_state_change(const char *cterm_name, uint16_t onu_id,
    const uint8_t *serial_number, xpon_onu_presence_flags presence_flags)
{
#ifdef TR385_ISSUE2
    sr_session_ctx_t *session = bcm_netconf_session_get();
    const struct ly_ctx *ctx = sr_get_context(sr_session_get_connection(session));
    struct lyd_node *notif = NULL;
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char date_time_string[64];
    char serial_number_string[13];
    const char *presence_state;
    char notif_xpath[200];
    int sr_rc = SR_ERR_INVAL_ARG;

    /* Don't send notification if ONU was discovered, but not yet activated and v-ani is present.
       In this case NETCONF server will attempt to activate the ONU, so this discovery state is transitional.
    */
    if (presence_flags == (XPON_ONU_PRESENCE_FLAG_V_ANI | XPON_ONU_PRESENCE_FLAG_ONU) &&
        (onu_id != XPON_ONU_ID_UNDEFINED))
    {
        NC_LOG_INFO("Transient discovery state for ONU %s:%u. NOT sending a state-change notification\n",
            cterm_name, onu_id);
        return BCM_ERR_OK;
    }

    do
    {
        if ((presence_flags & XPON_ONU_PRESENCE_FLAG_ONU) != 0)
        {
            if ((presence_flags & XPON_ONU_PRESENCE_FLAG_V_ANI) != 0)
            {
                presence_state = ((presence_flags & XPON_ONU_PRESENCE_FLAG_ONU_IN_O5) != 0) ?
                    "bbf-xpon-onu-types:onu-present-and-on-intended-channel-termination" :
                    ((onu_id != XPON_ONU_ID_UNDEFINED) ?
                       "bbf-xpon-onu-types:onu-present-and-v-ani-known-and-o5-failed" :
                       "bbf-xpon-onu-types:onu-present-and-v-ani-known-and-o5-failed-no-onu-id");

            }
            else
            {
                presence_state = ((presence_flags & XPON_ONU_PRESENCE_FLAG_ONU_ACTIVATION_FAILED) != 0) ?
                    "bbf-xpon-onu-types:onu-present-and-no-v-ani-known-and-o5-failed-undefined" :
                    "bbf-xpon-onu-types:onu-present-and-no-v-ani-known-and-o5-failed-no-onu-id";
            }
        }
        else
        {
            presence_state = ((presence_flags & XPON_ONU_PRESENCE_FLAG_V_ANI) != 0) ?
                "bbf-xpon-onu-types:onu-not-present-with-v-ani" :
                    "bbf-xpon-onu-types:onu-not-present-without-v-ani";
        }

        /* Check if the new state has to be notified */
        if (!xpon_cterm_is_onu_state_notifiable(cterm_name, presence_state))
        {
            NC_LOG_INFO("cterm %s  onu_id %u: skipping state transition report into presence state %s\n",
                cterm_name, onu_id, presence_state);
            return BCM_ERR_OK;
        }

        snprintf(notif_xpath, sizeof(notif_xpath),
            "/ietf-interfaces:interfaces-state/interface[name='%s']/"
            "bbf-xpon:channel-termination/bbf-xpon-onu-state:onu-presence-state-change", cterm_name);
        notif = lyd_new_path(NULL, ctx, notif_xpath, NULL, 0, 0);
        if (notif == NULL)
        {
            NC_LOG_ERR("Failed to create notification %s.\n", notif_xpath);
            break;
        }

        snprintf(serial_number_string, sizeof(serial_number_string),
            "%c%c%c%c%02X%02X%02X%02X",
            serial_number[0], serial_number[1], serial_number[2], serial_number[3],
            serial_number[4], serial_number[5], serial_number[6], serial_number[7]);
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

        if (nc_ly_sub_value_add(NULL, notif, notif_xpath, "onu-presence-state", (void *)(long)presence_state) == NULL)
        {
            break;
        }

        if (onu_id != XPON_ONU_ID_UNDEFINED)
        {
            char onu_id_str[16];
            snprintf(onu_id_str, sizeof(onu_id_str), "%u", onu_id);
            if (nc_ly_sub_value_add(NULL, notif, notif_xpath, "onu-id", onu_id_str) == NULL)
            {
                break;
            }
        }

        sr_rc = sr_event_notif_send_tree(session, notif);
        if (sr_rc != SR_ERR_OK)
        {
            NC_LOG_ERR("Failed to sent %s notification. Error '%s'\n",
                notif_xpath, sr_strerror(sr_rc));
            break;
        }

        NC_LOG_INFO("Sent '%s' notification for ONU %s on %s\n", presence_state, serial_number_string, cterm_name);

    } while (0);
#else /* #ifdef TR385_ISSUE2 */
    /* TR-385 issue 1 */
#define BBF_XPON_ONU_STATES_MODULE_NAME             "bbf-xpon-onu-states"
    sr_val_t values[5] = {};
    uint32_t num_values;
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char date_time_string[64];
    char serial_number_string[13];
    char *presence_state;
    int sr_rc;

    snprintf(serial_number_string, sizeof(serial_number_string),
        "%c%c%c%c%02X%02X%02X%02X",
        serial_number[0], serial_number[1], serial_number[2], serial_number[3],
        serial_number[4], serial_number[5], serial_number[6], serial_number[7]);

    values[0].xpath = "/" BBF_XPON_ONU_STATES_MODULE_NAME ":onu-state-change/detected-serial-number";
    values[0].type = SR_STRING_T;
    values[0].data.string_val = serial_number_string;

    snprintf(date_time_string, sizeof(date_time_string),
        "%.4d-%.2d-%.2dT%.2d:%.2d:%.2dZ",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    values[1].xpath = "/" BBF_XPON_ONU_STATES_MODULE_NAME ":onu-state-change/onu-state-last-change";
    values[1].type = SR_STRING_T;
    values[1].data.string_val = date_time_string;

    values[2].xpath = "/" BBF_XPON_ONU_STATES_MODULE_NAME ":onu-state-change/onu-state";
    values[2].type = SR_IDENTITYREF_T;

    if ((presence_flags & XPON_ONU_PRESENCE_FLAG_ONU) != 0)
    {
        presence_state = ((presence_flags & XPON_ONU_PRESENCE_FLAG_V_ANI) != 0) ?
            "bbf-xpon-onu-types:onu-present-and-on-intended-channel-termination" :
            "bbf-xpon-onu-types:onu-present-and-unexpected";
    }
    else
    {
        presence_state = ((presence_flags & XPON_ONU_PRESENCE_FLAG_V_ANI) != 0) ?
            "bbf-xpon-onu-types:onu-not-present-with-v-ani" :
            "bbf-xpon-onu-types:onu-not-present-without-v-ani";
    }
    values[2].data.string_val = presence_state;

    num_values = 3;
    if (onu_id != XPON_ONU_ID_UNDEFINED)
    {
        values[3].xpath = "/" BBF_XPON_ONU_STATES_MODULE_NAME ":onu-state-change/onu-id";
        values[3].type = SR_UINT32_T;
        values[3].data.uint32_val = onu_id;
        ++num_values;
    }
    if (cterm_name != NULL)
    {
        values[num_values].xpath = "/" BBF_XPON_ONU_STATES_MODULE_NAME ":onu-state-change/channel-termination-ref";
        values[num_values].type = SR_STRING_T;
        values[num_values].data.string_val = (char *)(long)cterm_name;
        ++num_values;
    }

    sr_rc = sr_event_notif_send(bcm_netconf_session_get(), "/" BBF_XPON_ONU_STATES_MODULE_NAME ":onu-state-change",
            values, num_values);
    if (sr_rc == SR_ERR_OK)
    {
        NC_LOG_INFO("Sent '%s' notification for ONU %s on %s\n", presence_state, serial_number_string, cterm_name);
    }
    else
    {
        NC_LOG_DBG("Failed to sent state change notification for ONU %s on %s. Error '%s'\n",
            serial_number_string, cterm_name, sr_strerror(sr_rc));
    }

#endif

    return (sr_rc == SR_ERR_OK) ? BCM_ERR_OK : BCM_ERR_INTERNAL;
}
