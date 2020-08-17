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
#ifndef DHCP_RELAY_UTILS__H
#define DHCP_RELAY_UTILS__H

#include <bcmos_system.h>
#include <dhcp.h>
#include <bbf-types.h>

typedef enum
{
    DHCP_RELAY_RESULT_FORWARD_UNCHANGED,
    DHCP_RELAY_RESULT_FORWARD_MODIFIED,
    DHCP_RELAY_RESULT_DISCARD,
} dhcp_relay_result;

#define DHCP_RELAY_OPT82_MAX_ID_LENGTH      63

/* DHCP relay interface */
typedef struct dhcp_relay_interface dhcp_relay_interface;

/* DHCP relay interface info */
typedef struct dhcp_relay_interface_info
{
    const char *name;
    char *circuit_id;
    char *remote_id;
    bcmos_bool is_trusted;
    const void *owner;
    const struct xpon_dhcpr_profile *profile;
    uint16_t pon_ni;
    uint16_t nni;
    bbf_match_criteria ds_filter;
    bbf_match_criteria us_filter;
    uint32_t bal_flow;
} dhcp_relay_interface_info;

/* DHCP relay interface */
struct dhcp_relay_interface
{
    dhcp_relay_interface_info info;
    uint8_t circuit_id_len;
    uint8_t remote_id_len;
    STAILQ_ENTRY(dhcp_relay_interface) next;
};

/** Initialize dhcp relay module */
bcmos_errno dhcp_relay_init(void);

/** Add DHCP relay profile.
 */
bcmos_errno dhcp_relay_profile_add(struct xpon_dhcpr_profile *profile);

/** Remove DHCP relay profile.
 */
bcmos_errno dhcp_relay_profile_delete(const char *profile_name);

/** Add DHCP relay interface.
 */
bcmos_errno dhcp_relay_interface_add(const dhcp_relay_interface_info *info, dhcp_relay_interface **p_iface);

/** Remove DHCP relay interface.
 */
bcmos_errno dhcp_relay_interface_delete(dhcp_relay_interface *iface);

/** Handle an upstream packet.
 * DHCP relay must add relay options if necessary.
 *
 * \param[in]       intf_id             Ingress interface id
 * \param[in]       packet_in           Received packet
 * \param[in]       packet_in_length    Received packet length
 * \param[out]      packet_out          Output packet buffer
 * \param[in,out]   p_packet_out_size   packet_out buffer size on input, packet_out lengtgh on output
 * \param[out]      p_iface             interface reference.
 * Returns: dhcp_relay_result. If DHCP_RELAY_RESULT_FORWARD_UNCHANGED, the caller should use
 * the original packet_in in the egress.
 */
dhcp_relay_result dhcp_relay_recv_upstream(uint16_t intf_id, const uint8_t *packet_in, uint32_t packet_in_length,
    uint8_t *packet_out, uint32_t *p_packet_out_length, const dhcp_relay_interface **p_iface);

/** Handle a downstream packet.
 * DHCP relay must strip relay options if necessary.
 *
 * \param[in]       intf_id             Ingress interface id
 * \param[in]       packet_in           Received packet
 * \param[in]       packet_in_length    Received packet length
 * \param[out]      packet_out          Output packet buffer
 * \param[in,out]   p_packet_out_size   packet_out buffer size on input, packet_out lengtgh on output
 * \param[out]      p_iface             interface reference.
 * Returns: dhcp_relay_result. If DHCP_RELAY_RESULT_FORWARD_UNCHANGED, the caller should use
 * the original packet_in in the egress.
 */
dhcp_relay_result dhcp_relay_recv_downstream(uint16_t intf_id, const uint8_t *packet_in, uint32_t packet_in_length,
    uint8_t *packet_out, uint32_t *p_packet_out_length, const dhcp_relay_interface **p_iface);

#endif /* DHCP_RELAY_UTILS__H */