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
 * Copyright(c) 2004-2018 by Internet Systems Consortium, Inc.("ISC")
 * Copyright(c) 1997-2003 by Internet Software Consortium
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *   Internet Systems Consortium, Inc.
 *   950 Charter Street
 *   Redwood City, CA 94063
 *   <info@isc.org>
 *   https://www.isc.org/
 *
 */

#include <dhcp-relay-utils.h>
#include <bbf-xpon-internal.h>
#include <bcm_dev_log.h>

static dev_log_id log_id_dhcpr;

static bcmolt_access_control_id dhcr_access_control_id = 0;

/* DHCP relay profile. Onlky 1 profile is supported in the moment */
static xpon_dhcpr_profile *dhcpr_profile;

/* DHCP relay interface list head */
static STAILQ_HEAD(, dhcp_relay_interface) dhcp_relay_interface_list;

/* Per-NNI and per-PON ACL status */
static int per_pon_acl_ref_count[BCM_MAX_PONS_PER_OLT];
static int per_nni_acl_ref_count[BCM_MAX_NNI_PER_OLT];

/* Find an interface that matches the circuit ID and/or remote_id
   specified in the Relay Agent Information option.
   Return the interface if found
*/
static const dhcp_relay_interface *find_interface_by_agent_option(
    struct dhcp_packet *packet, uint8_t *buf, int len)
{
    int i = 0;
    char circuit_id[64] = "";
    unsigned circuit_id_len = 0;
    char remote_id[64] = "";
    unsigned remote_id_len = 0;
    dhcp_relay_interface *iface, *iface_tmp;

    while (i < len) {
        /* If the next agent option overflows the end of the
            packet, the agent option buffer is corrupt. */
        if (i + 1 == len ||
            i + buf[i + 1] + 2 > len)
        {
            BCM_LOG(ERROR, log_id_dhcpr, "Agent option is corrupt\n");
            return NULL;
        }
        switch(buf[i]) {
            /* Remember where the circuit ID is... */
            case RAI_CIRCUIT_ID:

                circuit_id_len = buf[i + 1];
                memcpy(circuit_id, &buf[i + 2], MIN(circuit_id_len, sizeof(circuit_id) - 1));
                circuit_id[MIN(circuit_id_len, sizeof(circuit_id) - 1)] = 0;
                i += circuit_id_len + 2;
                continue;

            /* Remember where the remote ID is... */
            case RAI_REMOTE_ID:
                remote_id_len = buf[i + 1];
                memcpy(remote_id, &buf[i + 2], MIN(remote_id_len, sizeof(remote_id) - 1));
                remote_id[MIN(remote_id_len, sizeof(remote_id) - 1)] = 0;
                i += remote_id_len + 2;
                continue;

            default:
                i += buf[i + 1] + 2;
            break;
        }
    }

    /* If there's no circuit ID nor remote ID, it's not really ours. */
    if (!circuit_id_len && !remote_id_len)
    {
        BCM_LOG(ERROR, log_id_dhcpr, "No circuit-id nor remote-id\n");
        return NULL;
    }

    /* Scan the interface list looking for an interface whose
        name matches the one specified in circuit_id. */
    STAILQ_FOREACH_SAFE(iface, &dhcp_relay_interface_list, next, iface_tmp)
    {
        if (iface->info.circuit_id != NULL &&
            (iface->circuit_id_len != circuit_id_len ||
             memcmp(iface->info.circuit_id, circuit_id, circuit_id_len)))
        {
            continue;
        }
        if (iface->info.remote_id != NULL &&
            (iface->remote_id_len != remote_id_len ||
             memcmp(iface->info.remote_id, remote_id, remote_id_len)))
        {
            continue;
        }
        break;
    }
    if (iface == NULL)
    {
        BCM_LOG(ERROR, log_id_dhcpr, "Couldn't find an interface by circuit-id=%s, remote-id=%s\n",
            circuit_id, remote_id);
    }
    else
    {
        BCM_LOG(DEBUG, log_id_dhcpr, "Found an interface %s by circuit-id=%s, remote-id=%s\n",
            iface->info.name, circuit_id, remote_id);
    }

    return iface;
}


/* Make the circuit-id and/or remote-id for the specific interface */
static char *_dhcp_relay_make_id(const dhcp_relay_interface_info *info, const char *syntax)
{
    typedef enum
    {
        DHCPR_ID_SYNTAX_FIELD_ID_S_VID,
        DHCPR_ID_SYNTAX_FIELD_ID_C_VID,
        /* TODO: add more fields */
    } dhcpr_id_syntax_field_id;
    typedef struct dhcpr_id_syntax_field
    {
        const char *str;
        dhcpr_id_syntax_field_id id;
    } dhcpr_id_syntax_field;
    static const dhcpr_id_syntax_field id_fields[] = {
        { "S-VID", DHCPR_ID_SYNTAX_FIELD_ID_S_VID },
        { "N-VID", DHCPR_ID_SYNTAX_FIELD_ID_S_VID },
        { "C-VID", DHCPR_ID_SYNTAX_FIELD_ID_C_VID },
        { "N2VID", DHCPR_ID_SYNTAX_FIELD_ID_C_VID },
    };
    char buf[64];
    char *p_buf = buf;
    char *p_end = &buf[0] + sizeof(buf) - 1;
    const char *uint16_format = info->profile->use_leading_zeros ? "%04d" : "%d";

    while (*syntax && p_buf < p_end)
    {
        int i;

        /* Try to find an ID from the current position */
        for (i = 0; i < BCM_SIZEOFARRAY(id_fields); i++)
        {
            if (!memcmp(syntax, id_fields[i].str, strlen(id_fields[i].str)))
                break;
        }
        if (i == BCM_SIZEOFARRAY(id_fields))
        {
            /* ID not found. Copy character to the output string and continue */
            *(p_buf++) = *(syntax++);
        }
        else
        {
            /* Found an ID. Substitute it */
            switch(id_fields[i].id)
            {
                case DHCPR_ID_SYNTAX_FIELD_ID_S_VID:
                    if (!info->ds_filter.vlan_tag_match.num_tags)
                    {
                        BCM_LOG(ERROR, log_id_dhcpr, "Couldn't apply '%s' field. No outer tag\n", id_fields[i].str);
                        return NULL;
                    }
                    p_buf += snprintf(p_buf, sizeof(buf) - (p_buf - buf),
                        uint16_format, info->ds_filter.vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_OUTER].vlan_id);
                    break;

                case DHCPR_ID_SYNTAX_FIELD_ID_C_VID:
                    if (info->ds_filter.vlan_tag_match.num_tags < 2)
                    {
                        BCM_LOG(ERROR, log_id_dhcpr, "Couldn't apply '%s' field. No inner tag\n", id_fields[i].str);
                        return NULL;
                    }
                    p_buf += snprintf(p_buf, sizeof(buf) - (p_buf - buf),
                        uint16_format, info->ds_filter.vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_INNER].vlan_id);
                    break;

                default:
                    /* Can't really happen */
                    BCM_LOG(ERROR, log_id_dhcpr, "Field '%s' is not supported\n", id_fields[i].str);
                    return NULL;
            }
            syntax += strlen(id_fields[i].str);
        }
    }
    if (p_buf >= p_end)
    {
        BCM_LOG(ERROR, log_id_dhcpr, "circuit-id/remote-id is too long\n");
        return NULL;
    }
    *p_buf = 0;
    return bcmos_strdup(buf);
}


/* Find an interface for an upstream packet */
static const dhcp_relay_interface *_dhcp_relay_find_iface_by_us_packet(
    uint16_t intf_id, const bbf_match_criteria *match)
{
    dhcp_relay_interface *iface, *iface_tmp;
    STAILQ_FOREACH_SAFE(iface, &dhcp_relay_interface_list, next, iface_tmp)
    {
        if (iface->info.pon_ni != intf_id)
            continue;
        if (BBF_DOT1Q_TAG_PROP_IS_SET(&iface->info.us_filter.vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_OUTER], vlan_id) &&
            (!BBF_DOT1Q_TAG_PROP_IS_SET(&match->vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_OUTER], vlan_id) ||
             iface->info.us_filter.vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_OUTER].vlan_id !=
             match->vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_OUTER].vlan_id))
            continue;
        if (BBF_DOT1Q_TAG_PROP_IS_SET(&iface->info.us_filter.vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_INNER], vlan_id) &&
            (!BBF_DOT1Q_TAG_PROP_IS_SET(&match->vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_INNER], vlan_id) ||
             iface->info.us_filter.vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_INNER].vlan_id !=
             match->vlan_tag_match.tags[BBF_TAG_INDEX_TYPE_INNER].vlan_id))
            continue;
        break;
    }
    return iface;
}

static inline bcmos_bool _is_vlan_tpid(uint16_t tpid)
{
    return (tpid == 0x8100 || tpid == 0x88A8 || tpid == 0x9100);
}

/* Parse packet */
static bcmos_bool _dhcp_relay_parse_packet(const uint8_t *packet, uint32_t length,
    const uint8_t **p_ip_hdr, const uint8_t **p_payload, bbf_match_criteria *match)
{
    const uint16_t *p_tpid;
    uint16_t vlan;
    uint8_t ip_prot;
    uint8_t ihl;

    memset(match, 0, sizeof(*match));

    /* Store the source MAC address. It is going to be the destination address in the response */
    memcpy(&match->frame_destination_match.filter.value, packet+6, 6);
    p_tpid = (const uint16_t *)(packet + 12);
    if (_is_vlan_tpid(ntohs(*p_tpid)))
    {
        BBF_DOT1Q_TAG_PROP_SET(&match->vlan_tag_match.tags[0], tag_type, ntohs(*p_tpid));
        vlan = ntohs(*(++p_tpid));
        BBF_DOT1Q_TAG_PROP_SET(&match->vlan_tag_match.tags[0], vlan_id, (vlan & 0xfff));
        BBF_DOT1Q_TAG_PROP_SET(&match->vlan_tag_match.tags[0], pbit, (vlan >> 13));
        ++p_tpid;
    }
    if (_is_vlan_tpid(ntohs(*p_tpid)))
    {
        BBF_DOT1Q_TAG_PROP_SET(&match->vlan_tag_match.tags[1], tag_type, ntohs(*p_tpid));
        vlan = ntohs(*(++p_tpid));
        BBF_DOT1Q_TAG_PROP_SET(&match->vlan_tag_match.tags[1], vlan_id, (vlan & 0xfff));
        BBF_DOT1Q_TAG_PROP_SET(&match->vlan_tag_match.tags[1], pbit, (vlan >> 13));
        ++p_tpid;
    }
    /* Not IPv4 ? */
    if (ntohs(*p_tpid) != 0x0800)
    {
        BCM_LOG(ERROR, log_id_dhcpr, "Not IPv4 packet. Ethernet type: 0x%04x\n", ntohs(*p_tpid));
        return BCMOS_FALSE;
    }

    *p_ip_hdr = (const uint8_t *)(p_tpid + 1);
    ip_prot = (*p_ip_hdr)[9];
    if (ip_prot != 17)
    {
        BCM_LOG(ERROR, log_id_dhcpr, "Unexpected IP protocol %d. Expected UDP (17)", ip_prot);
        return BCMOS_FALSE;
    }
    ihl = ((*p_ip_hdr)[0] & 0x0f) * 4; /* IP header length in bytes */
    *p_payload = *p_ip_hdr + ihl + 8; /* UDP payload pointer. 8 is UDP header length */

    return BCMOS_TRUE;
}

/** Add relay options.
 * Updates 'packet' and 'length'.
 */
static dhcp_relay_result dhcp_relay_options_add(const dhcp_relay_interface *iface, struct dhcp_packet *packet,
    uint32_t *p_length, uint32_t max_size)
{
    uint32_t length = *p_length;
    int is_dhcp = 0, mms;
    unsigned optlen;
    uint8_t *op, *nextop, *sp, *max, *end_pad = NULL;

    /* If there's no cookie, it's a bootp packet, so we should just
        forward it unchanged. */
    if (memcmp(packet->options, DHCP_OPTIONS_COOKIE, 4))
        return DHCP_RELAY_RESULT_FORWARD_UNCHANGED;

    max = ((uint8_t *)packet) + DHCP_MTU_MAX;

    /* Commence processing after the cookie. */
    sp = op = &packet->options[4];

    while (op < max) {
        switch(*op) {
            /* Skip padding... */
            case DHO_PAD:
                /* Remember the first pad byte so we can commandeer
                    * padded space.
                    *
                    * XXX: Is this really a good idea?  Sure, we can
                    * seemingly reduce the packet while we're looking,
                    * but if the packet was signed by the client then
                    * this padding is part of the checksum(RFC3118),
                    * and its nonpresence would break authentication.
                    */
                if (end_pad == NULL)
                    end_pad = sp;

                if (sp != op)
                    *sp++ = *op++;
                else
                    sp = ++op;

                continue;

            /* If we see a message type, it's a DHCP packet. */
            case DHO_DHCP_MESSAGE_TYPE:
                is_dhcp = 1;
                goto skip;

            /*
             * If there's a maximum message size option, we
             * should pay attention to it
             */
            case DHO_DHCP_MAX_MESSAGE_SIZE:
                mms = ntohs(*(op + 2));
                if (mms < DHCP_MTU_MAX && mms >= DHCP_MTU_MIN)
                    max = ((uint8_t *)packet) + mms;
                goto skip;

            /* Quit immediately if we hit an End option. */
            case DHO_END:
                goto out;

            case DHO_DHCP_AGENT_OPTIONS:
                /* We shouldn't see a relay agent option in a
                    packet before we've seen the DHCP packet type,
                    but if we do, we have to leave it alone. */
                if (!is_dhcp)
                    goto skip;

                end_pad = NULL;

                /* There's already a Relay Agent Information option
                    in this packet.   How embarrassing.   Decide what
                    to do based on the mode the user specified. */
                if (!iface->info.is_trusted)
                {
                    BCM_LOG(ERROR, log_id_dhcpr, "Got message with Option82 from a non-trusted interface. Discarded\n");
                    return DHCP_RELAY_RESULT_DISCARD;
                }
                /* add additional option */
                goto skip;

            skip:
            /* Skip over other options. */
            default:
                /* Fail if processing this option will exceed the
                 * buffer(op[1] is malformed).
                 */
                nextop = op + op[1] + 2;
                if (nextop > max)
                {
                    BCM_LOG(ERROR, log_id_dhcpr, "Options area is too long. Discarded\n");
                    return DHCP_RELAY_RESULT_DISCARD;
                }

                end_pad = NULL;

                if (sp != op) {
                    memmove(sp, op, op[1] + 2);
                    sp += op[1] + 2;
                    op = nextop;
                }
                else
                {
                    op = sp = nextop;
                }
                break;
        }
    }
    out:

    /* If it's not a DHCP packet, we're not supposed to touch it. */
    if (!is_dhcp)
    {
        BCM_LOG(DEBUG, log_id_dhcpr, "Non-dhcp packet. Skipped\n");
        return DHCP_RELAY_RESULT_FORWARD_UNCHANGED;
    }

    /* If the packet was padded out, we can store the agent option
        at the beginning of the padding. */
    if (end_pad != NULL)
        sp = end_pad;


    /* Calculate option length */
    optlen = 0;
    if (iface->circuit_id_len)
        optlen += iface->circuit_id_len + 2;   /* RAI_CIRCUIT_ID + len */

    if (iface->remote_id_len)
        optlen += iface->remote_id_len + 2;    /* RAI_REMOTE_ID + len */

    /*
     * Is there room for the option, its code+len, and DHO_END?
     * If not, forward without adding the option.
     */
    if (max - sp < optlen + 3)
    {
        BCM_LOG(ERROR, log_id_dhcpr, "No room in packet (used %d of %d) "
                    "for %d-byte relay agent option: omitted\n",
                    (int) (sp - ((uint8_t *) packet)),
                    (int) (max - ((uint8_t *) packet)),
                    optlen + 3);
        return DHCP_RELAY_RESULT_DISCARD;
    }

    BCM_LOG(DEBUG, log_id_dhcpr, "Adding %d-byte relay agent option\n", optlen + 3);

    /* Okay, cons up *our* Relay Agent Information option. */
    *sp++ = DHO_DHCP_AGENT_OPTIONS;
    *sp++ = optlen;

    /* Copy in the circuit id... */
    if (iface->info.circuit_id != NULL)
    {
        *sp++ = RAI_CIRCUIT_ID;
        *sp++ = iface->circuit_id_len;
        memcpy(sp, iface->info.circuit_id, iface->circuit_id_len);
        sp += iface->circuit_id_len;
    }

    /* Copy in remote ID... */
    if (iface->info.remote_id)
    {
        *sp++ = RAI_REMOTE_ID;
        *sp++ = iface->remote_id_len;
        memcpy(sp, iface->info.remote_id, iface->remote_id_len);
        sp += iface->remote_id_len;
    }

    /*
     * Deposit an END option unless the packet is full (shouldn't
     * be possible).
     */
    if (sp < max)
        *sp++ = DHO_END;

    /* Recalculate total packet length. */
    length = sp -((uint8_t *)packet);

    /* Make sure the packet isn't short(this is unlikely, but WTH) */
    if (length < BOOTP_MIN_LEN)
    {
        memset(sp, DHO_PAD, BOOTP_MIN_LEN - length);
        length = BOOTP_MIN_LEN;
    }

    *p_length = length;

    return DHCP_RELAY_RESULT_FORWARD_MODIFIED;
}

/* 1-complement sum */
static inline uint16_t _sum1(uint16_t a, uint16_t b)
{
    uint32_t sum = a + b;
    if (sum >> 16 != 0)
        sum += 1;
    return (uint16_t)sum;
}

/* Update IP and UDP headers */
static void _dhcp_update_ip_udp_header(uint8_t *ip_hdr, uint8_t *udp_hdr, int delta, bcmos_bool is_request)
{
    uint16_t total_length = (ip_hdr[2] << 8) | ip_hdr[3];
    uint16_t new_total_length = total_length + delta;
    uint16_t ip_checksum = (ip_hdr[10] << 8) | ip_hdr[11];
    uint16_t udp_length;
    /* HC' = ~(C + (-m) + m') = ~(~HC + ~m + m') (RFC 1624) */
    ip_checksum = ~(_sum1(_sum1(~ip_checksum, ~total_length), new_total_length));
    ip_hdr[2] = new_total_length >> 8;
    ip_hdr[3] = new_total_length & 0xff;
    ip_hdr[10] = ip_checksum >> 8;
    ip_hdr[11] = ip_checksum & 0xff;

    /* Now update UDP payload length and 0 checksum */
    udp_length = (udp_hdr[4] << 8) | udp_hdr[5];
    udp_length += delta;
    /* Set src_port=67 for request and dst_port=68 for response */
    if (is_request)
        udp_hdr[1] = 67;
    else
        udp_hdr[1] = 68;
    udp_hdr[4] = udp_length >> 8;
    udp_hdr[5] = udp_length & 0xff;
    udp_hdr[6] = 0;
    udp_hdr[7] = 0;
}

/** Delete relay options.
 * Updates 'packet', 'length' and 'out'
 */
static dhcp_relay_result dhcp_relay_options_strip(struct dhcp_packet *packet,
    uint32_t *p_length, const dhcp_relay_interface **p_out)
{
    uint32_t length = *p_length;
    int is_dhcp = 0;
    uint8_t *op, *nextop, *sp, *max;
    const dhcp_relay_interface *out_if = NULL;

    /* If there's no cookie, it's a bootp packet, so we should just
        forward it unchanged. */
    if (memcmp(packet->options, DHCP_OPTIONS_COOKIE, 4))
        return DHCP_RELAY_RESULT_FORWARD_UNCHANGED;

    max = ((uint8_t *)packet) + length;
    sp = op = &packet->options[4];

    while (op < max) {
        switch(*op) {
            /* Skip padding... */
            case DHO_PAD:
                if (sp != op)
                    *sp = *op;
                ++op;
                ++sp;
                continue;

            /* If we see a message type, it's a DHCP packet. */
            case DHO_DHCP_MESSAGE_TYPE:
                is_dhcp = 1;
                goto skip;

            /* Quit immediately if we hit an End option. */
            case DHO_END:
                if (sp != op)
                    *sp++ = *op++;
                goto out;

            case DHO_DHCP_AGENT_OPTIONS:
                /* We shouldn't see a relay agent option in a
                    packet before we've seen the DHCP packet type,
                    but if we do, we have to leave it alone. */
                if (!is_dhcp)
                    goto skip;

                /* Do not process an agent option if it exceeds the
                    * buffer.  Fail this packet.
                    */
                nextop = op + op[1] + 2;
                if (nextop > max)
                    return (0);

                out_if = find_interface_by_agent_option(packet, op + 2, op[1]);
                if (out_if == NULL)
                    goto out;
                op = nextop;
                break;

            skip:
            /* Skip over other options. */
            default:
                /* Fail if processing this option will exceed the
                 * buffer(op[1] is malformed).
                 */
                nextop = op + op[1] + 2;
                if (nextop > max)
                    return (0);

                if (sp != op)
                {
                    memmove(sp, op, op[1] + 2);
                    sp += op[1] + 2;
                    op = nextop;
                }
                else
                {
                    op = sp = nextop;
                }
                break;
        }
    }
    out:

    /* If it's not a DHCP packet, we're not supposed to touch it. */
    if (!is_dhcp)
        return DHCP_RELAY_RESULT_FORWARD_UNCHANGED;

    /* If none of the agent options we found matched, or if we didn't
        find any agent options, count this packet as not having any
        matching agent options, and if we're relying on agent options
        to determine the outgoing interface, drop the packet. */

    if (out_if == NULL)
    {
        BCM_LOG(ERROR, log_id_dhcpr, "No DHCP agent option or can't find egress interface. Discarded");
        return DHCP_RELAY_RESULT_DISCARD;
    }

    /* Adjust the length... */
    if (sp != op) {
        length = sp -((uint8_t *)packet);

        /* Make sure the packet isn't short(this is unlikely,
            but WTH) */
        if (length < BOOTP_MIN_LEN) {
            memset(sp, DHO_PAD, BOOTP_MIN_LEN - length);
            length = BOOTP_MIN_LEN;
        }
    }

    *p_length = length;
    *p_out = out_if;

    return DHCP_RELAY_RESULT_FORWARD_MODIFIED;
}

/* Ethernet packet handler */
static void _dhcr_recv_eth_packet(bcmolt_oltid olt, bcmolt_msg *msg)
{
    bcmolt_access_control_receive_eth_packet *eth_packet = (bcmolt_access_control_receive_eth_packet *)msg;
    dhcp_relay_result ret;
    uint8_t *out_buf = NULL;
    uint32_t out_len;
    const dhcp_relay_interface *iface;
    bcmolt_flow_key flow_key = {};
    bcmolt_flow_send_eth_packet packet_out;
    bcmolt_bin_str packet_out_buffer;
    bcmos_errno err;

    do
    {
        /* If message if from another access control object - just return */
        if (eth_packet->key.id != dhcr_access_control_id)
            break;

        BCM_LOG(DEBUG, log_id_dhcpr, "Packet received from %s.%u: %u bytes\n",
            (eth_packet->data.interface_ref.intf_type == BCMOLT_INTERFACE_TYPE_PON) ? "PON" : "NNI",
            eth_packet->data.interface_ref.intf_id,
            eth_packet->data.buffer.len);

        out_len = eth_packet->data.buffer.len + 256;
        out_buf = bcmos_alloc(out_len);
        if (out_buf == NULL)
            break;

        /* Handle US or DS message */
        if (eth_packet->data.interface_ref.intf_type == BCMOLT_INTERFACE_TYPE_PON)
        {
            ret = dhcp_relay_recv_upstream(eth_packet->data.interface_ref.intf_id,
                eth_packet->data.buffer.arr, eth_packet->data.buffer.len,
                out_buf, &out_len, &iface);
            flow_key.flow_type = BCMOLT_FLOW_TYPE_UPSTREAM;
        }
        else
        {
            ret = dhcp_relay_recv_downstream(eth_packet->data.interface_ref.intf_id,
                eth_packet->data.buffer.arr, eth_packet->data.buffer.len,
                out_buf, &out_len, &iface);
            flow_key.flow_type = BCMOLT_FLOW_TYPE_DOWNSTREAM;
        }

        /* Don't forward if failed to modify */
        if (ret != DHCP_RELAY_RESULT_FORWARD_MODIFIED || iface == NULL)
        {
            /* TODO: forward unchanged buffer when send_to_ingress support is ready */
            break;
        }

        /* Send back to ingress */
        flow_key.flow_id = iface->info.bal_flow;
        BCMOLT_OPER_INIT(&packet_out, flow, send_eth_packet, flow_key);

        packet_out_buffer.len = out_len;
        packet_out_buffer.arr = out_buf;
        BCMOLT_MSG_FIELD_SET(&packet_out, buffer, packet_out_buffer);
        BCMOLT_MSG_FIELD_SET(&packet_out, inject_type, BCMOLT_INJECT_TYPE_INJECT_AT_INGRESS);
        err = bcmolt_oper_submit(olt, &packet_out.hdr);
        if (err != BCM_ERR_OK)
        {
            BCM_LOG(ERROR, log_id_dhcpr, "%s: Failed to forward packet. Error %s\n",
                iface->info.name, bcmos_strerror(err));
        }
        else
        {
            BCM_LOG(DEBUG, log_id_dhcpr, "%s: Packet forwarded: %u bytes\n",
                iface->info.name, out_len);
        }
        bcmos_free(out_buf);

    } while(0);

    bcmolt_msg_free(msg);

}

/* Add and configure access_control object for DHCP intercept */
static bcmos_errno interface_add_to_access_control(dhcp_relay_interface *iface, bcmos_bool create_acl)
{
    bcmos_errno err = BCM_ERR_OK;
    bcmos_bool created = BCMOS_FALSE;
    bcmolt_access_control_key acl_key = {.id = dhcr_access_control_id};
    bcmolt_rx_cfg rx_cfg = {
        .obj_type = BCMOLT_OBJ_ID_ACCESS_CONTROL,
        .rx_cb = _dhcr_recv_eth_packet,
        .subgroup = BCMOLT_ACCESS_CONTROL_AUTO_SUBGROUP_RECEIVE_ETH_PACKET
    };

    do
    {
        if (create_acl)
        {
            /* Subscribe to receive_eth_packet indication */
            err = bcmolt_ind_subscribe(netconf_agent_olt_id(), &rx_cfg);
            if (err != BCM_ERR_OK)
            {
                BCM_LOG(ERROR, log_id_dhcpr, "%s: Failed to subscribe to access_control.receive_eth_packet. Error %s\n",
                    iface->info.name, bcmos_strerror(err));
                break;
            }

            /* Create an intercept ACL */
            bcmolt_access_control_cfg acl_cfg;
            BCMOLT_CFG_INIT(&acl_cfg, access_control, acl_key);
            BCMOLT_MSG_FIELD_SET(&acl_cfg, classifier.ip_proto, 17);
            BCMOLT_MSG_FIELD_SET(&acl_cfg, classifier.dst_port, 67);
            BCMOLT_MSG_FIELD_SET(&acl_cfg, classifier.dst_port, 67);
            BCMOLT_MSG_FIELD_SET(&acl_cfg, forwarding_action.action, BCMOLT_ACCESS_CONTROL_FWD_ACTION_TYPE_TRAP_TO_HOST);
            BCMOLT_MSG_FIELD_SET(&acl_cfg, statistics_control, BCMOLT_CONTROL_STATE_ENABLE);
            err = bcmolt_cfg_set(netconf_agent_olt_id(), &acl_cfg.hdr);
            if (err != BCM_ERR_OK)
            {
                BCM_LOG(ERROR, log_id_dhcpr, "%s: Failed to create access_control object. Error %s\n",
                    iface->info.name, bcmos_strerror(err));
                break;
            }
            created = BCMOS_TRUE;
            BCM_LOG(INFO, log_id_dhcpr, "%s: access_control object created.\n", iface->info.name);
        }

        /* See if need to add PON and/or NNI interface */
        if (!per_pon_acl_ref_count[iface->info.pon_ni] || !per_nni_acl_ref_count[iface->info.nni])
        {
            bcmolt_access_control_interfaces_update acl_intf;
            bcmolt_intf_ref intf_refs[2] = {};
            bcmolt_intf_ref_list_u8 ref_list = {.arr = intf_refs};
            int num_intf_refs = 0;

            if (!per_pon_acl_ref_count[iface->info.pon_ni])
            {
                intf_refs[num_intf_refs].intf_type = BCMOLT_INTERFACE_TYPE_PON;
                intf_refs[num_intf_refs].intf_id = iface->info.pon_ni;
                ++num_intf_refs;
            }
            if (!per_nni_acl_ref_count[iface->info.nni])
            {
                intf_refs[num_intf_refs].intf_type = BCMOLT_INTERFACE_TYPE_NNI;
                intf_refs[num_intf_refs].intf_id = iface->info.nni;
                ++num_intf_refs;
            }

            BCMOLT_OPER_INIT(&acl_intf, access_control, interfaces_update, acl_key);
            ref_list.len = num_intf_refs;
            BCMOLT_MSG_FIELD_SET(&acl_intf, interface_ref_list, ref_list);
            BCMOLT_MSG_FIELD_SET(&acl_intf, command, BCMOLT_MEMBERS_UPDATE_COMMAND_ADD);
            err = bcmolt_oper_submit(netconf_agent_olt_id(), &acl_intf.hdr);
            if (err != BCM_ERR_OK)
            {
                BCM_LOG(ERROR, log_id_dhcpr, "%s: Failed to add interface references to access_control object. Error %s\n",
                    iface->info.name, bcmos_strerror(err));
                break;
            }
            ++per_pon_acl_ref_count[iface->info.pon_ni];
            ++per_nni_acl_ref_count[iface->info.nni];
        }
        BCM_LOG(INFO, log_id_dhcpr, "%s: %d references to PON %u and %d references to NNI %u in the access_control object.\n",
            iface->info.name,
            per_pon_acl_ref_count[iface->info.pon_ni], iface->info.pon_ni,
            per_nni_acl_ref_count[iface->info.nni], iface->info.nni);

    } while (0);

    if (err != BCM_ERR_OK)
    {
        if (create_acl)
        {
            bcmos_errno unsub_err = bcmolt_ind_unsubscribe(netconf_agent_olt_id(), &rx_cfg);
            BCMOS_TRACE_IF_ERROR(unsub_err);
        }
        if (created)
        {
            bcmolt_access_control_cfg acl_cfg;
            BCMOLT_CFG_INIT(&acl_cfg, access_control, acl_key);
            bcmolt_cfg_clear(netconf_agent_olt_id(), &acl_cfg.hdr);
        }
        return err;
    }

    return BCM_ERR_OK;
}

/* Remove interface references from the access_control object,
   and possibly the access_control object itself */
static bcmos_errno interface_remove_from_access_control(dhcp_relay_interface *iface, bcmos_bool remove_acl)
{
    bcmos_errno err = BCM_ERR_OK;
    bcmolt_access_control_key acl_key = {.id = dhcr_access_control_id};

    --per_pon_acl_ref_count[iface->info.pon_ni];
    --per_nni_acl_ref_count[iface->info.nni];
    if (remove_acl)
    {
        bcmolt_rx_cfg rx_cfg = {
            .obj_type = BCMOLT_OBJ_ID_ACCESS_CONTROL,
            .rx_cb = _dhcr_recv_eth_packet,
            .subgroup = BCMOLT_ACCESS_CONTROL_AUTO_SUBGROUP_RECEIVE_ETH_PACKET
        };
        /* Unsubscribe from receive_eth_packet indication */
        err = bcmolt_ind_unsubscribe(netconf_agent_olt_id(), &rx_cfg);
        BCMOS_TRACE_IF_ERROR(err);

        /* Delete an intercept ACL */
        bcmolt_access_control_cfg acl_cfg;
        BCMOLT_CFG_INIT(&acl_cfg, access_control, acl_key);
        err = bcmolt_cfg_clear(netconf_agent_olt_id(), &acl_cfg.hdr);
        if (err != BCM_ERR_OK)
        {
            BCM_LOG(ERROR, log_id_dhcpr, "%s: Failed to create access_control object. Error %s\n",
                iface->info.name, bcmos_strerror(err));
        }
        BCM_LOG(INFO, log_id_dhcpr, "%s: access_control object deleted.\n", iface->info.name);
    }
    else
    {
        if (!per_pon_acl_ref_count[iface->info.pon_ni] || !per_nni_acl_ref_count[iface->info.nni])
        {
            bcmolt_access_control_interfaces_update acl_intf;
            bcmolt_intf_ref intf_refs[2];
            bcmolt_intf_ref_list_u8 ref_list = {.arr = &intf_refs[0]};
            int num_intf_refs = 0;

            if (!per_pon_acl_ref_count[iface->info.pon_ni])
            {
                intf_refs[num_intf_refs].intf_type = BCMOLT_INTERFACE_TYPE_PON;
                intf_refs[num_intf_refs].intf_id = iface->info.pon_ni;
                ++num_intf_refs;
            }
            if (!per_nni_acl_ref_count[iface->info.nni])
            {
                intf_refs[num_intf_refs].intf_type = BCMOLT_INTERFACE_TYPE_NNI;
                intf_refs[num_intf_refs].intf_id = iface->info.nni;
                ++num_intf_refs;
            }

            BCMOLT_OPER_INIT(&acl_intf, access_control, interfaces_update, acl_key);
            ref_list.len = num_intf_refs;
            BCMOLT_MSG_FIELD_SET(&acl_intf, interface_ref_list, ref_list);
            BCMOLT_MSG_FIELD_SET(&acl_intf, command, BCMOLT_MEMBERS_UPDATE_COMMAND_REMOVE);
            err = bcmolt_oper_submit(netconf_agent_olt_id(), &acl_intf.hdr);
            if (err != BCM_ERR_OK)
            {
                BCM_LOG(ERROR, log_id_dhcpr, "%s: Failed to remove interface references to access_control object. Error %s\n",
                    iface->info.name, bcmos_strerror(err));
            }
        }
        BCM_LOG(INFO, log_id_dhcpr, "%s: %d references to PON %u and %d references to NNI %u in the access_control object.\n",
            iface->info.name,
            per_pon_acl_ref_count[iface->info.pon_ni], iface->info.pon_ni,
            per_nni_acl_ref_count[iface->info.nni], iface->info.nni);
    }

    return err;
}


/** Remove DHCP relay interface.
 */
static bcmos_errno _dhcp_relay_interface_delete(dhcp_relay_interface *iface, bcmos_bool update_acl)
{
    if (update_acl)
    {
        interface_remove_from_access_control(iface, STAILQ_EMPTY(&dhcp_relay_interface_list));
    }
    if (iface->info.circuit_id != NULL)
    {
        bcmos_free(iface->info.circuit_id);
        iface->info.circuit_id = NULL;
    }
    if (iface->info.remote_id != NULL)
    {
        bcmos_free(iface->info.remote_id);
        iface->info.remote_id = NULL;
    }
    BCM_LOG(INFO, log_id_dhcpr, "Removed DHCP relay interface %s.\n",
        iface->info.name);
    bcmos_free(iface);

    return BCM_ERR_OK;
}


/*
 * External interface
 */

/** Initialize DHCP relay library */
bcmos_errno dhcp_relay_init(void)
{
    log_id_dhcpr = bcm_dev_log_id_register("DHCPR", DEV_LOG_LEVEL_INFO, DEV_LOG_ID_TYPE_BOTH);
    STAILQ_INIT(&dhcp_relay_interface_list);
    return BCM_ERR_OK;
}

/** Add DHCP relay profile.
 */
bcmos_errno dhcp_relay_profile_add(struct xpon_dhcpr_profile *profile)
{
    if (profile == NULL || profile->hdr.name == NULL)
        return BCM_ERR_PARM;
    if (dhcpr_profile != NULL)
    {
        BCM_LOG(ERROR, log_id_dhcpr, "Only 1 DHCP relay profile is supported. Attempt to add profile %s when profile %s already exists\n",
            profile->hdr.name, dhcpr_profile->hdr.name);
        return BCM_ERR_TOO_MANY;
    }
    dhcpr_profile = profile;
    return BCM_ERR_OK;
}

/** Remove DHCP relay profile.
 */
bcmos_errno dhcp_relay_profile_delete(const char *profile_name)
{
    if (profile_name == NULL)
        return BCM_ERR_PARM;
    if (dhcpr_profile == NULL || strcmp(dhcpr_profile->hdr.name, profile_name))
        return BCM_ERR_NOENT;
    dhcpr_profile = NULL;
    return BCM_ERR_OK;
}

/** Add DHCP relay interface.
 *  If circuit_id and remote_id are not populated, they are auto-populated
 *  based on the profile.
 */
bcmos_errno dhcp_relay_interface_add(const dhcp_relay_interface_info *info, dhcp_relay_interface **p_iface)
{
    dhcp_relay_interface *iface;
    bcmos_errno err = BCM_ERR_PARM;
    bcmos_bool was_empty;

    if (info == NULL || p_iface == NULL || info->profile == NULL)
        return BCM_ERR_PARM;

    if (info->pon_ni >= BCM_MAX_PONS_PER_OLT || info->nni > BCM_MAX_NNI_PER_OLT)
        return BCM_ERR_PARM;

    iface = bcmos_calloc(sizeof(dhcp_relay_interface));
    if (iface == NULL)
        return BCM_ERR_NOMEM;

    do
    {
        iface->info = *info;
        /* Set circuit-id and remote-id if necessary */
        if (iface->info.circuit_id == NULL)
        {
            if ((info->profile->suboptions & DHCP_RELAY_OPTION82_SUBOPTION_CIRCUIT_ID) != 0 &&
                info->profile->circuit_id_syntax != NULL)
            {
                iface->info.circuit_id = _dhcp_relay_make_id(info, info->profile->circuit_id_syntax);
                if (iface->info.circuit_id == NULL)
                    break;
            }
        }
        else if ((info->profile->suboptions & DHCP_RELAY_OPTION82_SUBOPTION_CIRCUIT_ID) != 0)
        {
            iface->info.circuit_id = bcmos_strdup(iface->info.circuit_id);
        }
        iface->circuit_id_len = (iface->info.circuit_id != NULL) ? strlen(iface->info.circuit_id) : 0;

        if (iface->info.remote_id == NULL)
        {
            if ((info->profile->suboptions & DHCP_RELAY_OPTION82_SUBOPTION_REMOTE_ID) != 0 &&
                info->profile->remote_id_syntax != NULL)
            {
                iface->info.remote_id = _dhcp_relay_make_id(info, info->profile->remote_id_syntax);
                if (iface->info.remote_id == NULL)
                    break;
            }
        }
        else if ((info->profile->suboptions & DHCP_RELAY_OPTION82_SUBOPTION_REMOTE_ID) != 0)
        {
            iface->info.remote_id = bcmos_strdup(iface->info.remote_id);
        }
        iface->remote_id_len = (iface->info.remote_id != NULL) ? strlen(iface->info.remote_id) : 0;

        err = BCM_ERR_OK;
    } while (0);

    if (err != BCM_ERR_OK)
    {
        if (iface->info.circuit_id != NULL)
        {
            bcmos_free(iface->info.circuit_id);
            iface->info.circuit_id = NULL;
        }
        if (iface->info.remote_id != NULL)
        {
            bcmos_free(iface->info.remote_id);
            iface->info.remote_id = NULL;
        }
        bcmos_free(iface);
        return err;
    }
    was_empty = STAILQ_EMPTY(&dhcp_relay_interface_list);
    STAILQ_INSERT_TAIL(&dhcp_relay_interface_list, iface, next);
    err = interface_add_to_access_control(iface, was_empty);
    if (err != BCM_ERR_OK)
    {
        _dhcp_relay_interface_delete(iface, BCMOS_FALSE);
        return err;
    }
    BCM_LOG(INFO, log_id_dhcpr, "Added DHCP relay interface %s. circuit_id=%s remote_id=%s\n",
        info->name,
        iface->info.circuit_id ? iface->info.circuit_id : "none",
        iface->info.remote_id ? iface->info.remote_id : "none");
    *p_iface = iface;

    return BCM_ERR_OK;
}

/** Remove DHCP relay interface.
 */
bcmos_errno dhcp_relay_interface_delete(dhcp_relay_interface *iface)
{
    return _dhcp_relay_interface_delete(iface, BCMOS_TRUE);
}

/** Handle an upstream packet. */
dhcp_relay_result dhcp_relay_recv_upstream(uint16_t intf_id, const uint8_t *packet_in, uint32_t packet_in_length,
    uint8_t *packet_out, uint32_t *p_packet_out_length, const dhcp_relay_interface **p_iface)
{
    bbf_match_criteria match;
    const uint8_t *ip_hdr;
    const uint8_t *payload = NULL;
    const dhcp_relay_interface *iface = NULL;
    uint32_t payload_length, new_payload_length;
    struct dhcp_packet dhcp_payload;
    dhcp_relay_result ret;

    /* Validate parameters */
    if (packet_in == NULL || packet_out == NULL || p_packet_out_length == NULL)
    {
        BCM_LOG(ERROR, log_id_dhcpr, "Some of mandatory parameter(s) is NULL\n");
        return DHCP_RELAY_RESULT_DISCARD;
    }
    if (*p_packet_out_length < packet_in_length + 256)
    {
        BCM_LOG(ERROR, log_id_dhcpr, "packet_out buffer must be at least 256 bytes bigger than the received packet length\n");
        return DHCP_RELAY_RESULT_DISCARD;
    }

    /* Parse packet */
    if (!_dhcp_relay_parse_packet(packet_in, packet_in_length, &ip_hdr, &payload, &match))
        return DHCP_RELAY_RESULT_DISCARD;

    if (packet_in_length < payload - packet_in)
    {
        BCM_LOG(ERROR, log_id_dhcpr, "Payload length is insane\n");
        return DHCP_RELAY_RESULT_DISCARD;
    }
    payload_length = packet_in_length - (payload - packet_in);

    /* Find an interface. If not found - nothing to do */
    iface = _dhcp_relay_find_iface_by_us_packet(intf_id, &match);
    if (iface == NULL)
    {
        BCM_LOG(ERROR, log_id_dhcpr, "Can't find DHCP relay interface\n");
        return DHCP_RELAY_RESULT_DISCARD;
    }

    /* Copy DHCP payload to ensure proper alignment */
    memcpy(&dhcp_payload, payload, payload_length);

    /* Insert Option 82 */
    new_payload_length = payload_length;
    ret = dhcp_relay_options_add(iface, &dhcp_payload, &new_payload_length,
            *p_packet_out_length - (payload - packet_in));
    if (ret != DHCP_RELAY_RESULT_FORWARD_MODIFIED)
        return ret;

    /* Copy back the DHCP payload and update IP and UDP headers */
    memcpy(packet_out, packet_in, payload - packet_in);
    memcpy(packet_out + (payload - packet_in), &dhcp_payload, new_payload_length);

    /* Now need to update length in IP and UDP headers and adjust checksums */
    _dhcp_update_ip_udp_header(packet_out + (ip_hdr - packet_in),
        packet_out + (payload - packet_in) - 8,
        (int)(new_payload_length - payload_length),
        BCMOS_TRUE);
    *p_iface = iface;
    *p_packet_out_length = packet_in_length + (new_payload_length - payload_length);

    return ret;
}

/** Handle a downstream packet. */
dhcp_relay_result dhcp_relay_recv_downstream(uint16_t intf_id, const uint8_t *packet_in, uint32_t packet_in_length,
    uint8_t *packet_out, uint32_t *p_packet_out_length, const dhcp_relay_interface **p_iface)
{
    bbf_match_criteria match;
    const uint8_t *ip_hdr;
    const uint8_t *payload = NULL;
    const dhcp_relay_interface *iface = NULL;
    uint32_t payload_length, new_payload_length;
    struct dhcp_packet dhcp_payload;
    dhcp_relay_result ret;

    /* Validate parameters */
    if (packet_in == NULL || packet_out == NULL || p_packet_out_length == NULL)
    {
        BCM_LOG(ERROR, log_id_dhcpr, "Some of mandatory parameter(s) is NULL\n");
        return DHCP_RELAY_RESULT_DISCARD;
    }
    if (*p_packet_out_length < packet_in_length)
    {
        BCM_LOG(ERROR, log_id_dhcpr, "packet_out buffer is too short\n");
        return DHCP_RELAY_RESULT_DISCARD;
    }

    /* Parse packet */
    if (!_dhcp_relay_parse_packet(packet_in, packet_in_length, &ip_hdr, &payload, &match))
        return DHCP_RELAY_RESULT_DISCARD;

    if (packet_in_length < payload - packet_in)
    {
        BCM_LOG(ERROR, log_id_dhcpr, "Payload length is insane\n");
        return DHCP_RELAY_RESULT_DISCARD;
    }
    payload_length = packet_in_length - (payload - packet_in);

    /* Copy DHCP payload to ensure proper alignment */
    memcpy(&dhcp_payload, payload, payload_length);

    /* Strip Option 82 */
    new_payload_length = payload_length;
    ret = dhcp_relay_options_strip(&dhcp_payload, &new_payload_length, &iface);
    if (ret != DHCP_RELAY_RESULT_FORWARD_MODIFIED)
        return ret;

    /* Copy back the DHCP payload and update IP and UDP headers */
    memcpy(packet_out, packet_in, payload - packet_in);
    memcpy(packet_out + (payload - packet_in), &dhcp_payload, new_payload_length);

    /* Now need to update length in IP and UDP headers and adjust checksums */
    _dhcp_update_ip_udp_header(packet_out + (ip_hdr - packet_in),
        packet_out + (payload - packet_in) - 8,
        (int)(new_payload_length - payload_length),
        BCMOS_FALSE);
    *p_iface = iface;
    *p_packet_out_length = packet_in_length + (new_payload_length - payload_length);

    return ret;
}
