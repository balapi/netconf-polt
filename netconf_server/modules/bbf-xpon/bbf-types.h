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
 * bbf-types.h
 *
 * Data types directly derived from BBF YANG models
 */

#ifndef _BBF_TYPES_H_
#define _BBF_TYPES_H_

#include <bcmos_system.h>

/*
 * bbf-dot1q-types.yang
 */

/* VLAN type */
typedef enum
{
    BBF_DOT1Q_TAG_VLAN_TYPE_ANY,
    BBF_DOT1Q_TAG_VLAN_TYPE_S_VLAN = 0x88a8,
    BBF_DOT1Q_TAG_VLAN_TYPE_C_VLAN = 0x8100,
} bbf_dot1q_tag_vlan_type;

/* VLAN ID 1..4094 */
typedef uint16_t bbf_vlan_id;

/* PBIT */
typedef uint8_t bbf_pbit;

/* DEI */
typedef uint8_t bbf_dei;

/* ether-type */
typedef uint16_t ether_type;

/*
 * bbf-frame-classification.yang
 */

typedef enum
{
    BBF_MAC_ADDRESS_MATCH_TYPE_ANY,
    BBF_MAC_ADDRESS_MATCH_TYPE_ANY_MULTICAST,
    BBF_MAC_ADDRESS_MATCH_TYPE_ANY_UNICAST,
    BBF_MAC_ADDRESS_MATCH_TYPE_BROADCAST,
    BBF_MAC_ADDRESS_MATCH_TYPE_CFM_MULTICAST,   /* 01:80:C2:00:00:3X */
    BBF_MAC_ADDRESS_MATCH_TYPE_IPV4_MULTICAST,  /* 01:00:5E:00:00:00 - 01:00:5E:7F:FF:FF */
    BBF_MAC_ADDRESS_MATCH_TYPE_IPV6_MULTICAST,  /* 33:33:XX:XX:XX:XX */
    BBF_MAC_ADDRESS_MATCH_TYPE_FILTER
} bbf_mac_address_match_type;

typedef struct bbf_mac_address_match
{
    bbf_mac_address_match_type type;
    struct {
        bcmos_mac_address value;
        bcmos_mac_address mask;
    } filter;
} bbf_mac_address_match;

/* ethertype-match */
typedef uint16_t bbf_ethertype_match;

/* tag-index: 0..1 */
typedef uint8_t bbf_tag_index;

typedef enum
{
    BBF_TAG_INDEX_TYPE_OUTER,
    BBF_TAG_INDEX_TYPE_INNER,
} bbf_tag_index_type;

/* dot1q-tag-ranges-or-any */
typedef struct bbf_dot1q_tag
{
    uint32_t presence_mask;
    uint16_t tag_type;
    bbf_vlan_id vlan_id;
    bbf_pbit pbit;
    bbf_dei dei;
} bbf_dot1q_tag;

typedef enum {
    bbf_dot1q_tag_prop_id_tag_type,
    bbf_dot1q_tag_prop_id_vlan_id,
    bbf_dot1q_tag_prop_id_pbit,
    bbf_dot1q_tag_prop_id_dei
} bbf_dot1q_tag_prop_id;

#define BBF_DOT1Q_TAG_PROP_SET(_tag, _prop, _val) \
    do { \
        (_tag)->presence_mask |= (1 << bbf_dot1q_tag_prop_id_ ## _prop);\
        (_tag)->_prop = _val; \
    } while (0)

#define BBF_DOT1Q_TAG_PROP_IS_SET(_tag, _prop) \
    (((_tag)->presence_mask & (1 << bbf_dot1q_tag_prop_id_ ## _prop)) != 0)

/* vlan-tag-match-type */
typedef enum
{
    BBF_VLAN_TAG_MATCH_TYPE_ALL,
    BBF_VLAN_TAG_MATCH_TYPE_UNTAGGED,
    BBF_VLAN_TAG_MATCH_TYPE_VLAN_TAGGED,
} bbf_vlan_tag_match_type;

typedef struct bbf_multiple_vlan_tag_match
{
    bbf_vlan_tag_match_type tag_match_types[2]; /* indexed by bbf_tag_index_type. 0=outer */
    bbf_dot1q_tag tags[2];
    uint8_t num_tags;
} bbf_multiple_vlan_tag_match;

/* protocol-match */
typedef enum
{
    BBF_PROTOCOL_MATCH_ANY              = 0,
    BBF_PROTOCOL_MATCH_IGMP             = 0x1,      /* IP protocol type = 2 */
    BBF_PROTOCOL_MATCH_MLD              = 0x2,      /* IPv6 protocol type = 58 */
    BBF_PROTOCOL_MATCH_DHCPV4           = 0x4,      /* client: UDP src port=68, dst port=67 server: src port=67, dst port=68 */
    BBF_PROTOCOL_MATCH_DHCPV6           = 0x8,      /* client: UDP src port=547, dst port=548 server: src port=548, dst port=547 */
    BBF_PROTOCOL_MATCH_PPPOE_DISCOVERY  = 0x10,     /* ethertype=0x8863 */
#define ETHER_TYPE_PPPOE_DISCOVERY  0x8863
    BBF_PROTOCOL_MATCH_PPPOE_DATA       = 0x20,     /* ethertype=0x8864 */
#define ETHER_TYPE_PPPOE_DATA       0x8864
    BBF_PROTOCOL_MATCH_ARP              = 0x40,     /* ethertype=0x0806 */
#define ETHER_TYPE_ARP              0x0806
    BBF_PROTOCOL_MATCH_DOT1X            = 0x80,     /* ethertype=0x888E */
#define ETHER_TYPE_DOT1X            0x888E
    BBF_PROTOCOL_MATCH_LACP             = 0x100,    /* ethertype=0x8809 */
#define ETHER_TYPE_LACP             0x8809
    BBF_PROTOCOL_MATCH_IPV4             = 0x200,    /* ethertype=0x0800 */
#define ETHER_TYPE_IPV4             0x0800
    BBF_PROTOCOL_MATCH_IPV6             = 0x400,    /* ethertype=0x86DD */
#define ETHER_TYPE_IPV6             0x86DD
    BBF_PROTOCOL_MATCH_SPECIFIC         = 0x8000,   /* other specific ethernet type */
} bbf_protocol_match_type;

typedef struct bbf_protocol_match
{
    bbf_protocol_match_type match_type;
    uint16_t ether_type;
} bbf_protocol_match;

typedef struct bbf_match_criteria
{
    bbf_mac_address_match frame_destination_match;
    bbf_multiple_vlan_tag_match vlan_tag_match;
    bbf_protocol_match protocol_match;
} bbf_match_criteria;
/* flixible-rewrite */
typedef struct bbf_flexible_rewrite
{
    uint8_t num_pop_tags;
    uint8_t num_push_tags;
    bbf_dot1q_tag push_tags[2];
} bbf_flexible_rewrite;

/* interface-usage */
typedef enum
{
    BBF_INTERFACE_USAGE_UNDEFINED,
    BBF_INTERFACE_USAGE_NETWORK_PORT,   /* Connects access node to the network */
    BBF_INTERFACE_USAGE_SUBTENDED_NODE_PORT, /* Connects access node to another access node */
    BBF_INTERFACE_USAGE_INHERIT,        /* Inherit from lower-layer interface */
} bbf_interface_usage;

#endif /* _BBF_TYPES_H_ */
