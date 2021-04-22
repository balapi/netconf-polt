#ifndef _ONU_MGMT_MODEL_SUPPORTING_STRUCTS_H_
#define _ONU_MGMT_MODEL_SUPPORTING_STRUCTS_H_

/** \addtogroup api_data_types
 * @{
 */

#include <bcmos_system.h>
#include "onu_mgmt_model_supporting_typedefs.h"

typedef uint64_t bcmonu_mgmt_presence_mask;

/** Aggregate Port */
typedef struct
{
    bcmonu_mgmt_presence_mask presence_mask;
    uint16_t entity_id; /**< Entity ID */
    bcmonu_mgmt_agg_port_id agg_port_id; /**< Aggregate port ID */
} bcmonu_mgmt_agg_port_list_entry;

/* Constants associated with bcmonu_mgmt_agg_port_list_entry. */
#define BCMONU_MGMT_AGG_PORT_LIST_ENTRY_PRESENCE_MASK_ALL 0x0000000000000003ULL

/** Fixed-Length list: 64x agg_port_list_entry */
typedef struct
{
    bcmonu_mgmt_presence_mask arr_index_mask; /**< Bitmask of present array element indices. */
    bcmonu_mgmt_agg_port_list_entry arr[64]; /**< Array. */
} bcmonu_mgmt_arr_agg_port_list_entry_64;

/** Priority queue */
typedef struct
{
    bcmonu_mgmt_presence_mask presence_mask;
    uint16_t entity_id; /**< Entity ID */
    uint16_t port; /**< Port */
} bcmonu_mgmt_priority_queue;

/* Constants associated with bcmonu_mgmt_priority_queue. */
#define BCMONU_MGMT_PRIORITY_QUEUE_PRESENCE_MASK_ALL 0x0000000000000003ULL

/** Fixed-Length list: 128x priority_queue */
typedef struct
{
    bcmonu_mgmt_presence_mask arr_index_mask; /**< Bitmask of present array element indices. */
    bcmonu_mgmt_priority_queue arr[128]; /**< Array. */
} bcmonu_mgmt_arr_priority_queue_128;

/** UNI */
typedef struct
{
    bcmonu_mgmt_presence_mask presence_mask;
    uint16_t entity_id; /**< Entity ID */
    bcmonu_mgmt_uni_type type; /**< Type */
} bcmonu_mgmt_uni;

/* Constants associated with bcmonu_mgmt_uni. */
#define BCMONU_MGMT_UNI_PRESENCE_MASK_ALL 0x0000000000000003ULL

/** Fixed-Length list: 8x uni */
typedef struct
{
    bcmonu_mgmt_presence_mask arr_index_mask; /**< Bitmask of present array element indices. */
    bcmonu_mgmt_uni arr[8]; /**< Array. */
} bcmonu_mgmt_arr_uni_8;

/** Action presence mask */
typedef struct
{
    bcmonu_mgmt_presence_mask presence_mask;
    bcmonu_mgmt_flow_action_type_id type; /**< A bit combination of actions */
    uint8_t o_pcp; /**< Outer PCP */
    uint16_t o_vid; /**< Outer VID */
    uint8_t i_pcp; /**< Inner PCP */
    uint16_t i_vid; /**< Inner VID */
} bcmonu_mgmt_flow_action;

/* Constants associated with bcmonu_mgmt_flow_action. */
#define BCMONU_MGMT_FLOW_ACTION_PRESENCE_MASK_ALL 0x000000000000001FULL
#define BCMONU_MGMT_FLOW_ACTION_O_PCP_MIN 0
#define BCMONU_MGMT_FLOW_ACTION_O_PCP_MAX 7
#define BCMONU_MGMT_FLOW_ACTION_O_VID_MIN 0U
#define BCMONU_MGMT_FLOW_ACTION_O_VID_MAX 4095U
#define BCMONU_MGMT_FLOW_ACTION_I_PCP_MIN 0
#define BCMONU_MGMT_FLOW_ACTION_I_PCP_MAX 7
#define BCMONU_MGMT_FLOW_ACTION_I_VID_MIN 0U
#define BCMONU_MGMT_FLOW_ACTION_I_VID_MAX 4095U

/** Match presence mask */
typedef struct
{
    bcmonu_mgmt_presence_mask presence_mask;
    uint16_t ether_type; /**< Ethernet type */
    uint8_t o_pcp; /**< Outer PCP */
    uint16_t o_vid; /**< Outer VID */
    uint8_t i_pcp; /**< Inner PCP */
    uint16_t i_vid; /**< Inner VID */
    bcmos_bool o_untagged; /**< Outer tag not present. */
    bcmos_bool i_untagged; /**< Untagged Packet. */
} bcmonu_mgmt_flow_match;

/* Constants associated with bcmonu_mgmt_flow_match. */
#define BCMONU_MGMT_FLOW_MATCH_PRESENCE_MASK_ALL 0x000000000000007FULL
#define BCMONU_MGMT_FLOW_MATCH_O_PCP_MIN 0
#define BCMONU_MGMT_FLOW_MATCH_O_PCP_MAX 7
#define BCMONU_MGMT_FLOW_MATCH_O_VID_MIN 0U
#define BCMONU_MGMT_FLOW_MATCH_O_VID_MAX 4095U
#define BCMONU_MGMT_FLOW_MATCH_I_PCP_MIN 0
#define BCMONU_MGMT_FLOW_MATCH_I_PCP_MAX 7
#define BCMONU_MGMT_FLOW_MATCH_I_VID_MIN 0U
#define BCMONU_MGMT_FLOW_MATCH_I_VID_MAX 4095U

/** ONU key */
typedef struct
{
    bcmonu_mgmt_presence_mask presence_mask;
    uint8_t pon_ni; /**< PON Interface ID */
    uint16_t onu_id; /**< ONU ID */
} bcmonu_mgmt_flow_onu_key;

/* Constants associated with bcmonu_mgmt_flow_onu_key. */
#define BCMONU_MGMT_FLOW_ONU_KEY_PRESENCE_MASK_ALL 0x0000000000000003ULL

/** Action presence mask */
typedef struct
{
    bcmonu_mgmt_presence_mask presence_mask;
    bcmonu_mgmt_igmp_us_action_type_id type; /**< A bit combination of actions */
    uint8_t pcp; /**< IGMP PCP */
    uint16_t vid; /**< IGMP VID */
} bcmonu_mgmt_igmp_us_action;

/* Constants associated with bcmonu_mgmt_igmp_us_action. */
#define BCMONU_MGMT_IGMP_US_ACTION_PRESENCE_MASK_ALL 0x0000000000000007ULL
#define BCMONU_MGMT_IGMP_US_ACTION_PCP_MIN 0
#define BCMONU_MGMT_IGMP_US_ACTION_PCP_MAX 7
#define BCMONU_MGMT_IGMP_US_ACTION_VID_MIN 0U
#define BCMONU_MGMT_IGMP_US_ACTION_VID_MAX 4095U



/** @} */

#endif /* _ONU_MGMT_MODEL_SUPPORTING_STRUCTS_H_ */
