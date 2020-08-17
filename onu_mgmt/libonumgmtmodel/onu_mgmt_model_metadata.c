#include <bcmos_system.h>
#include <bcmolt_type_metadata.h>
#include "onu_mgmt_model_metadata.h"
#include "onu_mgmt_model_tags.h"

/* allow possibly unused descriptors to make the code easier to generate */
#ifdef __GNUC__
#define BCM_DESCR __attribute__ ((unused))
#else
#define BCM_DESCR
#endif

/** ===== Tags ===== */
static bcmolt_tag_descr tags[] =
{
};
/** ===== Types ===== */
const bcmolt_enum_val bcmonu_mgmt_admin_state_string_table[] =
{
    { .name = "down", .val = BCMONU_MGMT_ADMIN_STATE_DOWN, .tags = 0 },
    { .name = "up", .val = BCMONU_MGMT_ADMIN_STATE_UP, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_admin_state =
{
    .name = "admin_state",
    .descr = "Administrative state",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM,
    .size = sizeof(bcmonu_mgmt_admin_state),
    .x = { .e = { .base_type = &type_descr_uint8_t,.vals = bcmonu_mgmt_admin_state_string_table } },
};

static bcmolt_field_descr type_descr_bcmonu_mgmt_agg_port_list_entry_fields[] =
{
    {
        .name = "entity_id",
        .descr = "Entity ID",
        .id = BCMONU_MGMT_AGG_PORT_LIST_ENTRY_ID_ENTITY_ID,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_agg_port_list_entry, entity_id),
        .type = &type_descr_uint16_t,
    },
    {
        .name = "agg_port_id",
        .descr = "Aggregate port ID",
        .id = BCMONU_MGMT_AGG_PORT_LIST_ENTRY_ID_AGG_PORT_ID,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_agg_port_list_entry, agg_port_id),
        .type = &type_descr_uint16_t,
    },
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_agg_port_list_entry =
{
    .name = "agg_port_list_entry",
    .descr = "Aggregate Port",
    .size = sizeof(bcmonu_mgmt_agg_port_list_entry),
    .mask_offset = offsetof(bcmonu_mgmt_agg_port_list_entry, presence_mask),
    .base_type = BCMOLT_BASE_TYPE_ID_STRUCT,
    .x = { .s = { .num_fields = sizeof(type_descr_bcmonu_mgmt_agg_port_list_entry_fields) / sizeof(bcmolt_field_descr), .fields = type_descr_bcmonu_mgmt_agg_port_list_entry_fields } },
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_arr_agg_port_list_entry_64 =
{
    .name = "arr_agg_port_list_entry_64",
    .descr = "Fixed-Length list: 64x agg_port_list_entry",
    .size = sizeof(bcmonu_mgmt_arr_agg_port_list_entry_64),
    .mask_offset = offsetof(bcmonu_mgmt_arr_agg_port_list_entry_64, arr_index_mask),
    .base_type = BCMOLT_BASE_TYPE_ID_ARR_FIXED,
    .x = { .arr_fixed = { .elem_type = &type_descr_bcmonu_mgmt_agg_port_list_entry, .data_offset = offsetof(bcmonu_mgmt_arr_agg_port_list_entry_64, arr), .size = 64 } },
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_arr_priority_queue_128 =
{
    .name = "arr_priority_queue_128",
    .descr = "Fixed-Length list: 128x priority_queue",
    .size = sizeof(bcmonu_mgmt_arr_priority_queue_128),
    .mask_offset = offsetof(bcmonu_mgmt_arr_priority_queue_128, arr_index_mask),
    .base_type = BCMOLT_BASE_TYPE_ID_ARR_FIXED,
    .x = { .arr_fixed = { .elem_type = &type_descr_bcmonu_mgmt_priority_queue, .data_offset = offsetof(bcmonu_mgmt_arr_priority_queue_128, arr), .size = 128 } },
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_arr_uni_8 =
{
    .name = "arr_uni_8",
    .descr = "Fixed-Length list: 8x uni",
    .size = sizeof(bcmonu_mgmt_arr_uni_8),
    .mask_offset = offsetof(bcmonu_mgmt_arr_uni_8, arr_index_mask),
    .base_type = BCMOLT_BASE_TYPE_ID_ARR_FIXED,
    .x = { .arr_fixed = { .elem_type = &type_descr_bcmonu_mgmt_uni, .data_offset = offsetof(bcmonu_mgmt_arr_uni_8, arr), .size = 8 } },
};

const bcmolt_enum_val bcmonu_mgmt_downstream_mode_values_string_table[] =
{
    { .name = "inverse", .val = BCMONU_MGMT_DOWNSTREAM_MODE_VALUES_INVERSE, .tags = 0 },
    { .name = "match_vid_inverse_vid_forward_no_match", .val = BCMONU_MGMT_DOWNSTREAM_MODE_VALUES_MATCH_VID_INVERSE_VID_FORWARD_NO_MATCH, .tags = 0 },
    { .name = "match_vid_inverse_vid_discard_no_match", .val = BCMONU_MGMT_DOWNSTREAM_MODE_VALUES_MATCH_VID_INVERSE_VID_DISCARD_NO_MATCH, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_downstream_mode_values =
{
    .name = "downstream_mode_values",
    .descr = "downstream mode attribute values in OMCI Ext Vlan tag ME",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM,
    .size = sizeof(bcmonu_mgmt_downstream_mode_values),
    .x = { .e = { .base_type = &type_descr_uint8_t,.vals = bcmonu_mgmt_downstream_mode_values_string_table } },
};

static bcmolt_field_descr type_descr_bcmonu_mgmt_flow_action_fields[] =
{
    {
        .name = "type",
        .descr = "A bit combination of actions",
        .id = BCMONU_MGMT_FLOW_ACTION_ID_TYPE,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_action, type),
        .type = &type_descr_bcmonu_mgmt_flow_action_type_id,
    },
    {
        .name = "o_pcp",
        .descr = "Outer PCP",
        .id = BCMONU_MGMT_FLOW_ACTION_ID_O_PCP,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_action, o_pcp),
        .type = &type_descr_uint8_t,
    },
    {
        .name = "o_vid",
        .descr = "Outer VID",
        .id = BCMONU_MGMT_FLOW_ACTION_ID_O_VID,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_action, o_vid),
        .type = &type_descr_uint16_t,
    },
    {
        .name = "i_pcp",
        .descr = "Inner PCP",
        .id = BCMONU_MGMT_FLOW_ACTION_ID_I_PCP,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_action, i_pcp),
        .type = &type_descr_uint8_t,
    },
    {
        .name = "i_vid",
        .descr = "Inner VID",
        .id = BCMONU_MGMT_FLOW_ACTION_ID_I_VID,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_action, i_vid),
        .type = &type_descr_uint16_t,
    },
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_action =
{
    .name = "flow_action",
    .descr = "Action presence mask",
    .size = sizeof(bcmonu_mgmt_flow_action),
    .mask_offset = offsetof(bcmonu_mgmt_flow_action, presence_mask),
    .base_type = BCMOLT_BASE_TYPE_ID_STRUCT,
    .x = { .s = { .num_fields = sizeof(type_descr_bcmonu_mgmt_flow_action_fields) / sizeof(bcmolt_field_descr), .fields = type_descr_bcmonu_mgmt_flow_action_fields } },
};

const bcmolt_enum_val bcmonu_mgmt_flow_action_type_id_string_table[] =
{
    { .name = "none", .val = BCMONU_MGMT_FLOW_ACTION_TYPE_ID_NONE },
    { .name = "push", .val = BCMONU_MGMT_FLOW_ACTION_TYPE_ID_PUSH, .tags = 0 },
    { .name = "pop", .val = BCMONU_MGMT_FLOW_ACTION_TYPE_ID_POP, .tags = 0 },
    { .name = "translate_pcp", .val = BCMONU_MGMT_FLOW_ACTION_TYPE_ID_TRANSLATE_PCP, .tags = 0 },
    { .name = "translate_vid", .val = BCMONU_MGMT_FLOW_ACTION_TYPE_ID_TRANSLATE_VID, .tags = 0 },
    { .name = "push_inner_tag", .val = BCMONU_MGMT_FLOW_ACTION_TYPE_ID_PUSH_INNER_TAG, .tags = 0 },
    { .name = "pop_inner_tag", .val = BCMONU_MGMT_FLOW_ACTION_TYPE_ID_POP_INNER_TAG, .tags = 0 },
    { .name = "translate_inner_pcp", .val = BCMONU_MGMT_FLOW_ACTION_TYPE_ID_TRANSLATE_INNER_PCP, .tags = 0 },
    { .name = "translate_inner_vid", .val = BCMONU_MGMT_FLOW_ACTION_TYPE_ID_TRANSLATE_INNER_VID, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_action_type_id =
{
    .name = "flow_action_type_id",
    .descr = "Action type",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM_MASK,
    .size = sizeof(bcmonu_mgmt_flow_action_type_id),
    .x = { .e = { .base_type = &type_descr_uint8_t,.vals = bcmonu_mgmt_flow_action_type_id_string_table } },
};

const bcmolt_enum_val bcmonu_mgmt_flow_dir_id_string_table[] =
{
    { .name = "upstream", .val = BCMONU_MGMT_FLOW_DIR_ID_UPSTREAM, .tags = 0 },
    { .name = "downstream", .val = BCMONU_MGMT_FLOW_DIR_ID_DOWNSTREAM, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_dir_id =
{
    .name = "flow_dir_id",
    .descr = "Flow direction",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM,
    .size = sizeof(bcmonu_mgmt_flow_dir_id),
    .x = { .e = { .base_type = &type_descr_uint8_t,.vals = bcmonu_mgmt_flow_dir_id_string_table } },
};

static bcmolt_field_descr type_descr_bcmonu_mgmt_flow_match_fields[] =
{
    {
        .name = "ether_type",
        .descr = "Ethernet type",
        .id = BCMONU_MGMT_FLOW_MATCH_ID_ETHER_TYPE,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_match, ether_type),
        .type = &type_descr_uint16_t_hex,
    },
    {
        .name = "o_pcp",
        .descr = "Outer PCP",
        .id = BCMONU_MGMT_FLOW_MATCH_ID_O_PCP,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_match, o_pcp),
        .type = &type_descr_uint8_t,
    },
    {
        .name = "o_vid",
        .descr = "Outer VID",
        .id = BCMONU_MGMT_FLOW_MATCH_ID_O_VID,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_match, o_vid),
        .type = &type_descr_uint16_t,
    },
    {
        .name = "i_pcp",
        .descr = "Inner PCP",
        .id = BCMONU_MGMT_FLOW_MATCH_ID_I_PCP,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_match, i_pcp),
        .type = &type_descr_uint8_t,
    },
    {
        .name = "i_vid",
        .descr = "Inner VID",
        .id = BCMONU_MGMT_FLOW_MATCH_ID_I_VID,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_match, i_vid),
        .type = &type_descr_uint16_t,
    },
    {
        .name = "o_untagged",
        .descr = "Outer tag not present",
        .id = BCMONU_MGMT_FLOW_MATCH_ID_O_UNTAGGED,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_match, o_untagged),
        .type = &type_descr_bcmos_bool,
    },
    {
        .name = "i_untagged",
        .descr = "Untagged Packet",
        .id = BCMONU_MGMT_FLOW_MATCH_ID_I_UNTAGGED,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_match, i_untagged),
        .type = &type_descr_bcmos_bool,
    },
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_match =
{
    .name = "flow_match",
    .descr = "Match presence mask",
    .size = sizeof(bcmonu_mgmt_flow_match),
    .mask_offset = offsetof(bcmonu_mgmt_flow_match, presence_mask),
    .base_type = BCMOLT_BASE_TYPE_ID_STRUCT,
    .x = { .s = { .num_fields = sizeof(type_descr_bcmonu_mgmt_flow_match_fields) / sizeof(bcmolt_field_descr), .fields = type_descr_bcmonu_mgmt_flow_match_fields } },
};

static bcmolt_field_descr type_descr_bcmonu_mgmt_flow_onu_key_fields[] =
{
    {
        .name = "pon_ni",
        .descr = "PON Interface ID",
        .id = BCMONU_MGMT_FLOW_ONU_KEY_ID_PON_NI,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_onu_key, pon_ni),
        .type = &type_descr_uint8_t,
    },
    {
        .name = "onu_id",
        .descr = "ONU ID",
        .id = BCMONU_MGMT_FLOW_ONU_KEY_ID_ONU_ID,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_onu_key, onu_id),
        .type = &type_descr_uint16_t,
    },
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_onu_key =
{
    .name = "flow_onu_key",
    .descr = "ONU key",
    .size = sizeof(bcmonu_mgmt_flow_onu_key),
    .mask_offset = offsetof(bcmonu_mgmt_flow_onu_key, presence_mask),
    .base_type = BCMOLT_BASE_TYPE_ID_STRUCT,
    .x = { .s = { .num_fields = sizeof(type_descr_bcmonu_mgmt_flow_onu_key_fields) / sizeof(bcmolt_field_descr), .fields = type_descr_bcmonu_mgmt_flow_onu_key_fields } },
};

const bcmolt_enum_val bcmonu_mgmt_flow_type_string_table[] =
{
    { .name = "invalid", .val = BCMONU_MGMT_FLOW_TYPE_INVALID, .tags = 0 },
    { .name = "unicast", .val = BCMONU_MGMT_FLOW_TYPE_UNICAST, .tags = 0 },
    { .name = "multicast", .val = BCMONU_MGMT_FLOW_TYPE_MULTICAST, .tags = 0 },
    { .name = "broadcast", .val = BCMONU_MGMT_FLOW_TYPE_BROADCAST, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_type =
{
    .name = "flow_type",
    .descr = "Flow type",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM,
    .size = sizeof(bcmonu_mgmt_flow_type),
    .x = { .e = { .base_type = &type_descr_uint8_t,.vals = bcmonu_mgmt_flow_type_string_table } },
};

static bcmolt_field_descr type_descr_bcmonu_mgmt_igmp_us_action_fields[] =
{
    {
        .name = "type",
        .descr = "A bit combination of actions",
        .id = BCMONU_MGMT_IGMP_US_ACTION_ID_TYPE,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_igmp_us_action, type),
        .type = &type_descr_bcmonu_mgmt_igmp_us_action_type_id,
    },
    {
        .name = "pcp",
        .descr = "IGMP PCP",
        .id = BCMONU_MGMT_IGMP_US_ACTION_ID_PCP,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_igmp_us_action, pcp),
        .type = &type_descr_uint8_t,
    },
    {
        .name = "vid",
        .descr = "IGMP VID",
        .id = BCMONU_MGMT_IGMP_US_ACTION_ID_VID,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_igmp_us_action, vid),
        .type = &type_descr_uint16_t,
    },
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_igmp_us_action =
{
    .name = "igmp_us_action",
    .descr = "Action presence mask",
    .size = sizeof(bcmonu_mgmt_igmp_us_action),
    .mask_offset = offsetof(bcmonu_mgmt_igmp_us_action, presence_mask),
    .base_type = BCMOLT_BASE_TYPE_ID_STRUCT,
    .x = { .s = { .num_fields = sizeof(type_descr_bcmonu_mgmt_igmp_us_action_fields) / sizeof(bcmolt_field_descr), .fields = type_descr_bcmonu_mgmt_igmp_us_action_fields } },
};

const bcmolt_enum_val bcmonu_mgmt_igmp_us_action_type_id_string_table[] =
{
    { .name = "none", .val = BCMONU_MGMT_IGMP_US_ACTION_TYPE_ID_NONE },
    { .name = "add_vlan_tag", .val = BCMONU_MGMT_IGMP_US_ACTION_TYPE_ID_ADD_VLAN_TAG, .tags = 0 },
    { .name = "replace_tci", .val = BCMONU_MGMT_IGMP_US_ACTION_TYPE_ID_REPLACE_TCI, .tags = 0 },
    { .name = "replace_vid", .val = BCMONU_MGMT_IGMP_US_ACTION_TYPE_ID_REPLACE_VID, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_igmp_us_action_type_id =
{
    .name = "igmp_us_action_type_id",
    .descr = "Action type for IGMP on Upstream",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM_MASK,
    .size = sizeof(bcmonu_mgmt_igmp_us_action_type_id),
    .x = { .e = { .base_type = &type_descr_uint8_t,.vals = bcmonu_mgmt_igmp_us_action_type_id_string_table } },
};

static bcmolt_field_descr type_descr_bcmonu_mgmt_priority_queue_fields[] =
{
    {
        .name = "entity_id",
        .descr = "Entity ID",
        .id = BCMONU_MGMT_PRIORITY_QUEUE_ID_ENTITY_ID,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_priority_queue, entity_id),
        .type = &type_descr_uint16_t,
    },
    {
        .name = "port",
        .descr = "Port",
        .id = BCMONU_MGMT_PRIORITY_QUEUE_ID_PORT,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_priority_queue, port),
        .type = &type_descr_uint16_t,
    },
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_priority_queue =
{
    .name = "priority_queue",
    .descr = "Priority queue",
    .size = sizeof(bcmonu_mgmt_priority_queue),
    .mask_offset = offsetof(bcmonu_mgmt_priority_queue, presence_mask),
    .base_type = BCMOLT_BASE_TYPE_ID_STRUCT,
    .x = { .s = { .num_fields = sizeof(type_descr_bcmonu_mgmt_priority_queue_fields) / sizeof(bcmolt_field_descr), .fields = type_descr_bcmonu_mgmt_priority_queue_fields } },
};

const bcmolt_enum_val bcmonu_mgmt_status_string_table[] =
{
    { .name = "up", .val = BCMONU_MGMT_STATUS_UP, .tags = 0 },
    { .name = "down", .val = BCMONU_MGMT_STATUS_DOWN, .tags = 0 },
    { .name = "unknown", .val = BCMONU_MGMT_STATUS_UNKNOWN, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_status =
{
    .name = "status",
    .descr = "Operational Status",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM,
    .size = sizeof(bcmonu_mgmt_status),
    .x = { .e = { .base_type = &type_descr_uint32_t,.vals = bcmonu_mgmt_status_string_table } },
};

static bcmolt_field_descr type_descr_bcmonu_mgmt_uni_fields[] =
{
    {
        .name = "entity_id",
        .descr = "Entity ID",
        .id = BCMONU_MGMT_UNI_ID_ENTITY_ID,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_uni, entity_id),
        .type = &type_descr_uint16_t,
    },
    {
        .name = "type",
        .descr = "Type",
        .id = BCMONU_MGMT_UNI_ID_TYPE,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_uni, type),
        .type = &type_descr_bcmonu_mgmt_uni_type,
    },
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_uni =
{
    .name = "uni",
    .descr = "UNI",
    .size = sizeof(bcmonu_mgmt_uni),
    .mask_offset = offsetof(bcmonu_mgmt_uni, presence_mask),
    .base_type = BCMOLT_BASE_TYPE_ID_STRUCT,
    .x = { .s = { .num_fields = sizeof(type_descr_bcmonu_mgmt_uni_fields) / sizeof(bcmolt_field_descr), .fields = type_descr_bcmonu_mgmt_uni_fields } },
};

const bcmolt_enum_val bcmonu_mgmt_uni_type_string_table[] =
{
    { .name = "invalid", .val = BCMONU_MGMT_UNI_TYPE_INVALID, .tags = 0 },
    { .name = "pptp", .val = BCMONU_MGMT_UNI_TYPE_PPTP, .tags = 0 },
    { .name = "veip", .val = BCMONU_MGMT_UNI_TYPE_VEIP, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_uni_type =
{
    .name = "uni_type",
    .descr = "UNI type",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM,
    .size = sizeof(bcmonu_mgmt_uni_type),
    .x = { .e = { .base_type = &type_descr_uint8_t,.vals = bcmonu_mgmt_uni_type_string_table } },
};

static bcmolt_field_descr type_descr_bcmonu_mgmt_flow_cfg_data_fields[] =
{
    {
        .name = "admin_state",
        .descr = "Administrative state",
        .id = BCMONU_MGMT_FLOW_CFG_DATA_ID_ADMIN_STATE,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_cfg_data, admin_state),
        .type = &type_descr_bcmonu_mgmt_admin_state,
    },
    {
        .name = "oper_status",
        .descr = "Operational status",
        .id = BCMONU_MGMT_FLOW_CFG_DATA_ID_OPER_STATUS,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_cfg_data, oper_status),
        .type = &type_descr_bcmonu_mgmt_status,
        .flags = BCMOLT_FIELD_FLAGS_READ_ONLY,
    },
    {
        .name = "onu_key",
        .descr = "ONU Key",
        .id = BCMONU_MGMT_FLOW_CFG_DATA_ID_ONU_KEY,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_cfg_data, onu_key),
        .type = &type_descr_bcmonu_mgmt_flow_onu_key,
    },
    {
        .name = "flow_type",
        .descr = "Flow type",
        .id = BCMONU_MGMT_FLOW_CFG_DATA_ID_FLOW_TYPE,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_cfg_data, flow_type),
        .type = &type_descr_bcmonu_mgmt_flow_type,
    },
    {
        .name = "svc_port_id",
        .descr = "Service Port ID",
        .id = BCMONU_MGMT_FLOW_CFG_DATA_ID_SVC_PORT_ID,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_cfg_data, svc_port_id),
        .type = &type_descr_uint16_t,
    },
    {
        .name = "agg_port_id",
        .descr = "Aggregate Port ID",
        .id = BCMONU_MGMT_FLOW_CFG_DATA_ID_AGG_PORT_ID,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_cfg_data, agg_port_id),
        .type = &type_descr_uint16_t,
    },
    {
        .name = "uni_port",
        .descr = "UNI port",
        .id = BCMONU_MGMT_FLOW_CFG_DATA_ID_UNI_PORT,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_cfg_data, uni_port),
        .type = &type_descr_uint16_t,
    },
    {
        .name = "match",
        .descr = "Match",
        .id = BCMONU_MGMT_FLOW_CFG_DATA_ID_MATCH,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_cfg_data, match),
        .type = &type_descr_bcmonu_mgmt_flow_match,
    },
    {
        .name = "action",
        .descr = "Action",
        .id = BCMONU_MGMT_FLOW_CFG_DATA_ID_ACTION,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_cfg_data, action),
        .type = &type_descr_bcmonu_mgmt_flow_action,
    },
    {
        .name = "igmp_us_action",
        .descr = "IGMP action on Upstream",
        .id = BCMONU_MGMT_FLOW_CFG_DATA_ID_IGMP_US_ACTION,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_cfg_data, igmp_us_action),
        .type = &type_descr_bcmonu_mgmt_igmp_us_action,
    },
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_cfg_data =
{
    .name = "flow_cfg_data",
    .descr = "Flow: cfg",
    .size = sizeof(bcmonu_mgmt_flow_cfg_data),
    .mask_offset = offsetof(bcmonu_mgmt_flow_cfg_data, presence_mask),
    .base_type = BCMOLT_BASE_TYPE_ID_STRUCT,
    .x = { .s = { .num_fields = sizeof(type_descr_bcmonu_mgmt_flow_cfg_data_fields) / sizeof(bcmolt_field_descr), .fields = type_descr_bcmonu_mgmt_flow_cfg_data_fields } },
};

static bcmolt_field_descr type_descr_bcmonu_mgmt_flow_key_fields[] =
{
    {
        .name = "id",
        .descr = "Flow ID",
        .id = BCMOLT_FIELD_DESCR_ID_NONE,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_key, id),
        .type = &type_descr_uint32_t,
    },
    {
        .name = "dir",
        .descr = "Flow direction",
        .id = BCMOLT_FIELD_DESCR_ID_NONE,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_flow_key, dir),
        .type = &type_descr_bcmonu_mgmt_flow_dir_id,
    },
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_key =
{
    .name = "flow_key",
    .descr = "Flow: key",
    .size = sizeof(bcmonu_mgmt_flow_key),
    .mask_offset = BCMOLT_TYPE_DESCR_NO_MASK,
    .base_type = BCMOLT_BASE_TYPE_ID_STRUCT,
    .x = { .s = { .num_fields = sizeof(type_descr_bcmonu_mgmt_flow_key_fields) / sizeof(bcmolt_field_descr), .fields = type_descr_bcmonu_mgmt_flow_key_fields } },
};

static bcmolt_field_descr type_descr_bcmonu_mgmt_onu_cfg_data_fields[] =
{
    {
        .name = "admin_state",
        .descr = "Administrative state",
        .id = BCMONU_MGMT_ONU_CFG_DATA_ID_ADMIN_STATE,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_onu_cfg_data, admin_state),
        .type = &type_descr_bcmonu_mgmt_admin_state,
    },
    {
        .name = "oper_status",
        .descr = "Operational status",
        .id = BCMONU_MGMT_ONU_CFG_DATA_ID_OPER_STATUS,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_onu_cfg_data, oper_status),
        .type = &type_descr_bcmonu_mgmt_status,
        .flags = BCMOLT_FIELD_FLAGS_READ_ONLY,
    },
    {
        .name = "input_tpid",
        .descr = "Input TPID",
        .id = BCMONU_MGMT_ONU_CFG_DATA_ID_INPUT_TPID,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_onu_cfg_data, input_tpid),
        .type = &type_descr_uint16_t_hex,
    },
    {
        .name = "output_tpid",
        .descr = "Output TPID",
        .id = BCMONU_MGMT_ONU_CFG_DATA_ID_OUTPUT_TPID,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_onu_cfg_data, output_tpid),
        .type = &type_descr_uint16_t_hex,
    },
    {
        .name = "unis",
        .descr = "UNIs",
        .id = BCMONU_MGMT_ONU_CFG_DATA_ID_UNIS,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_onu_cfg_data, unis),
        .type = &type_descr_bcmonu_mgmt_arr_uni_8,
    },
    {
        .name = "num_of_unis",
        .descr = "Number of UNIs",
        .id = BCMONU_MGMT_ONU_CFG_DATA_ID_NUM_OF_UNIS,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_onu_cfg_data, num_of_unis),
        .type = &type_descr_uint32_t,
    },
    {
        .name = "agg_ports",
        .descr = "T-CONTs",
        .id = BCMONU_MGMT_ONU_CFG_DATA_ID_AGG_PORTS,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_onu_cfg_data, agg_ports),
        .type = &type_descr_bcmonu_mgmt_arr_agg_port_list_entry_64,
    },
    {
        .name = "num_of_agg_ports",
        .descr = "Number of T-CONTs",
        .id = BCMONU_MGMT_ONU_CFG_DATA_ID_NUM_OF_AGG_PORTS,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_onu_cfg_data, num_of_agg_ports),
        .type = &type_descr_uint32_t,
    },
    {
        .name = "us_priority_queues",
        .descr = "US priority queues",
        .id = BCMONU_MGMT_ONU_CFG_DATA_ID_US_PRIORITY_QUEUES,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_onu_cfg_data, us_priority_queues),
        .type = &type_descr_bcmonu_mgmt_arr_priority_queue_128,
    },
    {
        .name = "num_of_us_priority_queues",
        .descr = "Number of US priority queues",
        .id = BCMONU_MGMT_ONU_CFG_DATA_ID_NUM_OF_US_PRIORITY_QUEUES,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_onu_cfg_data, num_of_us_priority_queues),
        .type = &type_descr_uint32_t,
    },
    {
        .name = "ds_priority_queues",
        .descr = "DS priority queues",
        .id = BCMONU_MGMT_ONU_CFG_DATA_ID_DS_PRIORITY_QUEUES,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_onu_cfg_data, ds_priority_queues),
        .type = &type_descr_bcmonu_mgmt_arr_priority_queue_128,
    },
    {
        .name = "num_of_ds_priority_queues",
        .descr = "Number of DS priority queues",
        .id = BCMONU_MGMT_ONU_CFG_DATA_ID_NUM_OF_DS_PRIORITY_QUEUES,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_onu_cfg_data, num_of_ds_priority_queues),
        .type = &type_descr_uint32_t,
    },
    {
        .name = "downstream_mode",
        .descr = "downstream frames tagging action based on upstream rules. Sent in Extended vlan tagging ME for the ONU",
        .id = BCMONU_MGMT_ONU_CFG_DATA_ID_DOWNSTREAM_MODE,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_onu_cfg_data, downstream_mode),
        .type = &type_descr_bcmonu_mgmt_downstream_mode_values,
    },
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_onu_cfg_data =
{
    .name = "onu_cfg_data",
    .descr = "ONU: cfg",
    .size = sizeof(bcmonu_mgmt_onu_cfg_data),
    .mask_offset = offsetof(bcmonu_mgmt_onu_cfg_data, presence_mask),
    .base_type = BCMOLT_BASE_TYPE_ID_STRUCT,
    .x = { .s = { .num_fields = sizeof(type_descr_bcmonu_mgmt_onu_cfg_data_fields) / sizeof(bcmolt_field_descr), .fields = type_descr_bcmonu_mgmt_onu_cfg_data_fields } },
};

static bcmolt_field_descr type_descr_bcmonu_mgmt_onu_key_fields[] =
{
    {
        .name = "pon_ni",
        .descr = "PON Interface ID",
        .id = BCMOLT_FIELD_DESCR_ID_NONE,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_onu_key, pon_ni),
        .type = &type_descr_uint8_t,
    },
    {
        .name = "onu_id",
        .descr = "ONU ID",
        .id = BCMOLT_FIELD_DESCR_ID_NONE,
        .tags = 0,
        .offset = offsetof(bcmonu_mgmt_onu_key, onu_id),
        .type = &type_descr_uint16_t,
    },
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_onu_key =
{
    .name = "onu_key",
    .descr = "ONU: key",
    .size = sizeof(bcmonu_mgmt_onu_key),
    .mask_offset = BCMOLT_TYPE_DESCR_NO_MASK,
    .base_type = BCMOLT_BASE_TYPE_ID_STRUCT,
    .x = { .s = { .num_fields = sizeof(type_descr_bcmonu_mgmt_onu_key_fields) / sizeof(bcmolt_field_descr), .fields = type_descr_bcmonu_mgmt_onu_key_fields } },
};

const bcmolt_enum_val bcmonu_mgmt_obj_id_string_table[] =
{
    { .name = "flow", .val = BCMONU_MGMT_OBJ_ID_FLOW, .tags = 0 },
    { .name = "onu", .val = BCMONU_MGMT_OBJ_ID_ONU, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_obj_id =
{
    .name = "obj_id",
    .descr = "Identifiers for all objects in the system.",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM,
    .size = sizeof(bcmonu_mgmt_obj_id),
    .x = { .e = { .base_type = &type_descr_uint16_t,.vals = bcmonu_mgmt_obj_id_string_table } },
};

const bcmolt_enum_val bcmonu_mgmt_api_group_id_string_table[] =
{
    { .name = "flow_cfg", .val = BCMONU_MGMT_API_GROUP_ID_FLOW_CFG, .tags = 0 },
    { .name = "flow_key", .val = BCMONU_MGMT_API_GROUP_ID_FLOW_KEY, .tags = 0 },
    { .name = "onu_cfg", .val = BCMONU_MGMT_API_GROUP_ID_ONU_CFG, .tags = 0 },
    { .name = "onu_key", .val = BCMONU_MGMT_API_GROUP_ID_ONU_KEY, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_api_group_id =
{
    .name = "api_group_id",
    .descr = "Identifiers for all possible groups under all objects in the system.",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM,
    .size = sizeof(bcmonu_mgmt_api_group_id),
    .x = { .e = { .base_type = &type_descr_uint16_t,.vals = bcmonu_mgmt_api_group_id_string_table } },
};

const bcmolt_enum_val bcmonu_mgmt_agg_port_list_entry_id_string_table[] =
{
    { .name = "entity_id", .val = BCMONU_MGMT_AGG_PORT_LIST_ENTRY_ID_ENTITY_ID, .tags = 0 },
    { .name = "agg_port_id", .val = BCMONU_MGMT_AGG_PORT_LIST_ENTRY_ID_AGG_PORT_ID, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_agg_port_list_entry_id =
{
    .name = "agg_port_list_entry_id",
    .descr = "Identifiers for all fields in a 'agg_port_list_entry'.",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM,
    .size = sizeof(bcmonu_mgmt_agg_port_list_entry_id),
    .x = { .e = { .base_type = &type_descr_uint8_t,.vals = bcmonu_mgmt_agg_port_list_entry_id_string_table } },
};

const bcmolt_enum_val bcmonu_mgmt_flow_action_id_string_table[] =
{
    { .name = "type", .val = BCMONU_MGMT_FLOW_ACTION_ID_TYPE, .tags = 0 },
    { .name = "o_pcp", .val = BCMONU_MGMT_FLOW_ACTION_ID_O_PCP, .tags = 0 },
    { .name = "o_vid", .val = BCMONU_MGMT_FLOW_ACTION_ID_O_VID, .tags = 0 },
    { .name = "i_pcp", .val = BCMONU_MGMT_FLOW_ACTION_ID_I_PCP, .tags = 0 },
    { .name = "i_vid", .val = BCMONU_MGMT_FLOW_ACTION_ID_I_VID, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_action_id =
{
    .name = "flow_action_id",
    .descr = "Identifiers for all fields in a 'flow_action'.",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM,
    .size = sizeof(bcmonu_mgmt_flow_action_id),
    .x = { .e = { .base_type = &type_descr_uint8_t,.vals = bcmonu_mgmt_flow_action_id_string_table } },
};

const bcmolt_enum_val bcmonu_mgmt_flow_match_id_string_table[] =
{
    { .name = "ether_type", .val = BCMONU_MGMT_FLOW_MATCH_ID_ETHER_TYPE, .tags = 0 },
    { .name = "o_pcp", .val = BCMONU_MGMT_FLOW_MATCH_ID_O_PCP, .tags = 0 },
    { .name = "o_vid", .val = BCMONU_MGMT_FLOW_MATCH_ID_O_VID, .tags = 0 },
    { .name = "i_pcp", .val = BCMONU_MGMT_FLOW_MATCH_ID_I_PCP, .tags = 0 },
    { .name = "i_vid", .val = BCMONU_MGMT_FLOW_MATCH_ID_I_VID, .tags = 0 },
    { .name = "o_untagged", .val = BCMONU_MGMT_FLOW_MATCH_ID_O_UNTAGGED, .tags = 0 },
    { .name = "i_untagged", .val = BCMONU_MGMT_FLOW_MATCH_ID_I_UNTAGGED, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_match_id =
{
    .name = "flow_match_id",
    .descr = "Identifiers for all fields in a 'flow_match'.",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM,
    .size = sizeof(bcmonu_mgmt_flow_match_id),
    .x = { .e = { .base_type = &type_descr_uint8_t,.vals = bcmonu_mgmt_flow_match_id_string_table } },
};

const bcmolt_enum_val bcmonu_mgmt_flow_onu_key_id_string_table[] =
{
    { .name = "pon_ni", .val = BCMONU_MGMT_FLOW_ONU_KEY_ID_PON_NI, .tags = 0 },
    { .name = "onu_id", .val = BCMONU_MGMT_FLOW_ONU_KEY_ID_ONU_ID, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_onu_key_id =
{
    .name = "flow_onu_key_id",
    .descr = "Identifiers for all fields in a 'flow_onu_key'.",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM,
    .size = sizeof(bcmonu_mgmt_flow_onu_key_id),
    .x = { .e = { .base_type = &type_descr_uint8_t,.vals = bcmonu_mgmt_flow_onu_key_id_string_table } },
};

const bcmolt_enum_val bcmonu_mgmt_igmp_us_action_id_string_table[] =
{
    { .name = "type", .val = BCMONU_MGMT_IGMP_US_ACTION_ID_TYPE, .tags = 0 },
    { .name = "pcp", .val = BCMONU_MGMT_IGMP_US_ACTION_ID_PCP, .tags = 0 },
    { .name = "vid", .val = BCMONU_MGMT_IGMP_US_ACTION_ID_VID, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_igmp_us_action_id =
{
    .name = "igmp_us_action_id",
    .descr = "Identifiers for all fields in a 'igmp_us_action'.",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM,
    .size = sizeof(bcmonu_mgmt_igmp_us_action_id),
    .x = { .e = { .base_type = &type_descr_uint8_t,.vals = bcmonu_mgmt_igmp_us_action_id_string_table } },
};

const bcmolt_enum_val bcmonu_mgmt_priority_queue_id_string_table[] =
{
    { .name = "entity_id", .val = BCMONU_MGMT_PRIORITY_QUEUE_ID_ENTITY_ID, .tags = 0 },
    { .name = "port", .val = BCMONU_MGMT_PRIORITY_QUEUE_ID_PORT, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_priority_queue_id =
{
    .name = "priority_queue_id",
    .descr = "Identifiers for all fields in a 'priority_queue'.",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM,
    .size = sizeof(bcmonu_mgmt_priority_queue_id),
    .x = { .e = { .base_type = &type_descr_uint8_t,.vals = bcmonu_mgmt_priority_queue_id_string_table } },
};

const bcmolt_enum_val bcmonu_mgmt_uni_id_string_table[] =
{
    { .name = "entity_id", .val = BCMONU_MGMT_UNI_ID_ENTITY_ID, .tags = 0 },
    { .name = "type", .val = BCMONU_MGMT_UNI_ID_TYPE, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_uni_id =
{
    .name = "uni_id",
    .descr = "Identifiers for all fields in a 'uni'.",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM,
    .size = sizeof(bcmonu_mgmt_uni_id),
    .x = { .e = { .base_type = &type_descr_uint8_t,.vals = bcmonu_mgmt_uni_id_string_table } },
};

const bcmolt_enum_val bcmonu_mgmt_flow_cfg_data_id_string_table[] =
{
    { .name = "admin_state", .val = BCMONU_MGMT_FLOW_CFG_DATA_ID_ADMIN_STATE, .tags = 0 },
    { .name = "oper_status", .val = BCMONU_MGMT_FLOW_CFG_DATA_ID_OPER_STATUS, .tags = 0 },
    { .name = "onu_key", .val = BCMONU_MGMT_FLOW_CFG_DATA_ID_ONU_KEY, .tags = 0 },
    { .name = "flow_type", .val = BCMONU_MGMT_FLOW_CFG_DATA_ID_FLOW_TYPE, .tags = 0 },
    { .name = "svc_port_id", .val = BCMONU_MGMT_FLOW_CFG_DATA_ID_SVC_PORT_ID, .tags = 0 },
    { .name = "agg_port_id", .val = BCMONU_MGMT_FLOW_CFG_DATA_ID_AGG_PORT_ID, .tags = 0 },
    { .name = "uni_port", .val = BCMONU_MGMT_FLOW_CFG_DATA_ID_UNI_PORT, .tags = 0 },
    { .name = "match", .val = BCMONU_MGMT_FLOW_CFG_DATA_ID_MATCH, .tags = 0 },
    { .name = "action", .val = BCMONU_MGMT_FLOW_CFG_DATA_ID_ACTION, .tags = 0 },
    { .name = "igmp_us_action", .val = BCMONU_MGMT_FLOW_CFG_DATA_ID_IGMP_US_ACTION, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_cfg_data_id =
{
    .name = "flow_cfg_data_id",
    .descr = "Identifiers for all fields in a 'flow_cfg_data'.",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM,
    .size = sizeof(bcmonu_mgmt_flow_cfg_data_id),
    .x = { .e = { .base_type = &type_descr_uint8_t,.vals = bcmonu_mgmt_flow_cfg_data_id_string_table } },
};

const bcmolt_enum_val bcmonu_mgmt_flow_key_id_string_table[] =
{
    { .name = "id", .val = BCMONU_MGMT_FLOW_KEY_ID_ID, .tags = 0 },
    { .name = "dir", .val = BCMONU_MGMT_FLOW_KEY_ID_DIR, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_key_id =
{
    .name = "flow_key_id",
    .descr = "Identifiers for all fields in a 'flow_key'.",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM,
    .size = sizeof(bcmonu_mgmt_flow_key_id),
    .x = { .e = { .base_type = &type_descr_uint8_t,.vals = bcmonu_mgmt_flow_key_id_string_table } },
};

const bcmolt_enum_val bcmonu_mgmt_onu_cfg_data_id_string_table[] =
{
    { .name = "admin_state", .val = BCMONU_MGMT_ONU_CFG_DATA_ID_ADMIN_STATE, .tags = 0 },
    { .name = "oper_status", .val = BCMONU_MGMT_ONU_CFG_DATA_ID_OPER_STATUS, .tags = 0 },
    { .name = "input_tpid", .val = BCMONU_MGMT_ONU_CFG_DATA_ID_INPUT_TPID, .tags = 0 },
    { .name = "output_tpid", .val = BCMONU_MGMT_ONU_CFG_DATA_ID_OUTPUT_TPID, .tags = 0 },
    { .name = "unis", .val = BCMONU_MGMT_ONU_CFG_DATA_ID_UNIS, .tags = 0 },
    { .name = "num_of_unis", .val = BCMONU_MGMT_ONU_CFG_DATA_ID_NUM_OF_UNIS, .tags = 0 },
    { .name = "agg_ports", .val = BCMONU_MGMT_ONU_CFG_DATA_ID_AGG_PORTS, .tags = 0 },
    { .name = "num_of_agg_ports", .val = BCMONU_MGMT_ONU_CFG_DATA_ID_NUM_OF_AGG_PORTS, .tags = 0 },
    { .name = "us_priority_queues", .val = BCMONU_MGMT_ONU_CFG_DATA_ID_US_PRIORITY_QUEUES, .tags = 0 },
    { .name = "num_of_us_priority_queues", .val = BCMONU_MGMT_ONU_CFG_DATA_ID_NUM_OF_US_PRIORITY_QUEUES, .tags = 0 },
    { .name = "ds_priority_queues", .val = BCMONU_MGMT_ONU_CFG_DATA_ID_DS_PRIORITY_QUEUES, .tags = 0 },
    { .name = "num_of_ds_priority_queues", .val = BCMONU_MGMT_ONU_CFG_DATA_ID_NUM_OF_DS_PRIORITY_QUEUES, .tags = 0 },
    { .name = "downstream_mode", .val = BCMONU_MGMT_ONU_CFG_DATA_ID_DOWNSTREAM_MODE, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_onu_cfg_data_id =
{
    .name = "onu_cfg_data_id",
    .descr = "Identifiers for all fields in a 'onu_cfg_data'.",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM,
    .size = sizeof(bcmonu_mgmt_onu_cfg_data_id),
    .x = { .e = { .base_type = &type_descr_uint8_t,.vals = bcmonu_mgmt_onu_cfg_data_id_string_table } },
};

const bcmolt_enum_val bcmonu_mgmt_onu_key_id_string_table[] =
{
    { .name = "pon_ni", .val = BCMONU_MGMT_ONU_KEY_ID_PON_NI, .tags = 0 },
    { .name = "onu_id", .val = BCMONU_MGMT_ONU_KEY_ID_ONU_ID, .tags = 0 },
    BCMOLT_ENUM_LAST,
};

const bcmolt_type_descr type_descr_bcmonu_mgmt_onu_key_id =
{
    .name = "onu_key_id",
    .descr = "Identifiers for all fields in a 'onu_key'.",
    .base_type = BCMOLT_BASE_TYPE_ID_ENUM,
    .size = sizeof(bcmonu_mgmt_onu_key_id),
    .x = { .e = { .base_type = &type_descr_uint8_t,.vals = bcmonu_mgmt_onu_key_id_string_table } },
};

/** ===== Objects ===== */
/** ==== Object: flow ==== */
/** Group: flow - cfg. */
static bcmolt_multi_group_descr multi_descr_flow_cfg =
{
    .container_size = sizeof(bcmonu_mgmt_flow_multi_cfg),
    .key_offset = offsetof(bcmonu_mgmt_flow_multi_cfg, key),
    .next_key_offset = offsetof(bcmonu_mgmt_flow_multi_cfg, next_key),
    .filter_offset = offsetof(bcmonu_mgmt_flow_multi_cfg, filter),
    .request_offset = offsetof(bcmonu_mgmt_flow_multi_cfg, request),
    .more_offset = offsetof(bcmonu_mgmt_flow_multi_cfg, more),
    .num_responses_offset = offsetof(bcmonu_mgmt_flow_multi_cfg, num_responses),
    .responses_offset = offsetof(bcmonu_mgmt_flow_multi_cfg, responses),
};

static bcmolt_group_descr group_descr_flow_cfg =
{
    .container_size = sizeof(bcmonu_mgmt_flow_cfg),
    .data_offset = offsetof(bcmonu_mgmt_flow_cfg, data),
    .data_size = sizeof(bcmonu_mgmt_flow_cfg_data),
    .descr = "cfg.",
    .global_id = BCMONU_MGMT_API_GROUP_ID_FLOW_CFG,
    .id = 0,
    .key_offset = offsetof(bcmonu_mgmt_flow_cfg, key),
    .key_size = sizeof(bcmonu_mgmt_flow_key),
    .mgt_group = BCMOLT_MGT_GROUP_CFG,
    .multi = &multi_descr_flow_cfg,
    .name = "cfg",
    .obj_id = BCMONU_MGMT_OBJ_ID_FLOW,
    .subgroup_idx = 0,
    .tags = 0,
    .type = &type_descr_bcmonu_mgmt_flow_cfg_data,
};

/** Group: flow - key. */
static bcmolt_group_descr group_descr_flow_key =
{
    .container_size = 0,
    .data_offset = 0,
    .data_size = sizeof(bcmonu_mgmt_flow_key),
    .descr = "key.",
    .global_id = BCMONU_MGMT_API_GROUP_ID_FLOW_KEY,
    .id = 1,
    .key_offset = 0,
    .key_size = sizeof(bcmonu_mgmt_flow_key),
    .mgt_group = BCMOLT_MGT_GROUP_KEY,
    .name = "key",
    .obj_id = BCMONU_MGMT_OBJ_ID_FLOW,
    .subgroup_idx = 0,
    .tags = 0,
    .type = &type_descr_bcmonu_mgmt_flow_key,
};

static const bcmolt_group_descr *groups_flow[] =
{
    &group_descr_flow_cfg,
    &group_descr_flow_key,
};

static bcmolt_obj_descr obj_descr_flow =
{
    .name = "flow",
    .descr = "Flow.",
    .id = BCMONU_MGMT_OBJ_ID_FLOW,
    .tags = 0,
    .get_active_tags = (bcmolt_get_active_tags_cb)bcmonu_mgmt_flow_get_active_tags,
    .num_groups = BCM_SIZEOFARRAY(groups_flow),
    .groups = groups_flow,
};


/** ==== Object: onu ==== */
/** Group: onu - cfg. */
static bcmolt_multi_group_descr multi_descr_onu_cfg =
{
    .container_size = sizeof(bcmonu_mgmt_onu_multi_cfg),
    .key_offset = offsetof(bcmonu_mgmt_onu_multi_cfg, key),
    .next_key_offset = offsetof(bcmonu_mgmt_onu_multi_cfg, next_key),
    .filter_offset = offsetof(bcmonu_mgmt_onu_multi_cfg, filter),
    .request_offset = offsetof(bcmonu_mgmt_onu_multi_cfg, request),
    .more_offset = offsetof(bcmonu_mgmt_onu_multi_cfg, more),
    .num_responses_offset = offsetof(bcmonu_mgmt_onu_multi_cfg, num_responses),
    .responses_offset = offsetof(bcmonu_mgmt_onu_multi_cfg, responses),
};

static bcmolt_group_descr group_descr_onu_cfg =
{
    .container_size = sizeof(bcmonu_mgmt_onu_cfg),
    .data_offset = offsetof(bcmonu_mgmt_onu_cfg, data),
    .data_size = sizeof(bcmonu_mgmt_onu_cfg_data),
    .descr = "cfg.",
    .global_id = BCMONU_MGMT_API_GROUP_ID_ONU_CFG,
    .id = 0,
    .key_offset = offsetof(bcmonu_mgmt_onu_cfg, key),
    .key_size = sizeof(bcmonu_mgmt_onu_key),
    .mgt_group = BCMOLT_MGT_GROUP_CFG,
    .multi = &multi_descr_onu_cfg,
    .name = "cfg",
    .obj_id = BCMONU_MGMT_OBJ_ID_ONU,
    .subgroup_idx = 0,
    .tags = 0,
    .type = &type_descr_bcmonu_mgmt_onu_cfg_data,
};

/** Group: onu - key. */
static bcmolt_group_descr group_descr_onu_key =
{
    .container_size = 0,
    .data_offset = 0,
    .data_size = sizeof(bcmonu_mgmt_onu_key),
    .descr = "key.",
    .global_id = BCMONU_MGMT_API_GROUP_ID_ONU_KEY,
    .id = 1,
    .key_offset = 0,
    .key_size = sizeof(bcmonu_mgmt_onu_key),
    .mgt_group = BCMOLT_MGT_GROUP_KEY,
    .name = "key",
    .obj_id = BCMONU_MGMT_OBJ_ID_ONU,
    .subgroup_idx = 0,
    .tags = 0,
    .type = &type_descr_bcmonu_mgmt_onu_key,
};

static const bcmolt_group_descr *groups_onu[] =
{
    &group_descr_onu_cfg,
    &group_descr_onu_key,
};

static bcmolt_obj_descr obj_descr_onu =
{
    .name = "onu",
    .descr = "ONU.",
    .id = BCMONU_MGMT_OBJ_ID_ONU,
    .tags = 0,
    .get_active_tags = (bcmolt_get_active_tags_cb)bcmonu_mgmt_onu_get_active_tags,
    .num_groups = BCM_SIZEOFARRAY(groups_onu),
    .groups = groups_onu,
};


static const bcmolt_obj_descr *lookup_obj_by_id[] =
{
    [BCMONU_MGMT_OBJ_ID_FLOW] = &obj_descr_flow,
    [BCMONU_MGMT_OBJ_ID_ONU] = &obj_descr_onu,
};

static const bcmolt_group_descr *lookup_group_by_subgroup_idx[][BCMOLT_MGT_GROUP__NUM_OF][BCMONU_MGMT_FLOW_CFG_SUBGROUP__NUM_OF] =
{
    [BCMONU_MGMT_OBJ_ID_FLOW][BCMOLT_MGT_GROUP_KEY][0] = &group_descr_flow_key,
    [BCMONU_MGMT_OBJ_ID_FLOW][BCMOLT_MGT_GROUP_CFG][0] = &group_descr_flow_cfg,
    [BCMONU_MGMT_OBJ_ID_ONU][BCMOLT_MGT_GROUP_KEY][0] = &group_descr_onu_key,
    [BCMONU_MGMT_OBJ_ID_ONU][BCMOLT_MGT_GROUP_CFG][0] = &group_descr_onu_cfg,
};

static const bcmolt_group_descr *find_group_descr(bcmolt_meta_id obj, bcmolt_meta_id group)
{
    switch (obj)
    {
    case BCMONU_MGMT_OBJ_ID_FLOW:
        switch (group)
        {
        case 0:
            return &group_descr_flow_cfg;
        case 1:
            return &group_descr_flow_key;
        default:
            return NULL;
        }
    case BCMONU_MGMT_OBJ_ID_ONU:
        switch (group)
        {
        case 0:
            return &group_descr_onu_cfg;
        case 1:
            return &group_descr_onu_key;
        default:
            return NULL;
        }
    default:
        return NULL;
    }
}

static const bcmolt_group_descr *lookup_group_by_global_id[] =
{
    [BCMONU_MGMT_API_GROUP_ID_FLOW_CFG] = &group_descr_flow_cfg,
    [BCMONU_MGMT_API_GROUP_ID_FLOW_KEY] = &group_descr_flow_key,
    [BCMONU_MGMT_API_GROUP_ID_ONU_CFG] = &group_descr_onu_cfg,
    [BCMONU_MGMT_API_GROUP_ID_ONU_KEY] = &group_descr_onu_key,
};

static const bcmolt_metadata_set bcmonu_mgmt_api_metadata_private =
{
    .obj_id_count = BCMONU_MGMT_OBJ_ID__NUM_OF,
    .global_id_count = BCMONU_MGMT_API_GROUP_ID__NUM_OF,
    .max_subgroup_count = BCMONU_MGMT_FLOW_CFG_SUBGROUP__NUM_OF,
    .tag_count = sizeof(tags) / sizeof(bcmolt_tag_descr),
    .lookup_obj_by_id = lookup_obj_by_id,
    .find_group_descr = find_group_descr,
    .lookup_group_by_global_id = lookup_group_by_global_id,
    .lookup_group_by_subgroup_idx = &lookup_group_by_subgroup_idx[0][0][0],
    .tags = tags,
};

const bcmolt_metadata_set *bcmonu_mgmt_api_metadata = &bcmonu_mgmt_api_metadata_private;


