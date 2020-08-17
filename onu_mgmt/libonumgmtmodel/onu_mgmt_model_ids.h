#ifndef _ONU_MGMT_MODEL_IDS_H_
#define _ONU_MGMT_MODEL_IDS_H_

/** \addtogroup api_data_types
 * @{
 */

#include <bcmos_system.h>

/* For now, all enums are considered "IDs". This is easier than separating out ID types specifically. */

/** there is only one sub group for ONU Mgmt objects. Hence setting it to 1.
 (This definition is used in lookup_group_by_subgroup_idx[][][] generated as part of onu_mgmt_cli_helpers.c) */
/** @todo Question: why the code generator uses specifically flow based macro definition ? */
#define BCMONU_MGMT_FLOW_CFG_SUBGROUP__NUM_OF 1
 
/** Administrative state */
typedef enum
{
    BCMONU_MGMT_ADMIN_STATE__BEGIN = 0,
    BCMONU_MGMT_ADMIN_STATE_UP = 0, /**< Up */
    BCMONU_MGMT_ADMIN_STATE_DOWN = 1, /**< Down */
    BCMONU_MGMT_ADMIN_STATE__NUM_OF, /**< Constant to use for sizing arrays - note that enum may have holes. */
} bcmonu_mgmt_admin_state;

/** downstream mode attribute values in OMCI Ext Vlan tag ME */
typedef enum
{
    BCMONU_MGMT_DOWNSTREAM_MODE_VALUES__BEGIN = 0,
    BCMONU_MGMT_DOWNSTREAM_MODE_VALUES_INVERSE = 0, /**< Operation on DS frames based on Upstream rules as implemented in ONU */
    BCMONU_MGMT_DOWNSTREAM_MODE_VALUES_MATCH_VID_INVERSE_VID_FORWARD_NO_MATCH = 3, /**< Match DS frames on VID only (not Pbit) and inverse VID only; P-bit is passed unmodified. On no match pass unmodified. */
    BCMONU_MGMT_DOWNSTREAM_MODE_VALUES_MATCH_VID_INVERSE_VID_DISCARD_NO_MATCH = 6, /**< Match DS frames on VID only (not Pbit) and inverse VID only; P-bit is passed unmodified. On no match Discard. */
    BCMONU_MGMT_DOWNSTREAM_MODE_VALUES__NUM_OF, /**< Constant to use for sizing arrays - note that enum may have holes. */
} bcmonu_mgmt_downstream_mode_values;

/** Action type. */
typedef enum
{
    BCMONU_MGMT_FLOW_ACTION_TYPE_ID_NONE = 0,
    BCMONU_MGMT_FLOW_ACTION_TYPE_ID_PUSH = 0x1, /**< Push tag. */
    BCMONU_MGMT_FLOW_ACTION_TYPE_ID_POP = 0x2, /**< Pop tag. */
    BCMONU_MGMT_FLOW_ACTION_TYPE_ID_TRANSLATE_PCP = 0x4, /**< Translate PCP. */
    BCMONU_MGMT_FLOW_ACTION_TYPE_ID_TRANSLATE_VID = 0x8, /**< Translate VID. */
    BCMONU_MGMT_FLOW_ACTION_TYPE_ID_PUSH_INNER_TAG = 0x10, /**< Push Inner Tag. */
    BCMONU_MGMT_FLOW_ACTION_TYPE_ID_POP_INNER_TAG = 0x20, /**< Pop Inner Tag. */
    BCMONU_MGMT_FLOW_ACTION_TYPE_ID_TRANSLATE_INNER_PCP = 0x40, /**< Translate Inner PCP. */
    BCMONU_MGMT_FLOW_ACTION_TYPE_ID_TRANSLATE_INNER_VID = 0x80, /**< Translate Inner VID. */
} bcmonu_mgmt_flow_action_type_id;

/** Flow direction */
typedef enum
{
    BCMONU_MGMT_FLOW_DIR_ID__BEGIN = 0,
    BCMONU_MGMT_FLOW_DIR_ID_UPSTREAM = 0, /**< Upstream flow */
    BCMONU_MGMT_FLOW_DIR_ID_DOWNSTREAM = 1, /**< Downstream Flow */
    BCMONU_MGMT_FLOW_DIR_ID__NUM_OF, /**< Constant to use for sizing arrays - note that enum may have holes. */
} bcmonu_mgmt_flow_dir_id;

/** Flow type */
typedef enum
{
    BCMONU_MGMT_FLOW_TYPE__BEGIN = 0,
    BCMONU_MGMT_FLOW_TYPE_INVALID = 0, /**< Invalid flow type */
    BCMONU_MGMT_FLOW_TYPE_UNICAST = 1, /**< Unicast Flow */
    BCMONU_MGMT_FLOW_TYPE_MULTICAST = 2, /**< Multicast flow */
    BCMONU_MGMT_FLOW_TYPE_BROADCAST = 3, /**< Broadcast flow */
    BCMONU_MGMT_FLOW_TYPE__NUM_OF, /**< Constant to use for sizing arrays - note that enum may have holes. */
} bcmonu_mgmt_flow_type;

/** Action type for IGMP on Upstream. */
typedef enum
{
    BCMONU_MGMT_IGMP_US_ACTION_TYPE_ID_NONE = 0,
    BCMONU_MGMT_IGMP_US_ACTION_TYPE_ID_ADD_VLAN_TAG = 0x1, /**< Add VLAN Tag (including P bits). */
    BCMONU_MGMT_IGMP_US_ACTION_TYPE_ID_REPLACE_TCI = 0x4, /**< Replace the entire TCI (VID+ Pbits). */
    BCMONU_MGMT_IGMP_US_ACTION_TYPE_ID_REPLACE_VID = 0x8, /**< Replace only the VID. */
} bcmonu_mgmt_igmp_us_action_type_id;

/** Operational Status */
typedef enum
{
    BCMONU_MGMT_STATUS__BEGIN = 1,
    BCMONU_MGMT_STATUS_UP = 1, /**< Up. */
    BCMONU_MGMT_STATUS_DOWN = 2, /**< Down. */
    BCMONU_MGMT_STATUS_UNKNOWN = 4, /**< Unknown. */
    BCMONU_MGMT_STATUS__NUM_OF, /**< Constant to use for sizing arrays - note that enum may have holes. */
} bcmonu_mgmt_status;

/** UNI type */
typedef enum
{
    BCMONU_MGMT_UNI_TYPE__BEGIN = 0,
    BCMONU_MGMT_UNI_TYPE_INVALID = 0, /**< Invalid */
    BCMONU_MGMT_UNI_TYPE_PPTP = 1, /**< PPTP */
    BCMONU_MGMT_UNI_TYPE_VEIP = 2, /**< VEIP */
    BCMONU_MGMT_UNI_TYPE__NUM_OF, /**< Constant to use for sizing arrays - note that enum may have holes. */
} bcmonu_mgmt_uni_type;

/** Identifiers for all objects in the system. */
typedef enum
{
    BCMONU_MGMT_OBJ_ID__BEGIN = 0,
    BCMONU_MGMT_OBJ_ID_FLOW = 0, /**< Flow. */
    BCMONU_MGMT_OBJ_ID_ONU = 1, /**< ONU. */
    BCMONU_MGMT_OBJ_ID__NUM_OF, /**< Constant to use for sizing arrays - note that enum may have holes. */

    /* Lower-case versions for macro support. */
#define bcmonu_mgmt_obj_id__begin BCMONU_MGMT_OBJ_ID__BEGIN
#define bcmonu_mgmt_obj_id_flow BCMONU_MGMT_OBJ_ID_FLOW
#define bcmonu_mgmt_obj_id_onu BCMONU_MGMT_OBJ_ID_ONU
#define bcmonu_mgmt_obj_id__num_of BCMONU_MGMT_OBJ_ID__NUM_OF
#define bcmonu_mgmt_obj_id_all_properties 0xFFFF
#define bcmonu_mgmt_obj_id_full_mask 0x3

} bcmonu_mgmt_obj_id;

/** Identifiers for all possible groups under all objects in the system. */
typedef enum
{
    BCMONU_MGMT_API_GROUP_ID__BEGIN = 0,
    BCMONU_MGMT_API_GROUP_ID_FLOW_CFG = 0, /**< Flow - cfg. */
    BCMONU_MGMT_API_GROUP_ID_FLOW_KEY = 1, /**< Flow - key. */
    BCMONU_MGMT_API_GROUP_ID_ONU_CFG = 2, /**< ONU - cfg. */
    BCMONU_MGMT_API_GROUP_ID_ONU_KEY = 3, /**< ONU - key. */
    BCMONU_MGMT_API_GROUP_ID__NUM_OF, /**< Constant to use for sizing arrays - note that enum may have holes. */
} bcmonu_mgmt_api_group_id;

/** Identifiers for all fields in a 'agg_port_list_entry'. */
typedef enum
{
    BCMONU_MGMT_AGG_PORT_LIST_ENTRY_ID__BEGIN = 0,
    BCMONU_MGMT_AGG_PORT_LIST_ENTRY_ID_ENTITY_ID = 0, /**< Entity ID. */
    BCMONU_MGMT_AGG_PORT_LIST_ENTRY_ID_AGG_PORT_ID = 1, /**< Aggregate Port ID. */
    BCMONU_MGMT_AGG_PORT_LIST_ENTRY_ID__NUM_OF, /**< Constant to use for sizing arrays - note that enum may have holes. */

    /* Lower-case versions for macro support. */
#define bcmonu_mgmt_agg_port_list_entry_id__begin BCMONU_MGMT_AGG_PORT_LIST_ENTRY_ID__BEGIN
#define bcmonu_mgmt_agg_port_list_entry_id_entity_id BCMONU_MGMT_AGG_PORT_LIST_ENTRY_ID_ENTITY_ID
#define bcmonu_mgmt_agg_port_list_entry_id_agg_port_id BCMONU_MGMT_AGG_PORT_LIST_ENTRY_ID_AGG_PORT_ID
#define bcmonu_mgmt_agg_port_list_entry_id__num_of BCMONU_MGMT_AGG_PORT_LIST_ENTRY_ID__NUM_OF
#define bcmonu_mgmt_agg_port_list_entry_id_all_properties 0xFF
#define bcmonu_mgmt_agg_port_list_entry_id_full_mask 0x3

} bcmonu_mgmt_agg_port_list_entry_id;

/** Identifiers for all fields in a 'flow_action'. */
typedef enum
{
    BCMONU_MGMT_FLOW_ACTION_ID__BEGIN = 0,
    BCMONU_MGMT_FLOW_ACTION_ID_TYPE = 0, /**< Action bitmask. */
    BCMONU_MGMT_FLOW_ACTION_ID_O_PCP = 1, /**< Outer PCP. */
    BCMONU_MGMT_FLOW_ACTION_ID_O_VID = 2, /**< Outer VID. */
    BCMONU_MGMT_FLOW_ACTION_ID_I_PCP = 3, /**< Inner PCP. */
    BCMONU_MGMT_FLOW_ACTION_ID_I_VID = 4, /**< Inner VID. */
    BCMONU_MGMT_FLOW_ACTION_ID__NUM_OF, /**< Constant to use for sizing arrays - note that enum may have holes. */

    /* Lower-case versions for macro support. */
#define bcmonu_mgmt_flow_action_id__begin BCMONU_MGMT_FLOW_ACTION_ID__BEGIN
#define bcmonu_mgmt_flow_action_id_type BCMONU_MGMT_FLOW_ACTION_ID_TYPE
#define bcmonu_mgmt_flow_action_id_o_pcp BCMONU_MGMT_FLOW_ACTION_ID_O_PCP
#define bcmonu_mgmt_flow_action_id_o_vid BCMONU_MGMT_FLOW_ACTION_ID_O_VID
#define bcmonu_mgmt_flow_action_id_i_pcp BCMONU_MGMT_FLOW_ACTION_ID_I_PCP
#define bcmonu_mgmt_flow_action_id_i_vid BCMONU_MGMT_FLOW_ACTION_ID_I_VID
#define bcmonu_mgmt_flow_action_id__num_of BCMONU_MGMT_FLOW_ACTION_ID__NUM_OF
#define bcmonu_mgmt_flow_action_id_all_properties 0xFF
#define bcmonu_mgmt_flow_action_id_full_mask 0x1F

} bcmonu_mgmt_flow_action_id;

/** Identifiers for all fields in a 'flow_match'. */
typedef enum
{
    BCMONU_MGMT_FLOW_MATCH_ID__BEGIN = 0,
    BCMONU_MGMT_FLOW_MATCH_ID_ETHER_TYPE = 0, /**< Ethertype. */
    BCMONU_MGMT_FLOW_MATCH_ID_O_PCP = 1, /**< Outer PCP. */
    BCMONU_MGMT_FLOW_MATCH_ID_O_VID = 2, /**< Outer VID. */
    BCMONU_MGMT_FLOW_MATCH_ID_I_PCP = 3, /**< Inner PCP. */
    BCMONU_MGMT_FLOW_MATCH_ID_I_VID = 4, /**< Inner vid. */
    BCMONU_MGMT_FLOW_MATCH_ID_O_UNTAGGED = 5, /**< Outer tag not present. */
    BCMONU_MGMT_FLOW_MATCH_ID_I_UNTAGGED = 6, /**< Untagged Packet. */
    BCMONU_MGMT_FLOW_MATCH_ID__NUM_OF, /**< Constant to use for sizing arrays - note that enum may have holes. */

    /* Lower-case versions for macro support. */
#define bcmonu_mgmt_flow_match_id__begin BCMONU_MGMT_FLOW_MATCH_ID__BEGIN
#define bcmonu_mgmt_flow_match_id_ether_type BCMONU_MGMT_FLOW_MATCH_ID_ETHER_TYPE
#define bcmonu_mgmt_flow_match_id_o_pcp BCMONU_MGMT_FLOW_MATCH_ID_O_PCP
#define bcmonu_mgmt_flow_match_id_o_vid BCMONU_MGMT_FLOW_MATCH_ID_O_VID
#define bcmonu_mgmt_flow_match_id_i_pcp BCMONU_MGMT_FLOW_MATCH_ID_I_PCP
#define bcmonu_mgmt_flow_match_id_i_vid BCMONU_MGMT_FLOW_MATCH_ID_I_VID
#define bcmonu_mgmt_flow_match_id_o_untagged BCMONU_MGMT_FLOW_MATCH_ID_O_UNTAGGED
#define bcmonu_mgmt_flow_match_id_i_untagged BCMONU_MGMT_FLOW_MATCH_ID_I_UNTAGGED
#define bcmonu_mgmt_flow_match_id__num_of BCMONU_MGMT_FLOW_MATCH_ID__NUM_OF
#define bcmonu_mgmt_flow_match_id_all_properties 0xFF
#define bcmonu_mgmt_flow_match_id_full_mask 0x7F

} bcmonu_mgmt_flow_match_id;

/** Identifiers for all fields in a 'flow_onu_key'. */
typedef enum
{
    BCMONU_MGMT_FLOW_ONU_KEY_ID__BEGIN = 0,
    BCMONU_MGMT_FLOW_ONU_KEY_ID_PON_NI = 0, /**< PON Interface ID. */
    BCMONU_MGMT_FLOW_ONU_KEY_ID_ONU_ID = 1, /**< ONU ID. */
    BCMONU_MGMT_FLOW_ONU_KEY_ID__NUM_OF, /**< Constant to use for sizing arrays - note that enum may have holes. */

    /* Lower-case versions for macro support. */
#define bcmonu_mgmt_flow_onu_key_id__begin BCMONU_MGMT_FLOW_ONU_KEY_ID__BEGIN
#define bcmonu_mgmt_flow_onu_key_id_pon_ni BCMONU_MGMT_FLOW_ONU_KEY_ID_PON_NI
#define bcmonu_mgmt_flow_onu_key_id_onu_id BCMONU_MGMT_FLOW_ONU_KEY_ID_ONU_ID
#define bcmonu_mgmt_flow_onu_key_id__num_of BCMONU_MGMT_FLOW_ONU_KEY_ID__NUM_OF
#define bcmonu_mgmt_flow_onu_key_id_all_properties 0xFF
#define bcmonu_mgmt_flow_onu_key_id_full_mask 0x3

} bcmonu_mgmt_flow_onu_key_id;

/** Identifiers for all fields in a 'igmp_us_action'. */
typedef enum
{
    BCMONU_MGMT_IGMP_US_ACTION_ID__BEGIN = 0,
    BCMONU_MGMT_IGMP_US_ACTION_ID_TYPE = 0, /**< Action bitmask. */
    BCMONU_MGMT_IGMP_US_ACTION_ID_PCP = 1, /**< IGMP PCP. */
    BCMONU_MGMT_IGMP_US_ACTION_ID_VID = 2, /**< IGMP VID. */
    BCMONU_MGMT_IGMP_US_ACTION_ID__NUM_OF, /**< Constant to use for sizing arrays - note that enum may have holes. */

    /* Lower-case versions for macro support. */
#define bcmonu_mgmt_igmp_us_action_id__begin BCMONU_MGMT_IGMP_US_ACTION_ID__BEGIN
#define bcmonu_mgmt_igmp_us_action_id_type BCMONU_MGMT_IGMP_US_ACTION_ID_TYPE
#define bcmonu_mgmt_igmp_us_action_id_pcp BCMONU_MGMT_IGMP_US_ACTION_ID_PCP
#define bcmonu_mgmt_igmp_us_action_id_vid BCMONU_MGMT_IGMP_US_ACTION_ID_VID
#define bcmonu_mgmt_igmp_us_action_id__num_of BCMONU_MGMT_IGMP_US_ACTION_ID__NUM_OF
#define bcmonu_mgmt_igmp_us_action_id_all_properties 0xFF
#define bcmonu_mgmt_igmp_us_action_id_full_mask 0x7

} bcmonu_mgmt_igmp_us_action_id;

/** Identifiers for all fields in a 'priority_queue'. */
typedef enum
{
    BCMONU_MGMT_PRIORITY_QUEUE_ID__BEGIN = 0,
    BCMONU_MGMT_PRIORITY_QUEUE_ID_ENTITY_ID = 0, /**< Entity ID. */
    BCMONU_MGMT_PRIORITY_QUEUE_ID_PORT = 1, /**< Port. */
    BCMONU_MGMT_PRIORITY_QUEUE_ID__NUM_OF, /**< Constant to use for sizing arrays - note that enum may have holes. */

    /* Lower-case versions for macro support. */
#define bcmonu_mgmt_priority_queue_id__begin BCMONU_MGMT_PRIORITY_QUEUE_ID__BEGIN
#define bcmonu_mgmt_priority_queue_id_entity_id BCMONU_MGMT_PRIORITY_QUEUE_ID_ENTITY_ID
#define bcmonu_mgmt_priority_queue_id_port BCMONU_MGMT_PRIORITY_QUEUE_ID_PORT
#define bcmonu_mgmt_priority_queue_id__num_of BCMONU_MGMT_PRIORITY_QUEUE_ID__NUM_OF
#define bcmonu_mgmt_priority_queue_id_all_properties 0xFF
#define bcmonu_mgmt_priority_queue_id_full_mask 0x3

} bcmonu_mgmt_priority_queue_id;

/** Identifiers for all fields in a 'uni'. */
typedef enum
{
    BCMONU_MGMT_UNI_ID__BEGIN = 0,
    BCMONU_MGMT_UNI_ID_ENTITY_ID = 0, /**< Entity ID. */
    BCMONU_MGMT_UNI_ID_TYPE = 1, /**< type. */
    BCMONU_MGMT_UNI_ID__NUM_OF, /**< Constant to use for sizing arrays - note that enum may have holes. */

    /* Lower-case versions for macro support. */
#define bcmonu_mgmt_uni_id__begin BCMONU_MGMT_UNI_ID__BEGIN
#define bcmonu_mgmt_uni_id_entity_id BCMONU_MGMT_UNI_ID_ENTITY_ID
#define bcmonu_mgmt_uni_id_type BCMONU_MGMT_UNI_ID_TYPE
#define bcmonu_mgmt_uni_id__num_of BCMONU_MGMT_UNI_ID__NUM_OF
#define bcmonu_mgmt_uni_id_all_properties 0xFF
#define bcmonu_mgmt_uni_id_full_mask 0x3

} bcmonu_mgmt_uni_id;

/** Identifiers for all fields in a 'flow_cfg_data'. */
typedef enum
{
    BCMONU_MGMT_FLOW_CFG_DATA_ID__BEGIN = 0,
    BCMONU_MGMT_FLOW_CFG_DATA_ID_ADMIN_STATE = 0, /**< Administrative state. */
    BCMONU_MGMT_FLOW_CFG_DATA_ID_OPER_STATUS = 1, /**< Operational Status. */
    BCMONU_MGMT_FLOW_CFG_DATA_ID_ONU_KEY = 2, /**< ONU Key. */
    BCMONU_MGMT_FLOW_CFG_DATA_ID_FLOW_TYPE = 3, /**< Flow type. */
    BCMONU_MGMT_FLOW_CFG_DATA_ID_SVC_PORT_ID = 4, /**< Service Port ID. */
    BCMONU_MGMT_FLOW_CFG_DATA_ID_AGG_PORT_ID = 5, /**< Aggregate Port ID. */
    BCMONU_MGMT_FLOW_CFG_DATA_ID_UNI_PORT = 6, /**< UNI port. */
    BCMONU_MGMT_FLOW_CFG_DATA_ID_MATCH = 7, /**< Match. */
    BCMONU_MGMT_FLOW_CFG_DATA_ID_ACTION = 8, /**< Action. */
    BCMONU_MGMT_FLOW_CFG_DATA_ID_IGMP_US_ACTION = 9, /**< IGMP Action on US. */
    BCMONU_MGMT_FLOW_CFG_DATA_ID__NUM_OF, /**< Constant to use for sizing arrays - note that enum may have holes. */

    /* Lower-case versions for macro support. */
#define bcmonu_mgmt_flow_cfg_data_id__begin BCMONU_MGMT_FLOW_CFG_DATA_ID__BEGIN
#define bcmonu_mgmt_flow_cfg_data_id_admin_state BCMONU_MGMT_FLOW_CFG_DATA_ID_ADMIN_STATE
#define bcmonu_mgmt_flow_cfg_data_id_oper_status BCMONU_MGMT_FLOW_CFG_DATA_ID_OPER_STATUS
#define bcmonu_mgmt_flow_cfg_data_id_onu_key BCMONU_MGMT_FLOW_CFG_DATA_ID_ONU_KEY
#define bcmonu_mgmt_flow_cfg_data_id_flow_type BCMONU_MGMT_FLOW_CFG_DATA_ID_FLOW_TYPE
#define bcmonu_mgmt_flow_cfg_data_id_svc_port_id BCMONU_MGMT_FLOW_CFG_DATA_ID_SVC_PORT_ID
#define bcmonu_mgmt_flow_cfg_data_id_agg_port_id BCMONU_MGMT_FLOW_CFG_DATA_ID_AGG_PORT_ID
#define bcmonu_mgmt_flow_cfg_data_id_uni_port BCMONU_MGMT_FLOW_CFG_DATA_ID_UNI_PORT
#define bcmonu_mgmt_flow_cfg_data_id_match BCMONU_MGMT_FLOW_CFG_DATA_ID_MATCH
#define bcmonu_mgmt_flow_cfg_data_id_action BCMONU_MGMT_FLOW_CFG_DATA_ID_ACTION
#define bcmonu_mgmt_flow_cfg_data_id_igmp_us_action BCMONU_MGMT_FLOW_CFG_DATA_ID_IGMP_US_ACTION
#define bcmonu_mgmt_flow_cfg_data_id__num_of BCMONU_MGMT_FLOW_CFG_DATA_ID__NUM_OF
#define bcmonu_mgmt_flow_cfg_data_id_all_properties 0xFF
#define bcmonu_mgmt_flow_cfg_data_id_full_mask 0x3FF

} bcmonu_mgmt_flow_cfg_data_id;

/** Identifiers for all fields in a 'flow_key'. */
typedef enum
{
    BCMONU_MGMT_FLOW_KEY_ID__BEGIN = 0,
    BCMONU_MGMT_FLOW_KEY_ID_ID = 0, /**< Flow ID. */
    BCMONU_MGMT_FLOW_KEY_ID_DIR = 1, /**< Flow direction. */
    BCMONU_MGMT_FLOW_KEY_ID__NUM_OF, /**< Constant to use for sizing arrays - note that enum may have holes. */

    /* Lower-case versions for macro support. */
#define bcmonu_mgmt_flow_key_id__begin BCMONU_MGMT_FLOW_KEY_ID__BEGIN
#define bcmonu_mgmt_flow_key_id_id BCMONU_MGMT_FLOW_KEY_ID_ID
#define bcmonu_mgmt_flow_key_id_dir BCMONU_MGMT_FLOW_KEY_ID_DIR
#define bcmonu_mgmt_flow_key_id__num_of BCMONU_MGMT_FLOW_KEY_ID__NUM_OF
#define bcmonu_mgmt_flow_key_id_all_properties 0xFF
#define bcmonu_mgmt_flow_key_id_full_mask 0x3

} bcmonu_mgmt_flow_key_id;

/** Identifiers for all fields in a 'onu_cfg_data'. */
typedef enum
{
    BCMONU_MGMT_ONU_CFG_DATA_ID__BEGIN = 0,
    BCMONU_MGMT_ONU_CFG_DATA_ID_ADMIN_STATE = 0, /**< Administrative state. */
    BCMONU_MGMT_ONU_CFG_DATA_ID_OPER_STATUS = 1, /**< Operational Status. */
    BCMONU_MGMT_ONU_CFG_DATA_ID_INPUT_TPID = 2, /**< Input TPID. */
    BCMONU_MGMT_ONU_CFG_DATA_ID_OUTPUT_TPID = 3, /**< Output TPID. */
    BCMONU_MGMT_ONU_CFG_DATA_ID_UNIS = 4, /**< UNIs. */
    BCMONU_MGMT_ONU_CFG_DATA_ID_NUM_OF_UNIS = 5, /**< Number of UNIs. */
    BCMONU_MGMT_ONU_CFG_DATA_ID_AGG_PORTS = 6, /**< Aggregate Ports. */
    BCMONU_MGMT_ONU_CFG_DATA_ID_NUM_OF_AGG_PORTS = 7, /**< Number of Aggregate Ports. */
    BCMONU_MGMT_ONU_CFG_DATA_ID_US_PRIORITY_QUEUES = 8, /**< US priority queues. */
    BCMONU_MGMT_ONU_CFG_DATA_ID_NUM_OF_US_PRIORITY_QUEUES = 9, /**< Number of US priority queues. */
    BCMONU_MGMT_ONU_CFG_DATA_ID_DS_PRIORITY_QUEUES = 10, /**< DS priority queues. */
    BCMONU_MGMT_ONU_CFG_DATA_ID_NUM_OF_DS_PRIORITY_QUEUES = 11, /**< Number of DS priority queues. */
    BCMONU_MGMT_ONU_CFG_DATA_ID_DOWNSTREAM_MODE = 12, /**< downstream mode. */
    BCMONU_MGMT_ONU_CFG_DATA_ID__NUM_OF, /**< Constant to use for sizing arrays - note that enum may have holes. */

    /* Lower-case versions for macro support. */
#define bcmonu_mgmt_onu_cfg_data_id__begin BCMONU_MGMT_ONU_CFG_DATA_ID__BEGIN
#define bcmonu_mgmt_onu_cfg_data_id_admin_state BCMONU_MGMT_ONU_CFG_DATA_ID_ADMIN_STATE
#define bcmonu_mgmt_onu_cfg_data_id_oper_status BCMONU_MGMT_ONU_CFG_DATA_ID_OPER_STATUS
#define bcmonu_mgmt_onu_cfg_data_id_input_tpid BCMONU_MGMT_ONU_CFG_DATA_ID_INPUT_TPID
#define bcmonu_mgmt_onu_cfg_data_id_output_tpid BCMONU_MGMT_ONU_CFG_DATA_ID_OUTPUT_TPID
#define bcmonu_mgmt_onu_cfg_data_id_unis BCMONU_MGMT_ONU_CFG_DATA_ID_UNIS
#define bcmonu_mgmt_onu_cfg_data_id_num_of_unis BCMONU_MGMT_ONU_CFG_DATA_ID_NUM_OF_UNIS
#define bcmonu_mgmt_onu_cfg_data_id_agg_ports BCMONU_MGMT_ONU_CFG_DATA_ID_AGG_PORTS
#define bcmonu_mgmt_onu_cfg_data_id_num_of_agg_ports BCMONU_MGMT_ONU_CFG_DATA_ID_NUM_OF_AGG_PORTS
#define bcmonu_mgmt_onu_cfg_data_id_us_priority_queues BCMONU_MGMT_ONU_CFG_DATA_ID_US_PRIORITY_QUEUES
#define bcmonu_mgmt_onu_cfg_data_id_num_of_us_priority_queues BCMONU_MGMT_ONU_CFG_DATA_ID_NUM_OF_US_PRIORITY_QUEUES
#define bcmonu_mgmt_onu_cfg_data_id_ds_priority_queues BCMONU_MGMT_ONU_CFG_DATA_ID_DS_PRIORITY_QUEUES
#define bcmonu_mgmt_onu_cfg_data_id_num_of_ds_priority_queues BCMONU_MGMT_ONU_CFG_DATA_ID_NUM_OF_DS_PRIORITY_QUEUES
#define bcmonu_mgmt_onu_cfg_data_id_downstream_mode BCMONU_MGMT_ONU_CFG_DATA_ID_DOWNSTREAM_MODE
#define bcmonu_mgmt_onu_cfg_data_id__num_of BCMONU_MGMT_ONU_CFG_DATA_ID__NUM_OF
#define bcmonu_mgmt_onu_cfg_data_id_all_properties 0xFF
#define bcmonu_mgmt_onu_cfg_data_id_full_mask 0x1FFF

} bcmonu_mgmt_onu_cfg_data_id;

/** Identifiers for all fields in a 'onu_key'. */
typedef enum
{
    BCMONU_MGMT_ONU_KEY_ID__BEGIN = 0,
    BCMONU_MGMT_ONU_KEY_ID_PON_NI = 0, /**< PON Interface ID. */
    BCMONU_MGMT_ONU_KEY_ID_ONU_ID = 1, /**< ONU ID. */
    BCMONU_MGMT_ONU_KEY_ID__NUM_OF, /**< Constant to use for sizing arrays - note that enum may have holes. */

    /* Lower-case versions for macro support. */
#define bcmonu_mgmt_onu_key_id__begin BCMONU_MGMT_ONU_KEY_ID__BEGIN
#define bcmonu_mgmt_onu_key_id_pon_ni BCMONU_MGMT_ONU_KEY_ID_PON_NI
#define bcmonu_mgmt_onu_key_id_onu_id BCMONU_MGMT_ONU_KEY_ID_ONU_ID
#define bcmonu_mgmt_onu_key_id__num_of BCMONU_MGMT_ONU_KEY_ID__NUM_OF
#define bcmonu_mgmt_onu_key_id_all_properties 0xFF
#define bcmonu_mgmt_onu_key_id_full_mask 0x3

} bcmonu_mgmt_onu_key_id;



#define BCMONU_MGMT_OBJ_ID_ANY ((bcmonu_mgmt_obj_id)UINT16_MAX)

/** @} */

#endif /* _ONU_MGMT_MODEL_IDS_H_ */
