#ifndef _ONU_MGMT_MODEL_API_STRUCTS_H_
#define _ONU_MGMT_MODEL_API_STRUCTS_H_

#include <bcmos_system.h>
#include <bcmolt_buf.h>
#include "onu_mgmt_model_ids.h"
#include "onu_mgmt_model_types.h"
#include "onu_mgmt_model_supporting_structs.h"

/** \addtogroup object_model
 * @{
 */

/** Flow: key */
typedef struct
{
    uint32_t id; /**< Flow ID. */
    bcmonu_mgmt_flow_dir_id dir; /**< Flow direction. */
} bcmonu_mgmt_flow_key;

/** Flow: cfg */
typedef struct
{
    bcmonu_mgmt_presence_mask presence_mask;
    bcmonu_mgmt_admin_state admin_state; /**< Administrative state */
    bcmonu_mgmt_status oper_status; /**< Operational status */
    bcmonu_mgmt_flow_onu_key onu_key; /**< ONU Key. */
    bcmonu_mgmt_flow_type flow_type; /**< Flow type */
    bcmonu_mgmt_svc_port_id svc_port_id; /**< Service Port ID */
    bcmonu_mgmt_agg_port_id agg_port_id; /**< Aggregate Port ID */
    bcmonu_mgmt_uni_port uni_port; /**< UNI port */
    bcmonu_mgmt_flow_match match; /**< Match. */
    bcmonu_mgmt_flow_action action; /**< Action. */
    bcmonu_mgmt_igmp_us_action igmp_us_action; /**< IGMP action on Upstream */
} bcmonu_mgmt_flow_cfg_data;

/* Constants associated with bcmonu_mgmt_flow_cfg_data. */
#define BCMONU_MGMT_FLOW_CFG_DATA_PRESENCE_MASK_ALL 0x00000000000003FFULL

/** Transport message definition for "cfg" group of "flow" object. */
typedef struct
{
    bcmonu_mgmt_cfg hdr; /**< Transport header. */
    bcmonu_mgmt_flow_key key; /**< Object key. */
    bcmonu_mgmt_flow_cfg_data data; /**< All properties that must be set by the user. */
} bcmonu_mgmt_flow_cfg;

/** Multi-object message definition for "cfg" group of "flow" object. */
typedef struct
{
    bcmonu_mgmt_multi_cfg hdr; /**< Transport header. */
    bcmonu_mgmt_flow_key key; /**< Object key (can include wildcards). */
    bcmonu_mgmt_flow_cfg_data filter; /**< Only include responses that match these values. */
    bcmonu_mgmt_flow_cfg_data request; /**< Responses will include all present fields. */

    bcmos_bool more; /**< BCMOS_TRUE if not all responses were retreived by the last API call. */
    uint16_t num_responses; /**< Number of responses to the last API call. */
    bcmonu_mgmt_flow_cfg *responses; /**< Responses to the last API call. */

    bcmonu_mgmt_flow_key next_key; /**< Key iterator (do not set manually). */
} bcmonu_mgmt_flow_multi_cfg;

/** ONU: key */
typedef struct
{
    uint8_t pon_ni; /**< PON Interface ID */
    uint16_t onu_id; /**< ONU ID */
} bcmonu_mgmt_onu_key;

/** ONU: cfg */
typedef struct
{
    bcmonu_mgmt_presence_mask presence_mask;
    bcmonu_mgmt_admin_state admin_state; /**< Administrative state */
    bcmonu_mgmt_status oper_status; /**< Operational status */
    uint16_t input_tpid; /**< Input TPID */
    uint16_t output_tpid; /**< Output TPID */
    bcmonu_mgmt_arr_uni_8 unis; /**< UNIs */
    uint32_t num_of_unis; /**< Number of UNIs */
    bcmonu_mgmt_arr_agg_port_list_entry_64 agg_ports; /**< T-CONTs */
    uint32_t num_of_agg_ports; /**< Number of T-CONTs */
    bcmonu_mgmt_arr_priority_queue_128 us_priority_queues; /**< US priority queues */
    uint32_t num_of_us_priority_queues; /**< Number of US priority queues */
    bcmonu_mgmt_arr_priority_queue_128 ds_priority_queues; /**< DS priority queues */
    uint32_t num_of_ds_priority_queues; /**< Number of DS priority queues */
    bcmonu_mgmt_downstream_mode_values downstream_mode; /**< downstream frames tagging action based on upstream rules. Sent in Extended vlan tagging ME for the ONU */
} bcmonu_mgmt_onu_cfg_data;

/* Constants associated with bcmonu_mgmt_onu_cfg_data. */
#define BCMONU_MGMT_ONU_CFG_DATA_PRESENCE_MASK_ALL 0x0000000000001FFFULL
#define BCMONU_MGMT_ONU_CFG_DATA_UNIS_LENGTH 8
#define BCMONU_MGMT_ONU_CFG_DATA_AGG_PORTS_LENGTH 64
#define BCMONU_MGMT_ONU_CFG_DATA_US_PRIORITY_QUEUES_LENGTH 128
#define BCMONU_MGMT_ONU_CFG_DATA_DS_PRIORITY_QUEUES_LENGTH 128

/** Transport message definition for "cfg" group of "onu" object. */
typedef struct
{
    bcmonu_mgmt_cfg hdr; /**< Transport header. */
    bcmonu_mgmt_onu_key key; /**< Object key. */
    bcmonu_mgmt_onu_cfg_data data; /**< All properties that must be set by the user. */
} bcmonu_mgmt_onu_cfg;

/** Multi-object message definition for "cfg" group of "onu" object. */
typedef struct
{
    bcmonu_mgmt_multi_cfg hdr; /**< Transport header. */
    bcmonu_mgmt_onu_key key; /**< Object key (can include wildcards). */
    bcmonu_mgmt_onu_cfg_data filter; /**< Only include responses that match these values. */
    bcmonu_mgmt_onu_cfg_data request; /**< Responses will include all present fields. */

    bcmos_bool more; /**< BCMOS_TRUE if not all responses were retreived by the last API call. */
    uint16_t num_responses; /**< Number of responses to the last API call. */
    bcmonu_mgmt_onu_cfg *responses; /**< Responses to the last API call. */

    bcmonu_mgmt_onu_key next_key; /**< Key iterator (do not set manually). */
} bcmonu_mgmt_onu_multi_cfg;



/** @} */

typedef void (*onu_state_changed_cb)(bcmonu_mgmt_onu_key *key);
typedef void (*flow_state_changed_cb)(bcmonu_mgmt_flow_key *key);


#endif /* _ONU_MGMT_MODEL_API_STRUCTS_H_ */
