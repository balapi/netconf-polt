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

#ifndef _OMCI_SVC_COMMON_H_
#define _OMCI_SVC_COMMON_H_

#include <bcmos_system.h>
#include <bcm_dev_log.h>
#include <bcmolt_math.h>
#include <bcmolt_conv.h>
#include <bcmolt_api.h>
#include <onu_mgmt_model_types.h>
#include <omci_stack_model_types.h>
#include "omci_svc_adapter_common.h"
#include "omci_svc_adapt_old_code.h"

extern int omci_svc_is_issu;

/** @todo currently setting max ONUs per pon to 256. Later BAL topology query should return this */
#define OMCI_SVC_PON_TOPO_MAX_ONUS_PER_PON     (MAX(GPON_NUM_OF_ONUS, XGPON_NUM_OF_ONUS))

#define OMCI_SVC_PON_TOPO_CONTEXT(olt_id, pon_id) ((omci_svc_pon_context_t *)omci_svc_topo_pon_get_context(olt_id, pon_id))
#define OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, pon_id, onu_id) (&(OMCI_SVC_PON_TOPO_CONTEXT(olt_id, pon_id)->onus[onu_id]))
#define OMCI_SVC_PON_IS_VALID(olt_id, logical_pon_id)   (omci_svc_topo_pon_is_valid(olt_id, logical_pon_id))
#define OMCI_SVC_PON_IS_ONU_ID_VALID(olt_id, logical_pon_id, onu_id)   (omci_svc_topo_pon_is_onu_id_valid(olt_id, logical_pon_id, onu_id))

bcmos_errno omci_svc_topo_init_context(bcmolt_oltid olt_id, uint8_t max_pon_for_olt);
bcmos_errno omci_svc_topo_pon_set_context(bcmolt_oltid olt_id, uint32_t logical_pon_id, uint32_t max_num_of_onus, void *context);
void *omci_svc_topo_pon_get_context(bcmolt_oltid olt_id, uint32_t logical_pon_id);
bcmos_bool omci_svc_topo_pon_is_valid(bcmolt_oltid olt_id, uint32_t logical_pon_id);
bcmos_bool omci_svc_topo_pon_is_onu_id_valid(bcmolt_oltid olt_id, uint32_t logical_pon_id, bcmolt_pon_onu_id onu_id);


#define OMCI_LOG_COLOR_DEFAULT NULL
#define OMCI_LOG_COLOR_RED "\033[31m"
#define OMCI_LOG_COLOR_GREEN "\033[32m"
#define OMCI_LOG_COLOR_YELLOW "\033[33m"
#define OMCI_LOG_COLOR_BLUE "\033[34m"
#define OMCI_LOG_COLOR_BOLD "\033[1m"
#define OMCI_LOG_COLOR_RESET "\e[0m"

#define OMCI_LOG_COLOR_RX OMCI_LOG_COLOR_DEFAULT
#define OMCI_LOG_COLOR_TX OMCI_LOG_COLOR_DEFAULT

#define OMCI_SVC_LOG(level, olt_id, key, msg, fmt, args...) \
    do \
    { \
        omci_svc_onu *_onu = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, key->pon_ni, key->onu_id); \
        BCM_LOG_CALLER_FMT(level, omci_svc_log_id, "key={pon_ni=%u, onu_id=%u}, op_ref=%u: " \
            fmt, key->pon_ni, key->onu_id, _onu->op_ref, ## args); \
        if (msg) \
        { \
            bcmonu_mgmt_msg *_msg = msg; \
            snprintf(_msg->err_text, sizeof(_msg->err_text), "key={pon_ni=%u, onu_id=%u}, op_ref=%u: " \
                fmt, key->pon_ni, key->onu_id, _onu->op_ref, ## args); \
        } \
    } while (0)

/* We assume that for the same ONU there cannot be more than 16 concurrent flow add/delete operations. */
#define OMCI_SVC_FLOW_OP_QUEUE_SIZE 16

#define OMCI_SVC_ETH_UNI_PORT_ID_MASK 0x0FFF

/** This defines the bit positions & values to make a ME instance entity Id based on following:
  - VID (0-12th bits including 4096 used for any vid)
  - uni port included in entity Id (13th bit)
  - untagged flow (14th bit)
  - mcast/broadcast flow (15th bit)
  */
#define OMCI_SVC_O_VID_IS_MULTICAST_BROADCAST_MASK      0x8000
#define OMCI_SVC_O_VID_IS_MULTICAST_BROADCAST_SHIFT     15
/** Untagged flow would be designated as having vid of 4096 with a 1 in bit place 14 (starting from 0).
  This is needed to just assign an entity Id for a ME for untagged flow,
  and avoid conflicting with an ME associated actually with unicast or multicast VID value of 4096 (internal value to designate "Any VID") */
#define OMCI_SVC_O_VID_UNTAGGED_END_TO_END_FLOW_SHIFT   14
/** if VID+uni_port makes entity Id; 
  this is used for Flows classifying same VID on different UNI ports (e.g. Broadcast flow) */
#define OMCI_SVC_O_VID_PLUS_UNI_FLOW_SHIFT              13

#define OMCI_SVC_O_VID_VALUE_MASK                       0x1FFF

#define OMCI_SVC_O_VID_ENTITY_ID_HAS_UNI_PORT(o_vid_entity_id)  ((o_vid_entity_id) & (1 << OMCI_SVC_O_VID_PLUS_UNI_FLOW_SHIFT))

typedef enum
{
    BCMBAL_PON_MODE_GPON,
    BCMBAL_PON_MODE_XGPON,
} bcmbal_pon_mode;

#ifdef ENABLE_LOG
extern dev_log_id omci_svc_log_id;
#endif
extern bcmos_bool omci_ready;

typedef enum
{
    OMCI_SVC_EVENT_ID__BEGIN,
    OMCI_SVC_EVENT_ID_ACTIVATE = OMCI_SVC_EVENT_ID__BEGIN,
    OMCI_SVC_EVENT_ID_DEACTIVATE,
    OMCI_SVC_EVENT_ID_ACTIVATE_SUCCESS,
    OMCI_SVC_EVENT_ID_DEACTIVATE_SUCCESS,
    OMCI_SVC_EVENT_ID_MIB_RESET_SUCCESS,
    OMCI_SVC_EVENT_ID_MIB_UPLOAD_INIT_SUCCESS,
    OMCI_SVC_EVENT_ID_MIB_UPLOAD_MORE,
    OMCI_SVC_EVENT_ID_MIB_UPLOAD_LAST,
    OMCI_SVC_EVENT_ID_CREATE_SUCCESS,
    OMCI_SVC_EVENT_ID_SET_SUCCESS,
    OMCI_SVC_EVENT_ID_DELETE_SUCCESS,
    OMCI_SVC_EVENT_ID_ADD_ENTRY_SUCCESS,
    OMCI_SVC_EVENT_ID_REMOVE_ENTRY_SUCCESS,
    OMCI_SVC_EVENT_ID_LINK_UP,
    OMCI_SVC_EVENT_ID_LINK_DOWN,
    OMCI_SVC_EVENT_ID_START,
    OMCI_SVC_EVENT_ID_IS_ENTERED,
    OMCI_SVC_EVENT_ID__NUM_OF,
} omci_svc_event_id;

BCMOLT_TYPE2STR(omci_svc_event_id, extern);

typedef void (*omci_svc_sm_run_cb)(bcmolt_oltid olt_id, omci_svc_event_id event, bcmonu_mgmt_onu_key *key, void *context);
typedef void (*omci_svc_sm_rollback_cb)(bcmolt_oltid olt_id, bcmonu_mgmt_onu_key *key, bcmos_errno last_err, void *context);

/* Important: order in this state machine is important, as we move from one state to the next via ++ operator. */
typedef enum
{
    /* Up direction */
    OMCI_SVC_ONU_STATE_ID_INACTIVE,
    OMCI_SVC_ONU_STATE_ID_ACTIVATING,
    OMCI_SVC_ONU_STATE_ID_WAIT_FOR_LINK_UP,
    OMCI_SVC_ONU_STATE_ID_MIB_RESET,
    OMCI_SVC_ONU_STATE_ID_MIB_UPLOAD,
    OMCI_SVC_ONU_STATE_ID_CREATE_GAL_ETHERNET_PROFILE,
    OMCI_SVC_ONU_STATE_ID_CREATE_EXT_VLAN_TAG_OPER_CFG_DATA,
    OMCI_SVC_ONU_STATE_ID_SET_EXT_VLAN_TAG_OPER_CFG_DATA,
    OMCI_SVC_ONU_STATE_ID_CREATE_MAC_BRIDGE_SERVICE_PROFILE,
    OMCI_SVC_ONU_STATE_ID_CREATE_MAC_BRIDGE_PORT_CFG_DATA,
    OMCI_SVC_ONU_STATE_ID_CREATE_MULTICAST_OPERATIONS_PROFILE,
    OMCI_SVC_ONU_STATE_ID_CREATE_MULTICAST_SUBSCRIBER_CONFIG_INFO,
    OMCI_SVC_ONU_STATE_ID_UP_SEQUENCE_END,
    OMCI_SVC_ONU_STATE_ID_ACTIVE_WORKING,

    /* Down direction */
    OMCI_SVC_ONU_STATE_ID_DEACTIVATING,
    OMCI_SVC_ONU_STATE_ID_DOWN_SEQUENCE_END,

    OMCI_SVC_ONU_STATE_ID__NUM_OF,
} omci_svc_onu_state_id;

typedef enum
{
    OMCI_SVC_FLOW_OP_ID_ADD,
    OMCI_SVC_FLOW_OP_ID_DELETE,
} omci_svc_flow_op_id;

/* Important: order in this state machine is important, as we move from one state to the next via ++ operator. */
typedef enum
{
    /* Up direction */
    OMCI_SVC_FLOW_STATE_ID_INACTIVE,

    OMCI_SVC_FLOW_STATE_ID_SET_TCONT,
    OMCI_SVC_FLOW_STATE_ID_CREATE_GEM_PORT_NETWORK_CTP,

    /* Because there are mutual associations: 802.1p Mapper Service Profile <-> GEM Interworking TP, then:
     * 1. We create 802.1p Mapper Service Profile without associating it to GEM Interworking TP.
     * 2. We create GEM Interworking TP and associate it with the 802.1p Mapper Service Profile.
     * 3. Finally we can associate the 802.1p Mapper Service Profile with the GEM Interworking TP. */
    OMCI_SVC_FLOW_STATE_ID_CREATE_8021P_MAPPER_SERVICE_PROFILE,
    OMCI_SVC_FLOW_STATE_ID_CREATE_GEM_INTERWORKING_TP,
    OMCI_SVC_FLOW_STATE_ID_ADD_ENTRY_MULTICAST_GEM_INTERWORKING_TP,
    OMCI_SVC_FLOW_STATE_ID_SET_8021P_MAPPER_SERVICE_PROFILE,

    OMCI_SVC_FLOW_STATE_ID_CREATE_MAC_BRIDGE_PORT_CFG_DATA,
    OMCI_SVC_FLOW_STATE_ID_CREATE_VLAN_TAGGING_FILTER_DATA,
    OMCI_SVC_FLOW_STATE_ID_ADD_ENTRY_EXT_VLAN_TAG_OPER_CFG_DATA,
    OMCI_SVC_FLOW_STATE_ID_SET_MULTICAST_OPERATIONS_PROFILE,
    OMCI_SVC_FLOW_STATE_ID_ADD_ENTRY_MULTICAST_OPERATIONS_PROFILE_DYNAMIC_ACL,
    OMCI_SVC_FLOW_STATE_ID_UP_SEQUENCE_END,

    OMCI_SVC_FLOW_STATE_ID_ACTIVE,

    /* Down direction */
    OMCI_SVC_FLOW_STATE_ID_DELETE_ENTRY_MULTICAST_OPERATIONS_PROFILE_DYNAMIC_ACL,
    OMCI_SVC_FLOW_STATE_ID_UNSET_MULTICAST_OPERATIONS_PROFILE,
    OMCI_SVC_FLOW_STATE_ID_DELETE_ENTRY_EXT_VLAN_TAG_OPER_CFG_DATA,
    OMCI_SVC_FLOW_STATE_ID_DELETE_VLAN_TAGGING_FILTER_DATA,
    OMCI_SVC_FLOW_STATE_ID_DELETE_MAC_BRIDGE_PORT_CFG_DATA,
    /* Because there are mutual associations: 802.1p Mapper Service Profile <-> GEM Interworking TP (see comment in "UP direction" above), then we need to unset the association from
     * 802.1p Mapper Service Profile to GEM Interworking TP before deleting GEM Interworking TP. */
    OMCI_SVC_FLOW_STATE_ID_UNSET_8021P_MAPPER_SERVICE_PROFILE,
    OMCI_SVC_FLOW_STATE_ID_DELETE_ENTRY_MULTICAST_GEM_INTERWORKING_TP,
    OMCI_SVC_FLOW_STATE_ID_DELETE_GEM_INTERWORKING_TP,
    OMCI_SVC_FLOW_STATE_ID_DELETE_8021P_MAPPER_SERVICE_PROFILE,
    OMCI_SVC_FLOW_STATE_ID_DELETE_GEM_PORT_NETWORK_CTP,
    OMCI_SVC_FLOW_STATE_ID_UNSET_TCONT,
    OMCI_SVC_FLOW_STATE_ID_DOWN_SEQUENCE_END,

    OMCI_SVC_FLOW_STATE_ID__NUM_OF,
} omci_svc_flow_state_id;


typedef struct
{
    bcmonu_mgmt_flow_cfg flow;
    /* A flow after reversing its direction. This is needed because Extended VLAN Tagging Operation Data ME is working only with US flows, so if we got multicast flow (DS), we need its
     * reversed operation (US). For example, pop becomes push. */
    bcmonu_mgmt_flow_cfg flow_reversed;
    omci_svc_flow_op_id op_id;
    omci_svc_flow_state_id state;
    /* User callback and context to return to after flow SM completes. */
    bcmonu_mgmt_complete_cb cb;
    void *context;
    bcmos_bool is_clear;
} omci_svc_flow_op;

typedef struct
{
    bcmos_mutex mutex;
    char name[MAX_MUTEX_NAME_SIZE];
} omci_svc_mutex;

typedef struct
{
    omci_svc_flow_op queue[OMCI_SVC_FLOW_OP_QUEUE_SIZE];
    omci_svc_flow_op *head;
    omci_svc_flow_op *tail;
    uint16_t read_count;
    uint16_t write_count;
    omci_svc_mutex mutex;
} omci_svc_flow_op_queue;

/* flow cfg DB data structures */
typedef struct omci_svc_flow_cfg_entry
{
    TAILQ_ENTRY(omci_svc_flow_cfg_entry) next;
    bcmonu_mgmt_flow_cfg cfg;
} omci_svc_flow_cfg_entry;

typedef TAILQ_HEAD(, omci_svc_flow_cfg_entry) omci_svc_flow_cfg_db_t;


typedef struct omci_svc_uni
{
    TAILQ_ENTRY(omci_svc_uni) next;
    bcmonu_mgmt_uni uni;
} omci_svc_uni;

typedef struct omci_svc_tcont
{
    TAILQ_ENTRY(omci_svc_tcont) next;
    bcmonu_mgmt_agg_port_list_entry tcont;
    uint16_t ref_count;
} omci_svc_tcont;

typedef struct omci_svc_priority_queue
{
    TAILQ_ENTRY(omci_svc_priority_queue) next;
    bcmonu_mgmt_priority_queue queue;
} omci_svc_priority_queue;

typedef struct
{
    struct
    {
        uint16_t class_id;
        uint16_t entity_id;
    } me_id;
    uint16_t tp_ptr;
    uint16_t interwork_tp_ptr_pri_0;
    uint16_t interwork_tp_ptr_pri_1;
    uint16_t interwork_tp_ptr_pri_2;
    uint16_t interwork_tp_ptr_pri_3;
    uint16_t interwork_tp_ptr_pri_4;
    uint16_t interwork_tp_ptr_pri_5;
    uint16_t interwork_tp_ptr_pri_6;
    uint16_t interwork_tp_ptr_pri_7;
    uint8_t unmarked_frame_opt;
    char dscp_to_pbit_mapping[BCM_OMCI_CFG_DATA_DSCP_TO_PBIT_MAPPING_LEN];
    uint8_t default_pbit_marking;
    uint8_t mapper_tp_type;
} omci_svc_ieee_8021_p_mapper_svc_prof;


typedef struct omci_svc_o_vid
{
    DLIST_ENTRY(omci_svc_o_vid) next;
    uint16_t entity_id; /* Has VID value and control bits to indicate mcast etc */
    uint16_t ref_count;
    omci_svc_ieee_8021_p_mapper_svc_prof ieee_8021p_mapper_service_profile_me; /* Not relevant in case of multicast. */
} omci_svc_o_vid;

typedef struct omci_svc_o_vid_uni
{
    DLIST_ENTRY(omci_svc_o_vid_uni) next;
    uint16_t ctrl_bits;          /* mcast/bast, untagged, uniport (bits 15, 14, 13) */
    uint16_t o_vid;
    uint16_t uni_entity_id;     /* uni entity id as reported by ONU MIB */
    uint16_t entity_id; /* entity id which maps from o_vid & uni port (used for broadcast flow) */
    uint16_t ref_count;
    omci_svc_ieee_8021_p_mapper_svc_prof ieee_8021p_mapper_service_profile_me; /* Not relevant for mcast or broadcast. */
} omci_svc_o_vid_uni;

typedef struct omci_svc_gem_port
{
    DLIST_ENTRY(omci_svc_gem_port) next;
    bcmonu_mgmt_svc_port_id gem_port_id;
    uint16_t ref_count;
} omci_svc_gem_port;

typedef struct omci_svc_mac_bridge_port
{
    TAILQ_ENTRY(omci_svc_mac_bridge_port) next;
    uint8_t port_num;
    uint16_t entity_id;
} omci_svc_mac_bridge_port;

typedef struct omci_svc_onu_mib
{
    /* ME that will probably already exist on the ONU after MIB reset. */
    TAILQ_HEAD(, omci_svc_uni) unis;
    uint32_t num_of_unis;

    TAILQ_HEAD(, omci_svc_tcont) free_tconts;
    TAILQ_HEAD(, omci_svc_tcont) used_tconts;
    uint32_t num_of_tconts;

    TAILQ_HEAD(, omci_svc_priority_queue) us_priority_queues;
    uint32_t num_of_us_priority_queues;

    TAILQ_HEAD(, omci_svc_priority_queue) ds_priority_queues;
    uint32_t num_of_ds_priority_queues;

    /* ME that will probably be provisioned to the ONU by the OLT. */
    DLIST_HEAD(, omci_svc_o_vid) o_vids;
    DLIST_HEAD(, omci_svc_o_vid_uni) o_vid_unis;
    DLIST_HEAD(, omci_svc_gem_port) gem_ports;
    TAILQ_HEAD(, omci_svc_mac_bridge_port) free_mac_bridge_ports;
    TAILQ_HEAD(, omci_svc_mac_bridge_port) used_mac_bridge_ports;
    uint16_t input_tpid;
    uint16_t output_tpid;
} omci_svc_onu_mib;

typedef struct omci_svc_onu
{
    omci_svc_onu_state_id state;
    bcmonu_mgmt_admin_state admin_state;
    bcmonu_mgmt_status oper_status;
    bcmonu_mgmt_onu_cfg *onu_cfg;

    /* Next available operation reference */
    uint16_t op_ref;
    omci_svc_flow_op_queue flow_op_queue;
    bcmos_errno last_err;
    bcmos_bool is_clear;

    /* User callback and context to return to after ONU SM completes. */
    bcmonu_mgmt_complete_cb cb;
    void *context;

    /* ONU and flow have different state machines. */
    omci_svc_sm_run_cb sm_run_cb;
    omci_svc_sm_rollback_cb sm_rollback_cb;

    /* ONU MIB */
    omci_svc_onu_mib mib;

    void *iter; /* Generic iterator */

    /** 8 bit of Id generator for o_vid+uni based entity Id;
        @note the actual Id is set with control bits for broadcast, uni port inclusion etc,
                and stored in o_vid_unis entries.
     */
    uint8_t o_vid_uni_entity_id_gen;    /* 8 bit of Id generator for o_vid+uni based entity Id */
} omci_svc_onu;

/* Per PON context */
typedef struct
{
    omci_svc_onu onus[OMCI_SVC_PON_TOPO_MAX_ONUS_PER_PON]; /* Per ONU context */
} omci_svc_pon_context_t;

typedef struct omci_svc_onu_cfg_entry
{
    TAILQ_ENTRY(omci_svc_onu_cfg_entry) next;
    bcmonu_mgmt_onu_cfg cfg;
} omci_svc_onu_cfg_entry;

typedef TAILQ_HEAD(, omci_svc_onu_cfg_entry) omci_svc_onu_cfg_db_t;

typedef void (*omci_svc_sm_cb)(bcmonu_mgmt_onu_key *key, void *context);

bcmos_errno omci_svc_validate(bcmonu_mgmt_onu_key *key, bcmonu_mgmt_msg *msg);
void omci_svc_flow_op_queue_flush(omci_svc_onu *onu_context);
void omci_svc_flow_cfg_db_flush_for_onu(omci_svc_onu *onu_context, bcmonu_mgmt_onu_key *onu_key);

#endif

