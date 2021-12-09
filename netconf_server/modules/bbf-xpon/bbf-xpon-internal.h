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
 * bbf-xpon-internal.h
 */

#ifndef _BBF_XPON_INTERNAL_H_
#define _BBF_XPON_INTERNAL_H_

#define _GNU_SOURCE

#include <bbf-xpon.h>
#include <bcmolt_api.h>

#include "bbf-xpon_constants.h"
#include "bbf-types.h"

#include <libnetconf2/log.h>
#include <bcmolt_netconf_module_utils.h>

#define BBF_XPON_MAX_NAME_LENGTH    64

extern sr_subscription_ctx_t *sr_ctx;

/* Object type */
typedef enum
{
    XPON_OBJ_TYPE__FIRST,
    XPON_OBJ_TYPE_ENET = XPON_OBJ_TYPE__FIRST,
    XPON_OBJ_TYPE_CGROUP,
    XPON_OBJ_TYPE_CPART,
    XPON_OBJ_TYPE_CPAIR,
    XPON_OBJ_TYPE_CTERM,
    XPON_OBJ_TYPE_V_ANI,
    XPON_OBJ_TYPE_ANI,
    XPON_OBJ_TYPE_V_ANI_V_ENET,
    XPON_OBJ_TYPE_ANI_V_ENET,
    XPON_OBJ_TYPE_VLAN_SUBIF,
    XPON_OBJ_TYPE_TCONT,
    XPON_OBJ_TYPE_GEM,
    XPON_OBJ_TYPE_WAVELENGTH_PROFILE,
    XPON_OBJ_TYPE_TRAFFIC_DESCR_PROFILE,
    XPON_OBJ_TYPE_QOS_CLASSIFIER,
    XPON_OBJ_TYPE_QOS_POLICY,
    XPON_OBJ_TYPE_QOS_POLICY_PROFILE,
    XPON_OBJ_TYPE_FORWARDER_PORT,
    XPON_OBJ_TYPE_FORWARDER,
    XPON_OBJ_TYPE_FWD_SPLIT_HORIZON_PROFILE,
    XPON_OBJ_TYPE_FWD_DB,
    XPON_OBJ_TYPE_HARDWARE,
    XPON_OBJ_TYPE_DHCPR_PROFILE,
    XPON_OBJ_TYPE_TM_TC_ID_TO_Q_PROFILE,
    XPON_OBJ_TYPE_TM_BAC_PROFILE,
    XPON_OBJ_TYPE__LAST = XPON_OBJ_TYPE_DHCPR_PROFILE,

    XPON_OBJ_TYPE_ANY = (-2),
    XPON_OBJ_TYPE_INVALID = NC_TRANSACT_PLUGIN_ELEM_TYPE_INVALID
} xpon_obj_type;

/* admin state */
typedef enum
{
    XPON_ADMIN_STATE_DISABLED,
    XPON_ADMIN_STATE_ENABLED
} xpon_admin_state;

/* GEM / TCONT state */
typedef enum
{
    XPON_RESOURCE_STATE_NOT_CONFIGURED  = 0, /**< Resource is not configured */
    XPON_RESOURCE_STATE_INACTIVE        = 1, /**< Resource is associated wit ONU that isn't registered */
    XPON_RESOURCE_STATE_IN_PROGRESS     = 2, /**< Resource provisioning is in progress */
    XPON_RESOURCE_STATE_ACTIVE          = 3, /**< Resource is active */
} xpon_resource_state;

/* Object header */
typedef struct xpon_obj_hdr xpon_obj_hdr;
struct xpon_obj_hdr
{
    xpon_obj_type obj_type;
    const char *name;
    bcmolt_presence_mask presence_mask;
    STAILQ_ENTRY(xpon_obj_hdr) next;
    bcmos_bool being_deleted;
    bcmos_bool created_by_forward_reference;
};
typedef STAILQ_HEAD(xpon_obj_list, xpon_obj_hdr) xpon_obj_list;

/* Internal macro: Get a bitmask given a property ID enum */
#define XPON_PROP_MASK(_obj_type, _p) \
    (1ULL << (uint64_t)xpon_  ## _obj_type ## _prop_id_ ## _p)

#define XPON_STR_PROP_SET_PRESENT(_str, _str_type, _p) \
    ((_str)->presence_mask |= XPON_PROP_MASK(_str_type, _p))

#define XPON_STR_PROP_CLEAR(_str, _str_type, _p) \
    ((_str)->presence_mask &= ~XPON_PROP_MASK(_str_type, _p))

#define XPON_STR_PROP_IS_SET(_str, _str_type, _p) \
    (((_str)->presence_mask & XPON_PROP_MASK(_str_type, _p)) != 0)

#define XPON_STR_PROP_SET(_str, _str_type, _p, _val) \
    do { \
        XPON_STR_PROP_SET_PRESENT(_str, _str_type, _p);\
        (_str)->_p = _val;\
    } while (0)

#define XPON_PROP_SET_PRESENT(_obj, _obj_type, _p) \
    XPON_STR_PROP_SET_PRESENT(&(_obj)->hdr, _obj_type, _p)

#define XPON_PROP_CLEAR(_obj, _obj_type, _p) \
    XPON_STR_PROP_CLEAR(&(_obj)->hdr, _obj_type, _p)

#define XPON_PROP_IS_SET(_obj, _obj_type, _p) \
    XPON_STR_PROP_IS_SET(&(_obj)->hdr, _obj_type, _p)

#define XPON_PROP_SET(_obj, _obj_type, _p, _val) \
    do { \
        XPON_PROP_SET_PRESENT(_obj, _obj_type, _p);\
        (_obj)->_p = _val;\
    } while (0)

#define XPON_PROP_COPY(_src, _dst, _obj_type, _p) \
    do { \
        if (XPON_PROP_IS_SET(_src, _obj_type, _p)) \
            XPON_PROP_SET(_dst, _obj_type, _p, (_src)->_p);\
    } while (0)

#define XPON_PROP_COPY_TO_OLT(_xpon_obj, _xpon_obj_type, _xpon_prop, _olt_obj, _olt_prop) \
    do { \
        if (XPON_PROP_IS_SET(_xpon_obj, _xpon_obj_type, _xpon_prop)) \
            BCMOLT_MSG_FIELD_SET(_olt_obj, _olt_prop, (_xpon_obj)->_xpon_prop);\
    } while (0)

#define XPON_PROP_COPY_FROM_OLT(_xpon_obj, _xpon_obj_type, _xpon_prop, _olt_obj, _olt_obj_type, _olt_prop) \
    do { \
        if (BCMOLT_FIELD_IS_SET(&((_olt_obj)->data), _olt_obj_type, _olt_prop)) \
            XPON_PROP_SET(_xpon_obj, _xpon_obj_type, _xpon_prop, (_olt_obj)->data._olt_prop);\
    } while (0)

typedef struct xpon_channel_group xpon_channel_group;
typedef struct xpon_channel_partition xpon_channel_partition;
typedef struct xpon_channel_pair xpon_channel_pair;
typedef struct xpon_channel_termination xpon_channel_termination;
typedef struct xpon_v_ani xpon_v_ani;
typedef struct xpon_ani xpon_ani;
typedef struct xpon_v_ani_v_enet xpon_v_ani_v_enet;
typedef struct xpon_ani_v_enet xpon_ani_v_enet;
typedef struct xpon_wavelength_profile xpon_wavelength_profile;
typedef struct xpon_td_profile xpon_td_profile;
typedef struct xpon_tcont xpon_tcont;
typedef struct xpon_gem xpon_gem;
typedef struct xpon_enet xpon_enet;
typedef struct xpon_vlan_subif xpon_vlan_subif;
typedef struct xpon_qos_classifier xpon_qos_classifier;
typedef struct xpon_qos_policy xpon_qos_policy;
typedef struct xpon_qos_policy_profile xpon_qos_policy_profile;
typedef struct xpon_forwarder xpon_forwarder;
typedef struct xpon_forwarder_port xpon_forwarder_port;
typedef struct xpon_fwd_split_horizon_profile xpon_fwd_split_horizon_profile;
typedef struct xpon_fwd_db xpon_fwd_db;
typedef struct xpon_hardware xpon_hardware;
typedef struct xpon_dhcpr_profile xpon_dhcpr_profile;
typedef struct xpon_tm_tc_id_to_q_mapping_profile xpon_tm_tc_id_to_q_mapping_profile;
typedef struct xpon_tm_bac_profile xpon_tm_bac_profile;
typedef struct xpon_tm_root xpon_tm_root;

/* vlan-subif list head */
typedef STAILQ_HEAD(xpon_subif_list, xpon_vlan_subif) xpon_subif_list;

/* TCONT list head */
typedef STAILQ_HEAD(xpon_tcont_list, xpon_tcont) xpon_tcont_list;

/* GEM port list head */
typedef STAILQ_HEAD(xpon_gem_list, xpon_gem) xpon_gem_list;

/*
 * Scheduling support. See TR-383: bbf-qos-traffic0mngt.yang, bbf-qos-enhanced-scheduling.yang
 */

typedef struct xpon_tm_sched_queue xpon_tm_sched_queue;
typedef struct xpon_tm_sched_node xpon_tm_sched_node;
typedef struct xpon_tm_root xpon_tm_root;

typedef STAILQ_HEAD(xpon_tm_sched_queue_list, xpon_tm_sched_queue) xpon_tm_sched_queue_list;
typedef STAILQ_HEAD(xpon_tm_sched_node_list, xpon_tm_sched_node) xpon_tm_sched_node_list;

typedef enum
{
    xpon_tm_sched_level_1,
    xpon_tm_sched_level_2,
    xpon_tm_sched_level_3
} xpon_tm_sched_level;

typedef struct xpon_tm_sched_gen_attr
{
    bcmolt_presence_mask presence_mask;
    uint8_t weight;
    uint8_t extended_weight;
    uint8_t priority;
} xpon_tm_sched_gen_attr;

typedef enum
{
    xpon_tm_sched_gen_attr_prop_id_wight,
    xpon_tm_sched_gen_attr_prop_id_extended_wight,
    xpon_tm_sched_gen_attr_prop_id_priority,
} xpon_tm_sched_gen_attr_prop_id;

struct xpon_tm_sched_queue
{
    uint32_t queue_id;
    xpon_tm_sched_gen_attr sched_attr;
    STAILQ_ENTRY(xpon_tm_sched_queue) next;
};

typedef enum
{
    xpon_tm_sched_node_type_queue,
    xpon_tm_sched_node_type_scheduler,
    xpon_tm_sched_node_type_child_queue,
} xpon_tm_sched_node_type;

struct xpon_tm_sched_node
{
    const char *name;
    xpon_tm_sched_node_type node_type;
    xpon_tm_sched_level sched_level;
    union
    {
        xpon_tm_sched_queue_list queues;
        xpon_tm_sched_node_list nodes;
    };
    STAILQ_ENTRY(xpon_tm_sched_node) next;
};

typedef enum
{
    xpon_tm_root_child_type_queue,
    xpon_tm_root_child_type_node,
} xpon_tm_root_child_type;

struct xpon_tm_root
{
    xpon_tm_root_child_type child_type;
    union
    {
        xpon_tm_sched_queue_list queues;
        xpon_tm_sched_node_list nodes;
    };
    const char *tc_id_to_q_mapping_profile_name;
};

/*
 * Other scheduling support structures and objects are TODO
 * ---------------------------------------------------------- */

/* Wavelength profile */
struct xpon_wavelength_profile
{
    xpon_obj_hdr hdr;
    uint32_t us_channel_id;
    uint32_t ds_channel_id;
    uint32_t ds_wavelength;
};

/* wavelength profile properties */
typedef enum
{
    xpon_wavelen_profile_prop_id_us_channel_id,
    xpon_wavelen_profile_prop_id_ds_channel_id,
    xpon_wavelen_profile_prop_id_ds_wavelength
} xpon_wavelen_profile_prop_id;

/* TRaffic descriptor profile */
struct xpon_td_profile
{
    xpon_obj_hdr hdr;
    uint32_t fixed_bw;
    uint32_t assured_bw;
    uint32_t max_bw;
    bcmolt_additional_bw_eligibility additional_bw_eligiblity;
    uint8_t priority;
    uint8_t weight;
};

/* traffic descriptor profile properties */
typedef enum
{
    xpon_td_profile_prop_id_fixed_bw,
    xpon_td_profile_prop_id_assured_bw,
    xpon_td_profile_prop_id_max_bw,
    xpon_td_profile_prop_id_additional_bw_eligiblity,
    xpon_td_profile_prop_id_priority,
    xpon_td_profile_prop_id_weight,
} xpon_td_profile_prop_id;

/* TCONT */
struct xpon_tcont
{
    xpon_obj_hdr hdr;
    uint16_t alloc_id;
#define ALLOC_ID_UNDEFINED   0xffff
    xpon_td_profile *td_profile;
    xpon_v_ani *v_ani;
    xpon_tm_root tm_root;
    xpon_resource_state state;
    bcmolt_interface pon_ni;
    STAILQ_ENTRY(xpon_tcont) next; /* next on ONU */
};

/* tcont properties */
typedef enum
{
    xpon_tcont_prop_id_alloc_id,
    xpon_tcont_prop_id_td_profile,
    xpon_tcont_prop_id_v_ani,
    xpon_tcont_prop_id_tm_root,
} xpon_tcont_prop_id;

typedef enum
{
    XPON_GEM_TYPE_UNICAST,
    XPON_GEM_TYPE_MULTICAST,
    XPON_GEM_TYPE_BROADCAST
} xpon_gem_type;

/* GEM port */
struct xpon_gem
{
    xpon_obj_hdr hdr;
    xpon_gem_type type;
    uint16_t gemport_id;
    xpon_obj_hdr *interface;
    xpon_channel_pair *cpair;
    uint8_t traffic_class;
    bcmos_bool downstream_aes_indicator;
    bcmos_bool upstream_aes_indicator;
    xpon_tcont *tcont;
    xpon_resource_state state;
    xpon_v_ani *v_ani;
    bcmolt_interface pon_ni;
    STAILQ_ENTRY(xpon_gem) next; /* next on ONU */
};

/* gem properties */
typedef enum
{
    xpon_gem_prop_id_type,
    xpon_gem_prop_id_cpair,
    xpon_gem_prop_id_gemport_id,
    xpon_gem_prop_id_interface,
    xpon_gem_prop_id_traffic_class,
    xpon_gem_prop_id_downstream_aes_indicator,
    xpon_gem_prop_id_upstream_aes_indicator,
    xpon_gem_prop_id_tcont,
} xpon_gem_prop_id;

/* V-ANI info record */
struct xpon_v_ani
{
    xpon_obj_hdr hdr;
    bcmolt_onu_id onu_id;
    xpon_channel_partition *cpart;
    xpon_channel_pair *cpair;
    xpon_channel_pair *protection_cpair;
    xpon_channel_termination *cterm;
    xpon_admin_state admin_state;
    bcmolt_serial_number serial_number;
    bcmolt_bin_str_36 registration_id;
    bcmolt_onu_rate onu_rate;
    xpon_tm_root tm_root;
    char vomci_endpoint[BBF_XPON_MAX_NAME_LENGTH];

    bcmos_bool registered;
    bcmos_bool omci_ready;
    uint8_t num_unis;
    xpon_tcont_list tconts;
    xpon_gem_list gems;

    bcmolt_interface pon_ni;
    xpon_ani *linked_ani;
};

/* v-ani properties */
typedef enum
{
    xpon_v_ani_prop_id_admin_state,
    xpon_v_ani_prop_id_onu_id,
    xpon_v_ani_prop_id_serial_number,
    xpon_v_ani_prop_id_registration_id,
    xpon_v_ani_prop_id_cpart,
    xpon_v_ani_prop_id_cpair,
    xpon_v_ani_prop_id_protection_cpair,
    xpon_v_ani_prop_id_onu_rate,
    xpon_v_ani_prop_id_tm_root,
    xpon_v_ani_prop_id_vomci_endpoint,
} xpon_v_ani_prop_id;

/* ani info record */
struct xpon_ani
{
    xpon_obj_hdr hdr;
    bcmolt_onu_id onu_id;
    uint16_t management_gem_port_id;
    bcmos_bool upstream_fec;
    bcmos_bool management_gem_port_aes;

    xpon_v_ani *linked_v_ani;
};

/* v-ani properties */
typedef enum
{
    xpon_ani_prop_id_onu_id,
    xpon_ani_prop_id_management_gem_port_id,
    xpon_ani_prop_id_upstream_fec,
    xpon_ani_prop_id_management_gem_port_aes,
} xpon_ani_prop_id;

/* v-ani_v_enet info record */
struct xpon_v_ani_v_enet
{
    xpon_obj_hdr hdr;
    xpon_v_ani *v_ani;
    xpon_obj_hdr *linked_if;
    xpon_subif_list subifs;
};

/* v-ani_v_enet properties */
typedef enum
{
    xpon_v_ani_v_enet_prop_id_v_ani,
} xpon_v_ani_v_enet_prop_id;

/* ani_v_enet info record */
struct xpon_ani_v_enet
{
    xpon_obj_hdr hdr;
    xpon_ani *ani;
    xpon_tm_root tm_root;

    xpon_obj_hdr *linked_if;
    xpon_ani *lower_layer;
    xpon_subif_list subifs;
};

/* v-ani_v_enet properties */
typedef enum
{
    xpon_ani_v_enet_prop_id_ani,
    xpon_ani_v_enet_prop_id_tm_root,
} xpon_ani_v_enet_prop_id;

/* Raman mitigation type */
typedef enum
{
    XPON_RAMAN_MITIGATION_NONE,
    XPON_RAMAN_MITIGATION_MILLER,
    XPON_RAMAN_MITIGATION_8B10B,
} xpon_raman_mitigation_type;

/* Authentication method type */
typedef enum
{
    XPON_AUTH_METHOD_TYPE_SERIAL_NUMBER,
    XPON_AUTH_METHOD_TYPE_LOID,
    XPON_AUTH_METHOD_TYPE_REGISTRATION_ID,
    XPON_AUTH_METHOD_TYPE_OMCI,
    XPON_AUTH_METHOD_TYPE_DOT1X,
} xpon_auth_method_type;

/* Channel group */
struct xpon_channel_group
{
    xpon_obj_hdr hdr;

    /* Config info */
    char *system_id;
    uint32_t polling_period;
    xpon_raman_mitigation_type raman_mitigation_type;

    /* State info */
    /* ToDo */
};

/* Channel group properties */
typedef enum
{
    xpon_cgroup_prop_id_system_id,
    xpon_cgroup_prop_id_polling_period,
    xpon_cgroup_prop_id_raman_mitigation_type,
} xpon_cgroup_prop_id;

/* Channel partition */
struct xpon_channel_partition
{
    xpon_obj_hdr hdr;

    /* Config info */
    xpon_admin_state admin_state;
    xpon_channel_group *channel_group_ref;
    uint32_t channelpartition_index;
    bcmos_bool fec_downstream;
    uint16_t closest_onu_distance;
    uint16_t max_differential_xpon_distance;
    xpon_auth_method_type authentication_method;
    bcmos_bool multicast_aes_indicator;
    xpon_tm_root tm_root;

    /* State info */

    /* Internal */
    STAILQ_HEAD(, xpon_channel_pair) cpair_list;
};

/* Channel partition properties */
typedef enum
{
    xpon_cpart_prop_id_admin_state,
    xpon_cpart_prop_id_channel_group_ref,
    xpon_cpart_prop_id_channelpartition_index,
    xpon_cpart_prop_id_fec_downstream,
    xpon_cpart_prop_id_closest_onu_distance,
    xpon_cpart_prop_id_max_differential_xpon_distance,
    xpon_cpart_prop_id_authentication_method,
    xpon_cpart_prop_id_multicast_aes_indicator,
    xpon_cpart_prop_id_tm_root,
} xpon_cpart_prop_id;

/* Channel pair */
struct xpon_channel_pair
{
    xpon_obj_hdr hdr;

    /* Config info */
    xpon_admin_state admin_state;
    xpon_channel_group *channel_group_ref;
    xpon_channel_partition *channel_partition_ref;
    xpon_wavelength_profile *wavelen_prof_ref;

    /* ToDo: Other parameters */

    /* State info */
    xpon_channel_termination *primary_cterm;
    xpon_channel_termination *secondary_cterm;

    /* Internal */
    STAILQ_ENTRY(xpon_channel_pair) next;
};

/* Channel pair properties */
typedef enum
{
    xpon_cpair_prop_id_admin_state,
    xpon_cpair_prop_id_channel_group_ref,
    xpon_cpair_prop_id_channel_partition_ref,
    xpon_cpair_prop_id_wavelen_prof_ref,
    xpon_cpair_prop_id_channel_type,
} xpon_cpair_prop_id;

typedef struct notifiable_onu_presence_state
{
    char *presence_state;
    STAILQ_ENTRY(notifiable_onu_presence_state) next;
} notifiable_onu_presence_state;

/* Channel termination */
struct xpon_channel_termination
{
    xpon_obj_hdr hdr;

    /* Config info */
    bcmolt_interface pon_ni;
    xpon_admin_state admin_state;
    xpon_channel_pair *channel_pair_ref;
    xpon_hardware *port_layer_if;
    uint64_t hw_ponid;
    bcmos_bool interface_up;
    STAILQ_HEAD(, notifiable_onu_presence_state) notifiable_presence_states;
    xpon_tm_root tm_root;

    /* ToDo: Other parameters */

    /* State info */
    /* ToDo */
};

/* Channel termination properties */
typedef enum
{
    xpon_cterm_prop_id_admin_state,
    xpon_cterm_prop_id_channel_pair_ref,
    xpon_cterm_prop_id_hw_ponid,
    xpon_cterm_prop_id_port_layer_if,
    xpon_cterm_prop_id_notifiable_presence_states,
    xpon_cterm_prop_id_tm_root
} xpon_cterm_prop_id;

/*
 * vlan-subif
 */

/* ingress rule flow entry */
typedef struct bbf_subif_ingress_rule_flow bbf_subif_ingress_rule_flow;
struct bbf_subif_ingress_rule_flow
{
    const xpon_gem *gem;
    const xpon_qos_classifier *qos_class;
    bcmolt_flow_id flow_id;
    uint8_t flow_dir;
#define XPON_FLOW_DIR_UPSTREAM      0x1
#define XPON_FLOW_DIR_DOWNSTREAM    0x2
#define XPON_FLOW_DIR_MULTICAST     0x4
};

/* ingress rule */
typedef struct bbf_subif_ingress_rule bbf_subif_ingress_rule;
struct bbf_subif_ingress_rule
{
    const char *name;
    uint16_t priority;
    bbf_match_criteria match;
    bbf_flexible_rewrite rewrite;
    STAILQ_ENTRY(bbf_subif_ingress_rule) next;
    bcmos_bool being_deleted;
    struct dhcp_relay_interface *dhcpr_iface;
    bbf_subif_ingress_rule_flow flows[8]; /* Indexed by TC */
    bcmolt_group_id group_id;
    /* The following fileds are for per-flow mode support */
    bcmos_bool ds_rule;
    int base_gemport_id;   /* base GEM port id. -1=unset */
    int priority_to_tc[8]; /* Indexed by pbit. -1=unset */
    int ds_iwf_flow_id;
    int pon_ni;
};

typedef struct xpon_dhcpr_ref
{
    bcmos_bool trusted;
    bcmos_bool enabled;
    xpon_dhcpr_profile *profile;
} xpon_dhcpr_ref;

struct xpon_vlan_subif
{
    xpon_obj_hdr hdr;

    /* Config info */
    xpon_obj_hdr *subif_lower_layer;
    bbf_interface_usage usage;
    STAILQ_HEAD(, bbf_subif_ingress_rule) ingress;
    bbf_flexible_rewrite egress_rewrite;
    xpon_qos_policy_profile *qos_policy_profile;
    STAILQ_ENTRY(xpon_vlan_subif) next;
    xpon_forwarder_port *forwarder_port;
    xpon_dhcpr_ref dhcpr;
    xpon_tm_root tm_root;

    bcmos_bool is_olt_subif; /* TRUE=OLT subif, FALSE=ONU subif */
};

/* subif properties */
typedef enum
{
    xpon_vlan_subif_prop_id_subif_lower_layer,
    xpon_vlan_subif_prop_id_usage,
    xpon_vlan_subif_prop_id_ingress,
    xpon_vlan_subif_prop_id_egress_rewrite,
    xpon_vlan_subif_prop_id_qos_policy_profile,
    xpon_vlan_subif_prop_id_dhcpr,
    xpon_vlan_subif_prop_id_tm_root,

    /* Internal properties */
    xpon_vlan_subif_prop_id_flow_id,
    xpon_vlan_subif_prop_id_flow_dir,
} xpon_vlan_subif_prop_id;

/* xpon-enet */
struct xpon_enet
{
    xpon_obj_hdr hdr;

    /* Config info */
    bbf_interface_usage usage;
    xpon_obj_hdr *lower_layer;
    xpon_hardware *port_layer_if;
    bcmolt_interface intf_id;

    xpon_subif_list subifs;
    xpon_obj_hdr *linked_if;
};

/* enet properties */
typedef enum
{
    xpon_enet_prop_id_usage,
    xpon_enet_prop_id_lower_layer,
    xpon_enet_prop_id_port_layer_if,
} xpon_enet_prop_id;


/*
 * QoS
 *
 * The following definitions are bare-bone.
 * TODO: add more comprehensive support
 */

/*
 * qos-classifier
 */
struct xpon_qos_classifier
{
    xpon_obj_hdr hdr;
    bbf_match_criteria match;
    uint8_t traffic_class;
    xpon_qos_policy *policy;
};

/* xpon_qos_classifier properties */
typedef enum
{
    xpon_qos_classifier_prop_id_match,
    xpon_qos_classifier_prop_id_traffic_class,
} xpon_qos_classifier_prop_id;

/*
 * qos-policy
 */
struct xpon_qos_policy
{
    xpon_obj_hdr hdr;
    uint32_t num_classifiers;
#define XPON_MAX_QOS_CLASSIFIERS_PER_QOS_POLICY         16
    xpon_qos_classifier *classifier[XPON_MAX_QOS_CLASSIFIERS_PER_QOS_POLICY];
    xpon_qos_policy_profile *profile;
};

/*
 * qos-policy-profile
 */

struct xpon_qos_policy_profile
{
    xpon_obj_hdr hdr;
    uint32_t num_policies;
#define XPON_MAX_QOS_POLICIES_PER_QOS_POLICY_PROFILE    8
    xpon_qos_policy *policy[XPON_MAX_QOS_POLICIES_PER_QOS_POLICY_PROFILE];
};

/*
 * Forwarding
 */

/* Forwarding port */
struct xpon_forwarder_port
{
    const char *name;
    xpon_vlan_subif *subif;
    xpon_forwarder *forwarder;
    STAILQ_ENTRY(xpon_forwarder_port) next;
    bcmos_bool being_deleted;
};

struct xpon_forwarder
{
    xpon_obj_hdr hdr;
    STAILQ_HEAD(, xpon_forwarder_port) ports;
    xpon_fwd_split_horizon_profile *split_horizon_profile;
    xpon_fwd_db *mac_learning_db;
};

/* xpon_forwarder properties */
typedef enum
{
    xpon_forwarder_prop_id_ports,
    xpon_forwarder_prop_id_split_horizon_profile,
    xpon_forwarder_prop_id_mac_learning_db
} xpon_forwarder_prop_id;

struct xpon_fwd_split_horizon_profile
{
    xpon_obj_hdr hdr;
    bbf_interface_usage in_interface_usage;
    bbf_interface_usage out_interface_usage;
};

/* split_horozon_profile properties */
typedef enum
{
    xpon_fwd_split_horizon_profile_prop_id_in_interface_usage,
    xpon_fwd_split_horizon_profile_prop_id_out_interface_usage,
} xpon_fwd_split_horizon_profile_prop_id;

struct xpon_fwd_db
{
    xpon_obj_hdr hdr;
    bcmos_bool shared_database;
};

/* forwarding-database properties */
typedef enum
{
    xpon_fwd_db_prop_id_shared_database,
} xpon_fwd_db_prop_id;


/*
 * ietf-hardware
 */

typedef enum
{
    XPON_HARDWARE_CLASS_UNKNOWN,
    XPON_HARDWARE_CLASS_CHASSIS,
    XPON_HARDWARE_CLASS_BOARD,
    XPON_HARDWARE_CLASS_CAGE,
    XPON_HARDWARE_CLASS_TRANSCEIVER,
    XPON_HARDWARE_CLASS_TRANSCEIVER_LINK,
} xpon_hardware_class;

#define XPON_HW_MODEL_LENGTH    32
struct xpon_hardware
{
    xpon_obj_hdr hdr;
    xpon_hardware_class class;
    xpon_hardware *parent;
    char expected_model[XPON_HW_MODEL_LENGTH];
    uint32_t parent_rel_pos;
    xpon_channel_termination *cterm;
#define BCMOLT_PARENT_REL_POS_INVALID   0xffffffff
};

/* hardware properties */
typedef enum
{
    xpon_hardware_prop_id_class,
    xpon_hardware_prop_id_parent,
    xpon_hardware_prop_id_expected_model,
    xpon_hardware_prop_id_parent_rel_pos,
} xpon_hardware_prop_id;

/*
 * DHCP relay
 */

typedef enum
{
    DHCP_RELAY_OPTION82_SUBOPTION_NONE          = 0,
    DHCP_RELAY_OPTION82_SUBOPTION_CIRCUIT_ID    = 0x1,
    DHCP_RELAY_OPTION82_SUBOPTION_REMOTE_ID     = 0x2,
    DHCP_RELAY_OPTION82_SUBOPTION_ACCESS_LOOP   = 0x4
} dhcp_relay_option82_suboptions;

/* DHCP relay properties */
typedef enum
{
    xpon_dhcpr_profile_prop_id_max_packet_size,
    xpon_dhcpr_profile_prop_id_suboptions,
    xpon_dhcpr_profile_prop_id_circuit_id_syntax,
    xpon_dhcpr_profile_prop_id_remote_id_syntax,
    xpon_dhcpr_profile_prop_id_start_numbering_from_zero,
    xpon_dhcpr_profile_prop_id_use_leading_zeros,
} xpon_dhcpr_profile_prop_id;

/* DHCP relay profile - can be referenced by multiple sub-interfaces */
struct xpon_dhcpr_profile
{
    xpon_obj_hdr hdr;
    uint16_t max_packet_size;
    dhcp_relay_option82_suboptions suboptions;  /* A combination */
    char *circuit_id_syntax;
    char *remote_id_syntax;
    bcmos_bool start_numbering_from_zero;
    bcmos_bool use_leading_zeros;
};

/*
 * TM profiles - can be referenced by multiple tm-root
 */

/* Traffic Class --> queue_id mapper */
struct xpon_tm_tc_id_to_q_mapping_profile
{
    xpon_obj_hdr hdr;
    uint32_t queue_id[8];    /* Queue id by tc_id */
#define XPON_QUEUE_ID_INVALID       ((uint32_t)-1)
};

/* TM BAC profile properties */
typedef enum
{
    xpon_tm_bac_profile_prop_id_max_queue_size,
    xpon_tm_bac_profile_prop_id_bac_type,
} xpon_tm_bac_profile_prop_id;

/* BAC types */
typedef enum
{
    xpon_tm_bac_type_taildrop,
    xpon_tm_bac_type_red,
    xpon_tm_bac_type_wtaildrop,
    xpon_tm_bac_type_wred,
} xpon_tm_bac_type;

/* TM BAC profile (Admission Control) */
struct xpon_tm_bac_profile
{
    xpon_obj_hdr hdr;
    uint32_t max_queue_size;    /* Max queue size (bytes) */
    xpon_tm_bac_type bac_type;
    union
    {
        struct
        {
            uint32_t max_threshold; /* % of max_queue_size to start discarding */
        } taildrop;
        struct
        {
            uint32_t max_threshold; /* % of max_queue_size to start discarding */
            uint32_t min_threshold; /* % of max_queue_size to stop discarding */
            uint32_t probability;   /* Discard probability when between occupancy is min and max */
        } red;
    };
};

#define XPON_MAX_ONUS_PER_PON      (256+1)

#define SINGLE_LINE_B64         256

bcmos_errno xpon_interface_get_populate(sr_session_ctx_t *srs, const char *name,
    xpon_obj_type expected_obj_type, xpon_obj_hdr **p_obj);
void xpon_interface_delete(xpon_obj_hdr *obj);

bcmos_errno xpon_cgroup_init(sr_session_ctx_t *srs);
bcmos_errno xpon_cgroup_start(sr_session_ctx_t *srs);
void xpon_cgroup_exit(sr_session_ctx_t *srs);
bcmos_errno xpon_cgroup_transaction(sr_session_ctx_t *srs, nc_transact *tr);
bcmos_errno xpon_cgroup_get_by_name(const char *name, xpon_channel_group **p_cgroup, bcmos_bool *is_added);
void xpon_cgroup_delete(xpon_channel_group *cgroup);

bcmos_errno xpon_cpart_init(sr_session_ctx_t *srs);
bcmos_errno xpon_cpart_start(sr_session_ctx_t *srs);
void xpon_cpart_exit(sr_session_ctx_t *srs);
bcmos_errno xpon_cpart_transaction(sr_session_ctx_t *srs, nc_transact *tr);
bcmos_errno xpon_cpart_get_by_name(const char *name, xpon_channel_partition **p_cpart, bcmos_bool *is_added);
void xpon_cpart_delete(xpon_channel_partition *cpart);

bcmos_errno xpon_cpair_init(sr_session_ctx_t *srs);
bcmos_errno xpon_cpair_start(sr_session_ctx_t *srs);
void xpon_cpair_exit(sr_session_ctx_t *srs);
bcmos_errno xpon_cpair_transaction(sr_session_ctx_t *srs, nc_transact *tr);
bcmos_errno xpon_cpair_get_by_name(const char *name, xpon_channel_pair **p_cpair, bcmos_bool *is_added);
void xpon_cpair_delete(xpon_channel_pair *cpair);
int xpon_cpair_state_get_cb(sr_session_ctx_t *session, const char *xpath, struct lyd_node **parent);

bcmos_errno xpon_cterm_init(sr_session_ctx_t *srs);
bcmos_errno xpon_cterm_start(sr_session_ctx_t *srs);
void xpon_cterm_exit(sr_session_ctx_t *srs);
bcmos_errno xpon_cterm_transaction(sr_session_ctx_t *srs, nc_transact *tr);
bcmos_errno xpon_cterm_get_by_name(const char *name, xpon_channel_termination **p_cterm, bcmos_bool *is_added);
xpon_channel_termination *xpon_cterm_get_by_id(bcmolt_oltid olt, bcmolt_interface pon_ni);
void xpon_cterm_delete(xpon_channel_termination *cterm);
int xpon_cterm_state_get_cb(sr_session_ctx_t *session, const char *xpath, struct lyd_node **parent);
bcmos_bool xpon_cterm_is_onu_state_notifiable(const char *cterm_name, const char *state);

bcmos_errno xpon_v_ani_init(sr_session_ctx_t *srs);
bcmos_errno xpon_v_ani_start(sr_session_ctx_t *srs);
void xpon_v_ani_exit(sr_session_ctx_t *srs);
bcmos_errno xpon_v_ani_transaction(sr_session_ctx_t *srs, nc_transact *tr);
bcmos_errno xpon_v_ani_get_by_name(const char *name, xpon_v_ani **p_v_ani, bcmos_bool *is_added);
void bbf_xpon_onu_discovered(bcmolt_oltid olt, bcmolt_msg *msg);
void xpon_v_ani_delete(xpon_v_ani *v_ani);
xpon_v_ani *xpon_v_ani_get_by_id(bcmolt_interface intf_id, bcmolt_onu_id onu_id);
int xpon_v_ani_state_get_cb(sr_session_ctx_t *session, const char *xpath, struct lyd_node **parent);

bcmos_errno xpon_ani_init(sr_session_ctx_t *srs);
bcmos_errno xpon_ani_start(sr_session_ctx_t *srs);
void xpon_ani_exit(sr_session_ctx_t *srs);
bcmos_errno xpon_ani_transaction(sr_session_ctx_t *srs, nc_transact *tr);
bcmos_errno xpon_ani_get_by_name(const char *name, xpon_ani **p_ani, bcmos_bool *is_added);
void xpon_ani_delete(xpon_ani *ani);
int xpon_ani_state_get_cb(sr_session_ctx_t *session, const char *xpath, struct lyd_node **parent);

bcmos_errno xpon_v_ani_v_enet_init(sr_session_ctx_t *srs);
bcmos_errno xpon_v_ani_v_enet_start(sr_session_ctx_t *srs);
void xpon_v_ani_v_enet_exit(sr_session_ctx_t *srs);
bcmos_errno xpon_v_ani_v_enet_transaction(sr_session_ctx_t *srs, nc_transact *tr);
bcmos_errno xpon_v_ani_v_enet_get_by_name(const char *name, xpon_v_ani_v_enet **p_v_enet, bcmos_bool *is_added);
void xpon_v_ani_v_enet_delete(xpon_v_ani_v_enet *v_enet);
int xpon_v_ani_v_enet_state_get_cb(sr_session_ctx_t *session, const char *xpath, struct lyd_node **parent);

bcmos_errno xpon_ani_v_enet_init(sr_session_ctx_t *srs);
bcmos_errno xpon_ani_v_enet_start(sr_session_ctx_t *srs);
void xpon_ani_v_enet_exit(sr_session_ctx_t *srs);
bcmos_errno xpon_ani_v_enet_transaction(sr_session_ctx_t *srs, nc_transact *tr);
bcmos_errno xpon_ani_v_enet_get_by_name(const char *name, xpon_ani_v_enet **p_v_enet, bcmos_bool *is_added);
void xpon_ani_v_enet_delete(xpon_ani_v_enet *v_enet);
int xpon_ani_v_enet_state_get_cb(sr_session_ctx_t *session, const char *xpath, struct lyd_node **parent);

bcmos_errno xpon_enet_init(sr_session_ctx_t *srs);
bcmos_errno xpon_enet_start(sr_session_ctx_t *srs);
void xpon_enet_exit(sr_session_ctx_t *srs);
bcmos_errno xpon_enet_transaction(sr_session_ctx_t *srs, nc_transact *tr);
bcmos_errno xpon_enet_get_by_name(const char *name, xpon_enet **p_enet, bcmos_bool *is_added);
void xpon_enet_delete(xpon_enet *enet);
int xpon_enet_state_get_cb(sr_session_ctx_t *session, const char *xpath, struct lyd_node **parent);

bcmos_errno xpon_vlan_subif_init(sr_session_ctx_t *srs);
bcmos_errno xpon_vlan_subif_start(sr_session_ctx_t *srs);
void xpon_vlan_subif_exit(sr_session_ctx_t *srs);
bcmos_errno xpon_vlan_subif_transaction(sr_session_ctx_t *srs, nc_transact *tr);
bcmos_errno xpon_vlan_subif_get_by_name(const char *name, xpon_vlan_subif **p_subif, bcmos_bool *is_added);
void xpon_vlan_subif_delete(xpon_vlan_subif*subif);
int xpon_vlan_subif_state_get_cb(sr_session_ctx_t *session, const char *xpath, struct lyd_node **parent);
bcmos_errno xpon_vlan_subif_ingress_rule_get(xpon_vlan_subif *subif, const char *name,
    bbf_subif_ingress_rule **p_rule, bcmos_bool *is_added);
void xpon_vlan_subif_ingress_rule_delete(xpon_vlan_subif *subif, bbf_subif_ingress_rule *rule);
bbf_subif_ingress_rule *xpon_vlan_subif_ingress_rule_get_match(const bbf_subif_ingress_rule *from_rule,
    xpon_vlan_subif *to_subif);
bcmos_errno xpon_vlan_subif_subif_rule_get_next_match(const bbf_subif_ingress_rule *from_rule,
    xpon_obj_hdr *to_if, xpon_vlan_subif **to_subif, bbf_subif_ingress_rule **to_rule);

bcmos_errno xpon_tcont_init(sr_session_ctx_t *srs);
bcmos_errno xpon_tcont_start(sr_session_ctx_t *srs);
void xpon_tcont_exit(sr_session_ctx_t *srs);
bcmos_errno xpon_tcont_get_by_name(const char *name, xpon_tcont **p_tcont, bcmos_bool *is_added);
bcmos_errno xpon_tcont_get_populate(sr_session_ctx_t *srs, const char *name, xpon_tcont **p_tcont);
void xpon_tcont_delete(xpon_tcont *tcont);
bcmos_errno xpon_td_prof_get_by_name(const char *name, xpon_td_profile **p_prof, bcmos_bool *is_added);
bcmos_errno xpon_td_prof_get_populate(sr_session_ctx_t *srs, const char *name, xpon_td_profile **p_prof);
void xpon_td_prof_delete(xpon_td_profile *prof);

bcmos_errno xpon_gem_init(sr_session_ctx_t *srs);
bcmos_errno xpon_gem_start(sr_session_ctx_t *srs);
void xpon_gem_exit(sr_session_ctx_t *srs);
bcmos_errno xpon_gem_get_by_name(const char *name, xpon_gem **p_gem, bcmos_bool *is_added);
const xpon_gem *xpon_gem_get_by_traffic_class(const xpon_v_ani_v_enet *iface, uint8_t tc);
void xpon_gem_delete(xpon_gem *gem);

bcmos_errno xpon_wavelen_prof_init(sr_session_ctx_t *srs);
bcmos_errno xpon_wavelen_prof_start(sr_session_ctx_t *srs);
void xpon_wavelen_prof_exit(sr_session_ctx_t *srs);
bcmos_errno xpon_wavelen_prof_get_by_name(const char *name, xpon_wavelength_profile **p_prof, bcmos_bool *is_added);
void xpon_wavelen_prof_delete(xpon_wavelength_profile *prof);
bcmos_errno xpon_wavelen_prof_get_populate(sr_session_ctx_t *srs, const char *name, xpon_wavelength_profile **p_prof);

bcmos_errno xpon_qos_classifier_init(sr_session_ctx_t *srs);
bcmos_errno xpon_qos_classifier_start(sr_session_ctx_t *srs);
void xpon_qos_classifier_exit(sr_session_ctx_t *srs);
bcmos_errno xpon_qos_classifier_get_by_name(const char *name, xpon_qos_classifier **p_obj, bcmos_bool *is_added);
bcmos_errno xpon_qos_classifier_get_populate(sr_session_ctx_t *srs, const char *name, xpon_qos_classifier **p_obj);
void xpon_qos_classifier_delete(xpon_qos_classifier *obj);
const xpon_qos_classifier *xpon_qos_classifier_get_next(const xpon_qos_policy_profile *prof,
    const bbf_subif_ingress_rule *rule, const xpon_qos_classifier *prev);

bcmos_errno xpon_qos_policy_init(sr_session_ctx_t *srs);
bcmos_errno xpon_qos_policy_start(sr_session_ctx_t *srs);
void xpon_qos_policy_exit(sr_session_ctx_t *srs);
bcmos_errno xpon_qos_policy_get_by_name(const char *name, xpon_qos_policy **p_obj, bcmos_bool *is_added);
void xpon_qos_policy_delete(xpon_qos_policy *obj);
bcmos_errno xpon_qos_policy_get_populate(sr_session_ctx_t *srs, const char *name, xpon_qos_policy **p_obj);

bcmos_errno xpon_qos_policy_profile_init(sr_session_ctx_t *srs);
bcmos_errno xpon_qos_policy_profile_start(sr_session_ctx_t *srs);
void xpon_qos_policy_profile_exit(sr_session_ctx_t *srs);
bcmos_errno xpon_qos_policy_profile_get_by_name(const char *name, xpon_qos_policy_profile **p_obj, bcmos_bool *is_added);
void xpon_qos_policy_profile_delete(xpon_qos_policy_profile *obj);
bcmos_errno xpon_qos_policy_profile_get_populate(sr_session_ctx_t *srs, const char *name,
    xpon_qos_policy_profile **p_obj);

bcmos_errno xpon_link_init(sr_session_ctx_t *srs);
bcmos_errno xpon_link_start(sr_session_ctx_t *srs);
void xpon_link_exit(sr_session_ctx_t *srs);
void xpon_unlink(xpon_obj_hdr **p_link);

bcmos_errno xpon_forwarder_init(sr_session_ctx_t *srs);
bcmos_errno xpon_forwarder_start(sr_session_ctx_t *srs);
void xpon_forwarder_exit(sr_session_ctx_t *srs);
bcmos_errno xpon_forwarder_get_by_name(const char *name, xpon_forwarder **p_obj, bcmos_bool *is_added);
void xpon_forwarder_delete(xpon_forwarder *obj);

bcmos_errno xpon_fwd_split_horizon_profile_get_by_name(const char *name, xpon_fwd_split_horizon_profile **p_obj, bcmos_bool *is_added);
void xpon_fwd_split_horizon_profile_delete(xpon_fwd_split_horizon_profile *obj);

bcmos_errno xpon_fwd_db_get_by_name(const char *name, xpon_fwd_db **p_obj, bcmos_bool *is_added);
void xpon_fwd_db_delete(xpon_fwd_db *obj);

bcmos_errno xpon_fwd_port_add(xpon_forwarder *fwd, const char *name, xpon_forwarder_port **p_port);
bcmos_errno xpon_fwd_port_delete(xpon_forwarder *fwd, const char *name);
xpon_forwarder_port* xpon_fwd_port_get(xpon_forwarder *fwd, const char *name);
uint32_t xpon_fwd_port_num_of(xpon_forwarder *fwd);

bcmos_errno xpon_hardware_init(sr_session_ctx_t *srs);
bcmos_errno xpon_hardware_start(sr_session_ctx_t *srs);
void xpon_hardware_exit(sr_session_ctx_t *srs);
bcmos_errno xpon_hardware_get_by_name(const char *name, xpon_hardware **p_obj, bcmos_bool *is_added);
bcmos_errno xpon_hardware_get_populate(sr_session_ctx_t *srs, const char *name, xpon_hardware **p_component);
void xpon_hardware_delete(xpon_hardware *obj);

bcmos_errno xpon_dhcpr_init(sr_session_ctx_t *srs);
bcmos_errno xpon_dhcpr_start(sr_session_ctx_t *srs);
void xpon_dhcpr_exit(sr_session_ctx_t *srs);
bcmos_errno xpon_dhcpr_prof_get_by_name(const char *name, xpon_dhcpr_profile **p_prof,
    bcmos_bool *is_added);
void xpon_dhcpr_prof_delete(xpon_dhcpr_profile *prof);
bcmos_errno xpon_dhcpr_prof_get_populate(sr_session_ctx_t *srs, const char *name, xpon_dhcpr_profile **p_obj);

bcmos_errno xpon_tm_profile_init(sr_session_ctx_t *srs);
bcmos_errno xpon_tm_profile_start(sr_session_ctx_t *srs);
void xpon_tm_profile_exit(sr_session_ctx_t *srs);
bcmos_errno xpon_tm_tc_id_to_q_prof_get_by_name(const char *name, xpon_tm_tc_id_to_q_mapping_profile **p_prof,
    bcmos_bool *is_added);
void xpon_tm_tc_id_to_q_prof_delete(xpon_tm_tc_id_to_q_mapping_profile *prof);
bcmos_errno xpon_tm_tc_id_to_q_prof_get_populate(sr_session_ctx_t *srs, const char *name,
    xpon_tm_tc_id_to_q_mapping_profile **p_obj);
bcmos_errno xpon_tm_bac_prof_get_by_name(const char *name, xpon_tm_bac_profile **p_prof,
    bcmos_bool *is_added);
void xpon_tm_bac_prof_delete(xpon_tm_bac_profile *prof);
bcmos_errno xpon_tm_bac_prof_get_populate(sr_session_ctx_t *srs, const char *name,
    xpon_tm_bac_profile **p_obj);

/* Protection lock */
bcmos_errno bcmolt_xpon_utils_init(void);
void bcmolt_xpon_utils_exit(void);
void bbf_xpon_lock(void);
void bbf_xpon_unlock(void);

xpon_obj_type xpon_iftype_to_obj_type(const char *iftype);
const char *xpon_obj_type_to_str(xpon_obj_type);
bcmos_errno xpon_object_add(xpon_obj_hdr *hdr);
bcmos_errno xpon_object_delete(xpon_obj_hdr *hdr);
bcmos_errno xpon_object_get(const char *name, xpon_obj_hdr **p_hdr);
bcmos_errno xpon_object_get_or_add(const char *name, xpon_obj_type obj_type, uint32_t obj_size,
    xpon_obj_hdr **p_hdr, bcmos_bool *is_added);

bbf_interface_usage xpon_map_iface_usage(const char *usage);
void xpon_apply_actions_to_match(bbf_match_criteria *match, const bbf_flexible_rewrite *actions);
bcmos_bool xpon_is_match(const bbf_match_criteria *from, const bbf_match_criteria *to);
bcmos_errno xpon_add_flexible_match(sr_session_ctx_t *srs, bbf_match_criteria *match, const char *xpath,
    sr_val_t *old_val, sr_val_t *new_val);
bcmos_errno xpon_merge_match(bbf_match_criteria *match, const bbf_match_criteria *with_match);
bcmos_errno xpon_merge_actions(bbf_flexible_rewrite *actions, const bbf_flexible_rewrite *with_actions);
bcmos_bool xpon_is_actions_match(const bbf_flexible_rewrite *actions1, const bbf_flexible_rewrite *actions2);
bcmolt_tm_sched_id xpon_tm_sched_id(bcmolt_interface_type type, bcmolt_interface ni);
bcmos_errno xpon_tm_sched_create(bcmolt_interface_type type, bcmolt_interface ni);
bcmos_errno xpon_get_olt_topology(bcmolt_topology *topo);
uint16_t xpon_get_number_of_pons(void);
bcmos_errno xpon_match_diff(const bbf_match_criteria *from_match, const bbf_match_criteria *to_match,
    bbf_flexible_rewrite *actions);
bcmos_errno xpon_tm_qmp_create(bcmolt_tm_qmp_id id, bcmolt_tm_queue_set_id tmq_set_id, uint8_t pbit_to_queue_map[]);
bcmos_errno xpon_default_tm_qmp_create(bcmolt_tm_qmp_id id);

/* tm-mgmt */
bcmos_errno xpon_tm_root_attribute_populate(sr_session_ctx_t *srs,
    xpon_tm_root *tm_root, sr_val_t *sr_old_val, sr_val_t *sr_new_val);
bcmos_errno xpon_tm_root_delete(sr_session_ctx_t *srs, xpon_tm_root *tm_root);

/*
 * Apply configuration
 */

bcmos_errno xpon_apply_flow_delete(sr_session_ctx_t *srs, xpon_vlan_subif *subif, xpon_forwarder *forwarder);
bcmos_errno xpon_apply_flow_create(sr_session_ctx_t *srs, xpon_forwarder *fwd);
bcmos_errno xpon_create_onu_flows_on_subif(sr_session_ctx_t *srs, xpon_obj_hdr *uni, xpon_vlan_subif *subif);
bcmos_errno xpon_create_onu_flows_on_uni(sr_session_ctx_t *srs, xpon_obj_hdr *uni);

/*
 * Scheduled requests
 */
typedef enum
{
    BBF_XPON_REQUEST_TYPE_CFG,
    BBF_XPON_REQUEST_TYPE_OPER
} bbf_xpon_request_type;

bcmos_errno xpon_cfg_set_and_schedule_if_failed(sr_session_ctx_t *srs, bcmolt_cfg *cfg, uint32_t delay, bcmos_errno test_err, const char *test_text);
bcmos_errno xpon_oper_submit_and_schedule_if_failed(sr_session_ctx_t *srs, bcmolt_oper *oper, uint32_t delay, bcmos_errno test_err, const char *test_text);


typedef struct
{
    bcmolt_chip_family chip_family;
    bcmolt_system_mode system_mode;
    bcmolt_inni_mode inni_mode;
    bcmolt_inni_mux inni_mux;
} bbf_xpon_dev_info;

bcmos_errno xpon_device_cfg_get(bcmolt_ldid device, bbf_xpon_dev_info *info);

/*
 * VLAN table
 */
bcmos_errno xpon_vlan_add(bcmolt_interface pon_ni, uint16_t vlan, bcmolt_flow_id flow_id);
bcmos_errno xpon_vlan_delete(bcmolt_interface pon_ni, uint16_t vlan);

/*
 * Proprietary functions, not available in the github release
 */

#ifndef BCM_OPEN_SOURCE
bcmos_errno xpon_iwf_create(bcmolt_devid dev, bcmolt_interface lif, const bcmolt_topology *olt_topology);
bcmos_errno xpon_iwf_create_ds_flows(sr_session_ctx_t *srs,
    bbf_subif_ingress_rule *rule, const bbf_flexible_rewrite *actions,
    const xpon_v_ani *v_ani, bcmolt_vlan_to_flow_mapping_method mapping_method);
bcmos_errno xpon_iwf_delete_ds_flows(sr_session_ctx_t *srs, bbf_subif_ingress_rule *rule);
bcmos_errno xpon_iwf_create_us_flows(sr_session_ctx_t *srs,
    bbf_subif_ingress_rule *rule, const bbf_flexible_rewrite *actions,
    const xpon_v_ani *v_ani, bcmolt_vlan_to_flow_mapping_method mapping_method);
bcmos_errno xpon_iwf_delete_us_flows(sr_session_ctx_t *srs, bbf_subif_ingress_rule *rule);
bcmos_errno xpon_iwf_validate_and_find_base_gem(sr_session_ctx_t *srs,
    bbf_subif_ingress_rule *rule, bbf_subif_ingress_rule *ds_rule,
    const bbf_flexible_rewrite *actions, const xpon_v_ani *v_ani);
#endif


#endif /* _BBF_XPON_INTERNAL_H_ */
