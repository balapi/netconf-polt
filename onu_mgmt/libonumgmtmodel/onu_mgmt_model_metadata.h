/*
<:copyright-BRCM:2016-2020:Apache:standard

 Copyright (c) 2016-2020 Broadcom. All Rights Reserved

 The term “Broadcom” refers to Broadcom Inc. and/or its subsidiaries

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

:>
 */

#ifndef BCMONU_MGMT_MODEL_METADATA_H_
#define BCMONU_MGMT_MODEL_METADATA_H_

#include <bcmos_system.h>
#include <bcmolt_set_metadata.h>
#include "onu_mgmt_model_types.h"
#include "onu_mgmt_model_api_structs.h"
#include "onu_mgmt_model_tags.h"

/* Metadata set representing the ONU management API */
extern const bcmolt_metadata_set *bcmonu_mgmt_api_metadata;

/* Convenient accessors for generic metadata functions. */
#define bcmonu_mgmt_obj_descr_get(...) bcmolt_obj_descr_get(bcmonu_mgmt_api_metadata, __VA_ARGS__)
#define bcmonu_mgmt_group_descr_get(...) bcmolt_group_descr_get(bcmonu_mgmt_api_metadata, __VA_ARGS__)
#define bcmonu_mgmt_group_descr_get_by_group_id(...) \
    bcmolt_group_descr_get_by_group_id(bcmonu_mgmt_api_metadata, __VA_ARGS__)
#define bcmonu_mgmt_group_descr_get_by_global_id(...) \
    bcmolt_group_descr_get_by_global_id(bcmonu_mgmt_api_metadata, __VA_ARGS__)
#define bcmonu_mgmt_group_count_get(...) bcmolt_group_count_get(bcmonu_mgmt_api_metadata, __VA_ARGS__)
#define bcmonu_mgmt_group_id_split(...) bcmolt_group_id_split(bcmonu_mgmt_api_metadata, __VA_ARGS__)
#define bcmonu_mgmt_group_id_combine(...) bcmolt_group_id_combine(bcmonu_mgmt_api_metadata, __VA_ARGS__)
#define bcmonu_mgmt_tag_descr_get(...) bcmolt_tag_descr_get(bcmonu_mgmt_api_metadata, __VA_ARGS__)

/** Enum string tables. */
extern const bcmolt_enum_val bcmonu_mgmt_admin_state_string_table[];
extern const bcmolt_enum_val bcmonu_mgmt_downstream_mode_values_string_table[];
extern const bcmolt_enum_val bcmonu_mgmt_flow_action_type_id_string_table[];
extern const bcmolt_enum_val bcmonu_mgmt_flow_dir_id_string_table[];
extern const bcmolt_enum_val bcmonu_mgmt_flow_type_string_table[];
extern const bcmolt_enum_val bcmonu_mgmt_igmp_us_action_type_id_string_table[];
extern const bcmolt_enum_val bcmonu_mgmt_status_string_table[];
extern const bcmolt_enum_val bcmonu_mgmt_uni_type_string_table[];
extern const bcmolt_enum_val bcmonu_mgmt_obj_id_string_table[];
extern const bcmolt_enum_val bcmonu_mgmt_api_group_id_string_table[];
extern const bcmolt_enum_val bcmonu_mgmt_agg_port_list_entry_id_string_table[];
extern const bcmolt_enum_val bcmonu_mgmt_flow_action_id_string_table[];
extern const bcmolt_enum_val bcmonu_mgmt_flow_match_id_string_table[];
extern const bcmolt_enum_val bcmonu_mgmt_flow_onu_key_id_string_table[];
extern const bcmolt_enum_val bcmonu_mgmt_igmp_us_action_id_string_table[];
extern const bcmolt_enum_val bcmonu_mgmt_priority_queue_id_string_table[];
extern const bcmolt_enum_val bcmonu_mgmt_uni_id_string_table[];
extern const bcmolt_enum_val bcmonu_mgmt_flow_cfg_data_id_string_table[];
extern const bcmolt_enum_val bcmonu_mgmt_flow_key_id_string_table[];
extern const bcmolt_enum_val bcmonu_mgmt_onu_cfg_data_id_string_table[];
extern const bcmolt_enum_val bcmonu_mgmt_onu_key_id_string_table[];

/** Type descriptors exported for use with macros. */
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_admin_state;
#define type_descr_bcmonu_mgmt_agg_port_id type_descr_uint16_t
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_agg_port_list_entry;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_arr_agg_port_list_entry_64;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_arr_priority_queue_128;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_arr_uni_8;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_downstream_mode_values;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_action;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_action_type_id;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_dir_id;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_match;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_onu_key;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_type;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_igmp_us_action;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_igmp_us_action_type_id;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_priority_queue;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_status;
#define type_descr_bcmonu_mgmt_svc_port_id type_descr_uint16_t
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_uni;
#define type_descr_bcmonu_mgmt_uni_port type_descr_uint16_t
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_uni_type;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_cfg_data;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_key;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_onu_cfg_data;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_onu_key;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_obj_id;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_api_group_id;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_agg_port_list_entry_id;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_action_id;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_match_id;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_onu_key_id;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_igmp_us_action_id;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_priority_queue_id;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_uni_id;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_cfg_data_id;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_flow_key_id;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_onu_cfg_data_id;
extern const bcmolt_type_descr type_descr_bcmonu_mgmt_onu_key_id;

#endif /* BCMONU_MGMT_MODEL_METADATA_H_ */
