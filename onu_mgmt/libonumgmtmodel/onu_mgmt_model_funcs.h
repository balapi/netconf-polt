#ifndef ONU_MGMT_MODEL_FUNCS
#define ONU_MGMT_MODEL_FUNCS

#include <bcmos_system.h>
#include <bcmos_errno.h>
#include <bcmolt_string.h>
#include "onu_mgmt_model_ids.h"
#include "onu_mgmt_model_types.h"
#include "onu_mgmt_model_api_structs.h"


/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_admin_state_pack(
    bcmonu_mgmt_admin_state obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_admin_state_unpack(
    bcmonu_mgmt_admin_state *obj,
    bcmolt_buf *buf);

/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_downstream_mode_values_pack(
    bcmonu_mgmt_downstream_mode_values obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_downstream_mode_values_unpack(
    bcmonu_mgmt_downstream_mode_values *obj,
    bcmolt_buf *buf);

/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_flow_action_type_id_pack(
    bcmonu_mgmt_flow_action_type_id obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_flow_action_type_id_unpack(
    bcmonu_mgmt_flow_action_type_id *obj,
    bcmolt_buf *buf);

/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_flow_dir_id_pack(
    bcmonu_mgmt_flow_dir_id obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_flow_dir_id_unpack(
    bcmonu_mgmt_flow_dir_id *obj,
    bcmolt_buf *buf);

/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_flow_type_pack(
    bcmonu_mgmt_flow_type obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_flow_type_unpack(
    bcmonu_mgmt_flow_type *obj,
    bcmolt_buf *buf);

/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_igmp_us_action_type_id_pack(
    bcmonu_mgmt_igmp_us_action_type_id obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_igmp_us_action_type_id_unpack(
    bcmonu_mgmt_igmp_us_action_type_id *obj,
    bcmolt_buf *buf);

/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_status_pack(
    bcmonu_mgmt_status obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_status_unpack(
    bcmonu_mgmt_status *obj,
    bcmolt_buf *buf);

/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_uni_type_pack(
    bcmonu_mgmt_uni_type obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_uni_type_unpack(
    bcmonu_mgmt_uni_type *obj,
    bcmolt_buf *buf);

/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_obj_id_pack(
    bcmonu_mgmt_obj_id obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_obj_id_unpack(
    bcmonu_mgmt_obj_id *obj,
    bcmolt_buf *buf);

/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_api_group_id_pack(
    bcmonu_mgmt_api_group_id obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_api_group_id_unpack(
    bcmonu_mgmt_api_group_id *obj,
    bcmolt_buf *buf);

/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_agg_port_list_entry_id_pack(
    bcmonu_mgmt_agg_port_list_entry_id obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_agg_port_list_entry_id_unpack(
    bcmonu_mgmt_agg_port_list_entry_id *obj,
    bcmolt_buf *buf);

/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_flow_action_id_pack(
    bcmonu_mgmt_flow_action_id obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_flow_action_id_unpack(
    bcmonu_mgmt_flow_action_id *obj,
    bcmolt_buf *buf);

/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_flow_match_id_pack(
    bcmonu_mgmt_flow_match_id obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_flow_match_id_unpack(
    bcmonu_mgmt_flow_match_id *obj,
    bcmolt_buf *buf);

/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_flow_onu_key_id_pack(
    bcmonu_mgmt_flow_onu_key_id obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_flow_onu_key_id_unpack(
    bcmonu_mgmt_flow_onu_key_id *obj,
    bcmolt_buf *buf);

/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_igmp_us_action_id_pack(
    bcmonu_mgmt_igmp_us_action_id obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_igmp_us_action_id_unpack(
    bcmonu_mgmt_igmp_us_action_id *obj,
    bcmolt_buf *buf);

/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_priority_queue_id_pack(
    bcmonu_mgmt_priority_queue_id obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_priority_queue_id_unpack(
    bcmonu_mgmt_priority_queue_id *obj,
    bcmolt_buf *buf);

/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_uni_id_pack(
    bcmonu_mgmt_uni_id obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_uni_id_unpack(
    bcmonu_mgmt_uni_id *obj,
    bcmolt_buf *buf);

/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_flow_cfg_data_id_pack(
    bcmonu_mgmt_flow_cfg_data_id obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_flow_cfg_data_id_unpack(
    bcmonu_mgmt_flow_cfg_data_id *obj,
    bcmolt_buf *buf);

/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_flow_key_id_pack(
    bcmonu_mgmt_flow_key_id obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_flow_key_id_unpack(
    bcmonu_mgmt_flow_key_id *obj,
    bcmolt_buf *buf);

/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_onu_cfg_data_id_pack(
    bcmonu_mgmt_onu_cfg_data_id obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_onu_cfg_data_id_unpack(
    bcmonu_mgmt_onu_cfg_data_id *obj,
    bcmolt_buf *buf);

/** Packs an enumeration to bytes for transmission on the wire.
  *
  * \param obj The enumeration to pack.
  * \param buf Pointer to the buffer to write to.
  * \return Whether or not the pack was successful.
  */
bcmos_bool bcmonu_mgmt_onu_key_id_pack(
    bcmonu_mgmt_onu_key_id obj,
    bcmolt_buf *buf);

/** Unpacks an enumeration from bytes as received on the wire.
  *
  * \param obj Pointer to the enumeration to unpack.
  * \param buf Pointer to the buffer to read from.
  * \return Whether or not the unpack was successful.
  */
bcmos_bool bcmonu_mgmt_onu_key_id_unpack(
    bcmonu_mgmt_onu_key_id *obj,
    bcmolt_buf *buf);


/** Initializes a structure to default values.
 *
 * \param obj Pointer to the structure to initialize.
 */
void bcmonu_mgmt_agg_port_list_entry_set_default(bcmonu_mgmt_agg_port_list_entry *obj);

/** Checks if any field in the structure is set incorrectly (e.g. out of bounds).
 *
 * \param obj Pointer to the structure to validate.
 * \param err Filled in with the error (if validation fails).
 * \param err_details Filled in with a description of the error (if validation fails).
 * \return TRUE on success, FALSE on failure.
 */
bcmos_bool bcmonu_mgmt_agg_port_list_entry_validate(const bcmonu_mgmt_agg_port_list_entry *obj, bcmos_errno *err, bcmolt_string *err_details);


/** Initializes a structure to default values.
 *
 * \param obj Pointer to the structure to initialize.
 */
void bcmonu_mgmt_arr_agg_port_list_entry_64_set_default(bcmonu_mgmt_arr_agg_port_list_entry_64 *obj);

/** Checks if any field in the structure is set incorrectly (e.g. out of bounds).
 *
 * \param obj Pointer to the structure to validate.
 * \param err Filled in with the error (if validation fails).
 * \param err_details Filled in with a description of the error (if validation fails).
 * \return TRUE on success, FALSE on failure.
 */
bcmos_bool bcmonu_mgmt_arr_agg_port_list_entry_64_validate(const bcmonu_mgmt_arr_agg_port_list_entry_64 *obj, bcmos_errno *err, bcmolt_string *err_details);


/** Initializes a structure to default values.
 *
 * \param obj Pointer to the structure to initialize.
 */
void bcmonu_mgmt_priority_queue_set_default(bcmonu_mgmt_priority_queue *obj);

/** Checks if any field in the structure is set incorrectly (e.g. out of bounds).
 *
 * \param obj Pointer to the structure to validate.
 * \param err Filled in with the error (if validation fails).
 * \param err_details Filled in with a description of the error (if validation fails).
 * \return TRUE on success, FALSE on failure.
 */
bcmos_bool bcmonu_mgmt_priority_queue_validate(const bcmonu_mgmt_priority_queue *obj, bcmos_errno *err, bcmolt_string *err_details);


/** Initializes a structure to default values.
 *
 * \param obj Pointer to the structure to initialize.
 */
void bcmonu_mgmt_arr_priority_queue_128_set_default(bcmonu_mgmt_arr_priority_queue_128 *obj);

/** Checks if any field in the structure is set incorrectly (e.g. out of bounds).
 *
 * \param obj Pointer to the structure to validate.
 * \param err Filled in with the error (if validation fails).
 * \param err_details Filled in with a description of the error (if validation fails).
 * \return TRUE on success, FALSE on failure.
 */
bcmos_bool bcmonu_mgmt_arr_priority_queue_128_validate(const bcmonu_mgmt_arr_priority_queue_128 *obj, bcmos_errno *err, bcmolt_string *err_details);


/** Initializes a structure to default values.
 *
 * \param obj Pointer to the structure to initialize.
 */
void bcmonu_mgmt_uni_set_default(bcmonu_mgmt_uni *obj);

/** Checks if any field in the structure is set incorrectly (e.g. out of bounds).
 *
 * \param obj Pointer to the structure to validate.
 * \param err Filled in with the error (if validation fails).
 * \param err_details Filled in with a description of the error (if validation fails).
 * \return TRUE on success, FALSE on failure.
 */
bcmos_bool bcmonu_mgmt_uni_validate(const bcmonu_mgmt_uni *obj, bcmos_errno *err, bcmolt_string *err_details);


/** Initializes a structure to default values.
 *
 * \param obj Pointer to the structure to initialize.
 */
void bcmonu_mgmt_arr_uni_8_set_default(bcmonu_mgmt_arr_uni_8 *obj);

/** Checks if any field in the structure is set incorrectly (e.g. out of bounds).
 *
 * \param obj Pointer to the structure to validate.
 * \param err Filled in with the error (if validation fails).
 * \param err_details Filled in with a description of the error (if validation fails).
 * \return TRUE on success, FALSE on failure.
 */
bcmos_bool bcmonu_mgmt_arr_uni_8_validate(const bcmonu_mgmt_arr_uni_8 *obj, bcmos_errno *err, bcmolt_string *err_details);


/** Initializes a structure to default values.
 *
 * \param obj Pointer to the structure to initialize.
 */
void bcmonu_mgmt_flow_action_set_default(bcmonu_mgmt_flow_action *obj);

/** Checks if any field in the structure is set incorrectly (e.g. out of bounds).
 *
 * \param obj Pointer to the structure to validate.
 * \param err Filled in with the error (if validation fails).
 * \param err_details Filled in with a description of the error (if validation fails).
 * \return TRUE on success, FALSE on failure.
 */
bcmos_bool bcmonu_mgmt_flow_action_validate(const bcmonu_mgmt_flow_action *obj, bcmos_errno *err, bcmolt_string *err_details);


/** Initializes a structure to default values.
 *
 * \param obj Pointer to the structure to initialize.
 */
void bcmonu_mgmt_flow_match_set_default(bcmonu_mgmt_flow_match *obj);

/** Checks if any field in the structure is set incorrectly (e.g. out of bounds).
 *
 * \param obj Pointer to the structure to validate.
 * \param err Filled in with the error (if validation fails).
 * \param err_details Filled in with a description of the error (if validation fails).
 * \return TRUE on success, FALSE on failure.
 */
bcmos_bool bcmonu_mgmt_flow_match_validate(const bcmonu_mgmt_flow_match *obj, bcmos_errno *err, bcmolt_string *err_details);


/** Initializes a structure to default values.
 *
 * \param obj Pointer to the structure to initialize.
 */
void bcmonu_mgmt_flow_onu_key_set_default(bcmonu_mgmt_flow_onu_key *obj);

/** Checks if any field in the structure is set incorrectly (e.g. out of bounds).
 *
 * \param obj Pointer to the structure to validate.
 * \param err Filled in with the error (if validation fails).
 * \param err_details Filled in with a description of the error (if validation fails).
 * \return TRUE on success, FALSE on failure.
 */
bcmos_bool bcmonu_mgmt_flow_onu_key_validate(const bcmonu_mgmt_flow_onu_key *obj, bcmos_errno *err, bcmolt_string *err_details);


/** Initializes a structure to default values.
 *
 * \param obj Pointer to the structure to initialize.
 */
void bcmonu_mgmt_igmp_us_action_set_default(bcmonu_mgmt_igmp_us_action *obj);

/** Checks if any field in the structure is set incorrectly (e.g. out of bounds).
 *
 * \param obj Pointer to the structure to validate.
 * \param err Filled in with the error (if validation fails).
 * \param err_details Filled in with a description of the error (if validation fails).
 * \return TRUE on success, FALSE on failure.
 */
bcmos_bool bcmonu_mgmt_igmp_us_action_validate(const bcmonu_mgmt_igmp_us_action *obj, bcmos_errno *err, bcmolt_string *err_details);



/** Initializes a structure to default values.
 *
 * \param obj Pointer to the structure to initialize.
 */
void bcmonu_mgmt_flow_cfg_data_set_default(bcmonu_mgmt_flow_cfg_data *obj);

/** Checks if any field in the structure is set incorrectly (e.g. out of bounds).
 *
 * \param obj Pointer to the structure to validate.
 * \param err Filled in with the error (if validation fails).
 * \param err_details Filled in with a description of the error (if validation fails).
 * \return TRUE on success, FALSE on failure.
 */
bcmos_bool bcmonu_mgmt_flow_cfg_data_validate(const bcmonu_mgmt_flow_cfg_data *obj, bcmos_errno *err, bcmolt_string *err_details);


/** Gets the number of bytes that a multi-object container would occupy on the wire.
 *
 * Does not include the common header (msg->hdr->hdr).
 *
 * \param msg Pointer to the structure.
 * \return The structure size in bytes.
 */
uint32_t bcmonu_mgmt_flow_multi_cfg_get_packed_length(const bcmonu_mgmt_flow_multi_cfg *msg);

/** Packs a multi-object container to bytes for transmission on the wire.
 *
 * Assumes that the common header (msg->hdr->hdr) has already been packed.
 *
 * \param msg Pointer to the structure to pack.
 * \param buf Pointer to the buffer to write to.
 * eturn Error encountered during the pack (BCM_ERR_OK on success).
 */
bcmos_errno bcmonu_mgmt_flow_multi_cfg_pack(const bcmonu_mgmt_flow_multi_cfg *msg, bcmolt_buf *buf);

/** Unpacks a multi-object container from bytes as received on the wire.
 *
 * Assumes that the common header has already been unpacked.
 *
 * \param buf Pointer to the buffer to read from.
 * \param hdr The common header that has already been unpacked.
 * \param msg Pointer to the structure to unpack. This can be NULL, in which case the message will be dynamically allocated.
 * eturn Error encountered during the unpack (BCM_ERR_OK on success).
 */
bcmos_errno bcmonu_mgmt_flow_multi_cfg_unpack(bcmolt_buf *buf, const bcmonu_mgmt_msg *hdr, bcmonu_mgmt_flow_multi_cfg **msg);

/** Initializes a structure to default values.
 *
 * \param obj Pointer to the structure to initialize.
 */
void bcmonu_mgmt_flow_key_set_default(bcmonu_mgmt_flow_key *obj);

/** Checks if any field in the structure is set incorrectly (e.g. out of bounds).
 *
 * \param obj Pointer to the structure to validate.
 * \param err Filled in with the error (if validation fails).
 * \param err_details Filled in with a description of the error (if validation fails).
 * \return TRUE on success, FALSE on failure.
 */
bcmos_bool bcmonu_mgmt_flow_key_validate(const bcmonu_mgmt_flow_key *obj, bcmos_errno *err, bcmolt_string *err_details);


/** Initializes a structure to default values.
 *
 * \param obj Pointer to the structure to initialize.
 */
void bcmonu_mgmt_onu_cfg_data_set_default(bcmonu_mgmt_onu_cfg_data *obj);

/** Checks if any field in the structure is set incorrectly (e.g. out of bounds).
 *
 * \param obj Pointer to the structure to validate.
 * \param err Filled in with the error (if validation fails).
 * \param err_details Filled in with a description of the error (if validation fails).
 * \return TRUE on success, FALSE on failure.
 */
bcmos_bool bcmonu_mgmt_onu_cfg_data_validate(const bcmonu_mgmt_onu_cfg_data *obj, bcmos_errno *err, bcmolt_string *err_details);


/** Gets the number of bytes that a multi-object container would occupy on the wire.
 *
 * Does not include the common header (msg->hdr->hdr).
 *
 * \param msg Pointer to the structure.
 * \return The structure size in bytes.
 */
uint32_t bcmonu_mgmt_onu_multi_cfg_get_packed_length(const bcmonu_mgmt_onu_multi_cfg *msg);

/** Packs a multi-object container to bytes for transmission on the wire.
 *
 * Assumes that the common header (msg->hdr->hdr) has already been packed.
 *
 * \param msg Pointer to the structure to pack.
 * \param buf Pointer to the buffer to write to.
 * eturn Error encountered during the pack (BCM_ERR_OK on success).
 */
bcmos_errno bcmonu_mgmt_onu_multi_cfg_pack(const bcmonu_mgmt_onu_multi_cfg *msg, bcmolt_buf *buf);

/** Unpacks a multi-object container from bytes as received on the wire.
 *
 * Assumes that the common header has already been unpacked.
 *
 * \param buf Pointer to the buffer to read from.
 * \param hdr The common header that has already been unpacked.
 * \param msg Pointer to the structure to unpack. This can be NULL, in which case the message will be dynamically allocated.
 * eturn Error encountered during the unpack (BCM_ERR_OK on success).
 */
bcmos_errno bcmonu_mgmt_onu_multi_cfg_unpack(bcmolt_buf *buf, const bcmonu_mgmt_msg *hdr, bcmonu_mgmt_onu_multi_cfg **msg);

/** Initializes a structure to default values.
 *
 * \param obj Pointer to the structure to initialize.
 */
void bcmonu_mgmt_onu_key_set_default(bcmonu_mgmt_onu_key *obj);

/** Checks if any field in the structure is set incorrectly (e.g. out of bounds).
 *
 * \param obj Pointer to the structure to validate.
 * \param err Filled in with the error (if validation fails).
 * \param err_details Filled in with a description of the error (if validation fails).
 * \return TRUE on success, FALSE on failure.
 */
bcmos_bool bcmonu_mgmt_onu_key_validate(const bcmonu_mgmt_onu_key *obj, bcmos_errno *err, bcmolt_string *err_details);




#endif /* ONU_MGMT_MODEL_FUNCS */
