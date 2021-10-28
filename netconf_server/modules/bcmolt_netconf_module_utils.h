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
 * netconf_module_utils.h
 *
 *  Created on: 31 Aug 2017
 *      Author: igort
 */

#ifndef _NETCONF2_MODULE_UTILS_H_
#define _NETCONF2_MODULE_UTILS_H_

#include <bcmos_system.h>
#include <sysrepo.h>
#include <libyang/libyang.h>
#include <b64.h>
#include <bcmolt_netconf_module_init.h>

#ifdef ENABLE_LOG

#include <bcm_dev_log.h>
extern dev_log_id log_id_netconf;
#endif

#if defined(SYSREPO_LIBYANG_V2) && !defined(SR_ERR_NOMEM)
#define SR_ERR_NOMEM SR_ERR_NO_MEMORY
#endif

#define NC_LOG_ERR(fmt, args...)   BCM_LOG(ERROR, log_id_netconf, fmt, ##args);
#define NC_LOG_INFO(fmt, args...)  BCM_LOG(INFO, log_id_netconf, fmt, ##args);
#define NC_LOG_WARN(fmt, args...)  BCM_LOG(WARNING, log_id_netconf, fmt, ##args);
#define NC_LOG_DBG(fmt, args...)   BCM_LOG(DEBUG, log_id_netconf, fmt, ##args);

/*
 * Serialization primitives. Lock/unlock configuration
 */
void nc_config_lock(void);
void nc_config_unlock(void);

/* Datastore type */
typedef enum
{
    NC_DATASTORE_RUNNING,       /* Running configuration */
    NC_DATASTORE_STARTUP,       /* Startup configuration */
    NC_DATASTORE_CANDIDATE,     /* Candidate configuration */
    NC_DATASTORE_PENDING,       /* Pending configuration - to be applied when some preconditions are met */
} nc_datastore_type;


/*
 * Transaction support.
 * It is used to copy aside a list of nodes when dat apath modification callback is called.
 */

/* Sysrepo transaction data. Operation and linked list of old and new node values */
typedef struct nc_transact_elem nc_transact_elem;
struct nc_transact_elem
{
    sr_val_t *old_val;
    sr_val_t *new_val;
    STAILQ_ENTRY(nc_transact_elem) next;
};

typedef struct nc_transact
{
    sr_event_t event;
    int plugin_elem_type;   /* Plugin-specific element type (ie, iftype) */
#define NC_TRANSACT_PLUGIN_ELEM_TYPE_INVALID    (-1)
    STAILQ_HEAD(trans_elems, nc_transact_elem) elems;
    bcmos_bool do_not_free_values;
} nc_transact;

void nc_transact_init(nc_transact *tr, sr_event_t event);
bcmos_errno nc_transact_add(nc_transact *tr, sr_val_t **p_old_val, sr_val_t **p_new_val);
void nc_transact_free(nc_transact *tr);


/* Get leaf node name in the xpath.
 * It is the node that follows the last /
 */
const char *nc_xpath_leaf_get(const char *xpath, char *leaf, uint32_t leaf_size);

/* Get the key value from xpath
 *
 * xpath = node/node[keyname='keyvalue']/node/node
 *
 * Returns
 * - BCM_ERR_OK
 * - BCM_ERR_NOENT - no key in []
 * - BCM_ERR_OVERFLOW - key value parameter is too short
 */
bcmos_errno nc_xpath_key_get(const char *xpath, const char *keyname, char *value, uint32_t value_size);

/* Copy configuration */
void nc_cfg_copy(sr_session_ctx_t *srs, const char *model, nc_datastore_type from, nc_datastore_type to);

/* Copy running configuration to startup */
static inline void nc_cfg_running_to_startup(sr_session_ctx_t *srs, const char *model)
{
    nc_cfg_copy(srs, model, NC_DATASTORE_RUNNING, NC_DATASTORE_STARTUP);
}

/* Reset configuration */
void nc_cfg_reset(sr_session_ctx_t *srs, const char *model, nc_datastore_type ds);

/* Reset startup configuration */
static inline void nc_cfg_reset_startup(sr_session_ctx_t *srs, const char *model)
{
    nc_cfg_reset(srs, model, NC_DATASTORE_STARTUP);
}

/* Map BAL error code to sysrepo */
int nc_bcmos_errno_to_sr_errno(bcmos_errno err);

/* Map sysrepo errno to BAL */
bcmos_errno nc_sr_errno_to_bcmos_errno(int sr_rc);

/* Error log */
void nc_error_reply(sr_session_ctx_t *srs, const char *xpath, const char *format, ...);

#define NC_ERROR_REPLY(_srs, _xpath, _format, _args...) \
    do { \
        if (_srs != NULL) \
            nc_error_reply(_srs, _xpath, _format, ##_args); \
        NC_LOG_ERR(_format "\n", ##_args); \
    } while (0)

/* Add value to array of values.
 * Return SR_SRR_...
 */
int nc_sr_value_add(
    const char *xpath,
    sr_type_t type,
    const char *string_val,
    sr_val_t **values,
    size_t *values_cnt);

/* Add sub-value to the list of values.
 * The difference from nc_sr_value_add is that xpath is built internally
 * from 2 components: xpath_base and value_name
 */
int nc_sr_sub_value_add(
    const char *xpath_base,
    const char *value_name,
    sr_type_t type,
    const char *string_val,
    sr_val_t **values,
    size_t *values_cnt);

/* Type for libyang value containing data (as opposed to other nodes) */
#ifndef SYSREPO_LIBYANG_V2
#define NC_SR_GET_CHANGE_TREE_NEXT_PREF_DFLT_TYPE   bool
#define NC_LYD_DATA_NODE struct lyd_node_leaf_list
#define NC_LYD_DATA_NODE_STRING_VAL(node)  ((const NC_LYD_DATA_NODE *)(node))->value_str
#define NC_LYD_DATA_NODE_BOOL_VAL(node)    ((const NC_LYD_DATA_NODE *)(node))->value.bln
#else
#define NC_SR_GET_CHANGE_TREE_NEXT_PREF_DFLT_TYPE   int
#define NC_LYD_DATA_NODE struct lyd_node_term
#define NC_LYD_DATA_NODE_STRING_VAL(node)  lyd_get_value(node)
#define NC_LYD_DATA_NODE_BOOL_VAL(node)    ((const NC_LYD_DATA_NODE *)(node))->value.boolean
#endif
#define NC_LYD_DATA_NODE_VAL(node)         (&(((const NC_LYD_DATA_NODE *)(node))->value))

/* Add sub-value to the libyang context.
 * The difference from nc_sr_value_add is that xpath is built internally
 * from 2 components: xpath_base and value_name
 */
struct lyd_node *nc_ly_sub_value_add(
    const struct ly_ctx *ctx,
    struct lyd_node *parent,
    const char *xpath_base,
    const char *value_name,
    const char *string_val);

/* Set values in datastore from sr_val_t array */

/* Add value to array of values.
 * Return SR_SRR_...
 */
int nc_sr_values_set(sr_session_ctx_t *srs, sr_val_t *values, size_t values_cnt);

/* Free value pair
 * Variables *p_val1 and *p_val2 are released.
 * *p_val1 and *p_val2 are set =NULL
 */
void nc_sr_free_value_pair(sr_val_t **p_val1, sr_val_t **p_val2);

/* Translate binary data to hexadecimal string.
 * hex buffer size must be at least (len*2 + 1)
 */
void nc_bin_to_hex(const uint8_t *bin, uint32_t bin_len, char *hex);

/* Translate binary data from hexadecimal string to binary.
 * Returns the length of converted buffer >= 0
 * or BCM_ERR_PARM or BCM_ERR_OVERFLOW
 */
int nc_hex_to_bin(const char *hex, uint8_t *bin, uint32_t bin_len);

/* sysrepo operation name */
const char *sr_op_name(sr_change_oper_t op);

/* find a sibling node by name */
const struct lyd_node *nc_ly_get_sibling_node(const struct lyd_node *node, const char *name);

/* find a sibling or a parent+siblings node by name */
const struct lyd_node *nc_ly_get_sibling_or_parent_node(const struct lyd_node *node, const char *name);

/*
 * Save / restore transaction error
 */
void nc_sr_error_save(sr_session_ctx_t *srs, char **xpath, char **message);
void nc_sr_error_restore(sr_session_ctx_t *srs, char *xpath, char *message);

/*
 * Modules
 */
const struct lys_module *nc_ly_ctx_load_module(struct ly_ctx *ly_ctx, const char *module_name,
    const char *version, const char **features, bcmos_bool log_error);

/*
 * Notification
 */
bcmos_errno nc_sr_event_notif_send(sr_session_ctx_t *srs, struct lyd_node *notif, const char *notif_xpath);

static inline void nc_sr_event_notif_free(struct lyd_node *notif)
{
    if (notif != NULL)
#ifdef SYSREPO_LIBYANG_V2
        lyd_free_all(notif);
#else
        lyd_free_withsiblings(notif);
#endif
}

#endif /* _NETCONF2_MODULE_UTILS_H_ */
