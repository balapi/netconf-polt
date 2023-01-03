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
 * netconf_module_utils.c
 *
 *  Created on: 31 Aug 2017
 *      Author: igort
 */

#define _GNU_SOURCE
#include <bcmolt_netconf_module_utils.h>
#include <sysrepo/values.h>
#include <sys/stat.h>

/* datastore suffix */
static const char *nc_ds_suffix[] = {
    [NC_DATASTORE_RUNNING] = "running",
    [NC_DATASTORE_STARTUP] = "startup",
    [NC_DATASTORE_CANDIDATE] = "candidate",
    [NC_DATASTORE_PENDING] = "pending",
};

/*
 * Serialization primitives. Lock/unlock configuration
 */

static bcmos_mutex nc_config_lock_mutex;

void nc_config_lock(void)
{
    static bcmos_bool is_initialized = BCMOS_FALSE;
    if (!is_initialized)
    {
        bcmos_mutex_create(&nc_config_lock_mutex, 0, NULL);
        is_initialized = BCMOS_TRUE;
    }
    bcmos_mutex_lock(&nc_config_lock_mutex);
}

void nc_config_unlock(void)
{
    bcmos_mutex_unlock(&nc_config_lock_mutex);
}

/* Get leaf node name in the xpath.
 * It is the node that follows the last /
 */
const char *nc_xpath_leaf_get(const char *xpath, char *leaf, uint32_t leaf_size)
{
    const char *last_slash;
    const char *p_leaf;
    char *p_bra;

    if (!xpath)
        return NULL;

    last_slash = strrchr(xpath, '/');

    p_leaf = last_slash ? last_slash + 1 : xpath;
    strncpy(leaf, p_leaf, leaf_size);
    leaf[leaf_size - 1] = 0;
    p_bra = strchr(leaf, '[');
    if (p_bra)
        *p_bra = 0;
    return leaf;
}

static bcmos_bool nc_file_exist(const char *path)
{
    struct stat s;

    if (stat(path, &s) != 0)
        return BCMOS_FALSE;

    if ((s.st_mode & S_IFMT) != S_IFREG)
        return BCMOS_FALSE;

    return BCMOS_TRUE;
}

/* Get the key value from xpath
 *
 * xpath = node/node[keyname='keyvalue']/node/node
 *
 * Returns
 * - BCM_ERR_OK
 * - BCM_ERR_PARM - malformed xpath
 * - BCM_ERR_NOENT - no key in []
 * - BCM_ERR_OVERFLOW - key value parameter is too short
 */
bcmos_errno nc_xpath_key_get(const char *xpath, const char *keyname, char *value, uint32_t value_size)
{
    const char *bra, *ket, *eq;
    const char *name, *val, *val_last;
    const char *path;
    uint32_t keyname_len;
    bcmos_errno err = BCM_ERR_NOENT;

    if (!xpath)
        return BCM_ERR_NOENT;

    if (!keyname)
        return BCM_ERR_PARM;

    keyname_len = strlen(keyname);
    for (path = xpath, ket = NULL;
         (err != BCM_ERR_OK) && (bra = strchr(path, '[')) != NULL;
         path = ket)
    {
        name = bra + 1;
        eq = strchr(name, '=');
        if (!eq)
            return BCM_ERR_PARM;
        ket = strchr(eq, ']');
        if (!ket)
            return BCM_ERR_PARM;

        if (memcmp(keyname, name, keyname_len) || (keyname_len != (eq - name)))
            continue;

        /* Found the key */
        val = eq + 1;
        val_last = ket - 1;
        if (*val == '\'' || *val == '\"')
            ++val;
        if (*val_last == '\'' || *val_last == '\"')
            --val_last;

        if (val_last - val + 1 >= value_size)
            return BCM_ERR_OVERFLOW;

        memcpy(value, val, val_last - val + 1);
        value[val_last - val + 1] = 0;
        err = BCM_ERR_OK;
    }

    return err;
}


/* Copy configuration from 1 datastore to another */
void nc_cfg_copy(sr_session_ctx_t *srs, const char *model, nc_datastore_type from, nc_datastore_type to)
{
    char *src_path = NULL;
    char *cmd = NULL;
    int n1, n2;

    n1 = asprintf(&src_path, SR_DATA_SEARCH_DIR "/%s.%s", model, nc_ds_suffix[from]);
    n2 = asprintf(&cmd, "cp -f " SR_DATA_SEARCH_DIR "/%s.%s " SR_DATA_SEARCH_DIR "/%s.%s",
        model, nc_ds_suffix[from], model, nc_ds_suffix[to]);

    if (!cmd || !src_path || n1 < 0 || n2 < 0)
    {
        NC_LOG_ERR("%s: failed to copy configuration from %s to %s: no memory\n",
            model, nc_ds_suffix[from], nc_ds_suffix[to]);
        if (cmd)
            free(cmd);
        if (src_path)
            free(src_path);
        return;
    }

    /* Reset destination datastore if source doesn't exist */
    if (!nc_file_exist(src_path))
    {
        NC_LOG_INFO("File %s doesn't exist\n", src_path);
        nc_cfg_reset(srs, model, to);
        free(cmd);
        free(src_path);
        return;
    }

    if (system(cmd))
    {
        NC_LOG_ERR("%s: failed to copy configuration from %s to %s: IO error\n",
            model, nc_ds_suffix[from], nc_ds_suffix[to]);
    }
    else
    {
        NC_LOG_INFO("%s: %s configuration copied to %s\n", model, nc_ds_suffix[from], nc_ds_suffix[to]);
    }
    free(cmd);
    free(src_path);
}

/* Reset startup configuration */
void nc_cfg_reset(sr_session_ctx_t *srs, const char *model, nc_datastore_type ds)
{
    char *fname = NULL, *cmd = NULL;
    int rc = -1;
    int n1, n2;

    n1 = asprintf(&fname, SR_DATA_SEARCH_DIR "/%s.%s", model, nc_ds_suffix[ds]);
    n2 = asprintf(&cmd, "touch %s", fname);
    if (!fname || !cmd || n1 < 0 || n2 < 0)
    {
        NC_LOG_ERR("%s: failed to reset %s configuration: no memory\n", model, nc_ds_suffix[ds]);
        if (fname)
            free(fname);
        if (cmd)
            free(cmd);
        return;
    }

    /* Do nothing if file doesn't exist */
    if (!nc_file_exist(fname))
    {
        free(fname);
        free(cmd);
        return;
    }

    if (!unlink(fname))
        rc = system(cmd);
    free(fname);
    free(cmd);
    if (rc)
    {
        NC_LOG_ERR("%s: failed to reset %s configuration: IO error\n", model, nc_ds_suffix[ds]);
    }
    else
    {
        NC_LOG_INFO("%s: %s configuration has been reset\n", model, nc_ds_suffix[ds]);
    }
}

/* Error log */
void nc_error_reply(sr_session_ctx_t *srs, const char *xpath, const char *format, ...)
{
    va_list args;
    char *msg = NULL;
    int n;

    va_start(args, format);
    n = vasprintf(&msg, format, args);
    va_end(args);
    if (msg && n > 0)
    {
#ifdef SYSREPO_LIBYANG_V2
        if (xpath != NULL)
            sr_session_set_error_message(srs, "xpath=%s\n%s", xpath, msg);
        else
            sr_session_set_error_message(srs, "%s", msg);
#else
        sr_set_error(srs, xpath, msg);
#endif
        free(msg);
    }
}

/* Add value to the list of values */
int nc_sr_value_add(
    const char *xpath,
    sr_type_t type,
    const char *string_val,
    sr_val_t **values,
    size_t *values_cnt)
{
    size_t new_count = *values_cnt + 1;
    sr_val_t *new_val;
    uint64_t num_val;
    int sr_rc;

    if (*values_cnt)
    {
        sr_rc = sr_realloc_values(*values_cnt, new_count, values);
    }
    else
    {
        sr_rc = sr_new_values(new_count, values);
    }
    if (sr_rc)
        return SR_ERR_NOMEM;
    new_val = &((*values)[*values_cnt]);
    num_val = strtoull(string_val, NULL, 0);
    do {
        sr_rc = sr_val_set_xpath(new_val, xpath);
        if (sr_rc)
            break;
        switch (type)
        {
            case SR_BINARY_T:
            case SR_BITS_T:
            case SR_ENUM_T:
            case SR_IDENTITYREF_T:
            case SR_INSTANCEID_T:
            case SR_STRING_T:
                sr_rc = sr_val_set_str_data(new_val, type, string_val);
                break;
            case SR_CONTAINER_PRESENCE_T:
            case SR_BOOL_T:
                new_val->data.bool_val = !strcmp(string_val, "true");
                break;
            case SR_INT8_T:
                new_val->data.int8_val = (int8_t)num_val;
                break;
            case SR_INT16_T:
                new_val->data.int16_val = (int16_t)num_val;
                break;
            case SR_INT32_T:
                new_val->data.int32_val = (int32_t)num_val;
                break;
            case SR_INT64_T:
                new_val->data.int64_val = (int64_t)num_val;
                break;
            case SR_UINT8_T:
                new_val->data.uint8_val = (uint8_t)num_val;
                break;
            case SR_UINT16_T:
                new_val->data.uint16_val = (uint16_t)num_val;
                break;
            case SR_UINT32_T:
                new_val->data.uint32_val = (uint32_t)num_val;
                break;
            case SR_UINT64_T:
                new_val->data.uint64_val = (uint64_t)num_val;
                break;
            default:
                sr_rc = SR_ERR_INVAL_ARG;
        }
    } while (0);

    if (sr_rc)
    {
        sr_val_t *dup_values = NULL;
        /* Create a copy of values array in order to shrink it */
        if (*values_cnt)
            sr_dup_values(*values, *values_cnt, &dup_values);
        sr_free_values(*values, new_count);
        *values = dup_values;
        if (dup_values == NULL)
            *values_cnt = 0;
        return sr_rc;
    }

    new_val->type = type;
    *values_cnt = new_count;

    return SR_ERR_OK;
}

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
    size_t *values_cnt)
{
    char xpath_buf[256];
    char *xpath = xpath_buf;
    int sr_rc;

    if (snprintf(xpath, sizeof(xpath_buf), "%s/%s", xpath_base, value_name) > sizeof(xpath_buf) - 1)
    {
        if (asprintf(&xpath, "%s/%s", xpath_base, value_name) <= 0)
            return SR_ERR_NOMEM;
    }
    sr_rc = nc_sr_value_add(xpath, type, string_val, values, values_cnt);
    if (sr_rc != SR_ERR_OK)
    {
        NC_LOG_ERR("Failed to add attribute %s. Error %s\n", xpath, sr_strerror(sr_rc));
    }
    if (xpath != xpath_buf)
        free(xpath);
    return sr_rc;
}

/* Add sub-value to the list of values.
 * The difference from nc_sr_value_add is that xpath is built internally
 * from 2 components: xpath_base and value_name
 */
struct lyd_node *nc_ly_sub_value_add(
    const struct ly_ctx *ctx,
    struct lyd_node *parent,
    const char *xpath_base,
    const char *value_name,
    const char *string_val)
{
    char xpath_buf[256];
    char *xpath = xpath_buf;
    struct lyd_node *result = NULL;

    if (value_name != NULL)
    {
        if (snprintf(xpath, sizeof(xpath_buf), "%s/%s", xpath_base, value_name) > sizeof(xpath_buf) - 1)
        {
            if (asprintf(&xpath, "%s/%s", xpath_base, value_name) <= 0)
                return parent;
        }
    }
    else
    {
        xpath = (char *)(long)xpath_base;
    }
#ifdef SYSREPO_LIBYANG_V2
    lyd_new_path(parent, ctx, xpath, (void *)(long)string_val,
        LYD_NEW_PATH_CANON_VALUE, &result);
#else
    result = lyd_new_path(parent, ctx, xpath, (void *)(long)string_val, LYD_ANYDATA_CONSTSTRING, 0);
#endif
    NC_LOG_DBG("lyd_new_path(%s, ctx, \"%s\", \"%s\", 0, 0) -> %s\n",
        (parent && parent->schema) ? parent->schema->name : "NULL",
        xpath,
        string_val ? string_val : "NULL",
        (result && result->schema) ? result->schema->name : "NULL");
    if (result == NULL)
    {
        NC_LOG_ERR("Error '%s'. Failed to add attribute %s.\n", ly_errmsg(ctx), xpath);
    }
    if (xpath != xpath_buf && xpath != xpath_base)
        free(xpath);
    return result ? result : parent;
}

/* Add value to array of values.
 * Return SR_SRR_...
 */
int nc_sr_values_set(sr_session_ctx_t *srs, sr_val_t *values, size_t values_cnt)
{
    size_t i;
    int sr_rc = SR_ERR_OK;

    for (i=0; i<values_cnt; i++)
    {
        sr_rc = sr_set_item(srs, values[i].xpath, &values[i], SR_EDIT_DEFAULT);
        if (sr_rc != SR_ERR_OK)
        {
            NC_LOG_ERR("Failed to set value for xpath %s. Error %s\n", values[i].xpath, sr_strerror(sr_rc));
            break;
        }
    }
    return sr_rc;
}

/* Free value pair
 * Variables *p_val1 and *p_val2 are released.
 * *p_val1 and *p_val2 are set =NULL
 */
void nc_sr_free_value_pair(sr_val_t **p_val1, sr_val_t **p_val2)
{
    if (*p_val1)
    {
        sr_free_val(*p_val1);
        *p_val1 = NULL;
    }
    if (*p_val2)
    {
        sr_free_val(*p_val2);
        *p_val2 = NULL;
    }
}

/*
 * Transaction support utilities
 */

void nc_transact_init(nc_transact *tr, sr_event_t event)
{
    tr->event = event;
    tr->plugin_elem_type = NC_TRANSACT_PLUGIN_ELEM_TYPE_INVALID;
    STAILQ_INIT(&tr->elems);
}

bcmos_errno nc_transact_add(nc_transact *tr, sr_val_t **p_old_val, sr_val_t **p_new_val)
{
    nc_transact_elem *elem = bcmos_alloc(sizeof(nc_transact_elem));
    if (elem == NULL)
    {
        NC_LOG_ERR("Can't collect transaction for %s\n",
            (*p_old_val && (*p_old_val)->xpath) ? (*p_old_val)->xpath :
                (*p_new_val && (*p_new_val)->xpath) ? (*p_new_val)->xpath : "Unknown");
        return BCM_ERR_NOMEM;
    }
    elem->old_val = *p_old_val;
    elem->new_val = *p_new_val;
    STAILQ_INSERT_TAIL(&tr->elems, elem, next);
    *p_old_val = NULL;
    *p_new_val = NULL;
    return BCM_ERR_OK;
}

void nc_transact_free(nc_transact *tr)
{
    nc_transact_elem *elem;

    while ((elem=STAILQ_FIRST(&tr->elems)))
    {
        if (!tr->do_not_free_values)
        {
            if (elem->old_val)
                sr_free_val(elem->old_val);
            if (elem->new_val)
                sr_free_val(elem->new_val);
        }
        STAILQ_REMOVE_HEAD(&tr->elems, next);
        bcmos_free(elem);
    }
}

/* Map error code from bcmos --> sysrepo */
int nc_bcmos_errno_to_sr_errno(bcmos_errno err)
{
    int sr_rc = SR_ERR_INTERNAL;

    switch(err)
    {
    case BCM_ERR_OK: sr_rc = SR_ERR_OK;
    break;

    case BCM_ERR_PARM: sr_rc = SR_ERR_INVAL_ARG;
    break;

    case BCM_ERR_NOMEM: sr_rc = SR_ERR_NOMEM;
    break;

    case BCM_ERR_NOT_SUPPORTED: sr_rc = SR_ERR_UNSUPPORTED;
    break;

    case BCM_ERR_IN_PROGRESS: sr_rc = SR_ERR_OPERATION_FAILED;
    break;

    case BCM_ERR_NOENT: sr_rc = SR_ERR_NOT_FOUND;
    break;

    case BCM_ERR_ALREADY: sr_rc = SR_ERR_EXISTS;
    break;

    default: sr_rc = SR_ERR_INTERNAL;
    break;
    }

    return sr_rc;
}



/* Map sysrepo errno to BAL */
bcmos_errno nc_sr_errno_to_bcmos_errno(int sr_rc)
{
    bcmos_errno err;

    switch (sr_rc)
    {
    case SR_ERR_OK: err = BCM_ERR_OK;
    break;

    case SR_ERR_INVAL_ARG: err = BCM_ERR_PARM;
    break;

    case SR_ERR_NOMEM: err = BCM_ERR_NOMEM;
    break;

    case SR_ERR_UNSUPPORTED: err = BCM_ERR_NOT_SUPPORTED;
    break;

    default: err = BCM_ERR_INTERNAL;
    break;
    }

    return err;
}

/* Translate binary data to hexadeciumal string.
 * hex buffer size must be at least (len*2 + 1)
 */
#define BIN_TO_HEX(_n) ((_n) >= 0 && (_n) <= 9) ? '0' + (_n) : 'A' + ((_n) - 10)

void nc_bin_to_hex(const uint8_t *bin, uint32_t len, char *hex)
{
    int i;
    char *p = hex;

    for (i=0; i<len; i++)
    {
        *(p++) = BIN_TO_HEX((bin[i] >> 4) & 0x0f);
        *(p++) = BIN_TO_HEX(bin[i] & 0x0f);
    }
    *p = 0;
}

/* Translate binary data from hexadecimal string to binary.
 */
int nc_hex_to_bin(const char *hex, uint8_t *bin, uint32_t bin_len)
{
    int src_len = (int)strlen(hex);
    int i = src_len, j, shift = 0;

    if (!bin || !bin_len || (src_len%2))
        return BCM_ERR_PARM;
    if (src_len > 2*bin_len)
        return BCM_ERR_OVERFLOW;

    /* Calculate hex buffer length and fill it up from right-to-left
     * in order to start the process from LS nibble
     */
    memset(bin, 0, bin_len);
    bin_len = src_len / 2;
    j = bin_len - 1;
    while( i )
    {
        int c = hex[--i];

        if ( (c>='0') && (c<='9') )
            c = c - '0';
        else if ( (c>='a') && (c<='f') )
            c = 0xA + c - 'a';
        else if ( (c>='A') && (c<='F') )
            c = 0xA + c - 'A';
        else
            return BCM_ERR_PARM;

        bin[j] |= (uint8_t)(c<<shift); /* shift can have 1 of 2 values: 0 and 4 */

        j     -= shift>>2;              /* move to the next byte if we've just filled the ms nibble */
        shift ^= 4;                     /* alternate nibbles */
    }

    return bin_len;
}

/* sysrepo operation name */
const char *sr_op_name(sr_change_oper_t op)
{
    static const char *op_name[] = {
        [SR_OP_CREATED] = "CREATED",    /**< The item has been created by the change. */
        [SR_OP_MODIFIED] = "MODIFIED",  /**< The value of the item has been modified by the change. */
        [SR_OP_DELETED] = "DELETED",    /**< The item has been deleted by the change. */
        [SR_OP_MOVED] = "MOVED"        /**< The item has been moved in the subtree by the change (applicable for leaf-lists and user-ordered lists). */
    };
    return op_name[op];
}

/* find a sibling node by name */
const struct lyd_node *nc_ly_get_sibling_node(const struct lyd_node *node, const char *name)
{
    const struct lyd_node *n;

    /* Go over prev siblings */
    n = node->prev;
    while (n && n != node && strcmp(n->schema->name, name))
        n = n->prev;
    if (n != NULL && n != node)
        return n;
    /* Go over next siblings */
    n = node->next;
    while (n && n != node && strcmp(n->schema->name, name))
        n = n->next;
    return (n == node) ? NULL : n;
}

/* find a sibling or a parent+siblings node by name */
const struct lyd_node *nc_ly_get_sibling_or_parent_node(const struct lyd_node *node, const char *name)
{
    const struct lyd_node *n;
    const struct lyd_node *parent;

    n = nc_ly_get_sibling_node(node, name);
    if (n != NULL)
        return n;
#ifdef SYSREPO_LIBYANG_V2
    parent = lyd_parent(node);
#else
    parent = node->parent;
#endif
    if (parent && !strcmp(parent->schema->name, name))
        return parent;
    while (parent && n == NULL)
    {
        n = nc_ly_get_sibling_node(parent, name);
#ifdef SYSREPO_LIBYANG_V2
        parent = lyd_parent(parent);
#else
        parent = parent->parent;
#endif
    }

    return n;
}

/*
 * Save / restore transaction error
 */
void nc_sr_error_save(sr_session_ctx_t *srs, char **xpath, char **message)
{
    const sr_error_info_t *sr_err_info=NULL;

    *xpath = NULL;
    *message = NULL;
#ifdef SYSREPO_LIBYANG_V2
    sr_session_get_error(srs, &sr_err_info);
    if (sr_err_info != NULL && sr_err_info->err_count)
    {
        if (sr_err_info->err[0].message)
            *message = bcmos_strdup(sr_err_info->err[0].message);
    }
#else
    sr_get_error(srs, &sr_err_info);
    if (sr_err_info != NULL && sr_err_info->err != NULL)
    {
        if (sr_err_info->err->xpath)
            *xpath = bcmos_strdup(sr_err_info->err->xpath);
        if (sr_err_info->err->message)
            *message = bcmos_strdup(sr_err_info->err->message);
    }
#endif
}

void nc_sr_error_restore(sr_session_ctx_t *srs, char *xpath, char *message)
{
    if (message != NULL)
    {
#ifdef SYSREPO_LIBYANG_V2
        if (xpath != NULL)
            sr_session_set_error_message(srs, "xpath=%s\n%s", xpath, message);
        else
            sr_session_set_error_message(srs, "%s", message);
#else
        sr_set_error(srs, xpath, message);
#endif
    }
    if (xpath != NULL)
        bcmos_free(xpath);
    if (message != NULL)
        bcmos_free(message);
}

/*
 * Send notification
 */
bcmos_errno nc_sr_event_notif_send(sr_session_ctx_t *srs, struct lyd_node *notif, const char *notif_xpath)
{
    int sr_rc;

#if SR_VERSION_MAJOR > 6
    sr_rc = sr_notif_send_tree(
#else
    sr_rc = sr_event_notif_send_tree(
#endif
        srs, notif
#ifdef SYSREPO_LIBYANG_V2
                , 0, 0
#endif
            );
    if (sr_rc != SR_ERR_OK)
    {
        NC_LOG_ERR("Failed to sent %s notification. Error '%s'\n",
            notif_xpath, sr_strerror(sr_rc));
    }
    return nc_sr_errno_to_bcmos_errno(sr_rc);
}

/*
 * Modules
 */
const struct lys_module *nc_ly_ctx_load_module(struct ly_ctx *ly_ctx, const char *module_name,
    const char *version, const char **features, bcmos_bool log_error)
{
    const struct lys_module *mod;

#ifdef SYSREPO_LIBYANG_V2
    mod = ly_ctx_load_module(ly_ctx, module_name, version, features);
#else
    mod = ly_ctx_get_module(ly_ctx, module_name, version, 1);
    if (mod == NULL)
        mod = ly_ctx_load_module(ly_ctx, module_name, version);
#endif
    if (mod == NULL)
    {
        if (log_error)
            NC_LOG_ERR("Can't load schema '%s'. Error '%s'\n", module_name, ly_errmsg(ly_ctx));
        return NULL;
    }

#ifndef SYSREPO_LIBYANG_V2
    if (features != NULL)
    {
        for( ; *features; features++)
        {
            if (lys_features_enable(mod, *features))
            {
                NC_LOG_ERR("%s: can't enable feature %s\n", module_name, *features);
                mod = NULL;
                break;
            }
        }
    }
#endif

    return mod;
}
