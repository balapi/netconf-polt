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
 * bbf-xpon-tm-mgmt.c
 */
#include "bbf-xpon-internal.h"


/*
 * tm-root handling
 */

/* Populate tm-root attribute */
bcmos_errno xpon_tm_root_attribute_populate(sr_session_ctx_t *srs,
    xpon_tm_root *tm_root, sr_val_t *sr_old_val, sr_val_t *sr_new_val)
{
    const char *iter_xpath;
    char leafbuf[BCM_MAX_LEAF_LENGTH];
    const char *leaf;
    sr_val_t *val = (sr_new_val != NULL) ? sr_new_val : sr_old_val;
    bcmos_errno err = BCM_ERR_OK;

    NC_LOG_DBG("old_val=%s new_val=%s type=%d\n",
        sr_old_val ? sr_old_val->xpath : "none",
        sr_new_val ? sr_new_val->xpath : "none",
        sr_old_val ? sr_old_val->type : sr_new_val->type);

    if (val->type == SR_LIST_T || val->type == SR_CONTAINER_T)
    {
        /* no semantic meaning */
        return BCM_ERR_OK;
    }

    iter_xpath = val->xpath;
    leaf = nc_xpath_leaf_get(iter_xpath, leafbuf, sizeof(leafbuf));
    if (leaf == NULL)
    {
        /* no semantic meaning */
        return BCM_ERR_OK;
    }

    do
    {
        /* Go over supported leafs */
    } while (0);

    return err;
}

bcmos_errno xpon_tm_root_delete(sr_session_ctx_t *srs, xpon_tm_root *tm_root)
{
    return BCM_ERR_OK;
}
