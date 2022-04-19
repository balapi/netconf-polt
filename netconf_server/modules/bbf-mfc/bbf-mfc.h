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

#ifndef _BBF_MFC_H_
#define _BBF_MFC_H_

#include <bcmos_system.h>
#include <libyang/libyang.h>
#include <sysrepo.h>

#define BBF_POLT_MFC_MODULE_NAME            "bbf-obbaa-mfc-conf"
#define BBF_NF_CLIENT_MODULE_NAME           "bbf-nf-client"
#define BBF_NF_ENDPOINT_FILTER_MODULE_NAME  "bbf-nf-endpoint-filter"
#define BBF_POLT_MFC_CLIENT_PATH            "/bbf-obbaa-mfc-conf:remote-network-function/nf-client"
#define BBF_POLT_MFC_CLIENT_REMOTE_ENDPOINTS_PATH  BBF_POLT_MFC_CLIENT_PATH "/client-parameters/nf-initiate/remote-endpoints"

typedef enum
{
    BBF_MFC_ACTION_NONE,
    BBF_MFC_ACTION_REDIRECT,
    BBF_MFC_ACTION_COPY
} bbf_mfc_action;

bcmos_errno bbf_polt_mfc_module_init(sr_session_ctx_t *srs, struct ly_ctx *ly_ctx);
bcmos_errno bbf_polt_mfc_module_start(sr_session_ctx_t *srs, struct ly_ctx *ly_ctx);
void bbf_polt_mfc_module_exit(sr_session_ctx_t *srs, struct ly_ctx *ly_ctx);

#endif
