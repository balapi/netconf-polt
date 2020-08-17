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
 * bbf-xpon.h
 */

#ifndef _BBF_XPON_H_
#define _BBF_XPON_H_

#include <bcmos_system.h>
#include <libyang/libyang.h>
#include <sysrepo.h>

bcmos_errno bbf_xpon_module_init(sr_session_ctx_t *srs, struct ly_ctx *ly_ctx);
bcmos_errno bbf_xpon_module_start(sr_session_ctx_t *srs, struct ly_ctx *ly_ctx);
void bbf_xpon_module_exit(sr_session_ctx_t *srs, struct ly_ctx *ly_ctx);

#endif /* _BBF_XPON_H_ */
