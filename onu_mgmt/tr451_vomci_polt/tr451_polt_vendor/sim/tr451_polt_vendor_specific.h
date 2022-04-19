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

/*
 * tr451_polt_vendor_specific.h
 */

#ifndef TR451_POLT_VENDOR_SPECIFIC_H_
#define TR451_POLT_VENDOR_SPECIFIC_H_

#define TR451_POLT_MAX_PONS_PER_OLT        16
#define TR451_POLT_MAX_ONUS_PER_PON        128

#define TR451_POLT_ENABLE_VENDOR_CLI

/**
 * @brief  Initialize vendor CLI
 * @param[in]  *dir: main vomci direcory
 * @returns BCM_ERR_OK(0) or error code <0
 */
bcmos_errno tr451_vendor_cli_init(bcmcli_entry *dir);


#ifdef __cplusplus
extern "C"
#endif
void tr451_onu_auth_report_status_set_cb_set(void (*cb)(xpon_onu_auth_action_status status));

#endif /* TR451_POLT_VENDOR_SPECIFIC_H_ */
