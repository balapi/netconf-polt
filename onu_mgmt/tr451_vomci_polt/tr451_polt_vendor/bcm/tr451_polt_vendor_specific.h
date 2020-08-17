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

#ifdef __cplusplus
extern "C"
{
#endif
#include <bcmos_hash_table.h>
#include <bcmolt_host_api.h>

#define BCM_DEFAULT_OLT_ID          0

#define TR451_POLT_MAX_PONS_PER_OLT        16
#define TR451_POLT_MAX_ONUS_PER_PON        128

/* channel-termination -> pon_id mapping */
bcmos_errno bcm_tr451_channel_termination_mapper_init(void);
bcmos_errno bcm_tr451_channel_termination_mapper_add(const char *channel_termination_name, bcmolt_interface pon_ni);
const char *bcm_tr451_channel_termination_mapper_get_name_by_id(bcmolt_interface pon_ni);
bcmos_errno bcm_tr451_channel_termination_mapper_get_id_by_name(const char *name, bcmolt_interface *pon_ni);

/* Debug functions */
void bcm_tr451_omci_rx_from_onu(bcmolt_devid device_id, bcmolt_msg *msg);
void bcm_tr451_stats_get(const char **endpoint_name, uint32_t *omci_sent,
   uint32_t *omci_recv, uint32_t *send_errors);

#ifdef __cplusplus
}
#endif

#define TR451_POLT_ENABLE_VENDOR_CLI
/**
 * @brief  Initialize vendor CLI
 * @param[in]  *dir: main vomci direcory
 * @returns BCM_ERR_OK(0) or error code <0
 */
bcmos_errno tr451_vendor_cli_init(bcmcli_entry *dir);

#endif /* TR451_POLT_VENDOR_SPECIFIC_H_ */
