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
 * bcm_tr451_polt_vendor_internal.h
 */

#ifndef BCM_TR451_POLT_VENDOR_INTERNAL_H_
#define BCM_TR451_POLT_VENDOR_INTERNAL_H_

/* Report ONU discovered */
bcmos_errno bcm_tr451_vendor_onu_added(bcmolt_interface pon_ni, bcmolt_onu_id onu_id, const bcmolt_serial_number *serial);

/* Report ONU removed */
bcmos_errno bcm_tr451_vendor_onu_removed(bcmolt_interface pon_ni, bcmolt_onu_id onu_id);

/* Report packet received from ONU */
bcmos_errno bcm_tr451_vendor_packet_received_from_onu(bcmolt_onu_omci_packet *bcm_packet);

#endif /* BCM_TR451_POLT_VENDOR_INTERNAL_H_ */
