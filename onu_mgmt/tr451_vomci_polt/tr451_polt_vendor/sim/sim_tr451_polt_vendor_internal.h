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
 * sim_tr451_polt_vendor_internal.h
 */

#ifndef SIM_TR451_POLT_VENDOR_INTERNAL_H_
#define SIM_TR451_POLT_VENDOR_INTERNAL_H_

/* Receive handling mode */
typedef enum
{
    TR451_POLT_SIM_RX_MODE_DISCARD,
    TR451_POLT_SIM_RX_MODE_LOOPBACK,
    TR451_POLT_SIM_RX_MODE_ONU_SIM
} tr451_polt_sim_rx_mode;

/* Receive handling configuration */
typedef struct
{
   tr451_polt_sim_rx_mode mode;
   union
   {
      struct
      {
         uint32_t skip; /* Send back 1 reply for every skip+1 requests */
      } loopback;
      struct
      {
         uint16_t local_port;       /* 0=autoassign */
         uint32_t remote_address;   /* ONU simulator address */
         uint16_t remote_port;      /* ONU simulator port */
      } onu_sim;
   };
} tr451_polt_sim_rx_cfg;

/* Packet header for ONU sim communication */
typedef struct
{
#define TR451_ONU_SIM_CTERM_NAME_SIZE  30
   char cterm_name[TR451_ONU_SIM_CTERM_NAME_SIZE];
   uint16_t onu_id;
} tr451_onu_sim_packet_header;

/* Set receive handling mode */
bcmos_errno sim_tr451_vendor_rx_cfg_set(const tr451_polt_sim_rx_cfg *cfg);

/* Report ONU discovered */
bcmos_errno sim_tr451_vendor_onu_added(const char *cterm, uint16_t onu_id,
   const tr451_polt_onu_serial_number *serial, uint8_t *registration_id,
   xpon_onu_presence_flags flags);

/* Report ONU removed */
bcmos_errno sim_tr451_vendor_onu_removed(const char *cterm, uint16_t onu_id,
   const tr451_polt_onu_serial_number *serial, xpon_onu_presence_flags flags);

/* Report packet received from ONU */
bcmos_errno sim_tr451_vendor_packet_received_from_onu(const char *cterm, uint16_t onu_id,
   const uint8_t *data, uint32_t length);

#endif /* SIM_TR451_POLT_VENDOR_INTERNAL_H_ */
