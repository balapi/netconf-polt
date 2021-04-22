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

/** TR-451 pOLT vendor interface
 * This header file declares functions that should be implemented by vendor-specific plugin
 * and dependant types.
 */

#ifndef BCM_TR451_VENDOR__H
#define BCM_TR451_VENDOR__H

#ifdef __cplusplus
extern "C"
{
#endif

#include <bcmos_system.h>
#include <bcmcli.h>
#include <bcm_tr451_polt.h>

#ifdef __cplusplus
}
#endif

#include <tr451_polt_vendor_specific.h>

#include <tr451_vomci_sbi_message.pb.h>
using tr451_vomci_sbi_message::v1::OmciPacket;
using tr451_vomci_sbi_message::v1::OnuHeader;

/** OmciPacket that can be enqueued */
class OmciPacketEntry: public OmciPacket {
    public:
        STAILQ_ENTRY(OmciPacketEntry) next;
};

/** ONU serial number */
typedef struct
{
   uint8_t data[8]; /* in binary format. 4 bytes vendor_id followed by 4 bytes vendor-specific id */
} tr451_polt_onu_serial_number;

/** ONU information */
typedef struct
{
   const char *cterm_name;          /* Channel termination name */
   tr451_polt_onu_serial_number serial_number;
   union
   {
      uint8_t password[10];         /* ITU.T G.984.3 */
      uint8_t registration_id[36];  /* ITU.T G.987.3, G.989.3, G.9807 */
   };
   uint16_t pon_interface_id;       /* PON interface ID on the front panel */
#define POLT_PON_ID_UNDEFINED    0xffff
   uint16_t onu_id;
#define POLT_ONU_ID_UNDEFINED    0xffff
   xpon_onu_presence_flags presence_flags; /* ONU presence flags */
} tr451_polt_onu_info;

/**
 * @brief  Initialize TR-451 vendor library
 * @returns BCM_ERR_OK(0) or error code <0
 */
bcmos_errno tr451_vendor_init(void);

/**
 * @brief  Terminate TR-451 vendor library
 * @returns BCM_ERR_OK(0) or error code <0
 */
bcmos_errno tr451_vendor_init(void);

/**
 * @brief  Send packet to ONU
 * @note The function can be called for multiple ONUs simultaneously
 *      from different execution context. It is the responsibility of the
 *      implementer to make it thread-safe.
 * @param[in]  &packet:     OMCI packet received from vOMCI peer
 * @returns BCM_ERR_OK(0) or error code <0
 */
bcmos_errno tr451_vendor_omci_send_to_onu(const OmciPacket &packet);

/** Callbacks for reporting events */
typedef struct
{
   void *user_handle;      /**< Handle that is passed transparently to event callbacks */

   /**
    * @brief  Callback function to be called when OMCI packet is received from ONU.
    * @note It is the responsibility of the callback to release the packet eventually
    */
   void (*tr451_omci_rx_cb)(void *user_handle, OmciPacketEntry *packet);

   /**
    * @brief  Callback function to be called upon ONU state change
    */
   void (*tr451_onu_state_change_cb)(void *user_handle, const tr451_polt_onu_info *onu_info);

   /**
    * @brief  Send onu state change notification.
    *   Usually this callback is called when ONU is added using CLI command
    */
   bcmos_errno (*tr451_onu_state_change_notify_cb)(void *user_handle, const tr451_polt_onu_info *onu_info);

} tr451_vendor_event_cfg;

/**
 * @brief  Register to receive OMCI packets
 * @note
 * @param[in]  rx_cb:           Receive callback function to be called when OMCI packet is received
 * @param[in]  *rx_cb_handle:   Handle to pass to rx_cb
 * @returns BCM_ERR_OK(0) or error code <0
 */
bcmos_errno tr451_vendor_event_register(const tr451_vendor_event_cfg *cb_cfg);

#endif /* #ifndef BCM_TR451_VENDOR__H */
