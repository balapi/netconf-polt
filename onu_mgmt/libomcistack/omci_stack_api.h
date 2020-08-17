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

#ifndef _OMCI_STACK_API_H_
#define _OMCI_STACK_API_H_

/**
 * @file omci_stack_api.h
 * @brief This file has the api interface to the broadcom omci stack. These apis will be called
 * by service layer for sending out OMCI Managed Entity messages to ONU. The APIs for receiving indications
 * will also be part of this file.
 */
#include <bcmos_system.h>
#include <omci_stack_me_hdr.h>
#include <omci_stack_protocol_prop.h>
#include <omci_stack_common.h>
#include <omci_stack_model_types.h>

/**
 *  @brief Software download support structures
 */

#define BCM_OMCI_SWDL_BASELINE_SECTION_SIZE     (BCM_OMCI_FORMAT_BASE_MSG_LEN - 17)
#define BCM_OMCI_SWDL_EXTENDED_SECTION_SIZE     (BCM_OMCI_FORMAT_EXTENDED_MSG_LEN_MAX - 15)

/** Software download start request */
typedef struct
{
    uint8_t win_size;       /* Window size - 1 */
    uint32_t image_size;    /* Image size (bytes) */
    uint8_t num_inst;       /* Number of instances for simultaneous download 1..9 */
    uint16_t slot_me[9];    /* s/w image entity instance */
} bcm_omci_swdl_start;

/** Software download end request */
typedef struct
{
    uint32_t crc32;
    uint32_t image_size;
    uint8_t num_inst;
    uint16_t slot_me[9];
} bcm_omci_swdl_end;

/* Software download activate request */
typedef enum
{
    BCM_OMCI_SWDL_ACTIVATE_MODE_UNCONDITIONALLY    = 0x0,
    BCM_OMCI_SWDL_ACTIVATE_MODE_IF_NO_CALLS        = 0x1,
    BCM_OMCI_SWDL_ACTIVATE_MODE_IF_NO_EMRG_CALLS   = 0x2,
} bcm_omci_swdl_activate_mode;

/** Alarm report */
typedef struct
{
#define BCM_OMCI_MAX_ALARM_BITMAP_BYTE_SIZE      28
    uint8_t alarm_bitmap[BCM_OMCI_MAX_ALARM_BITMAP_BYTE_SIZE];
    uint8_t alarm_seq_number;
} bcm_omci_alarm;

/** AVC report */
typedef struct
{
    uint32_t todo;
} bcm_omci_avc;

/** MIB upload response.
 * Union branch is selected by operation
 */
typedef union
{
    /** BCM_OMCI_MSG_TYPE_MIB_UPLOAD */
    struct
    {
        uint32_t me_count;
    } mib_upload;

    /** BCM_OMCI_MSG_TYPE_MIB_UPLOAD_NEXT */
    struct
    {
        bcmos_bool is_last;
    } mib_upload_next;
} bcm_omci_mib_upload_response;

/** Software download response.
 * Union branch is selected by operation
 */
typedef union
{
    /** BCM_OMCI_MSG_TYPE_START_SW_DOWNLOAD */
    struct
    {
        uint8_t win_size;   /* Window size - 1 */
        uint8_t num_inst;   /* Number of instances responding */
        uint16_t me_id;     /* s/w image entity instance */
        uint8_t result[9];  /* Result array*/
    } swdl_start;

    /** BCM_OMCI_MSG_TYPE_DOWNLOAD_SECTION */
    struct
    {
        uint8_t section_num;
    } swdl_section;

    /** BCM_OMCI_MSG_TYPE_END_SW_DOWNLOAD */
    struct
    {
        uint8_t num_inst;
        struct
        {
            uint16_t slot_me;
            uint8_t result;
        } slot[9];
    } swdl_end;
} bcm_omci_swdl_response;

/*
 * OMCI stack functions called from by application or OMCI service layer
 */

/*
 * Initialization functions
 */

typedef enum
{
    BCM_OMCI_LOAD_BALANCE_NONE,     /**< Automatic load balancing is disabled.
                                        Application can assign RX modules to ONUs explicitly using bcm_omci_onu_init() */
    BCM_OMCI_LOAD_BALANCE_ONU       /**< RX threads are assigned to ONUs based on per-thread ONU occupancy */
} bcm_omci_load_balance_policy;

/** OMCI Stack initialization parameters */
typedef struct bcm_omci_stack_init_parms
{
    bcmolt_oltid    max_olts;   /**< Max number of supported OLTs */

    /** Transmit raw message handler */
    bcmos_errno (*transmit_cb)(bcm_omci_me_key *key, void *msg_buf, uint16_t msg_len);

    /*
     * Receive message handlers.
     * NOTE: me_hdr passed to all response handlers must be released using
     *       bcm_omci_me_free()
     */

    /** Response handler.
     * This handler is called for most of OMCI responses, transmit errors or timeout.
     * The exceptiopns are responses to the following operations, which are handled by separate callbacks
     * - MIB_UPLOAD, MIB_UPLOAD_NEXT
     * - START_SW_DOWNLOAD, DOWNLOAD_SECTION, END_SW_DOWNLOAD
     */
    void (*response_cb)(bcm_omci_me_hdr *me);

    /** MIB upload response handler
     * This handler is called for MIB upload related responses
     */
    void (*mib_upload_response_cb)(bcm_omci_me_hdr *me, bcm_omci_mib_upload_response *data);

    /** Software download response handler
     * This handler is called for Software Download related responses
     */
    void (*swdl_response_cb)(bcm_omci_me_hdr *me, bcm_omci_swdl_response *data);

    /*
     * Autonomous message handlers
     */

    /** Alarm message handler */
    void (*alarm_cb)(bcm_omci_me_key *key, bcm_omci_alarm *alarm);

    /** AVC message handler */
    void (*avc_cb)(bcm_omci_me_key *key, bcm_omci_avc *avc);

    /*
     * Load balancing support
     */
    bcm_omci_load_balance_policy load_balance_policy;
    uint32_t rx_msg_pool_size;  /**< Max number of received messages "in-flight" */
#define BCM_OMCI_DEFAULT_RX_MSG_POOL_SIZE	1024
    uint32_t num_rx_threads;    /**< Number of threads handling OMCI receive.
                                    Each ONU is assigned a thread at init time.
                                    For good server utilization num_rx_threads should be
                                    equal or exceed the number of CPU cores
                                */
#define BCM_OMCI_NUM_RX_THREADS_DEFAULT     16

} bcm_omci_stack_init_parms;


/**
 * @brief API Initialization to be called once by the omci service layer
 */
bcmos_errno bcm_omci_stack_init(const bcm_omci_stack_init_parms *init_parms);

/**
 * @brief API to de-initialize omci stack, called by the omci service layer
 */
bcmos_errno bcm_omci_stack_deinit(void);

/** OLT initialization parameters */
typedef struct bcm_omci_olt_init_parms
{
    bcmolt_interface    max_pons;           /**< Max number of supported PONs */
    bcmolt_onu_id       max_onus_per_pon;   /**< Max number of supported ONUs per PON */
    /* Other parameters TBD */
} bcm_omci_olt_init_parms;

/**
 * @brief OLT-level initialization
 */
bcmos_errno bcm_omci_olt_init(bcmolt_oltid oltid, const bcm_omci_olt_init_parms *init_parms);

/**
 * @brief OLT-level de-initialization
 */
bcmos_errno bcm_omci_olt_deinit(bcmolt_oltid oltid);

/** ONU initialization parameters */
typedef struct bcm_omci_onu_init_parms
{
    bcmos_module_id rx_module;              /**< thread+module handling OMCI RX flow for the ONU */
} bcm_omci_onu_init_parms;

/**
 * @brief  ONU level initialization
 */
bcmos_errno bcm_omci_onu_init(bcmolt_oltid oltid, bcmolt_interface logical_pon,
    bcmolt_onu_id onu_id, const bcm_omci_onu_init_parms *init_parms);

/**
 * @brief  ONU level de-initialization
 */
bcmos_errno bcm_omci_onu_deinit(bcmolt_oltid oltid, bcmolt_interface logical_pon, bcmolt_onu_id onu_id);

/**
 * @brief  Hand over received OMCI message to OMCI stack
 *
 * @param  *me_key:         Message key
 * @param  *omci_msg:       Raw OMCI message
 * @param  omci_msg_len:    Raw OMCI message length
 * @retval BCM_ERR_OK(0) or error < 0
 */
bcmos_errno bcm_omci_recv_msg(bcm_omci_me_key *me_key, void *omci_msg, uint16_t omci_msg_len);


/**
 * @brief API to be called by omci service layer to set an ME with action Create
 *
 * @param[in]   me_hdr     ME header followed by ME-specific data
 */
bcmos_errno bcm_omci_create_req(bcm_omci_me_hdr *me_hdr);

/**
 * @brief API to be called by omci service layer to set an ME with action Set
 *
 * @param[in]   me_hdr     ME header followed by ME-specific data
 */
bcmos_errno bcm_omci_set_req(bcm_omci_me_hdr *me_hdr);

/**
 * @brief API to be called by omci service layer to get an ME from ONU side
 *
 * @param[in]   me_hdr     ME header followed by ME-specific data
 */
bcmos_errno bcm_omci_get_req(bcm_omci_me_hdr *me_hdr);

/**
 * @brief API to be called by omci service layer to Delete an ME on ONU
 *
 * @param[in]   me_key     olt, pon, onu and obj_type must be set
 */
bcmos_errno bcm_omci_delete_req(bcm_omci_me_key *me_key);

/**
 * @brief API to be called by omci service layer for MIB Reset Req
 *
 * @param[in]   me_key     olt, pon and onu must be set
 */
bcmos_errno bcm_omci_mib_reset_req(bcm_omci_me_key *me_key);

/**
 * @brief API to be called by omci service layer for MIB Upload Req
 *
 * @param[in]   me_key     olt, pon and onu must be set
 */
bcmos_errno bcm_omci_mib_upload_req(bcm_omci_me_key *me_key);

/**
 * @brief API to be called by omci service layer for MIB Upload Next Req
 *
 * @param[in]   me_key     olt, pon and onu must be set
 */
bcmos_errno bcm_omci_mib_upload_next_req(bcm_omci_me_key *me_key);

/**
 * @brief API to be called by omci service layer to set an ME with action Reboot
 *
 * @param[in]   me_key     olt, pon, onu and instance must be set
 */
bcmos_errno bcm_omci_reboot_req(bcm_omci_me_key *me_key);

/**
 * @brief API to be called by omci service layer to start software download
 *
 * @param[in]   me_key     olt, pon, onu and instance must be set
 * @param[in]   data       Software download request data
 */
bcmos_errno bcm_omci_swdl_start_req(bcm_omci_me_key *me_key, bcm_omci_swdl_start *data);

/**
 * @brief API that returns full s/w download section size
 */
static inline uint32_t bcm_omci_swdl_max_section_size(bcmos_bool is_extended)
{
    return is_extended ? BCM_OMCI_SWDL_EXTENDED_SECTION_SIZE : BCM_OMCI_SWDL_BASELINE_SECTION_SIZE;
}

/**
 * @brief API to be called by omci service layer to send software download section
 *
 * @param[in]   me_key          olt, pon, onu and instance must be set
 * @param[in]   section_num     ME content
 * @param[in]   data_length     Section data length
 * @param[in]   data            Section data
 * @param[in]   ack_required    TRUE if ack is required
 * @param[in]   extended_omci   TRUE - use extended OMCI format
 */
bcmos_errno bcm_omci_swdl_section_req(bcm_omci_me_key *me_key,
    uint8_t section_num, uint16_t data_length, uint8_t *data,
    bcmos_bool ack_required, bcmos_bool extended_omci);

/**
 * @brief API to be called by omci service layer to end software download
 *
 * @param[in]   me_key          olt, pon, onu and instance must be set
 * @param[in]   data            ME content
 */
bcmos_errno bcm_omci_swdl_end_req(bcm_omci_me_key *me_key, bcm_omci_swdl_end *data);

/**
 * @brief API to be called by omci service layer to activate s/w image
 *
 * @param[in]   me_key          olt, pon, onu and instance must be set
 * @param[in]   mode            activation mode
 */
bcmos_errno bcm_omci_swdl_activate_req(bcm_omci_me_key *me_key, bcm_omci_swdl_activate_mode mode);

/**
 * @brief API to be called by omci service layer to commit s/w image
 *
 * @param[in]   me_key          olt, pon, onu and instance must be set
 */
bcmos_errno bcm_omci_swdl_commit_req(bcm_omci_me_key *me_key);

/**
 * @brief Function to be called by omci service layer to synchronize time on onu-g
 *
 * @param[in]   me_key          olt, pon and onu must be set
 */
bcmos_errno bcm_omci_sync_time_req(bcm_omci_me_key *me_key);

/**
 * @brief  Free me_hdr block
 * @param  *me_hdr:
 * @retval None
 */
void bcm_omci_me_free(bcm_omci_me_hdr *me_hdr);

#endif /*_OMCI_STACK_API_H_ */
