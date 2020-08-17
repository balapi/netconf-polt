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

#ifndef OMCI_TRANSPORT_H
#define OMCI_TRANSPORT_H

#include <omci_stack_api.h>

/*
 * G.988 protocol messages
 */

/* Header Part for both Baseline OMCI (Device ID 0x0A) and Extended OMCI (Device ID 0x0B)  */
typedef __PACKED_ATTR_START__ struct
{
    uint16_t	tci;
    uint8_t		msg_type;
    uint8_t    	device_id;
    uint16_t    me_id_class;
    uint16_t    me_id_instance;
}__PACKED_ATTR_END__ omci_msg_hdr;

/* Baseline OMCI Trailer */
typedef __PACKED_ATTR_START__ struct
{
    uint8_t		cpcs_uu;
    uint8_t		cpi;
    uint16_t    cpcs_sdu;
    uint32_t    crc;
}__PACKED_ATTR_END__ omci_msg_baseline_trailer;

/* Extended OMCI Trailer */
typedef __PACKED_ATTR_START__ struct
{
    uint32_t	mic;
}__PACKED_ATTR_END__ omci_msg_extended_trailer;


#define   OMCI_MSG_HDR_LEN  sizeof(omci_msg_hdr) /* 8 Bytes */
#define   OMCI_MSG_BASELINE_CONTENT_LEN  32
#define   OMCI_MSG_CRC_OR_MIC_LEN  4

/* Baseline OMCI Message */
typedef __PACKED_ATTR_START__ struct
{
    omci_msg_hdr                hdr;
    uint8_t                     content[OMCI_MSG_BASELINE_CONTENT_LEN];
    omci_msg_baseline_trailer   trailer;
}__PACKED_ATTR_END__ omci_msg_baseline;

#define   OMCI_MSG_EXTENDED_CONTENT_LEN  BCM_OMCI_FORMAT_EXTENDED_MSG_LEN_MAX - 14 /* hdr x 8, len x 2, content, mic x 4 */

/* Extended OMCI Message */
typedef __PACKED_ATTR_START__ struct
{
    omci_msg_hdr	             hdr;
    uint16_t                     content_length;
    uint8_t                      content[OMCI_MSG_EXTENDED_CONTENT_LEN];
    omci_msg_extended_trailer    trailer;
}__PACKED_ATTR_END__ omci_msg_extended;

#define   OMCI_HIGH_PRIORITY_MSG                 0x8000
#define   OMCI_BASELINE_TCI_MASK                 0x7FFF
#define   OMCI_EXTENDED_TCI_MASK                 0xFFFF

#define   OMCI_TRAILER_CPSU_SDU_LEN 			(uint16_t)0x0028

/* OMCI_MT_SWDL_SECTION | AR =  0x14 | 0x40*/
#define   OMCI_SWDL_SECTION_ACK_REQUEST      ( 0x54 )
/* OMCI_MT_SWDL_SECTION | AR =  0x14 */
#define   OMCI_SWDL_SECTION_NO_ACK_REQUEST   ( 0x14 )

/* Max number of messages that can wait for acknowledge per ONU */
#define OMCI_TL_MAX_MSGS_IN_PROGRESS	8

/*
 * Transport data structures
 */

/** OMCI rx message block */
typedef struct omci_rx_msg
{
    bcm_omci_me_hdr me_hdr;
    omci_msg_baseline omci_msg;
    uint16_t omci_msg_len;
    bcmos_bool is_auto;
} omci_rx_msg;


/** Variable-length data buffer */
typedef struct omci_data_buf
{
    uint32_t len;   /**< Buffer length. */
    uint8_t *val;   /**< Data pointer */
} omci_data_buf;

typedef struct
{
    omci_data_buf               data;
    bcmos_bool                  ar;
    uint16_t                    sent_msg_counter;
    bcmos_timer                 timer;
    bcm_omci_me_key             key;
    bcm_omci_msg_type           omci_msg_type;
} omci_tx_msg;

/** rx_worker thread control structure */
typedef struct omci_rx_worker
{
    bcmos_task                  task;
    bcmos_module_id             module;
    uint32_t                    num_onus;	/* number of ONUs associated with the worker */
} omci_rx_worker;

/** @brief ony db in transport layer for Stack to use */
typedef struct
{
    uint8_t         mib_data_sync;
    uint16_t        tci;
    omci_tx_msg     sent_msg[OMCI_TL_MAX_MSGS_IN_PROGRESS];
    uint16_t        num_of_mib_upload_next_commands;
    uint16_t        mib_upload_next_commands_counter;
    bcmos_module_id rx_module;
    omci_rx_worker *rx_worker;
    void           *me_layer_context;      /* context saved by ME layer for the ONU */
    bcmos_mutex     onu_lock;
} omci_transport_onu_rec;

typedef struct
{
    omci_transport_onu_rec **onu_db;
    uint32_t max_onus_per_pon;  	/* max onus per pon (for now same for all pons) */
} omci_transport_pon_rec;

/** db array for max pons supported */
typedef struct
{
    uint32_t max_pon_ports;
    omci_transport_pon_rec *pon_db; /* an arary of pon_dbs, one for each logical pon */
} omci_transport_olt_rec;

/** db array for max OLTs supported */
typedef struct
{
    uint32_t max_olts;
    uint32_t num_rx_workers;
    bcm_omci_load_balance_policy load_balance_policy;
    omci_rx_worker *rx_workers;     /* array of num_rx_workers elements containing number of ONUs allocated to rx_worker thread */
    omci_transport_olt_rec *olt_db; /* an arary of olt_dbs, one for each OLT */
    bcmos_msg_pool rx_msg_pool;     /* message pool for inter-task forwarding */
    bcmos_mutex lock;
} omci_transport_system_db;


/** @brief pon db array for max pons on an OLT */
/** @note this needs to be accessible from ME layer also */
extern omci_transport_system_db omci_transport_db;

/* Get ONU DB context */
static inline omci_transport_onu_rec *omci_db_onu_get(bcmolt_oltid olt, bcmolt_interface pon, bcmolt_onu_id onu)
{
    omci_transport_olt_rec *olt_rec;
    omci_transport_pon_rec *pon_rec;

    if (olt >= omci_transport_db.max_olts || omci_transport_db.olt_db == NULL)
        return NULL;
    olt_rec = &omci_transport_db.olt_db[olt];
    if (pon >= olt_rec->max_pon_ports || olt_rec->pon_db == NULL)
        return NULL;
    pon_rec = &olt_rec->pon_db[pon];
    if (onu >= pon_rec->max_onus_per_pon || pon_rec->onu_db == NULL)
        return NULL;
    return pon_rec->onu_db[onu];
}

/* Get ONU DB context my ME key */
static inline omci_transport_onu_rec *omci_db_onu_get_by_key(const bcm_omci_me_key *key)
{
    return omci_db_onu_get(key->olt_id, key->logical_pon, key->onu_id);
}


#define OMCI_BASELINE_MSG_RESPONSE_RESULT_OFFSET 0
#define OMCI_EXTENDED_MSG_RESPONSE_RESULT_OFFSET 2

#define OMCI_MSG_TYPE_DB_FIELD_MASK 0x80
#define OMCI_MSG_TYPE_AR_FIELD_MASK 0x40
#define OMCI_MSG_TYPE_AK_FIELD_MASK 0x20
#define OMCI_MSG_TYPE_MT_FIELD_MASK 0x1F

static inline uint16_t omci_msg_read_tci(omci_msg_hdr *hdr)
{
    if(BCM_OMCI_MSG_FORMAT_BASE == hdr->device_id)
        return (BCMOS_ENDIAN_BIG_TO_CPU_U16(hdr->tci) & OMCI_BASELINE_TCI_MASK);
    else
        return (BCMOS_ENDIAN_BIG_TO_CPU_U16(hdr->tci) & OMCI_EXTENDED_TCI_MASK);
}

static inline bcm_omci_msg_type omci_msg_read_msg_type(omci_msg_hdr *hdr)
{
    return (bcm_omci_msg_type)(hdr->msg_type & OMCI_MSG_TYPE_MT_FIELD_MASK);
}

static inline bcmos_bool omci_msg_is_acknowledge_req_bit_set(omci_msg_hdr *hdr)
{
    return (bcmos_bool)(hdr->msg_type & OMCI_MSG_TYPE_AR_FIELD_MASK);
}

static inline uint8_t omci_msg_set_acknowledge_req_bit(omci_msg_hdr *hdr)
{
    return (hdr->msg_type |= OMCI_MSG_TYPE_AR_FIELD_MASK);
}

static inline bcmos_bool omci_msg_is_acknowledgement_bit_set(omci_msg_hdr *hdr)
{
    return (bcmos_bool)(hdr->msg_type & OMCI_MSG_TYPE_AK_FIELD_MASK);
}

static inline uint8_t omci_msg_set_acknowledgement_bit(omci_msg_hdr *hdr)
{
    return (hdr->msg_type |= OMCI_MSG_TYPE_AK_FIELD_MASK);
}

static inline uint16_t omci_msg_read_me_id_class(omci_msg_hdr *hdr)
{
    return (BCMOS_ENDIAN_BIG_TO_CPU_U16(hdr->me_id_class));
}

static inline void omci_msg_write_me_id_class(omci_msg_hdr *hdr, uint16_t me_id_class)
{
    hdr->me_id_class = BCMOS_ENDIAN_CPU_TO_BIG_U16(me_id_class);
}

static inline uint16_t omci_msg_read_me_id_instance(omci_msg_hdr *hdr)
{
    return (BCMOS_ENDIAN_BIG_TO_CPU_U16(hdr->me_id_instance));
}

static inline void omci_msg_write_me_id_instanc(omci_msg_hdr *hdr, uint16_t me_id_instanc)
{
    hdr->me_id_instance = BCMOS_ENDIAN_CPU_TO_BIG_U16(me_id_instanc);
}

static inline uint16_t omci_msg_read_cpcs_sdu(omci_msg_baseline_trailer *trailer)
{
    return (BCMOS_ENDIAN_BIG_TO_CPU_U16(trailer->cpcs_sdu));
}

static inline void omci_msg_write_cpcs_sdu(omci_msg_baseline_trailer *trailer, uint16_t cpcs_sdu)
{
    trailer->cpcs_sdu = BCMOS_ENDIAN_CPU_TO_BIG_U16(cpcs_sdu);
}

static inline uint32_t omci_msg_read_crc(omci_msg_baseline_trailer *trailer)
{
    return (BCMOS_ENDIAN_BIG_TO_CPU_U32(trailer->crc));
}

static inline void omci_msg_write_crc(omci_msg_baseline_trailer *trailer, uint32_t crc)
{
    trailer->crc = BCMOS_ENDIAN_CPU_TO_BIG_U32(crc);
}

bcmos_errno omci_transport_init(const bcm_omci_stack_init_parms *init_parms);
void omci_transport_deinit(void);
bcmos_errno omci_transport_olt_init(bcmolt_oltid olt, bcmolt_interface max_pons, bcmolt_onu_id max_onus_per_pon);
void omci_transport_olt_deinit(bcmolt_oltid olt);
bcmos_errno omci_transport_onu_init(bcmolt_oltid olt, bcmolt_interface logical_pon, bcmolt_onu_id onu_id,
    const bcm_omci_onu_init_parms *init_parms);
void omci_transport_onu_deinit(bcmolt_oltid olt, bcmolt_interface logical_pon, bcmolt_onu_id onu_id);
bcmos_errno omci_transport_buf_alloc(uint8_t **buf, uint16_t *len, bcm_omci_msg_format omci_format);
bcmos_errno omci_transport_send_msg(bcm_omci_me_hdr *me_hdr, uint8_t *msg_content,
    uint16_t msg_content_len, bcmos_bool request_ack);
bcmos_errno omci_transport_send_msg_operation(bcm_omci_me_hdr *me_hdr);
bcmos_errno omci_transport_send_mib_upload_next_request(bcm_omci_me_hdr *me_hdr);
void omci_transport_mib_upload_num_cmds_set(bcm_omci_me_key *me_key, uint16_t num_cmds);
bcm_omci_result omci_transport_mib_upload_next(bcm_omci_me_key *me_key);
void omci_transport_increment_mib_data_sync(bcmolt_oltid olt, bcmolt_interface pon, bcmolt_onu_id onu_id);
void omci_transport_reset_mib_data_sync(bcmolt_oltid olt, bcmolt_interface pon, bcmolt_onu_id onu_id);


#endif /* OMCI_TRANSPORT_H */

