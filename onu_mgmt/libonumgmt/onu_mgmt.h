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

#ifndef _ONU_MGMT_H_
#define _ONU_MGMT_H_

/**
 * @file onu_mgmt.h
 * @brief Function declarations and all inclusions required for the ONU Management API
 *
 * @defgroup onu_mgmt_api ONU Management API
 */

#include <bcmolt_system_types_typedefs.h>
#include <onu_mgmt_model_types.h>
#ifdef ENABLE_LOG
#include <bcm_dev_log.h>
#endif

/************************************************************************************
  Extra adaptations needed to build onu mgmt in Aspen tree
************************************************************************************/
typedef uint16_t bcmolt_pon_onu_id;
typedef void (*config_line_cb)(char *name, char *value);
void onu_mgmt_util_parse_config(FILE *fp, config_line_cb line_cb);
/************************************************************************************/



/** @{ */

typedef void (*onu_mgmt_notify_cb)(bcmonu_mgmt_cfg *cfg);

typedef enum
{
    ONU_MGMT_STATE_UNINITIALIZED,
    ONU_MGMT_STATE_INITIALIZED,     /* overall onu mgmt state */
    ONU_MGMT_STATE_OLT_DOWN,        /* olt specific state = olt down */
    ONU_MGMT_STATE_OLT_READY,       /* olt specific state  = olt ready */
} onu_mgmt_state;

typedef struct onu_mgmt_notify_entity
{
    SLIST_ENTRY(onu_mgmt_notify_entity) next;
    onu_mgmt_notify_cb cb;
} onu_mgmt_notify_entity;

typedef enum
{
    BCM_ONU_MGMT_SVC_OMCI,
    BCM_ONU_MGMT_SVC_DPOE2,
    BCM_ONU_MGMT_SVC_CTC3,

    BCM_ONU_MGMT_SVC__COUNT
} bcm_onu_mgmt_svc;


typedef struct
{
    onu_mgmt_state state;
    bcmos_module_id module_id; /* module on behalf the proxy messages will be handled. */
    bcmos_bool is_loopback;
    bcm_onu_mgmt_svc onu_mgmt_svc;
    SLIST_HEAD(, onu_mgmt_notify_entity) onu_notify_entities; /* Entities that will be notified upon an event to a ONU object. */
    SLIST_HEAD(, onu_mgmt_notify_entity) flow_notify_entities; /* Entities that will be notified upon an event to a flow object. */
    onu_mgmt_state olt_state[BCM_MAX_OLTS];  /* olt states */
} onu_mgmt_context_t;

extern onu_mgmt_context_t onu_mgmt_context;

#ifdef ENABLE_LOG
extern dev_log_id onu_mgmt_log_id;
#endif

extern uint8_t onu_mgmt_my_olt_id;

bcmos_errno bcmonu_mgmt_cfg_set(bcmolt_oltid olt_id, bcmonu_mgmt_cfg *cfg);
bcmos_errno bcmonu_mgmt_cfg_get(bcmolt_oltid olt_id, bcmonu_mgmt_cfg *cfg);
bcmos_errno bcmonu_mgmt_cfg_clear(bcmolt_oltid olt_id, bcmonu_mgmt_cfg *cfg);
bcmos_errno bcmonu_mgmt_multi_cfg_get(bcmolt_oltid olt_id, bcmonu_mgmt_multi_cfg *cfg, bcmonu_mgmt_filter_flags filter_flags);


/* 'module_id' is the module on behalf the proxy messages will be handled. */
bcmos_errno bcmonu_mgmt_init(bcmos_module_id module_id);
bcmos_errno bcmonu_mgmt_deinit(bcmos_module_id module_id);
bcmos_errno bcmonu_mgmt_olt_init(bcmolt_oltid olt_id);

bcmos_bool bcmonu_mgmt_is_loopback(void);
void bcmonu_mgmt_set_loopback(bcmos_bool is_loopback);

bcm_onu_mgmt_svc bcmonu_mgmt_svc_get(void);

bcmos_errno bcmonu_mgmt_onu_notify_register(onu_mgmt_notify_cb cb);
void bcmonu_mgmt_onu_notify_unregister(onu_mgmt_notify_cb cb);

bcmos_errno bcmonu_mgmt_flow_notify_register(onu_mgmt_notify_cb cb);
void bcmonu_mgmt_flow_notify_unregister(onu_mgmt_notify_cb cb);

/** @} */

#endif

