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

#include <bcmolt_api.h>
#include <bcm_dev_log.h>
#include "onu_mgmt_test.h"
#include "omci_svc_adapter_common.h"
#include "omci_svc_common.h"
#include "omci_svc_flow.h"
#include "omci_svc_onu.h"
#include "omci_svc.h"

/* The input TPID and output TPID are values that are common to all flows of the same ONU.
 * Here are the defaults, but they may be changed. */
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_INPUT_TPID 0x8100
#define OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_OUTPUT_TPID 0x8100

static bcmos_errno omci_svc_flow_op_queue_create(bcmolt_oltid olt_id, bcmolt_pon_ni pon_id, bcmolt_pon_onu_id onu_id)
{
    omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, pon_id, onu_id);
    omci_svc_flow_op_queue *queue = &onu_context->flow_op_queue;

    queue->head = queue->queue;
    queue->tail = queue->queue;

    snprintf(queue->mutex.name, sizeof(queue->mutex.name), "omci_svc%u_%u_flow_op_queue_mutex", pon_id, onu_id);
    return bcmos_mutex_create(&queue->mutex.mutex, 0, queue->mutex.name);
}

static void omci_svc_onu_mib_init(omci_svc_onu *onu_context)
{
    TAILQ_INIT(&onu_context->mib.unis);
    TAILQ_INIT(&onu_context->mib.free_tconts);
    TAILQ_INIT(&onu_context->mib.used_tconts);
    TAILQ_INIT(&onu_context->mib.us_priority_queues);
    TAILQ_INIT(&onu_context->mib.ds_priority_queues);
}

bcmos_errno omci_svc_init(onu_state_changed_cb onu_cb)
{
    bcmos_errno rc;
#ifdef ENABLE_LOG
    if (omci_svc_log_id == DEV_LOG_INVALID_ID)
    {
        omci_svc_log_id = bcm_dev_log_id_register("OMCI_SVC", DEV_LOG_LEVEL_INFO, DEV_LOG_ID_TYPE_BOTH);
        BUG_ON(omci_svc_log_id == DEV_LOG_INVALID_ID);
    }

    /** @todo this logging is only for OCS stack, if and when it is migrated to Aspen tree */
    //omci_svc_omci_logging_init();
#endif

    omci_onu_state_changed = onu_cb;

    /* initialize a couple of global lists */
    /** @note each of the lists store for all olts */
    TAILQ_INIT(&omci_svc_onu_cfg_db);
    TAILQ_INIT(&omci_svc_flow_cfg_db);

    /** initialize Omci stack overall */
    rc = omci_svc_omci_init();
    BCMOS_TRACE_CHECK_RETURN(rc, rc, "omci_svc_omci_init()\n");

    BCM_LOG(INFO, omci_svc_log_id, "OMCI SVC is initialized\n");

    return BCM_ERR_OK;
}

bcmos_errno omci_svc_deinit(void)
{
    uint16_t o;
    /** @note there is no separate olt deinit function */
    for (o=0; o<BCM_MAX_OLTS; o++)
    {
        omci_svc_unsubscribe_omci_proxy_ind(o);
    }
    omci_svc_omci_deinit();

    BCM_LOG(INFO, omci_svc_log_id, "OMCI SVC is now de-initialized\n");

    return BCM_ERR_OK;
}

/** @brief query host side pon topology using Aspen API for OLT Get */
static bcmos_errno omci_svc_query_pon_topology(bcmolt_oltid olt_id, uint8_t *max_pon_for_olt)
{
	bcmos_errno rc = BCM_ERR_OK;
    bcmolt_olt_cfg olt_cfg;
    bcmolt_olt_key key = {};
	bcmolt_topology_map topo_map[BCM_MAX_PONS_PER_OLT] = {};
    bcmolt_topology topo = { .topology_maps = { .len = BCM_MAX_PONS_PER_OLT, .arr = &topo_map[0] } };

    *max_pon_for_olt = 0;

    BCMOLT_CFG_INIT(&olt_cfg, olt, key);
    BCMOLT_FIELD_SET_PRESENT(&olt_cfg.data, olt_cfg_data, topology);
    BCMOLT_CFG_LIST_BUF_SET(&olt_cfg, olt, topo.topology_maps.arr, sizeof(bcmolt_topology_map) * topo.topology_maps.len);

    /** test utility: for actual topo query use the onu mgmt/BAL default olt id (= 0) */
    olt_id = bcmonu_mgmt_test_olt_id != BCMONU_MGMT_OLT_INVALID ? bcmonu_mgmt_test_default_olt_id : olt_id;

    rc = bcmolt_cfg_get(olt_id, &olt_cfg.hdr);
    if (BCM_ERR_OK == rc)
    {
        *max_pon_for_olt = olt_cfg.data.topology.topology_maps.len;
    }
	
    return rc;
}

bcmos_errno omci_svc_olt_init(bcmolt_oltid olt_id)
{
    uint32_t i;
    bcmos_errno rc;
    bcmolt_pon_onu_id onu_id;
    uint32_t logical_pon_id;
    uint8_t max_pon_for_olt = 0;


    /** query topology for OLT */
    rc = omci_svc_query_pon_topology(olt_id, &max_pon_for_olt);
        if (BCM_ERR_OK != rc)
        {
        BCM_LOG(ERROR, omci_svc_log_id, "Failed to query Topology for OLT id=%u, error:%s\n", 
                olt_id, bcmos_strerror(rc));
            return rc;
        }

    rc = omci_svc_topo_init_context(olt_id, max_pon_for_olt);
        if (BCM_ERR_OK != rc)
        {
        BCM_LOG(ERROR, omci_svc_log_id, "Failed to initialize omci svc topo context for OLT id=%u, error:%s\n", 
                olt_id, bcmos_strerror(rc));
            return rc;
        }

        /** initialize DB for each logical pon present in Topology */
        for (logical_pon_id=0; logical_pon_id < max_pon_for_olt; logical_pon_id++)
        {
            omci_svc_pon_context_t *omci_svc_pon_context; 
            omci_svc_pon_context = bcmos_calloc(sizeof(*omci_svc_pon_context));
            if (!omci_svc_pon_context)
            {
                BCM_LOG(ERROR, omci_svc_log_id, "Memory allocation failed for omci svc pon context (sizeof=%u)\n", (uint32_t)sizeof(*omci_svc_pon_context));
                return BCM_ERR_NOMEM;
            }

        omci_svc_topo_pon_set_context(olt_id, logical_pon_id, OMCI_SVC_PON_TOPO_MAX_ONUS_PER_PON, omci_svc_pon_context);

            for (onu_id=0; onu_id < OMCI_SVC_PON_TOPO_MAX_ONUS_PER_PON; onu_id++)
            {
            omci_svc_onu *onu_context = OMCI_SVC_ONU_TOPO_CONTEXT(olt_id, logical_pon_id, onu_id);

                onu_context->state = OMCI_SVC_ONU_STATE_ID_INACTIVE;
                onu_context->admin_state = BCMONU_MGMT_ADMIN_STATE_DOWN;
                onu_context->oper_status = BCMONU_MGMT_STATUS_DOWN; /* default oper status is DOWN, similar to BAL side */
                onu_context->mib.input_tpid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_INPUT_TPID;
                onu_context->mib.output_tpid = OMCI_SVC_EXT_VLAN_TAG_OPER_CFG_DATA_OUTPUT_TPID;
                DLIST_INIT(&onu_context->mib.o_vids);
                DLIST_INIT(&onu_context->mib.gem_ports);
                TAILQ_INIT(&onu_context->mib.free_mac_bridge_ports);
                /* Because MAC bridge port is uint8_t, we can have up to 255 ANI ports (0 is dedicated to the UNI side). */
                for (i = 1; i <= UCHAR_MAX; i++)
                {
                    omci_svc_mac_bridge_port *mac_bridge_port_entry;

                    mac_bridge_port_entry = bcmos_calloc(sizeof(*mac_bridge_port_entry));
                    if (!mac_bridge_port_entry)
                    {
                        BCM_LOG(ERROR, omci_svc_log_id, "Memory allocation failed (sizeof=%u)\n", (uint32_t)sizeof(*mac_bridge_port_entry));
                        return BCM_ERR_NOMEM;
                    }
                    mac_bridge_port_entry->port_num = i;
                    TAILQ_INSERT_TAIL(&onu_context->mib.free_mac_bridge_ports, mac_bridge_port_entry, next);
                }
                TAILQ_INIT(&onu_context->mib.used_mac_bridge_ports);
                omci_svc_flow_op_queue_create(olt_id, logical_pon_id, onu_id);
                omci_svc_onu_mib_init(onu_context);
            }
        }

    /** subscribe for Onu:omci_packet INdications (per olt) */
    rc = omci_svc_subscribe_omci_proxy_ind(olt_id);
    BCMOS_TRACE_CHECK_RETURN(rc, rc, "omci_svc_subscribe_omci_proxy_ind() for olt_id=%u\n", olt_id);

    /* Initialize OMCI stack not more than once. */
    rc = omci_svc_omci_init_for_olt(olt_id);
    BCMOS_TRACE_CHECK_RETURN(rc, rc, "omci_svc_omci_init_for_olt() for olt_id=%u\n", olt_id);

    BCM_LOG(INFO, omci_svc_log_id, "OMCI SVC OLT [%d] is initialized\n", olt_id);

    return BCM_ERR_OK;
}

bcmos_errno bcmomci_svc_cfg_set(bcmonu_mgmt_cfg *cfg)
{
    switch (cfg->hdr.obj_type)
    {
    case BCMONU_MGMT_OBJ_ID_ONU:
        return omci_svc_onu_set((bcmonu_mgmt_onu_cfg *)cfg, cfg->hdr.complete_cb, cfg->hdr.context);
    case BCMONU_MGMT_OBJ_ID_FLOW:
        return omci_svc_flow_set((bcmonu_mgmt_flow_cfg *)cfg, cfg->hdr.complete_cb, cfg->hdr.context, BCMOS_FALSE);
    default:
        return BCM_ERR_NOT_SUPPORTED;
    }
    return BCM_ERR_OK;
}

bcmos_errno bcmomci_svc_cfg_get(bcmonu_mgmt_cfg *cfg)
{
    switch (cfg->hdr.obj_type)
    {
    case BCMONU_MGMT_OBJ_ID_ONU:
        return omci_svc_onu_get((bcmonu_mgmt_onu_cfg *)cfg);
    case BCMONU_MGMT_OBJ_ID_FLOW:
        return omci_svc_flow_get((bcmonu_mgmt_flow_cfg *)cfg);
    default:
        return BCM_ERR_NOT_SUPPORTED;
    }
    return BCM_ERR_OK;
}

bcmos_errno bcmomci_svc_cfg_clear(bcmonu_mgmt_cfg *cfg)
{
    switch (cfg->hdr.obj_type)
    {
    case BCMONU_MGMT_OBJ_ID_ONU:
        return omci_svc_onu_clear((bcmonu_mgmt_onu_cfg *)cfg, cfg->hdr.complete_cb, cfg->hdr.context);
    case BCMONU_MGMT_OBJ_ID_FLOW:
        return omci_svc_flow_clear((bcmonu_mgmt_flow_cfg *)cfg, cfg->hdr.complete_cb, cfg->hdr.context);
    default:
        return BCM_ERR_NOT_SUPPORTED;
    }
    return BCM_ERR_OK;
}

