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

#include <bcmos_system.h>
#include <bcm_dev_log.h>
#include "omci_transport.h"
#include "omci_stack_internal.h"
#include "omci_stack_common.h"

#ifdef ENABLE_LOG
static dev_log_id omci_transport_log_id = DEV_LOG_INVALID_ID;
#endif

static bcmos_bool omci_transport_task_is_running = BCMOS_FALSE;
static bcmos_task omci_transport_task;
#define OMCI_TRANSPORT_QUEUE_SIZE  128
#define OMCI_MSG_ACK_TIMOUT_MICROSECS  5000000
/** @broef default should be 3 retries */
#define MAX_OMCI_TX_RETRIES 3
#define ONU_AUTONOMOUS_OMCI_MESSAGE_TCI_VAL  0

#define OMCI_TRANSPORT_PON_TOPO_MAX_ONUS_PER_PON      (MAX(GPON_NUM_OF_ONUS, XGPON_NUM_OF_ONUS))

/** System data base */
omci_transport_system_db omci_transport_db;

/* Get current tci value for an ONU */
#define GET_TCI(_onu_rec) (_onu_rec->tci)

/* Increment TCI in basic TCI value space to allow a mix of basic and extended mesasages for the same ONU */
#define INCREMENT_TCI(_onu_rec) \
    do \
    { \
        _onu_rec->tci++; \
        _onu_rec->tci &= OMCI_BASELINE_TCI_MASK; \
        if (_onu_rec->tci == 0) \
            _onu_rec->tci++; \
   } while (0)

#define GET_NEXT_REQ_SEQ_NUM(_onu_rec) (_onu_rec->mib_upload_next_commands_counter)

/* prototypes */
static bcmos_errno omci_transport_bcmos_timer_stop(omci_tx_msg *sent_msg);
static bcmos_errno omci_transport_bcmos_timer_start(omci_tx_msg *sent_msg);
static bcmos_errno _omci_transport_pon_init(omci_transport_pon_rec *pon_rec, uint32_t max_onus_per_pon);
static void _omci_transport_pon_deinit(omci_transport_pon_rec *pon_rec);
static void _omci_transport_onu_deinit(omci_transport_pon_rec *pon_rec, bcmolt_onu_id onu_id);

void omci_transport_increment_mib_data_sync(bcmolt_oltid olt, bcmolt_interface logical_pon, bcmolt_onu_id onu_id)
{
    omci_transport_onu_rec *onu_rec = omci_db_onu_get(olt, logical_pon, onu_id);
    if (onu_rec == NULL)
        return; /* Race condition. ONU was removed */
    ++onu_rec->mib_data_sync;
    /* Avoid setting Mib data sync to zero since it's an illegal value */
    if (!onu_rec->mib_data_sync)
        onu_rec->mib_data_sync = 1;
}

void omci_transport_reset_mib_data_sync(bcmolt_oltid olt, bcmolt_interface logical_pon, bcmolt_onu_id onu_id)
{
    omci_transport_onu_rec *onu_rec = omci_db_onu_get(olt, logical_pon, onu_id);
    if (onu_rec == NULL)
        return; /* Race condition. ONU was removed */
    onu_rec->mib_data_sync = 0;
}

static bcmos_errno onu_omci_ack_timer_create(bcmolt_oltid olt, bcmolt_interface pon, bcmolt_onu_id onu_id,
    bcmos_module_id module_id, bcmos_timer *timer, F_bcmos_timer_handler handler)
{
    bcmos_timer_parm timer_params = {};
    char timer_name[MAX_TIMER_NAME_SIZE];

    snprintf(timer_name, sizeof(timer_name), "olt%u_pon%u_onu%u_timer", olt, pon, onu_id);
    timer_params.name = timer_name;
    timer_params.owner = module_id;
    timer_params.periodic = BCMOS_FALSE;
    timer_params.handler = handler;
    return bcmos_timer_create(timer, &timer_params);
}

static void onu_omci_ack_timer_destroy(bcmos_timer *timer)
{
    bcmos_timer_destroy(timer);
}

static void omci_transport_release_sent_msg(omci_tx_msg *sent_msg)
{
    if (sent_msg->data.val)
    {
        BCM_LOG(DEBUG, omci_transport_log_id, "release OMCI sent message for OLT:%u  PON:%u  ONU:%u, TCI:0x%X\n",
                sent_msg->key.olt_id, sent_msg->key.logical_pon, sent_msg->key.onu_id,
                (sent_msg->data.val ? omci_msg_read_tci((omci_msg_hdr *)sent_msg->data.val) : 0));
        bcmos_free(sent_msg->data.val);
        sent_msg->data.val = NULL;
    }
    sent_msg->data.len = 0;
    sent_msg->sent_msg_counter = 0;
}

static bcmos_errno omci_transport_send_to_olt(omci_tx_msg *sent_msg)
{
    bcmos_errno rc = BCM_ERR_OK;

    do
    {
        BCM_LOG(DEBUG,
                omci_transport_log_id,
                "%s OMCI message to OLT %u PON %u ONU ID %u},"
                " (buf = %p, Msg len = %u, TCI = 0x%x), retry msg counter = %u, ar=%d\n",
                sent_msg->sent_msg_counter > 0 ? "Resending (after ACK timeout)" : "Sending",
                sent_msg->key.olt_id, sent_msg->key.logical_pon, sent_msg->key.onu_id,
                sent_msg->data.val, sent_msg->data.len,
                (sent_msg->data.val ? omci_msg_read_tci((omci_msg_hdr *)sent_msg->data.val) : 0),
                sent_msg->sent_msg_counter,
                sent_msg->ar);

        /* Send the OMCI packet through the broadcom svc layer adapter call to Maple proxy */
        rc = omci_init_parms.transmit_cb(&sent_msg->key, sent_msg->data.val, sent_msg->data.len);

        if (BCM_ERR_OK != rc)
        {
            BCM_LOG(ERROR,
                    omci_transport_log_id,
                    "Failed to send OMCI message to OLT %u PON %u ONU ID %u, rc=%s (Msg val = %p, len = %u)\n",
                    sent_msg->key.olt_id, sent_msg->key.logical_pon, sent_msg->key.onu_id,
                    bcmos_strerror(rc), sent_msg->data.val, sent_msg->data.len);
            break;
        }

        if (sent_msg->ar)
        {
            sent_msg->sent_msg_counter++;
            omci_transport_bcmos_timer_start(sent_msg);
        }
        else
        {
            omci_transport_release_sent_msg(sent_msg);
        }
    } while(0);

    return rc;
}

/* Report error to OMCI stack */
static void omci_transport_report_error(omci_tx_msg *sent_msg, bcmos_errno err)
{
    bcm_omci_me_hdr hdr;
    _BCM_OMCI_HDR_INIT(&hdr, sent_msg->key);
    hdr.omci_msg_type = sent_msg->omci_msg_type;
    bcm_omci_req_error(&hdr, err);
}

/* Note that this handler is already called at the context of the TX module */
static bcmos_timer_rc onu_omci_ack_timer_handler(bcmos_timer *timer, long data)
{
    omci_tx_msg *sent_msg = container_of(timer, omci_tx_msg, timer);

    BCM_LOG(INFO, omci_transport_log_id, "Retransmission: OLT %u PON %u ONU %u\n",
        sent_msg->key.olt_id, sent_msg->key.logical_pon, sent_msg->key.onu_id);

    /* check if send msg buffer is still valid */
    if (NULL == sent_msg->data.val)
    {
        BCM_LOG(WARNING, omci_transport_log_id, "%s: NULL sent_msg.val, and len = %u\n",
            __FUNCTION__, sent_msg->data.len);
        return BCMOS_TIMER_STOP;
    }

    /** @note the sent_msg_counter is already incremented before checking here. Hence check for > MAX_OMCI_TX_RETRIES */
    if (sent_msg->sent_msg_counter > MAX_OMCI_TX_RETRIES)
    {
        BCM_LOG(ERROR, omci_transport_log_id, "OMCI message max retries reached : for OLT %u PON %u ONU %d was sent %d times (max retries is %d) \n",
            sent_msg->key.olt_id, sent_msg->key.logical_pon, sent_msg->key.onu_id, sent_msg->sent_msg_counter, MAX_OMCI_TX_RETRIES);

        omci_transport_bcmos_timer_stop(sent_msg);
        omci_transport_report_error(sent_msg, BCM_ERR_TIMEOUT);
        omci_transport_release_sent_msg(sent_msg);
    }
    else
    {
        bcmos_errno rc;
        /* Retransmit */
        rc = omci_transport_send_to_olt(sent_msg);
        if (BCM_ERR_OK != rc)
        {
            /* Give up immediately. It is not going to succeed. */
            omci_transport_report_error(sent_msg, rc);
            omci_transport_release_sent_msg(sent_msg);
        }
    }

    return BCMOS_TIMER_STOP;
}

/* Initialize encoder/decoder */
static void omci_encode_decode_init(void)
{
    bcm_omci_obj_id o;
    int a;

    for (o = BCM_OMCI_OBJ_ID__BEGIN + 1; o < BCM_OMCI_OBJ_ID__NUM_OF; o++)
    {
        for (a = 0; a < me_and_attr_properties_arr[o].num_properties; a++)
        {
            bcm_omci_me_attr_prop *prop = &me_and_attr_properties_arr[o].me_attr_properties[a];
            if (prop->attr_access_type & ATTR_ACCESS_TYPE_SET_BY_CREATE)
                me_and_attr_properties_arr[o].set_by_create_mask |= (1 << a);
            if (prop->attr_access_type & ATTR_ACCESS_TYPE_WRITE)
                me_and_attr_properties_arr[o].set_mask |= (1 << a);
            if (prop->attr_present_type == ATTR_TYPE_MANDATORY)
                me_and_attr_properties_arr[o].mandatory_mask |= (1 << a);
        }
    }
}

/*
 * OMCI transport (de)initialization
 */

/* Initialize OMCI transport data base */
bcmos_errno omci_transport_init(const bcm_omci_stack_init_parms *init_parms)
{
    bcmos_module_parm module_params =
    {
        .qparm =
        {
            .name = "omci_transport_module"
        }
    };
    bcmos_task_parm task_params =
    {
        .name         = "omci_transport_task",
        .priority     = TASK_PRIORITY_OMCI_TRANSPORT,
        .core         = BCMOS_CPU_CORE_ANY /* No CPU affinity */
    };
    bcmos_errno rc;

    if (!init_parms->max_olts)
        return BCM_ERR_PARM;

#ifdef ENABLE_LOG
    if (omci_transport_log_id == DEV_LOG_INVALID_ID)
    {
        omci_transport_log_id = bcm_dev_log_id_register("OMCI_TRANSPORT", DEV_LOG_LEVEL_INFO, DEV_LOG_ID_TYPE_BOTH);
        BUG_ON(omci_transport_log_id == DEV_LOG_INVALID_ID);
    }
#endif

    if (omci_transport_db.olt_db != NULL)
        return BCM_ERR_ALREADY;

    rc = bcmos_mutex_create(&omci_transport_db.lock, 0, "omci_lock");
    if (rc != BCM_ERR_OK)
        return rc;

    omci_transport_db.olt_db = bcmos_calloc(init_parms->max_olts * sizeof(omci_transport_olt_rec));
    if (omci_transport_db.olt_db == NULL)
    {
        bcmos_mutex_destroy(&omci_transport_db.lock);
        return BCM_ERR_NOMEM;
    }

    rc = bcmos_task_create(&omci_transport_task, &task_params);
    if (rc != BCM_ERR_OK)
        goto err3;

    rc = bcmos_module_create(BCMOS_MODULE_ID_OMCI_TRANSPORT, &omci_transport_task, &module_params);
    if (rc != BCM_ERR_OK)
        goto err2;

    /* Create RX worker tasks and modules */
    if (init_parms->load_balance_policy != BCM_OMCI_LOAD_BALANCE_NONE)
    {
        uint32_t num_rx_threads = init_parms->num_rx_threads ?
            init_parms->num_rx_threads : BCM_OMCI_MAX_RX_WORKER_THREADS;
        char rx_worker_name[32];
        bcmos_task_parm rx_worker_params =
        {
            .priority     = TASK_PRIORITY_OMCI_RX_WORKER,
            .core         = BCMOS_CPU_CORE_ANY /* No CPU affinity */
        };
        bcmos_module_parm rx_worker_module_params = {};
        bcmos_msg_pool_parm rx_msg_pool_parm = {
            .name = "omci_rx",
            .size = init_parms->rx_msg_pool_size ?
                init_parms->rx_msg_pool_size : BCM_OMCI_DEFAULT_RX_MSG_POOL_SIZE,
            .data_size = sizeof(omci_rx_msg)
        };
        int t;

        if (num_rx_threads > BCM_OMCI_MAX_RX_WORKER_THREADS)
        {
            BCM_LOG(ERROR, omci_transport_log_id, "num_rx_threads is out of range 1..%d\n", BCM_OMCI_MAX_RX_WORKER_THREADS);
            rc = BCM_ERR_PARM;
            goto err1;
        }

        /* Create message pool for rx message forwarding */
        rc = bcmos_msg_pool_create(&omci_transport_db.rx_msg_pool, &rx_msg_pool_parm);
        if (rc != BCM_ERR_OK)
            goto err1;

        omci_transport_db.rx_workers = (omci_rx_worker *)bcmos_calloc(sizeof(omci_rx_worker) * num_rx_threads);
        if (omci_transport_db.rx_workers == NULL)
        {
            rc = BCM_ERR_NOMEM;
            goto err0;
        }

        /* Create rx worker tasks and modules */
        for (t = 0; t < num_rx_threads; t++)
        {
            snprintf(rx_worker_name, sizeof(rx_worker_name) - 1, "omci_rx_worker_%d", t);
            rx_worker_params.name = rx_worker_name;
            rx_worker_module_params.qparm.name = rx_worker_name;

            rc = bcmos_task_create(&omci_transport_db.rx_workers[t].task, &rx_worker_params);
            if (rc != BCM_ERR_OK)
                break;

            rc = bcmos_module_create(BCMOS_MODULE_ID_OMCI_RX_WORKER0 + t, &omci_transport_db.rx_workers[t].task,
                &rx_worker_module_params);
            if (rc != BCM_ERR_OK)
            {
                bcmos_task_destroy(&omci_transport_db.rx_workers[t].task);
                break;
            }
        }

        /* Cleanup if failed */
        if (t < num_rx_threads)
        {
            for ( --t; t >= 0; --t)
            {
                bcmos_module_destroy(BCMOS_MODULE_ID_OMCI_RX_WORKER0 + t);
                bcmos_task_destroy(&omci_transport_db.rx_workers[t].task);
            }
            bcmos_free(omci_transport_db.rx_workers);
            omci_transport_db.rx_workers = NULL;
            goto err0;
        }

        omci_transport_db.num_rx_workers = num_rx_threads;
    }

    /* Initialize encoder/decoder */
    omci_encode_decode_init();

    omci_transport_db.load_balance_policy = init_parms->load_balance_policy;
    omci_transport_task_is_running = BCMOS_TRUE;
    omci_transport_db.max_olts = init_parms->max_olts;

    return BCM_ERR_OK;
err0:
    bcmos_msg_pool_destroy(&omci_transport_db.rx_msg_pool);
err1:
    bcmos_module_destroy(BCMOS_MODULE_ID_OMCI_TRANSPORT);
err2:
    bcmos_task_destroy(&omci_transport_task);
err3:
    bcmos_free(omci_transport_db.olt_db);
    omci_transport_db.olt_db = NULL;
    bcmos_mutex_destroy(&omci_transport_db.lock);
    return rc;
}

/* De-initialize OMCI transport data base */
void omci_transport_deinit(void)
{
    int olt;
    if (omci_transport_db.olt_db == NULL)
        return;
    if (omci_transport_task_is_running)
    {
        bcmos_module_destroy(BCMOS_MODULE_ID_OMCI_TRANSPORT);
        bcmos_task_destroy(&omci_transport_task);
        omci_transport_task_is_running = BCMOS_FALSE;
    }
    for (olt = 0; olt < omci_transport_db.max_olts; olt++)
    {
        if (omci_transport_db.olt_db[olt].pon_db != NULL)
            omci_transport_olt_deinit(olt);
    }
    bcmos_free(omci_transport_db.olt_db);
    omci_transport_db.olt_db = NULL;
    omci_transport_db.max_olts = 0;

    /* Clean up load balancing support */
    if (omci_transport_db.load_balance_policy != BCM_OMCI_LOAD_BALANCE_NONE)
    {
        /* Kill RX worker threads if any */
        if (omci_transport_db.rx_workers != NULL)
        {
            int t;
            for (t = 0; t < omci_transport_db.num_rx_workers; t++)
            {
                bcmos_module_destroy(BCMOS_MODULE_ID_OMCI_RX_WORKER0 + t);
                bcmos_task_destroy(&omci_transport_db.rx_workers[t].task);
            }
            bcmos_free(omci_transport_db.rx_workers);
            omci_transport_db.rx_workers = NULL;
            omci_transport_db.num_rx_workers = 0;
        }
        bcmos_msg_pool_destroy(&omci_transport_db.rx_msg_pool);
    }

    bcmos_mutex_destroy(&omci_transport_db.lock);
}

/* Initialize OLT */
bcmos_errno omci_transport_olt_init(bcmolt_oltid olt, bcmolt_interface num_pon_ports, bcmolt_onu_id max_onus_per_pon)
{
    omci_transport_olt_rec *olt_rec;
    uint32_t pon;
    bcmos_errno rc = BCM_ERR_OK;

    if (!num_pon_ports || !max_onus_per_pon)
        return BCM_ERR_PARM;

    if (omci_transport_db.olt_db == NULL)
        return BCM_ERR_STATE;

    if (olt >= omci_transport_db.max_olts)
        return BCM_ERR_RANGE;

    bcmos_mutex_lock(&omci_transport_db.lock);
    do
    {
        if (omci_transport_db.olt_db[olt].pon_db != NULL)
        {
            rc = BCM_ERR_ALREADY;
            break;
        }

        olt_rec = &omci_transport_db.olt_db[olt];
        olt_rec->pon_db = bcmos_calloc(num_pon_ports * sizeof(omci_transport_pon_rec));
        if (olt_rec->pon_db == NULL)
        {
            rc = BCM_ERR_NOMEM;
            break;
        }

        olt_rec->max_pon_ports = num_pon_ports;
        for (pon=0; pon < num_pon_ports && rc == BCM_ERR_OK; pon++)
        {
            rc = _omci_transport_pon_init(&olt_rec->pon_db[pon], max_onus_per_pon);
        }
    } while (0);
    bcmos_mutex_unlock(&omci_transport_db.lock);

    if (rc != BCM_ERR_OK)
    {
        omci_transport_olt_deinit(olt);
        return rc;
    }

    return BCM_ERR_OK;
}

/* De-initialize OLT in OMCI transport data base */
void omci_transport_olt_deinit(bcmolt_oltid olt)
{
    omci_transport_pon_rec *pon_rec;
    bcmolt_interface pon;

    if (omci_transport_db.olt_db == NULL || olt >= omci_transport_db.max_olts)
        return;
    bcmos_mutex_lock(&omci_transport_db.lock);
    do
    {
        if (omci_transport_db.olt_db[olt].pon_db == NULL)
            break;
        for (pon=0; pon < omci_transport_db.olt_db[olt].max_pon_ports; pon++)
        {
            pon_rec = &omci_transport_db.olt_db[olt].pon_db[pon];
            _omci_transport_pon_deinit(pon_rec);
        }
        bcmos_free(omci_transport_db.olt_db[olt].pon_db);
        omci_transport_db.olt_db[olt].pon_db = NULL;
        omci_transport_db.olt_db[olt].max_pon_ports = 0;
    } while (0);
    bcmos_mutex_unlock(&omci_transport_db.lock);
}

/* Initialize PON record in OMCI transport data base */
static bcmos_errno _omci_transport_pon_init(omci_transport_pon_rec *pon_rec, uint32_t max_onus_per_pon)
{
    bcmos_errno rc;

    bcmos_mutex_lock(&omci_transport_db.lock);
    do
    {
        if (pon_rec->onu_db != NULL)
        {
            rc = BCM_ERR_ALREADY;
            break;
        }
        pon_rec->onu_db = bcmos_calloc(max_onus_per_pon * sizeof(omci_transport_pon_rec *));
        if (pon_rec->onu_db == NULL)
        {
            rc = BCM_ERR_NOMEM;
            break;
        }
        pon_rec->max_onus_per_pon = max_onus_per_pon;
        rc = BCM_ERR_OK;
    } while (0);
    bcmos_mutex_unlock(&omci_transport_db.lock);

    return rc;
}

/* Un-initialize PON record in OMCI data base */
static void _omci_transport_pon_deinit(omci_transport_pon_rec *pon_rec)
{
    bcmolt_onu_id onu_id;

    bcmos_mutex_lock(&omci_transport_db.lock);
    do
    {
        if (!pon_rec->onu_db)
            break;

        for (onu_id=0; onu_id < pon_rec->max_onus_per_pon; onu_id++)
        {
            _omci_transport_onu_deinit(pon_rec, onu_id);
        }

        bcmos_free(pon_rec->onu_db);
        pon_rec->onu_db = NULL;
        pon_rec->max_onus_per_pon = 0;
    } while (0);
    bcmos_mutex_unlock(&omci_transport_db.lock);
}

/* Un-initialize ONU record in OMCI DB */
static void _omci_transport_onu_deinit(omci_transport_pon_rec *pon_rec, bcmolt_onu_id onu_id)
{
    omci_transport_onu_rec *onu_rec;
    int m;

    if (pon_rec->onu_db==NULL)
        return;
    onu_rec = pon_rec->onu_db[onu_id];
    if (onu_rec == NULL)
        return;

    bcmos_mutex_destroy(&onu_rec->onu_lock);

    for (m = 0; m < OMCI_TL_MAX_MSGS_IN_PROGRESS; m++)
    {
        omci_tx_msg *sent_msg = &onu_rec->sent_msg[m];
        omci_transport_release_sent_msg(sent_msg);
        onu_omci_ack_timer_destroy(&sent_msg->timer);
    }

    if (onu_rec->rx_worker != NULL)
        --onu_rec->rx_worker->num_onus;

    bcmos_free(onu_rec);
    pon_rec->onu_db[onu_id] = NULL;
}


/* Assign rx_worker to onu_rec. Choose rx_worker associated with min number of ONUs */
static void _omci_transport_assign_rx_worker(omci_transport_onu_rec *onu_rec)
{
    int t;
    int min_t = 0;
    uint32_t min_onus = 0xffffffff;

    for (t = 0; t < omci_transport_db.num_rx_workers; t++)
    {
        if (omci_transport_db.rx_workers[t].num_onus < min_onus)
        {
            min_onus = omci_transport_db.rx_workers[t].num_onus;
            min_t = t;
        }
    }

    onu_rec->rx_worker = &omci_transport_db.rx_workers[min_t];
    onu_rec->rx_module = onu_rec->rx_worker->module;
    ++onu_rec->rx_worker->num_onus;
}

/* Initialize ONU on OMCI transport data base */
bcmos_errno omci_transport_onu_init(bcmolt_oltid olt, bcmolt_interface pon, bcmolt_onu_id onu_id,
    const bcm_omci_onu_init_parms *init_parms)
{
    omci_transport_pon_rec *pon_rec;
    omci_transport_onu_rec *onu_rec;
    int m;
    bcmos_errno rc = BCM_ERR_OK;

    BCM_LOG(DEBUG, omci_transport_log_id, "ONU Init: OLT %u PON %u ONU %u\n", olt, pon, onu_id);

    if (omci_transport_db.olt_db == NULL || olt >= omci_transport_db.max_olts)
        return BCM_ERR_PARM;

    bcmos_mutex_lock(&omci_transport_db.lock);
    do
    {
        if (omci_transport_db.olt_db[olt].pon_db == NULL ||
            pon >= omci_transport_db.olt_db[olt].max_pon_ports)
        {
            rc = BCM_ERR_PARM;
            break;
        }

        pon_rec = &omci_transport_db.olt_db[olt].pon_db[pon];
        if (onu_id >= pon_rec->max_onus_per_pon ||
            pon_rec->onu_db == NULL)
        {
            rc = BCM_ERR_PARM;
            break;
        }

        if (pon_rec->onu_db[onu_id] != NULL)
        {
            rc = BCM_ERR_ALREADY;
            break;
        }

        onu_rec = bcmos_calloc(sizeof(omci_transport_onu_rec));
        if (onu_rec == NULL)
        {
            rc = BCM_ERR_NOMEM;
            break;
        }

        rc = bcmos_mutex_create(&onu_rec->onu_lock, 0, "omci_onu_lock");
        if (rc != BCM_ERR_OK)
        {
            bcmos_free(onu_rec);
            break;
        }

        /* Associate rx_worker thread with the ONU */
        if (omci_transport_db.load_balance_policy == BCM_OMCI_LOAD_BALANCE_ONU &&
            init_parms->rx_module == BCMOS_MODULE_ID_NONE)
        {
            /* Assign worker thread that has minimal number of associated ONUs */
            _omci_transport_assign_rx_worker(onu_rec);
        }

        for (m = 0; m < OMCI_TL_MAX_MSGS_IN_PROGRESS; m++)
        {
            omci_tx_msg *sent_msg = &onu_rec->sent_msg[m];
            rc = onu_omci_ack_timer_create(olt, pon, onu_id,
                (onu_rec->rx_module == BCMOS_MODULE_ID_NONE) ? BCMOS_MODULE_ID_OMCI_TRANSPORT : onu_rec->rx_module,
                &sent_msg->timer, onu_omci_ack_timer_handler);
            if (BCM_ERR_OK != rc)
            {
                BCM_LOG(ERROR, omci_transport_log_id, "Failed to create OMCI ack timer for OLT %u PON %u ONU % d\n",
                    olt, pon, onu_id);
                break;
            }
        }
        if (rc != BCM_ERR_OK)
        {
            if (onu_rec->rx_worker != NULL)
                --onu_rec->rx_worker->num_onus;
            bcmos_mutex_destroy(&onu_rec->onu_lock);
            bcmos_free(onu_rec);
            break;
        }

        pon_rec->onu_db[onu_id] = onu_rec;
    } while (0);
    bcmos_mutex_unlock(&omci_transport_db.lock);

    return rc;
}

/* Un-initialize ONU in OMCI transport data base */
void omci_transport_onu_deinit(bcmolt_oltid olt, bcmolt_interface pon, bcmolt_onu_id onu_id)
{
    BCM_LOG(DEBUG, omci_transport_log_id, "ONU Deactivate on Logical PON %u, ONU Id %u\n", pon, onu_id);

    bcmos_mutex_lock(&omci_transport_db.lock);
    do
    {
        if (omci_transport_db.olt_db[olt].pon_db == NULL ||
            pon >= omci_transport_db.olt_db[olt].max_pon_ports ||
            onu_id >= omci_transport_db.olt_db[olt].pon_db[pon].max_onus_per_pon ||
            omci_transport_db.olt_db[olt].pon_db[pon].onu_db == NULL)
        {
            break;
        }
        _omci_transport_onu_deinit(&omci_transport_db.olt_db[olt].pon_db[pon], onu_id);
    } while (0);
    bcmos_mutex_unlock(&omci_transport_db.lock);
}

static void omci_build_hdr(omci_msg_hdr *omci_hdr, bcm_omci_me_hdr *me_hdr, uint16_t tci, bcmos_bool ar)
{
    uint8_t msg_type = (ar ? OMCI_MSG_TYPE_AR_FIELD_MASK : 0x00) | ((uint8_t)me_hdr->omci_msg_type & OMCI_MSG_TYPE_MT_FIELD_MASK);
    omci_hdr->tci = BCMOS_ENDIAN_CPU_TO_BIG_U16(tci);
    omci_hdr->msg_type = msg_type;
    omci_hdr->device_id = (uint8_t)me_hdr->omci_format;
    omci_hdr->me_id_class = BCMOS_ENDIAN_CPU_TO_BIG_U16(me_hdr->key.entity_class);
    omci_hdr->me_id_instance = BCMOS_ENDIAN_CPU_TO_BIG_U16(me_hdr->key.entity_instance);
}

static void omci_build_baseline_trailer(omci_msg_baseline_trailer *trailer)
{
    trailer->cpcs_uu = 0;
    trailer->cpi = 0;
    trailer->cpcs_sdu = BCMOS_ENDIAN_CPU_TO_BIG_U16(OMCI_TRAILER_CPSU_SDU_LEN);
    trailer->crc = 0;
}

bcmos_errno omci_transport_buf_alloc(uint8_t **buf, uint16_t *len, bcm_omci_msg_format omci_format)
{
    uint8_t *omci_msg;

    if (BCM_OMCI_MSG_FORMAT_EXTENDED == omci_format)
    {
        omci_msg = bcmos_calloc(sizeof(omci_msg_extended));
        *len = sizeof(omci_msg_extended) - OMCI_MSG_HDR_LEN;
    }
    else
    {
        omci_msg = bcmos_calloc(sizeof(omci_msg_baseline));
        *len = sizeof(omci_msg_baseline) - OMCI_MSG_HDR_LEN;
    }
    BCMOS_TRACE_CHECK_RETURN((omci_msg == NULL), BCM_ERR_NOMEM, "Error allocating memory for encode buffer\n");

    *buf = omci_msg + OMCI_MSG_HDR_LEN;

    return BCM_ERR_OK;
}

/* Find free seent_msg block */
static omci_tx_msg *omci_transport_get_free_sent_msg(omci_transport_onu_rec *onu_rec)
{
    int m;
    for (m = 0; m < OMCI_TL_MAX_MSGS_IN_PROGRESS; m++)
    {
        omci_tx_msg *sent_msg = &onu_rec->sent_msg[m];
        if (NULL == sent_msg->data.val)
            return sent_msg;
    }
    return NULL;
}

/* Lock ONU context against concurrent access */
static void omci_transport_onu_lock(omci_transport_onu_rec *onu_rec)
{
    bcmos_mutex_lock(&onu_rec->onu_lock);
}

/* Unlock ONU context */
static void omci_transport_onu_unlock(omci_transport_onu_rec *onu_rec)
{
    bcmos_mutex_unlock(&onu_rec->onu_lock);
}

bcmos_errno omci_transport_send_msg(bcm_omci_me_hdr *me_hdr, uint8_t *msg_content,
    uint16_t omci_payload_len, bcmos_bool request_ack)
{
    omci_msg_baseline *omci_msg;
    omci_transport_onu_rec *onu_rec;
    omci_tx_msg *sent_msg;
    bcmos_errno rc = BCM_ERR_OK;

    /** @note omci payload length can be 0 i.e. the msg just has a OMCI hdr */
    if ((NULL == msg_content))
    {
        BCM_LOG(ERROR, omci_transport_log_id, "msg_content = %p, is not correct. (omci payload length = %d)\n",
            msg_content, omci_payload_len);
        return BCM_ERR_PARM;
    }

    omci_msg = (omci_msg_baseline *)(msg_content-OMCI_MSG_HDR_LEN);

    /* ONU context must be protected against concurrent access */
    onu_rec = omci_db_onu_get_by_key(&me_hdr->key);
    if (onu_rec == NULL)
    {
        BCM_LOG(ERROR, omci_transport_log_id, "ONU doesn't exist: OLT %u PON %u ONU %u\n",
            me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id);
        bcmos_free(omci_msg);
        return BCM_ERR_PARM;
    }
    omci_transport_onu_lock(onu_rec);

    sent_msg = omci_transport_get_free_sent_msg(onu_rec);
    if (NULL == sent_msg)
    {
        BCM_LOG(ERROR, omci_transport_log_id, "request to send new omci msg, but too many previous msg not ACKed yet: {Phy PON: %u, ONU ID: %u}\n",
            me_hdr->key.logical_pon, me_hdr->key.onu_id);
        omci_transport_onu_unlock(onu_rec);
        bcmos_free(omci_msg);
        return BCM_ERR_TOO_MANY_REQS;
    }
    INCREMENT_TCI(onu_rec);
    omci_build_hdr(&omci_msg->hdr, me_hdr, GET_TCI(onu_rec),  request_ack);

    sent_msg->data.val = (uint8_t *)omci_msg; /* Mark sent_msg block as busy */

    omci_transport_onu_unlock(onu_rec);

    if (me_hdr->omci_format == BCM_OMCI_MSG_FORMAT_EXTENDED)
    {
        sent_msg->data.len = omci_payload_len + sizeof(omci_msg_hdr);
    }
    else
    {
        omci_build_baseline_trailer(&omci_msg->trailer);
        sent_msg->data.len = sizeof(*omci_msg) - OMCI_MSG_CRC_OR_MIC_LEN;
    }

    /* Keep the message so we can retransmit it in case of no ack within ack timeout*/
    sent_msg->sent_msg_counter = 0;
    sent_msg->ar = request_ack;
    sent_msg->key = me_hdr->key;
    sent_msg->omci_msg_type = me_hdr->omci_msg_type;

    BCM_LOG(DEBUG, omci_transport_log_id,
            "Send OMCI message {OLT:%u PON:%u, ONU: %u, class:%s, instance:%u, msg type:%s TCI=%u (%p)}, retry msg counter = %u\n",
            me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id,
            BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_instance,
            BCM_OMCI_MSG_TYPE_STR(me_hdr->omci_msg_type),
            omci_msg_read_tci((omci_msg_hdr *)sent_msg->data.val),
            omci_msg,
            sent_msg->sent_msg_counter);

#ifdef ENABLE_LOG
    /** dump the encoded buffer */
    bcm_omci_stack_util_dump_raw_buf(&me_hdr->key, sent_msg->data.val,
        sent_msg->data.len, omci_transport_log_id);
#endif

    rc = omci_transport_send_to_olt(sent_msg);

    return rc;
}

bcmos_errno omci_transport_send_msg_operation(bcm_omci_me_hdr *me_hdr)
{
    bcmos_errno rc;
    uint8_t *buf = NULL;
    uint16_t len = 0;

    if (BCM_OMCI_MSG_FORMAT_EXTENDED == me_hdr->omci_format)
    {
        BCM_LOG(ERROR, omci_transport_log_id, "Extended OMCI format is currently not supported\n");
        return BCM_ERR_NOT_SUPPORTED;
    }

    rc = omci_transport_buf_alloc(&buf, &len, me_hdr->omci_format);
    if (BCM_ERR_OK != rc)
    {
        return rc;
    }

    rc = omci_transport_send_msg(me_hdr, buf, OMCI_MSG_BASELINE_CONTENT_LEN, BCMOS_TRUE);

    return rc;
}

static bcmos_errno omci_transport_validate_recv_msg(bcm_omci_me_key *me_key, omci_msg_hdr *msg_hdr,
    uint16_t omci_msg_len, omci_transport_onu_rec **onu_rec_p, omci_tx_msg **sent_msg_p)
{
    omci_tx_msg *sent_msg = NULL;
    omci_transport_onu_rec *onu_rec;
    int m;

    *sent_msg_p = NULL;

    if (BCM_OMCI_MSG_FORMAT_BASE == msg_hdr->device_id)
    {
        if (omci_msg_len != sizeof(omci_msg_baseline))
        {
            BCM_LOG(ERROR, omci_transport_log_id, "Logical PON %u, ONU Id %u - Illegal RX OMCI message length. (Expected %u Bytes. Received %u Bytes)\n",
                me_key->logical_pon, me_key->onu_id, (uint32_t)sizeof(omci_msg_baseline), omci_msg_len);
            return BCM_ERR_RANGE;
        }
    }
    else if (BCM_OMCI_MSG_FORMAT_EXTENDED != msg_hdr->device_id)
    {
        BCM_LOG(ERROR, omci_transport_log_id, "Logical PON %u, ONU Id %u - unexpected OMCI message format %02x\n",
            me_key->logical_pon, me_key->onu_id, msg_hdr->device_id);
        return BCM_ERR_RANGE;
    }

    onu_rec = omci_db_onu_get_by_key(me_key);
    if (onu_rec == NULL)
    {
        BCM_LOG(ERROR, omci_transport_log_id, "Received message from unknown ONU: OLT %u PON %u ONU %u\n",
            me_key->olt_id, me_key->logical_pon, me_key->onu_id);
        return BCM_ERR_NOENT;
    }

    /* Lookup in unacknowledged message array */
    for (m = 0; m < OMCI_TL_MAX_MSGS_IN_PROGRESS; m++)
    {
        sent_msg = &onu_rec->sent_msg[m];
        if (NULL == sent_msg->data.val)
            continue;
        if ((omci_msg_read_tci(msg_hdr)) == (omci_msg_read_tci((omci_msg_hdr *)sent_msg->data.val)))
            break;
    }
    if (m >= OMCI_TL_MAX_MSGS_IN_PROGRESS)
    {
        BCM_LOG(INFO, omci_transport_log_id, "OLT %u PON %u ONU %u: couldn't find request matching ACK with TCI 0x%04X\n",
            me_key->olt_id, me_key->logical_pon, me_key->onu_id, omci_msg_read_tci(msg_hdr));
        return BCM_ERR_OUT_OF_SYNC;
    }

    /** just adding some debug dump if the omci transaction is in retry mode */
    if (sent_msg->sent_msg_counter > 1)
    {
        BCM_LOG(INFO, omci_transport_log_id, "Received OMCI msg in retry phase: OLT %u PON %u ONU %u, num times msg sent: %u \n",
            me_key->olt_id, me_key->logical_pon, me_key->onu_id, sent_msg->sent_msg_counter);
    }

    *onu_rec_p = onu_rec;
    *sent_msg_p = sent_msg;

    return BCM_ERR_OK;
}

static bcmos_errno omci_transport_validate_recv_auto_msg(bcm_omci_me_key *me_key, omci_msg_hdr *msg_hdr, uint16_t omci_msg_len,
    omci_transport_onu_rec **onu_rec_p)
{
    omci_transport_onu_rec *onu_rec;

    onu_rec = omci_db_onu_get_by_key(me_key);
    if (onu_rec == NULL)
    {
        BCM_LOG(ERROR, omci_transport_log_id, "Received message from unknown ONU: OLT %u PON %u ONU %u\n",
            me_key->olt_id, me_key->logical_pon, me_key->onu_id);
        return BCM_ERR_NOENT;
    }

    if (BCM_OMCI_MSG_FORMAT_BASE != msg_hdr->device_id)
    {
        BCM_LOG(ERROR, omci_transport_log_id, "OLT %u PON %u ONU %u: Extended OMCI format is currently not supported\n",
            me_key->olt_id, me_key->logical_pon, me_key->onu_id);
        return BCM_ERR_NOT_SUPPORTED;
    }

    if (omci_msg_len != sizeof(omci_msg_baseline))
    {
        BCM_LOG(ERROR, omci_transport_log_id, "OLT %u PON %u ONU %u: Illegal RX OMCI message length. (Expected %u Bytes. Received %u Bytes)\n",
            me_key->olt_id, me_key->logical_pon, me_key->onu_id, (uint32_t)sizeof(omci_msg_baseline), omci_msg_len);
        return BCM_ERR_RANGE;
    }
    *onu_rec_p = onu_rec;

    return BCM_ERR_OK;
}

bcmos_errno omci_transport_send_mib_upload_next_request(bcm_omci_me_hdr *me_hdr)
{
    omci_transport_onu_rec *onu_rec = omci_db_onu_get_by_key(&me_hdr->key);
    bcmos_errno rc;
    uint16_t next_cmd_seq_number;
    uint8_t *buf = NULL;
    uint16_t len = 0;

    if (onu_rec == NULL)
        return BCM_ERR_NOENT; /* Race condition. ONU was removed in the middle of MIB upload */

    if (BCM_OMCI_MSG_FORMAT_EXTENDED == me_hdr->omci_format)
    {
        BCM_LOG(ERROR, omci_transport_log_id, "Extended OMCI format is currently not supported\n");
        return BCM_ERR_NOT_SUPPORTED;
    }

    rc = omci_transport_buf_alloc(&buf, &len, me_hdr->omci_format);
    if (BCM_ERR_OK != rc)
    {
        return rc;
    }

    /* Setting the MIB upload next command sequence number as big endian */
    next_cmd_seq_number = GET_NEXT_REQ_SEQ_NUM(onu_rec);
    next_cmd_seq_number = BCMOS_ENDIAN_CPU_TO_BIG_U16(next_cmd_seq_number);
    memcpy(&buf[0], &next_cmd_seq_number, sizeof(next_cmd_seq_number));

    rc = omci_transport_send_msg(me_hdr, buf, OMCI_MSG_BASELINE_CONTENT_LEN, BCMOS_TRUE);

    return rc;
}

/** @brief stop timer and keep a flag to make sure the timer really got stopped */
static bcmos_errno omci_transport_bcmos_timer_stop(omci_tx_msg *sent_msg)
{
    bcmos_timer_stop(&sent_msg->timer);

    return BCM_ERR_OK;
}

/** @brief start timer */
static bcmos_errno omci_transport_bcmos_timer_start(omci_tx_msg *sent_msg)
{
    bcmos_timer_start(&sent_msg->timer, OMCI_MSG_ACK_TIMOUT_MICROSECS);

    return BCM_ERR_OK;
}

/* Set total number of expected MIB_UPLOAD_NEXT_RESPONSE */
void omci_transport_mib_upload_num_cmds_set(bcm_omci_me_key *me_key, uint16_t num_cmds)
{
    omci_transport_onu_rec *onu_rec = omci_db_onu_get_by_key(me_key);
    if (onu_rec)
    {
        onu_rec->num_of_mib_upload_next_commands = num_cmds;
        onu_rec->mib_upload_next_commands_counter = 0;
    }
}

/* Increment MIB_UPLOAD_NEXT response counter and return the relevant return code (MORE / LAST) */
bcm_omci_result omci_transport_mib_upload_next(bcm_omci_me_key *me_key)
{
    omci_transport_onu_rec *onu_rec = omci_db_onu_get_by_key(me_key);
    bcm_omci_result result = BCM_OMCI_RESULT_IND_MORE;

    if (onu_rec == NULL)
        return BCM_OMCI_RESULT_TL_ERROR; /* Race condition. ONU was removed during MIB upload */

    onu_rec->mib_upload_next_commands_counter++;
    if (onu_rec->num_of_mib_upload_next_commands <= onu_rec->mib_upload_next_commands_counter)
    {
        BCM_LOG(DEBUG, omci_transport_log_id, "Logical PON %u, ONU Id %u - Reached LAST: counter = %u, max =%u\n",
            me_key->logical_pon, me_key->onu_id,
            onu_rec->mib_upload_next_commands_counter,
            onu_rec->num_of_mib_upload_next_commands);

        onu_rec->mib_upload_next_commands_counter = 0;
        result = BCM_OMCI_RESULT_IND_LAST;
    }
    return result;
}

/* Handle received message in the "current" context */
static void bcm_omci_handle_rx_msg(bcm_omci_me_hdr *me_hdr, omci_msg_baseline *omci_msg, uint16_t omci_msg_len, bcmos_bool is_auto)
{
    BCM_LOG(DEBUG, omci_transport_log_id,
        "Received OMCI message {OLT:%u PON:%u ONU:%u, class: %s(%d), instance: %u, msg type: %s, recv TCI: 0x%X}\n",
        me_hdr->key.olt_id, me_hdr->key.logical_pon, me_hdr->key.onu_id,
        BCM_OMCI_ME_CLASS_VAL_STR(me_hdr->key.entity_class), me_hdr->key.entity_class,
        me_hdr->key.entity_instance, BCM_OMCI_MSG_TYPE_STR(me_hdr->omci_msg_type),
        omci_msg_read_tci(&omci_msg->hdr));

#ifdef ENABLE_LOG
    bcm_omci_stack_util_dump_raw_buf(&me_hdr->key, (uint8_t *)omci_msg,
        sizeof(*omci_msg), omci_transport_log_id);
#endif

    /* Report to ME layer */
    if (is_auto)
        bcm_omci_auto(me_hdr, omci_msg->content, OMCI_MSG_BASELINE_CONTENT_LEN);
    else
        bcm_omci_rsp(me_hdr, omci_msg->content, OMCI_MSG_BASELINE_CONTENT_LEN);
}

/* Receive message handler. Called in the target context associated with ONU */
static void bcm_omci_recv_handler(bcmos_module_id module_id, bcmos_msg *msg)
{
    omci_rx_msg *rx_msg = (omci_rx_msg *)msg->data;
    bcm_omci_handle_rx_msg(&rx_msg->me_hdr, &rx_msg->omci_msg, rx_msg->omci_msg_len, rx_msg->is_auto);
    bcmos_msg_free(msg);
}

/* Receive function called by OMCI stack integration code */
bcmos_errno bcm_omci_recv_msg(bcm_omci_me_key *me_key, void *omci_msg, uint16_t omci_msg_len)
{
    bcmos_errno rc = BCM_ERR_OK;
    bcm_omci_me_hdr me_hdr = { .key = *me_key };
    omci_msg_baseline *omci_msg_baseline_p = (omci_msg_baseline *)omci_msg;
    uint16_t tci;
    bcmos_bool is_auto;
    omci_tx_msg *sent_msg = NULL;
    omci_transport_onu_rec *onu_rec = NULL;

    tci = omci_msg_read_tci(&omci_msg_baseline_p->hdr);
    is_auto = (tci == ONU_AUTONOMOUS_OMCI_MESSAGE_TCI_VAL);
    me_hdr.key.entity_class = omci_msg_read_me_id_class(&omci_msg_baseline_p->hdr);
    me_hdr.key.entity_instance = omci_msg_read_me_id_instance(&omci_msg_baseline_p->hdr);
    me_hdr.obj_type = bcm_omci_me_class_val2bcm_omci_obj_id_conv(me_hdr.key.entity_class);
    me_hdr.omci_format = (BCM_OMCI_MSG_FORMAT_BASE == omci_msg_baseline_p->hdr.device_id) ?
        BCM_OMCI_MSG_FORMAT_BASE : BCM_OMCI_MSG_FORMAT_EXTENDED;
    me_hdr.omci_msg_type = omci_msg_read_msg_type(&omci_msg_baseline_p->hdr);
    me_hdr.dir = is_auto ? BCM_OMCI_OBJ_MSG_DIR_REQUEST : BCM_OMCI_OBJ_MSG_DIR_RESPONSE;

    if (is_auto)
    {
        rc = omci_transport_validate_recv_auto_msg(&me_hdr.key, &omci_msg_baseline_p->hdr, omci_msg_len, &onu_rec);
        if (BCM_ERR_OK != rc)
        {
            return rc;
        }
        me_hdr.key.cookie = 0;
    }
    else
    {
        rc = omci_transport_validate_recv_msg(&me_hdr.key, &omci_msg_baseline_p->hdr, omci_msg_len, &onu_rec, &sent_msg);
        if (BCM_ERR_OK != rc)
        {
            return rc;
        }
        me_hdr.key.cookie = sent_msg->key.cookie;
        omci_transport_bcmos_timer_stop(sent_msg);
        omci_transport_release_sent_msg(sent_msg);
    }

    /* Forward to RX task if necessary */
    if (onu_rec->rx_module)
    {
        bcmos_msg *os_msg = bcmos_msg_pool_alloc(&omci_transport_db.rx_msg_pool);
        omci_rx_msg *rx_msg;
        /* If rx msg pool is exhausted - handle message in this context */
        if (os_msg == NULL)
        {
            BCM_LOG(ERROR, omci_transport_log_id, "RX msg pool is empty. Can't forward message from OLT:%u PON:%u ONU:%u\n",
                me_hdr.key.olt_id, me_hdr.key.logical_pon, me_hdr.key.onu_id);
            bcm_omci_handle_rx_msg(&me_hdr, omci_msg_baseline_p, omci_msg_len, is_auto);
            return BCM_ERR_OK;
        }

        /* Forward to the module associated with ONU */
        os_msg->handler = bcm_omci_recv_handler;
        rx_msg = (omci_rx_msg *)os_msg->data;
        rx_msg->is_auto = is_auto;
        rx_msg->me_hdr = me_hdr;
        rx_msg->omci_msg_len = omci_msg_len;
        rx_msg->omci_msg = *omci_msg_baseline_p;
        bcmos_msg_send_to_module(onu_rec->rx_module, os_msg, BCMOS_MSG_SEND_AUTO_FREE);
    }
    else
    {
        /* Handle in this context */
        bcm_omci_handle_rx_msg(&me_hdr, omci_msg_baseline_p, omci_msg_len, is_auto);
    }

    return BCM_ERR_OK;
}

