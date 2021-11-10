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
#include <onu_mgmt_model_funcs.h>
#include <onu_mgmt_test.h>
#include <omci_svc.h>
#ifdef ONU_MGMT_DPOE_SVC
#include <dpoe2_svc.h>
#endif
#include "onu_mgmt.h"

#define CONFIG_FILE_NAME "onu_mgmt_config.ini"

#define BCMONU_MGMT_IS_INITIALIZED()\
{\
    BCMOS_TRACE_CHECK_RETURN( \
            onu_mgmt_context.state != ONU_MGMT_STATE_INITIALIZED, \
	        BCM_ERR_STATE, \
	        "ONU Mgmt is not initialized\n");\
}

#define BCMONU_MGMT_OLT_IS_READY(olt_id)\
{\
    BCMOS_TRACE_CHECK_RETURN( \
            olt_id >= BCM_MAX_OLTS, \
	        BCM_ERR_RANGE, \
	        "ONU Mgmt OLT id [%d] exceeds range\n", olt_id);\
 \
    BCMOS_TRACE_CHECK_RETURN( \
            onu_mgmt_context.olt_state[olt_id] != ONU_MGMT_STATE_OLT_READY, \
	        BCM_ERR_STATE, \
	        "ONU Mgmt OLT is not Ready\n");\
}

static const char *onu_mgmt_svc_name[BCM_ONU_MGMT_SVC__COUNT] =
{
    [BCM_ONU_MGMT_SVC_OMCI] = "omci",
    [BCM_ONU_MGMT_SVC_DPOE2] = "oam_dpoe2",
    [BCM_ONU_MGMT_SVC_CTC3] = "oam_ctc3"
};


/** @brief control block for ONU Mgmt */
onu_mgmt_context_t onu_mgmt_context;

#ifdef ENABLE_LOG
dev_log_id onu_mgmt_log_id = DEV_LOG_INVALID_ID;
#endif

/** @brief stores OLT ID that ONU_Mgmt is associated with.
  * It is passed in by OLT Agent when it calls ONU Mgmt init.
  */
uint8_t onu_mgmt_my_olt_id = 0;


static void onu_mgmt_onu_state_changed_notify(bcmonu_mgmt_onu_key *key)
{
    onu_mgmt_notify_entity *iter;

    SLIST_FOREACH(iter, &onu_mgmt_context.onu_notify_entities, next)
    {
        bcmonu_mgmt_onu_cfg onu;

        BCMONU_MGMT_CFG_INIT(&onu, onu, *key);
        /** @note CFG_INIT by default sets presence mask to 0 which means "all properties" */
        /** @todo pass in olt_id or deprecate that and pass olt_id in key, in future */
        bcmonu_mgmt_cfg_get(0, &onu.hdr);
        iter->cb(&onu.hdr);
    }
}

#ifdef ONU_MGMT_DPOE_SVC
static void onu_mgmt_flow_state_changed_notify(bcmonu_mgmt_flow_key *key)
{
    onu_mgmt_notify_entity *iter;

    SLIST_FOREACH(iter, &onu_mgmt_context.flow_notify_entities, next)
    {
        bcmonu_mgmt_flow_cfg flow;

        BCMONU_MGMT_CFG_INIT(&flow, flow, *key);
        /** @note CFG_INIT by default sets presence mask to 0 which means "all properties" */
        /** @todo pass in olt_id or deprecate that and pass olt_id in key, in future */
        bcmonu_mgmt_cfg_get(0, &flow.hdr);
        iter->cb(&flow.hdr);
    }
}
#endif

static void onu_mgmt_config_line_handle(char *name, char *value)
{
    BCM_LOG(INFO, onu_mgmt_log_id, "%s=%s\n", name, value);

    /* parse entry */
    if (strcmp(name, "onu_mgmt_svc") == 0)
    {
        bcm_onu_mgmt_svc svc;
        for (svc = 0; svc < BCM_ONU_MGMT_SVC__COUNT; ++svc)
        {
            if (strcmp(value, onu_mgmt_svc_name[svc]) == 0)
            {
                break;
            }
        }
        if (svc < BCM_ONU_MGMT_SVC__COUNT)
        {
            onu_mgmt_context.onu_mgmt_svc = svc;
        }
        else
        {
            BCM_LOG(ERROR, onu_mgmt_log_id, "%s is not a valid value for %s\n", value, name);
        }
    }
    else
    {
        BCM_LOG(ERROR, onu_mgmt_log_id, "%s/%s: Unknown name/value config file pair!\n",name, value);
    }
}

static void onu_mgmt_log_config(void)
{
    if (onu_mgmt_context.onu_mgmt_svc < BCM_ONU_MGMT_SVC__COUNT)
    {
        BCM_LOG(INFO, onu_mgmt_log_id, "\tonu_mgmt_svc = %s\n", onu_mgmt_svc_name[onu_mgmt_context.onu_mgmt_svc]);
    }
    else
    {
        BCM_LOG(ERROR, onu_mgmt_log_id, "\tNo valid default for onu_mgmt_svc (%d)\n", onu_mgmt_context.onu_mgmt_svc);
    }
}

/** @brief A function that reads onu mgmt config file */
static void onu_mgmt_parse_config(void)
{
    FILE *fp = fopen(CONFIG_FILE_NAME, "r");

    if (fp == NULL)
    {
        BCM_LOG(INFO, onu_mgmt_log_id, "No config file (%s) found, using defaults:\n", CONFIG_FILE_NAME);
        onu_mgmt_log_config();
        return;
    }

    BCM_LOG(INFO, onu_mgmt_log_id, "ONU Mgmt configuration params as read from %s:\n", CONFIG_FILE_NAME);

    onu_mgmt_util_parse_config(fp, onu_mgmt_config_line_handle);

    BCM_LOG(INFO, onu_mgmt_log_id, "\n");

    /* Close file */
    fclose(fp);
}

bcmos_errno bcmonu_mgmt_init(bcmos_module_id module_id, int is_issu)
{
    bcmos_errno rc;
    uint16_t o;

#ifdef ENABLE_LOG
    if (onu_mgmt_log_id == DEV_LOG_INVALID_ID)
    {
        onu_mgmt_log_id = bcm_dev_log_id_register("onu_mgmt", DEV_LOG_LEVEL_INFO, DEV_LOG_ID_TYPE_BOTH);
        BUG_ON(onu_mgmt_log_id == DEV_LOG_INVALID_ID);
    }
#endif

    if (onu_mgmt_context.state != ONU_MGMT_STATE_UNINITIALIZED)
    {
        BCM_LOG(WARNING, onu_mgmt_log_id, "ONU Mgmt is already initialized\n");
        return BCM_ERR_STATE;
    }

    if (module_id == BCMOS_MODULE_ID_NONE)
    {
        BCM_LOG(ERROR, onu_mgmt_log_id, "ONU Mgmt: Invalid module ID\n");
        return BCM_ERR_PARM;
    }

    if (is_issu)
    {
        BCM_LOG(INFO, onu_mgmt_log_id, "ONU Mgmt: issu=%d\n", is_issu);
        BCM_LOG(INFO, onu_mgmt_log_id, "ONU Mgmt: Note issu is just a stub mode of warm restart of ONU mgmt module\n");
    }

    onu_mgmt_context.module_id = module_id;
    SLIST_INIT(&onu_mgmt_context.onu_notify_entities);
    SLIST_INIT(&onu_mgmt_context.flow_notify_entities);

    /* default to OMCI */
    onu_mgmt_context.onu_mgmt_svc = BCM_ONU_MGMT_SVC_OMCI;
    onu_mgmt_parse_config();

    switch (onu_mgmt_context.onu_mgmt_svc)
    {
    case BCM_ONU_MGMT_SVC_OMCI:
        rc = omci_svc_init(onu_mgmt_onu_state_changed_notify, is_issu);
        BCMOS_RETURN_IF_ERROR(rc);
        break;
#ifdef ONU_MGMT_DPOE_SVC
    case BCM_ONU_MGMT_SVC_DPOE2:
        rc = bcm_dpoe2_svc_init(onu_mgmt_onu_state_changed_notify, onu_mgmt_flow_state_changed_notify);
        BCMOS_RETURN_IF_ERROR(rc);
        break;
    case BCM_ONU_MGMT_SVC_CTC3:
        /* TODO: init CTC 3.0 service layer */
        return BCM_ERR_NOT_SUPPORTED;
#endif
    default:
        return BCM_ERR_NOT_SUPPORTED;
    }

    /* init individual olt states to down */
    for (o=0; o<BCM_MAX_OLTS; o++)
    {
        onu_mgmt_context.olt_state[o] = ONU_MGMT_STATE_OLT_DOWN;
    }

    onu_mgmt_context.state = ONU_MGMT_STATE_INITIALIZED;
    BCM_LOG(INFO, onu_mgmt_log_id, "ONU Mgmt is initialized\n");

    return BCM_ERR_OK;
}

bcmos_errno bcmonu_mgmt_deinit(bcmos_module_id module_id)
{
    bcmos_errno rc;
    uint16_t o;

    if (onu_mgmt_context.state != ONU_MGMT_STATE_INITIALIZED)
    {
        BCM_LOG(ERROR, onu_mgmt_log_id, "ONU Mgmt is not in INITIALIZED state \n");
        return BCM_ERR_STATE;
    }

    switch (onu_mgmt_context.onu_mgmt_svc)
    {
    case BCM_ONU_MGMT_SVC_OMCI:
        rc = omci_svc_deinit();
        BCMOS_RETURN_IF_ERROR(rc);
        break;
#ifdef ONU_MGMT_DPOE_SVC
    case BCM_ONU_MGMT_SVC_DPOE2:
        rc = bcm_dpoe2_svc_deinit();
        BCMOS_RETURN_IF_ERROR(rc);
        break;
    case BCM_ONU_MGMT_SVC_CTC3:
        /* TODO: deinit CTC 3.0 service layer */
        return BCM_ERR_NOT_SUPPORTED;
#endif
    default:
        return BCM_ERR_NOT_SUPPORTED;
    }

    for (o=0; o<BCM_MAX_OLTS; o++)
    {
        onu_mgmt_context.olt_state[o] = ONU_MGMT_STATE_UNINITIALIZED;
    }

    onu_mgmt_context.state = ONU_MGMT_STATE_UNINITIALIZED;

    BCM_LOG(INFO, onu_mgmt_log_id, "ONU Mgmt is now de-initialized\n");

    return BCM_ERR_OK;
}

bcmos_errno bcmonu_mgmt_olt_init(bcmolt_oltid olt_id)
{
    bcmos_errno rc;

    /** Test utility */
    olt_id = ONU_MGMT_TEST_SET_TEST_OLT_ID(olt_id);

    if (onu_mgmt_context.state != ONU_MGMT_STATE_INITIALIZED)
    {
        BCM_LOG(ERROR, onu_mgmt_log_id, "ONU Mgmt is not initialized\n");
        return BCM_ERR_STATE;
    }

    if (onu_mgmt_context.olt_state[olt_id] == ONU_MGMT_STATE_OLT_READY)
    {
        BCM_LOG(ERROR, onu_mgmt_log_id, "ONU Mgmt OLT [%d] is already initialized\n", olt_id);
        return BCM_ERR_STATE;
    }

    switch (onu_mgmt_context.onu_mgmt_svc)
    {
    case BCM_ONU_MGMT_SVC_OMCI:
        rc = omci_svc_olt_init(olt_id);
        BCMOS_RETURN_IF_ERROR(rc);
    break;

#ifdef ONU_MGMT_DPOE_SVC
    case BCM_ONU_MGMT_SVC_DPOE2:
        rc = bcm_dpoe2_svc_olt_init(olt_id);
        BCMOS_RETURN_IF_ERROR(rc);
    break;

    case BCM_ONU_MGMT_SVC_CTC3:
        /* TODO: CTC 3.0 service layer OLT init */
        return BCM_ERR_NOT_SUPPORTED;
#endif

    default:
        return BCM_ERR_NOT_SUPPORTED;
    }

    onu_mgmt_context.olt_state[olt_id] = ONU_MGMT_STATE_OLT_READY;
    BCM_LOG(INFO, onu_mgmt_log_id, "ONU Mgmt OLT [%d] is initialized\n", olt_id);

    return BCM_ERR_OK;
}

bcmos_errno bcmonu_mgmt_cfg_set(bcmolt_oltid olt_id, bcmonu_mgmt_cfg *cfg)
{
    /** test utility */
    olt_id = ONU_MGMT_TEST_SET_TEST_OLT_ID(olt_id);

    BCMONU_MGMT_IS_INITIALIZED();
    BCMONU_MGMT_OLT_IS_READY(olt_id);

    cfg->hdr.type = BCMONU_MGMT_MSG_TYPE_SET;
    cfg->hdr.olt_id = olt_id;

    switch (onu_mgmt_context.onu_mgmt_svc)
    {
    case BCM_ONU_MGMT_SVC_OMCI:
        return bcmomci_svc_cfg_set(cfg);
#ifdef ONU_MGMT_DPOE_SVC
    case BCM_ONU_MGMT_SVC_DPOE2:
        return bcm_dpoe2_svc_cfg_set(cfg);
    case BCM_ONU_MGMT_SVC_CTC3:
        /* TODO: call CTC 3.0 service layer cfg set */
        return BCM_ERR_NOT_SUPPORTED;
#endif
    default:
        return BCM_ERR_NOT_SUPPORTED;
    }
}

bcmos_errno bcmonu_mgmt_cfg_get(bcmolt_oltid olt_id, bcmonu_mgmt_cfg *cfg)
{
    /** test utility */
    olt_id = ONU_MGMT_TEST_SET_TEST_OLT_ID(olt_id);

    BCMONU_MGMT_IS_INITIALIZED();
    BCMONU_MGMT_OLT_IS_READY(olt_id);

    cfg->hdr.type = BCMONU_MGMT_MSG_TYPE_GET;
    cfg->hdr.dir = BCMONU_MGMT_MSG_DIR_RESPONSE; /* This is to allow bcmonu_mgmt_apicli_msg_dump() to work on a GET request. */
    cfg->hdr.olt_id = olt_id;

    switch (onu_mgmt_context.onu_mgmt_svc)
    {
    case BCM_ONU_MGMT_SVC_OMCI:
        return bcmomci_svc_cfg_get(cfg);
#ifdef ONU_MGMT_DPOE_SVC
    case BCM_ONU_MGMT_SVC_DPOE2:
        return bcm_dpoe2_svc_cfg_get(cfg);
    case BCM_ONU_MGMT_SVC_CTC3:
        /* TODO: call CTC 3.0 service layer cfg get */
        return BCM_ERR_NOT_SUPPORTED;
#endif
    default:
        return BCM_ERR_NOT_SUPPORTED;
    }
}

bcmos_errno bcmonu_mgmt_cfg_clear(bcmolt_oltid olt_id, bcmonu_mgmt_cfg *cfg)
{
    /** test utility */
    olt_id = ONU_MGMT_TEST_SET_TEST_OLT_ID(olt_id);

    BCMONU_MGMT_IS_INITIALIZED();
    BCMONU_MGMT_OLT_IS_READY(olt_id);

    /** @todo pass on olt_id to sub calls */
    cfg->hdr.type = BCMONU_MGMT_MSG_TYPE_CLEAR;
    cfg->hdr.dir = BCMONU_MGMT_MSG_DIR_RESPONSE; /* This is to allow bcmonu_mgmt_apicli_msg_dump() to work on a CLEAR request. */
    cfg->hdr.olt_id = olt_id;

    switch (onu_mgmt_context.onu_mgmt_svc)
    {
    case BCM_ONU_MGMT_SVC_OMCI:
        return bcmomci_svc_cfg_clear(cfg);
#ifdef ONU_MGMT_DPOE_SVC
    case BCM_ONU_MGMT_SVC_DPOE2:
        return bcm_dpoe2_svc_cfg_clear(cfg);
    case BCM_ONU_MGMT_SVC_CTC3:
        /* TODO: call CTC 3.0 service layer cfg get */
        return BCM_ERR_NOT_SUPPORTED;
#endif
    default:
        return BCM_ERR_NOT_SUPPORTED;
    }
}

/** @todo multi cfg get is not supported for ONU Mgmt for now */
bcmos_errno bcmonu_mgmt_multi_cfg_get(bcmolt_oltid olt_id, bcmonu_mgmt_multi_cfg *cfg, bcmonu_mgmt_filter_flags filter_flags)
{
    return BCM_ERR_NOT_SUPPORTED;
}

bcmos_bool bcmonu_mgmt_is_loopback(void)
{
    return onu_mgmt_context.is_loopback;
}

void bcmonu_mgmt_set_loopback(bcmos_bool is_loopback)
{
    onu_mgmt_context.is_loopback = is_loopback;
}

bcm_onu_mgmt_svc bcmonu_mgmt_svc_get(void)
{
    return onu_mgmt_context.onu_mgmt_svc;
}

bcmos_errno bcmonu_mgmt_onu_notify_register(onu_mgmt_notify_cb cb)
{
    onu_mgmt_notify_entity *notify_entity;

    notify_entity = bcmos_calloc(sizeof(*notify_entity));
    if (!notify_entity)
    {
        BCM_LOG(ERROR, onu_mgmt_log_id, "Memory allocation failed (sizeof=%u)\n", (uint32_t)sizeof(*notify_entity));
        return BCM_ERR_NOMEM;
    }
    notify_entity->cb = cb;
    SLIST_INSERT_HEAD(&onu_mgmt_context.onu_notify_entities, notify_entity, next);

    return BCM_ERR_OK;
}

void bcmonu_mgmt_onu_notify_unregister(onu_mgmt_notify_cb cb)
{
    onu_mgmt_notify_entity *iter, *tmp;

    SLIST_FOREACH_SAFE(iter, &onu_mgmt_context.onu_notify_entities, next, tmp)
    {
        if (iter->cb == cb)
        {
            SLIST_REMOVE(&onu_mgmt_context.onu_notify_entities, iter, onu_mgmt_notify_entity, next);
            bcmos_free(iter);
            return;
        }
    }
}

bcmos_errno bcmonu_mgmt_flow_notify_register(onu_mgmt_notify_cb cb)
{
    onu_mgmt_notify_entity *notify_entity;

    notify_entity = bcmos_calloc(sizeof(*notify_entity));
    if (!notify_entity)
    {
        BCM_LOG(ERROR, onu_mgmt_log_id, "Memory allocation failed (sizeof=%u)\n", (uint32_t)sizeof(*notify_entity));
        return BCM_ERR_NOMEM;
    }
    notify_entity->cb = cb;
    SLIST_INSERT_HEAD(&onu_mgmt_context.flow_notify_entities, notify_entity, next);

    return BCM_ERR_OK;
}

void bcmonu_mgmt_flow_notify_unregister(onu_mgmt_notify_cb cb)
{
    onu_mgmt_notify_entity *iter, *tmp;

    SLIST_FOREACH_SAFE(iter, &onu_mgmt_context.flow_notify_entities, next, tmp)
    {
        if (iter->cb == cb)
        {
            SLIST_REMOVE(&onu_mgmt_context.flow_notify_entities, iter, onu_mgmt_notify_entity, next);
            bcmos_free(iter);
            return;
        }
    }
}



/************************************************************************************
  Extra adaptations needed to build onu mgmt in Aspen tree.
************************************************************************************/

#define MAX_CONFIG_FILE_LINE_LEN 256
#define MAX_CONFIG_PARAM_NAME_LEN 64
#define MAX_CONFIG_PARAM_VALUE_LEN 64

/**
 * @brief A trim helper function
 *
 *  This function is used to get rid of trailing and leading whitespace
 *  including the "\n" from fgets()
 *
 * @param s   A pointer to the string that is to be trimmed
 *
 * @returns -char *, the trimmed sting
 *
 */
static char *trim (char * s)
{
    /* Initialize start, end pointers */
    int len = strlen(s);
    char *s1 = s, *s2 = &s[len - 1];

    /* Trim and delimit right side */
    while ( (isspace (*s2)) && (s2 >= s1) )
    {
        s2--;
        len--;
    }

    *(s2+1) = '\0';

    /* Trim left side */
    while ( (isspace (*s1)) && (s1 < s2) )
    {
        s1++;
        len--;
    }

    /* Copy finished string. Use memmove, as it is guaranteed to correctly handle overlapping strings. */
    memmove (s, s1, len + 1);
    return s;
}



void onu_mgmt_util_parse_config(FILE *fp, config_line_cb line_cb)
{
    char *s, buff[MAX_CONFIG_FILE_LINE_LEN];
    char name[MAX_CONFIG_PARAM_NAME_LEN], value[MAX_CONFIG_PARAM_VALUE_LEN];

    /* Read next line */
    while ((s = fgets(buff, sizeof buff, fp)) != NULL)
    {
        /* Skip blank lines and comments */
        if (buff[0] == '\n' || buff[0] == '#')
            continue;

        /* Parse name/value pair from line */
        s = strtok(buff, "=");
        if (s == NULL)
        {
            continue;
        }
        else
        {
            strncpy(name, s, MAX_CONFIG_PARAM_NAME_LEN);
        }

        s = strtok(NULL, "=");

        if (s == NULL)
        {
            continue;
        }
        else
        {
            strncpy(value, s, MAX_CONFIG_PARAM_VALUE_LEN);
        }

        trim(value);

        line_cb(name, value);
    } /* while */
}
