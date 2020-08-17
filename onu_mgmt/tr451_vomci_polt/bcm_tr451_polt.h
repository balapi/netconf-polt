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
 * bcm_tr451_polt.h
 */

#ifndef BCM_TR451_POLT_H_
#define BCM_TR451_POLT_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <bcmos_system.h>
#include <bcmcli.h>
#include <bcm_dev_log.h>

typedef enum
{
   TR451_FILTER_TYPE_ANY,
   TR451_FILTER_TYPE_VENDOR_ID,
   TR451_FILTER_TYPE_SERIAL_NUMBER
} tr451_polt_filter_type;

typedef struct tr451_endpoint
{
   const char *name;
   const char *host_name;
   uint16_t port;

   /* The following field is for internal use */
   STAILQ_ENTRY(tr451_endpoint) next;
} tr451_endpoint;

/* Server endpoint */
typedef struct tr451_server_endpoint
{
   tr451_endpoint endpoint;
} tr451_server_endpoint;

/* Client endpoint */
typedef struct tr451_client_endpoint
{
   const char *name;
   STAILQ_HEAD(, tr451_endpoint) entry_list; /* Client attempts connecting to the entries 1-by-1 untilll successful */
} tr451_client_endpoint;

typedef struct tr451_polt_filter
{
   const char *name;
   tr451_polt_filter_type type;
   uint16_t priority;
   uint8_t serial_number[8];
} tr451_polt_filter;

typedef struct tr451_polt_init_parms
{
   const char *polt_name;
   bcm_dev_log_level log_level;
} tr451_polt_init_parms;

bcmos_errno bcm_tr451_polt_init(const tr451_polt_init_parms *init_parms);

typedef void (*bcm_tr451_polt_grpc_server_connect_disconnect_cb)
   (void *data, const char *server_name, const char *client_name, bcmos_bool is_connected);
typedef void (*bcm_tr451_polt_grpc_client_connect_disconnect_cb)
   (void *data, const char *remote_endpoint_name, const char *access_point_name, bcmos_bool is_connected);

tr451_client_endpoint *bcm_tr451_client_endpoint_alloc(const char *name);
bcmos_errno bcm_tr451_client_endpoint_add_entry(tr451_client_endpoint *ep, const tr451_endpoint *entry);
void bcm_tr451_client_endpoint_free(tr451_client_endpoint *ep);

/* Authentication */
bcmos_errno bcm_tr451_auth_set(const char *priv_key_file, const char *my_cert_file, const char *peer_cert_file);
bcmos_errno bcm_tr451_auth_get(const char **p_priv_key_file, const char **p_my_cert_file, const char **p_peer_cert_file);

/* Server interface */
bcmos_errno bcm_tr451_polt_grpc_server_init(void);
bcmos_errno bcm_tr451_polt_grpc_server_enable_disable(bcmos_bool is_enabled);
bcmos_errno bcm_tr451_polt_grpc_server_create(const tr451_server_endpoint *endpoint);
bcmos_errno bcm_tr451_polt_grpc_server_start(const char *endpoint_name);
bcmos_errno bcm_tr451_polt_grpc_server_stop(const char *endpoint_name);
bcmos_errno bcm_tr451_polt_grpc_server_delete(const char *endpoint_name);
const char *bcm_tr451_polt_grpc_server_client_get_next(const char *prev);
bcmos_errno bcm_tr451_polt_grpc_server_connect_disconnect_cb_register(
   bcm_tr451_polt_grpc_server_connect_disconnect_cb cb, void *data);

bcmos_errno bcm_tr451_polt_grpc_server_filter_set(const tr451_polt_filter *filter, const char *endpoint_name);
bcmos_errno bcm_tr451_polt_grpc_server_filter_get(const char *filter_name, tr451_polt_filter *filter);
bcmos_errno bcm_tr451_polt_grpc_server_filter_delete(const char *filter_name);
void bcm_tr451_polt_grpc_server_shutdown(void);

/* Client interface */
bcmos_errno bcm_tr451_polt_grpc_client_init(void);
bcmos_errno bcm_tr451_polt_grpc_client_enable_disable(bcmos_bool is_enabled);
bcmos_errno bcm_tr451_polt_grpc_client_create(const tr451_client_endpoint *endpoint);
bcmos_errno bcm_tr451_polt_grpc_client_start(const char *endpoint_name);
bcmos_errno bcm_tr451_polt_grpc_client_stop(const char *endpoint_name);
bcmos_errno bcm_tr451_polt_grpc_client_delete(const char *endpoint_name);
bcmos_errno bcm_tr451_polt_grpc_client_connect_disconnect_cb_register(
   bcm_tr451_polt_grpc_client_connect_disconnect_cb cb, void *data);

bcmos_errno bcm_tr451_polt_grpc_client_filter_set(const tr451_polt_filter *filter, const char *endpoint_name);
bcmos_errno bcm_tr451_polt_grpc_client_filter_get(const char *filter_name, tr451_polt_filter *filter);
bcmos_errno bcm_tr451_polt_grpc_client_filter_delete(const char *filter_name);

/* callback for ONU status change reporting */
typedef bcmos_errno (*xpon_v_ani_state_change_report_cb)(const char *cterm_name, uint16_t onu_id,
    const uint8_t *serial_number, bcmos_bool is_present, bcmos_bool is_active);
bcmos_errno bcm_tr451_onu_state_change_notify_cb_register(xpon_v_ani_state_change_report_cb cb);

void bcm_tr451_polt_cli_init(void);

#ifdef __cplusplus
}
#endif

/* Include vendor-specific services that can be used for integration with vendor's NETCONF server */
#include <tr451_polt_vendor_specific.h>

#endif /* BCM_DOLT_H_ */
