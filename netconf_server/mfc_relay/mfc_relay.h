#ifndef MFC_RELAY_H_
#define MFC_RELAY_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <bcmos_system.h>
#include <bcmolt_api.h>

typedef struct mfc_relay_init_parms
{
    bcmolt_oltid olt;
#ifdef ENABLE_LOG
    bcm_dev_log_level log_level;
#endif
} mfc_relay_init_parms;

typedef struct mfc_relay_client_parms
{
    const char *endpoint_name;
    const char *local_endpoint_name;
    const char *access_point_name;
    const char *server_address;
    uint16_t port;
} mfc_relay_client_parms;

bcmos_errno bcm_mfc_relay_init(const mfc_relay_init_parms *init_config);
void bcm_mfc_relay_exit(void);

bcmos_errno bcm_mfc_relay_client_enable_disable(bcmos_bool enable);
bcmos_errno bcm_mfc_relay_client_create(const mfc_relay_client_parms *cfg);
bcmos_errno bcm_mfc_relay_client_delete(const char *endpoint_name);

typedef void (*bcmolt_mfc_connect_disconnect_cb)
    (void *data, const char *remote_endpoint_name, const char *access_point_name,
    bcmos_bool is_connected);
bcmos_errno bcm_mfc_connect_disconnect_cb_register(
    bcmolt_mfc_connect_disconnect_cb cb, void *data);

#ifdef __cplusplus
}
#endif

#endif
