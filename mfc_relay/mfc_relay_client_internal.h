#ifndef MFC_RELAY_H_
#define MFC_RELAY_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <bcmos_system.h>
#include <bcmolt_api.h>
bcmos_errno bcm_mfc_relay_init(int olt);
bcmos_errno
    bcm_mfc_relay_start ();
bcmos_errno
    bcm_mfc_relay_stop ();
bcmos_errno Mfc_disconnect();
typedef void (*bcm_mfc_grpc_client_connect_disconnect_cb)
    (void *data, const char *remote_endpoint_name, const char *access_point_name, bcmos_bool is_connected);
    typedef struct globalMfc {
        char a1Ipaddress[50];
        char EndpointName [50];
        char AccessName[50];
        char DeviceName[50];
        unsigned int port;
        bool bIsStarted;
    }tGlobMfcConfig;
bcmos_errno
bcm_mfc_grpc_client_connect_disconnect_cb_register  (bcm_mfc_grpc_client_connect_disconnect_cb cb, void *data);
bcmos_errno bcm_mfc_grpc_client_delete (const char * endpoint_name);
bcmos_errno
bcm_mfc_grpc_client_edit_config (const char * endpoint_name, const char * access_point_name,uint16_t
                        port,const char * host_name);
bcmos_errno bcm_mfc_grpc_client_enable_disable(bcmos_bool enable);

#ifdef __cplusplus
}
#endif
#endif
