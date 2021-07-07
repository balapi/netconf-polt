#include <mfc_relay_client.h>
#include <bcmcli.h>

bcmos_errno _mfc_config_ip_port(bcmcli_session *sess, const bcmcli_cmd_parm parm[], uint16_t nParms);
bcmos_errno _mfc_disconnect(bcmcli_session *sess, const bcmcli_cmd_parm parm[], uint16_t nParms);
extern tGlobMfcConfig gGlobalMfcConfig;
bcmos_errno _mfc_disconnect(bcmcli_session *sess, const bcmcli_cmd_parm parm[], uint16_t nParms)
{
    Mfc_disconnect();
    return BCM_ERR_OK;
}

bcmos_errno _mfc_config_ip_port(bcmcli_session *sess, const bcmcli_cmd_parm parm[], uint16_t nParms)
{
    bcmos_errno rc;
    strcpy(gGlobalMfcConfig.a1Ipaddress,parm[0].value.string);
    gGlobalMfcConfig.port = parm[1].value.number;
    rc = bcm_mfc_relay_start();
    if (rc != BCM_ERR_OK)
    {
        bcmos_printf("Mfc relay init failed\n");
        return rc;
    }
    return BCM_ERR_OK;
}

void
bcm_mfc_relay_cli_init ()
{
    BCMCLI_MAKE_CMD(NULL, "connect-Mfc-relay", "Run CLI script", _mfc_config_ip_port,
            BCMCLI_MAKE_PARM("ip", "Ip address of Control relay", BCMCLI_PARM_STRING, 0),
            BCMCLI_MAKE_PARM("port", "Port number", BCMCLI_PARM_NUMBER, BCMCLI_PARM_FLAG_NONE));
    BCMCLI_MAKE_CMD(NULL,"disconnect","Disconnect control-relay",_mfc_disconnect,
            BCMCLI_MAKE_PARM("Mfc-relay", " Mfc-relay", BCMCLI_PARM_STRING, 0));
    return;
}
