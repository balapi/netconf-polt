
#include <mfc_relay.h>
#include <mfc_relay_internal.h>
#include <bcmolt_netconf_constants.h>

/* Debug Trace */
dev_log_id log_id_mfc_relay;

bcmolt_mfc_connect_disconnect_cb mfc_conn_discon_cb;
void *mfc_conn_discon_cb_data;

static mfc_relay_init_parms mfc_init_config;
static STAILQ_HEAD(, MfcRelay) mfc_relay_list;

static int _client_tx_to_cp_task_handler(long data);

MfcRelay::MfcRelay(const char *endpoint_name) : endpoint_name_(endpoint_name)
{
    bcmos_errno err;

    STAILQ_INIT(&mfc_ind_list_);
    err = bcmos_mutex_create(&mfc_ind_lock_, 0, "mfc_ind");
    BUG_ON(err != BCM_ERR_OK);
    err = bcmos_sem_create(&mfc_ind_sem_, 0, 0, "mfc_ind");
    BUG_ON(err != BCM_ERR_OK);

    /* Create task that listens for indications from the OLT and forwards to the cp */
    bcmos_task_parm tp = {};
    tp.name = "tx_to_cp";
    tp.priority = TASK_PRIORITY_TRANSPORT_PROXY;
    tp.handler = _client_tx_to_cp_task_handler;
    tp.data = (long)this;
    err = bcmos_task_create(&tx_to_cp_task_, &tp);
    if (err != BCM_ERR_OK)
    {
        MFC_LOG_ERR("Couldn't create tx_to_cp task. Error '%s'\n", bcmos_strerror(err));
        BUG();
    }
    STAILQ_INSERT_TAIL(&mfc_relay_list, this, next);
}

MfcRelay::~MfcRelay()
{
    MfcPacketEntry *pkt;
    STAILQ_REMOVE_SAFE(&mfc_relay_list, this, MfcRelay, next);
    while ((pkt=pop_olt_packet()) != nullptr)
        delete pkt;
    bcmos_sem_destroy(&mfc_ind_sem_);
    bcmos_mutex_destroy(&mfc_ind_lock_);
    bcmos_task_destroy(&tx_to_cp_task_);
}

MfcPacketEntry *MfcRelay::pop_olt_packet()
{
    MfcPacketEntry *mfc_packet;
    bcmos_mutex_lock(&mfc_ind_lock_);
    mfc_packet = STAILQ_FIRST(&mfc_ind_list_);
    if (mfc_packet != nullptr)
    {
        STAILQ_REMOVE_HEAD(&mfc_ind_list_, next);
    }
    bcmos_mutex_unlock(&mfc_ind_lock_);
    return mfc_packet;

}

static int _client_tx_to_cp_task_handler(long data)
{
    bcmos_task *my_task = bcmos_task_current();
    MfcRelay *mfcr = (MfcRelay *)data;
    bcmos_errno err;

    while (!my_task->destroy_request)
    {
        err = mfcr->wait_for_olt_packet();
        if (err != BCM_ERR_OK && err != BCM_ERR_TIMEOUT)
        {
            MFC_LOG_ERR(" ===== Failed waiting the packet  =====\n");
            break;
        }

        MfcPacketEntry *pkt;
        while ((pkt =  mfcr->pop_olt_packet()) != nullptr && !my_task->destroy_request)
        {
            err = mfcr->tx_to_cp(*pkt);
            if (err != BCM_ERR_OK)
            {
                MFC_LOG_ERR("==== packet transmission to the BAA failed ====\n");
            }
            delete pkt;
        }
    }

    my_task->destroyed = BCMOS_TRUE;

    return 0;
}

static uint8_t mfc_parse_vlan_prty(const uint8_t *payload)
{
    uint16_t tpid = ntohs(*(uint16_t *)(payload + 12));
    uint8_t prty = 0;

    if (tpid == 0x8100 || tpid == 0x88A8 || tpid == 0x9100)
    {
        uint16_t vid = ntohs(*(uint16_t *)(payload + 14));
        prty = (vid >> 13) & 0x7;
    }
    return prty;
}

bcmos_errno mfc_relay_tx_to_olt(const ControlRelayPacket &grpc_packet)
{
    bcmolt_bin_str packet_out_buffer;
    const std::string &payload = grpc_packet.packet();
    packet_out_buffer.len = payload.length();
    packet_out_buffer.arr = (uint8_t *)payload.data();

    const char *vsi_name = grpc_packet.device_interface().c_str();
    const char *rule_name = grpc_packet.originating_rule().c_str();
    bcmolt_flow_key flow_key = { };
    bcmolt_flow_intf_ref intf_ref = {};
    bcmolt_service_port_id svc_port_id = 0;
    uint8_t prty;
    bcmos_errno err;

    prty = mfc_parse_vlan_prty(packet_out_buffer.arr);

    flow_key.flow_id = BCM_FLOW_ID_INVALID;
    err = bbf_xpon_get_intf_by_vsi_rule_prty(vsi_name, rule_name, prty,
        &flow_key, &intf_ref, &svc_port_id);
    if (err != BCM_ERR_OK)
    {
        MFC_LOG_ERR("Can't map packet from VSI %s, rule %s to ingress interface. Ignored\n", vsi_name, rule_name);
        return err;
    }

    bcmolt_flow_send_eth_packet packet_out;
    if (flow_key.flow_id == BCM_FLOW_ID_INVALID)
    {
        // TODO: need to create a default BAL flow with ingress_intf==host
        MFC_LOG_ERR("TODO: missing default interfaces for INJECT_AT_INGRESS. Can't inject packet for VSI %s, rule %s\n",
            vsi_name, rule_name);
        return BCM_ERR_NOT_SUPPORTED;
    }
    BCMOLT_OPER_INIT(&packet_out, flow, send_eth_packet, flow_key);
    BCMOLT_MSG_FIELD_SET(&packet_out, buffer, packet_out_buffer);
    BCMOLT_MSG_FIELD_SET(&packet_out, inject_type, BCMOLT_INJECT_TYPE_INJECT_AT_INGRESS);
    BCMOLT_MSG_FIELD_SET(&packet_out, ingress_intf, intf_ref);
    if (svc_port_id)
        BCMOLT_MSG_FIELD_SET(&packet_out, svc_port_id, svc_port_id);
    err = bcmolt_oper_submit(mfc_init_config.olt, &packet_out.hdr);
    if (err != BCM_ERR_OK)
    {
        MFC_LOG_ERR("Can't forward packet from VSI %s, rule %s over BAL flow %u:%d. Error '%s'\n",
            vsi_name, rule_name, flow_key.flow_id, flow_key.flow_type, bcmos_strerror(err));
        return err;
    }
    MFC_LOG_DBG(" Packet forwarded from VSI %s, rule %s over BAL flow %u:%d. %u bytes\n",
        vsi_name, rule_name, flow_key.flow_id, flow_key.flow_type, packet_out_buffer.len);
    return BCM_ERR_OK;
}

void MfcRelay::push_olt_packet(MfcPacketEntry *pkt)
{
    bcmos_mutex_lock(&mfc_ind_lock_);
    STAILQ_INSERT_TAIL(&mfc_ind_list_, pkt, next);
    // Kick thread that unwinds the queue if the queue was empty
    if (STAILQ_FIRST(&mfc_ind_list_) == pkt)
    {
        bcmos_sem_post(&mfc_ind_sem_);
    }
    bcmos_mutex_unlock(&mfc_ind_lock_);
}

MfcRelay *mfc_relay_get_by_endpoint_name(const char *endpoint_name)
{
    MfcRelay *mfcr, *mfcr_tmp;

    // Find MfcRelay object by endpoint name
    STAILQ_FOREACH_SAFE(mfcr, &mfc_relay_list, next, mfcr_tmp)
    {
        if (!strcmp(endpoint_name, mfcr->endpoint_name()))
            break;
    }

    return mfcr;
}

static void mfc_rx_from_olt(bcmolt_oltid olt, bcmolt_msg *msg)
{
    /* Identify vsi, rule and endpoint */
    bcmolt_access_control_receive_eth_packet *eth_packet = (bcmolt_access_control_receive_eth_packet *)msg;
    bcmolt_access_control_id acl_id = eth_packet->key.id;
    const char *vsi_name = nullptr;
    const char *rule_name = nullptr;
    const char *endpoint_name = nullptr;
    MfcRelay *mfcr;
    bcmos_errno err;

    do
    {
        // Get VSI and rule by acl_id
        err = bbf_xpon_get_vsi_and_rule_by_acl_id(eth_packet->key.id, &vsi_name, &rule_name, &endpoint_name);
        if (err != BCM_ERR_OK)
        {
            MFC_LOG_ERR("Can't find VSI and rule for packet trapped with ACL id %u\n", eth_packet->key.id);
            break;
        }
        if (vsi_name == nullptr || rule_name == nullptr || endpoint_name == nullptr)
        {
            MFC_LOG_ERR("Either VSI, rule or endpoint name is NULL for packet trapped with ACL id %u\n",
                eth_packet->key.id);
            break;
        }

        mfcr = mfc_relay_get_by_endpoint_name(endpoint_name);
        if (mfcr == nullptr)
        {
            MFC_LOG_ERR("Can't find MfcRelay object '%s' for packet trapped with ACL id %u\n",
                endpoint_name, eth_packet->key.id);
            break;
        }

        MfcPacketEntry *pkt = new MfcPacketEntry();
        pkt->set_device_interface(vsi_name);
        pkt->set_originating_rule(rule_name);
        pkt->set_packet(eth_packet->data.buffer.arr, eth_packet->data.buffer.len);
        MFC_LOG_DBG(" interface '%s' rule '%s' len = %d -> endpoint %s\n",
            vsi_name, rule_name, eth_packet->data.buffer.len, endpoint_name);

        mfcr->push_olt_packet(pkt);
    } while (1);

    bcmolt_msg_free(msg);
}

/*
 * External "C" interface
 */

bcmos_errno bcm_mfc_relay_init(const mfc_relay_init_parms *init_config)
{
    bcmos_errno err;

    if (log_id_mfc_relay)
        return BCM_ERR_ALREADY;
    if (init_config == nullptr)
        return BCM_ERR_PARM;

#ifdef ENABLE_LOG
    log_id_mfc_relay = bcm_dev_log_id_register("MFC", init_config->log_level, DEV_LOG_ID_TYPE_BOTH);
#endif
    mfc_init_config = *init_config;
    STAILQ_INIT(&mfc_relay_list);

    bcmolt_rx_cfg rx_cfg = {};
    rx_cfg.obj_type = BCMOLT_OBJ_ID_ACCESS_CONTROL;
    rx_cfg.rx_cb = mfc_rx_from_olt;
    rx_cfg.subgroup = BCMOLT_ACCESS_CONTROL_AUTO_SUBGROUP_RECEIVE_ETH_PACKET;
    err = bcmolt_ind_subscribe(mfc_init_config.olt, &rx_cfg);
    if (err != BCM_ERR_OK)
    {
        MFC_LOG_ERR("access_control subscription failed. Error '%s'\n", bcmos_strerror(err));
        return err;
    }

    /* Create upstream and downstream interfaces with ingress==host */

    return BCM_ERR_OK;
}

void bcm_mfc_relay_exit(void)
{
    MfcRelay *mfcr, *mfcr_tmp;
    STAILQ_FOREACH_SAFE(mfcr, &mfc_relay_list, next, mfcr_tmp)
    {
        delete mfcr;
    }

    bcmolt_rx_cfg rx_cfg = {};
    rx_cfg.obj_type = BCMOLT_OBJ_ID_ACCESS_CONTROL;
    rx_cfg.rx_cb = mfc_rx_from_olt;
    rx_cfg.subgroup = BCMOLT_ACCESS_CONTROL_AUTO_SUBGROUP_RECEIVE_ETH_PACKET;
    bcmolt_ind_unsubscribe(mfc_init_config.olt, &rx_cfg);

#ifdef ENABLE_LOG
    bcm_dev_log_id_unregister(log_id_mfc_relay);
#endif
}

bcmos_errno bcm_mfc_connect_disconnect_cb_register(
    bcmolt_mfc_connect_disconnect_cb cb, void *data)
{
    mfc_conn_discon_cb = cb;
    mfc_conn_discon_cb_data = data;
    return BCM_ERR_OK;
}
