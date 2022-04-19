
#include <mfc_relay.h>
#include <mfc_relay_internal.h>


#define BCM_OLT_UPSTREAM_EGRESS_INJECT 4
#define IGMP_QUERY_DESTINATION_ADDRESS 0xe0000001

static int client_connect_and_listen_task_handler(long data);

static bcmos_task tx_task;

class MfcClient : public MfcRelay
{
  public:
    MfcClient(const mfc_relay_client_parms *parms);
    virtual ~MfcClient();

    bool isConnected() { return connected_; }
    void setConnected(bool status) { connected_ = status; }
    const char *local_endpoint_name() { return local_endpoint_name_.c_str(); }
    const char *access_name() { return access_point_name_.c_str(); }
    const char *server_address() { return server_address_.c_str(); }
    uint16_t server_port() { return server_port_; }
    void connext_and_listen_for_rx_from_cp();
    bcmos_errno tx_to_cp (ControlRelayPacket &pkt);

  private:

    void listen_for_mfc_relay_rx_from_cp();
    bcmos_errno say_hello();

    bool connected_;
    bool stopping_;
    string local_endpoint_name_;
    string access_point_name_;
    string server_address_;
    uint16_t server_port_;
    bcmos_task listen_task_;
    std::unique_ptr<::control_relay_service::v1::ControlRelayHelloService::Stub> hello_stub_;
    std::unique_ptr<::control_relay_service::v1::ControlRelayPacketService::Stub> message_stub_;
    ClientContext *listen_context_;
    std::shared_ptr<Channel> channel_;
};

MfcClient::MfcClient(const mfc_relay_client_parms *parms) : MfcRelay(parms->endpoint_name)
{
    bcmos_errno err;

    connected_ = false;
    listen_context_ = nullptr;

    local_endpoint_name_ = parms->local_endpoint_name;
    access_point_name_ = parms->access_point_name;
    server_address_ = parms->server_address;
    server_port_ = parms->port;

    /* Create listening task for messages toward OLT */
    bcmos_task_parm tp = {};
    tp.name = parms->local_endpoint_name;
    tp.priority = TASK_PRIORITY_VOMCI_DOLT_CLIENT;
    tp.handler = client_connect_and_listen_task_handler;
    tp.data = (long)this;
    err = bcmos_task_create(&listen_task_, &tp);
    if (err != BCM_ERR_OK)
    {
        MFC_LOG_ERR("Couldn't create listening task. Error '%s'\n", bcmos_strerror(err));
        BUG();
    }
}

MfcClient::~MfcClient()
{
    if (listen_context_ != nullptr)
    {
        listen_context_->TryCancel();
        while (listen_context_ != nullptr)
            bcmos_usleep(10000);
    }
    bcmos_task_destroy(&listen_task_);
}

void MfcClient::listen_for_mfc_relay_rx_from_cp()
{
    bcmos_errno err;

    if (listen_context_ != nullptr) /*cancel if old call any*/
    {
        listen_context_->TryCancel();
        while (listen_context_ != nullptr)
        {
            bcmos_usleep(10000);
        }
    }

    listen_context_ = new ClientContext();
    Empty request;
    ControlRelayPacket tx_packet;
    std::unique_ptr<::grpc::ClientReaderInterface< ::control_relay_service::v1::ControlRelayPacket>> reader(
            message_stub_->ListenForPacketRx(listen_context_, request));
    while (reader->Read(&tx_packet))
    {
        MFC_LOG_DBG(" Received packet structure \n device %s \n interface %s \n rule %s \n pkt %s\n",tx_packet.device_name().c_str(),tx_packet.device_interface().c_str(),tx_packet.originating_rule().c_str(),tx_packet.mutable_packet()->c_str());
        err = mfc_relay_tx_to_olt(tx_packet);
        if(err != BCM_ERR_OK)
        {
            MFC_LOG_ERR(" Failed to forward packet. Error %s\n",bcmos_strerror(err));
        }
    }
    reader->Finish();

    /* There appears to be a race-condition bug in grpc library.
       It sometimes crashes when attempty to destroy mutex that another grpc task still waiting on
       sleep a little here\
    */
    bcmos_usleep(10000);

    delete listen_context_;
    listen_context_ = nullptr;
}

bcmos_errno MfcClient::tx_to_cp(ControlRelayPacket &pkt)
{
    ClientContext context;
    ::google::protobuf::Empty response;
    Status status;
    if (message_stub_ == nullptr)
        return BCM_ERR_STATE;
    pkt.set_device_name(local_endpoint_name_.c_str());
    status = message_stub_->PacketTx(&context, pkt, &response);
    return status.ok() ? BCM_ERR_OK: BCM_ERR_IO;
}

bcmos_errno MfcClient::say_hello()
{
    HelloRequest request;
    HelloResponse response;
    ClientContext context;

    DeviceHello *olt = new DeviceHello();
    olt->set_device_name(local_endpoint_name_.c_str());
    request.set_allocated_device(olt);

    hello_stub_ = ::control_relay_service::v1::ControlRelayHelloService::NewStub(channel_);
    Status status = hello_stub_->Hello(&context, request, &response);

    if (!status.ok())
    {
        std::cout << status.error_message() << std::endl;
        std::cout << status.error_code() << std::endl;
        return BCM_ERR_IO;
    }
    return BCM_ERR_OK;
}

void MfcClient::connext_and_listen_for_rx_from_cp()
{
    bcmos_task *my_task = bcmos_task_current();
    bcmos_errno err = BCM_ERR_OK;
    bool ready = false;
    string host_port = server_address_ + string(":") + std::to_string(server_port_);

    listen_context_ = nullptr;
    connected_ = true;

    /* Create connection with the server */
    ready = false;
    while(!ready && !my_task->destroy_request)
    {
        MFC_LOG_DBG(" Connecting to server %s\n", host_port.c_str());
        channel_ = grpc::CreateChannel(host_port, grpc::InsecureChannelCredentials());
        if (channel_ == nullptr || channel_->GetState(true) == GRPC_CHANNEL_SHUTDOWN)
        {
            bcmos_usleep(1*1000000);
            continue;
        }
        ready = true;
    }
    if (my_task->destroy_request)
        return;

    do
    {
        err = say_hello();
        if (err != BCM_ERR_OK && !my_task->destroy_request)
        {
            bcmos_usleep(1*1000000);
        }
    } while (err != BCM_ERR_OK && !my_task->destroy_request);
    if (my_task->destroy_request)
        return;

    if (mfc_conn_discon_cb != nullptr)
    {
        mfc_conn_discon_cb(mfc_conn_discon_cb_data,
            endpoint_name(), access_point_name_.c_str(), BCMOS_TRUE);
    }
    connected_ = true;
    MFC_LOG_INFO("Connected to server %s\n", host_port.c_str());

    message_stub_ = ::control_relay_service::v1::ControlRelayPacketService::NewStub(channel_);
    listen_for_mfc_relay_rx_from_cp();
    if (mfc_conn_discon_cb != nullptr)
    {
        mfc_conn_discon_cb(mfc_conn_discon_cb_data,
            endpoint_name(), access_point_name_.c_str(), BCMOS_FALSE);
    }
}

static int client_connect_and_listen_task_handler(long data)
{
    MfcClient *client = (MfcClient *)data;
    bcmos_task *my_task = bcmos_task_current();

    do
    {
        client->connext_and_listen_for_rx_from_cp();
    } while(!my_task->destroy_request);

    my_task->destroyed = BCMOS_TRUE;

    return 0;
}

bcmos_errno bcm_mfc_relay_client_create(const mfc_relay_client_parms *client_cfg)
{
    MfcRelay *mfcr;

    if (client_cfg == nullptr || !client_cfg->endpoint_name || ! *client_cfg->endpoint_name)
        return BCM_ERR_PARM;

    mfcr = mfc_relay_get_by_endpoint_name(client_cfg->endpoint_name);
    if (mfcr != nullptr)
    {
        MFC_LOG_ERR("mfc_relay with endpoint name '%s' already exists\n", client_cfg->endpoint_name);
        return BCM_ERR_TOO_MANY;
    }

    MFC_LOG_DBG("====== bcm_mfc_relay_started ==============\n");
    new MfcClient(client_cfg);

    return BCM_ERR_OK;
}

bcmos_errno bcm_mfc_relay_client_delete(const char *endpoint_name)
{
    MfcRelay *mfcr = mfc_relay_get_by_endpoint_name(endpoint_name);
    if (mfcr == nullptr)
        return BCM_ERR_NOENT;

    delete mfcr;

    return BCM_ERR_OK;
}
