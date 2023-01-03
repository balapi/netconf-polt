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

#include <bcm_tr451_polt_internal.h>

// Task that handles transmission of OMCI packets received from ONUs to vOMCI
static int _client_tx_task_handler(long data)
{
    bcmos_task *self = bcmos_task_current();
    BcmPoltClient *owner = (BcmPoltClient *)data;

    while (!self->destroy_request)
    {
        VomciConnection *connection = owner->connection();
        bcmos_errno err;

        if (connection == nullptr)
            continue; // Paranoya

        err = connection->WaitForPacketFromOnu();
        if (err != BCM_ERR_OK && err != BCM_ERR_TIMEOUT)
            break;

        // Got notification that 1 or more OMCI packets are waiting in the queue.
        // Drain the queue and send all packets to vOMCI peer
        OmciPacketEntry *omci_packet;
        while (!self->destroy_request &&
            (omci_packet = connection->PopPacketFromOnuFromTxQueue()) != nullptr)
        {
            // Convert to gRPC and transmit
            if (owner->OmciTxToVomci(omci_packet) == BCM_ERR_OK)
            {
                ++connection->stats.packets_onu_to_vomci_sent;
            }
            else
            {
                ++connection->stats.packets_onu_to_vomci_disc;
            }
        }
    }
    self->destroyed = BCMOS_TRUE;
    return 0;
}

BcmPoltClient::BcmPoltClient(const tr451_client_endpoint *ep):
    GrpcProcessor(GrpcProcessor::processor_type::GRPC_PROCESSOR_TYPE_CLIENT, ep->name),
    endpoint_(ep->name, ep->local_name)
{
    connection_ = nullptr;
    listen_context_ = nullptr;

    const tr451_endpoint *entry;
    STAILQ_FOREACH(entry, &ep->entry_list, next)
    {
        endpoint_.AddEntry(entry);
    }
}

BcmPoltClient::~BcmPoltClient()
{
    Stop();
    BCM_POLT_LOG(INFO, "client '%s': Destroyed\n", endpoint_.name());
}

void BcmPoltClient::CancelListenForVomciTx()
{
    if (listen_context_ != nullptr)
    {
        listen_context_->TryCancel();
        while (listen_context_ != nullptr)
        {
            bcmos_usleep(10000);
        }
    }
}

// Stop client
void BcmPoltClient::Stop()
{
    if (!stopping)
    {
        stopping = true;
        CancelListenForVomciTx();
        Disconnected();
        GrpcProcessor::Stop();
        BCM_POLT_LOG(INFO, "client %s: Stopped\n", endpoint_.name());
    }
}

bcmos_errno BcmPoltClient::Connect(const Endpoint *entry)
{
    bool ready = false;

    // Create a channel to the server
    string host_port = entry->host_name() + string(":") + std::to_string(entry->port());

    while(!ready)
    {
        // See if authentication is required
        string my_key, my_cert, peer_cert;
        bool use_auth = false;
        grpc::SslCredentialsOptions sslOpts;
        grpc::ChannelArguments channelArgs;
        if (bcm_tr451_auth_data(my_key, my_cert, peer_cert))
        {
            sslOpts.pem_root_certs = peer_cert;
            sslOpts.pem_private_key = my_key;
            sslOpts.pem_cert_chain = my_cert;
            channelArgs.SetSslTargetNameOverride(entry->name());
            use_auth = true;
        }
        BCM_POLT_LOG(INFO, "client %s.%s: establishing %s connection with the server at %s:%u\n",
            endpoint_.name(), entry->name(),
            use_auth ? "ssl" : "unsecured",
            entry->host_name(), entry->port());
        channel_ = grpc::CreateCustomChannel(host_port,
            use_auth ? grpc::SslCredentials(sslOpts) : grpc::InsecureChannelCredentials(), channelArgs);

        if (channel_ == nullptr || channel_->GetState(true) == GRPC_CHANNEL_SHUTDOWN)
        {
            BCM_POLT_LOG(ERROR, "client %s.%s: couldn't connect with the server at %s:%u.\n",
                endpoint_.name(), entry->name(), entry->host_name(), entry->port());
            bcmos_usleep(1*1000000);
            continue;
        }
        ready = true;
    }

    return BCM_ERR_OK;
}

// Send Hello
bcmos_errno BcmPoltClient::Hello(const Endpoint *entry)
{
    hello_stub_ = ::tr451_vomci_sbi_service::v1::VomciHelloSbi::NewStub(channel_);
    ClientContext context;
    HelloVomciRequest hello_request;
    HelloVomciResponse hello_response;
    Status status;

    ::tr451_vomci_sbi_message::v1::Hello *olt = new ::tr451_vomci_sbi_message::v1::Hello();
    olt->set_endpoint_name(endpoint_.name_for_hello());
    hello_request.set_allocated_local_endpoint_hello(olt);
    status = hello_stub_->HelloVomci(&context, hello_request, &hello_response);
    if (!status.ok())
    {
        BCM_POLT_LOG(INFO, "client %s.%s: 'hello' exchange with server at %s:%u failed. Re-connecting..\n",
            endpoint_.name(), entry->name(), entry->host_name(), entry->port());
        return BCM_ERR_IO;
    }
    const char *vomci_name = nullptr;
    if (hello_response.has_remote_endpoint_hello())
        vomci_name = hello_response.remote_endpoint_hello().endpoint_name().c_str();
    if (vomci_name == nullptr || !*vomci_name)
        vomci_name = endpoint_.name();
    BCM_POLT_LOG(INFO, "client %s.%s: 'hello' exchange with the server at %s:%u completed: connected to vomci %s\n",
        endpoint_.name(), entry->name(), entry->host_name(), entry->port(), vomci_name);
    if (connection_ != nullptr)
        delete connection_;
    connection_ = new VomciConnection(this, entry->name(), endpoint_.name_for_hello(), vomci_name);
    connection_->setConnected(true);
    return BCM_ERR_OK;
}

// Listen for OMCI messages from vOMCI
void BcmPoltClient::ListenForVomciTx()
{
    CancelListenForVomciTx(); // cancel old call if any
    listen_context_ = new ClientContext();
    Empty request;
    std::unique_ptr< ::grpc::ClientReaderInterface<VomciMessage>> reader(
        message_stub_->ListenForVomciRx(listen_context_, request));
    VomciMessage tx_msg;
    while (connection_ != nullptr && reader->Read(&tx_msg))
    {
        if (!tx_msg.has_omci_packet_msg())
        {
            BCM_POLT_LOG(INFO, "%s: Received message is not a packet. Ignored\n", endpoint_.name());
            continue;
        }
        OmciTxToOnu(tx_msg.omci_packet_msg(), connection_ ? connection_->peer() : nullptr);
    }
    reader->Finish();

    // There appears to be a race-condition bug in grpc library.
    // It sometimes crashes when attempty to destroy mutex that another grpc task still waiting on
    // sleep a little here
    bcmos_usleep(10000);

    delete listen_context_;
    listen_context_ = nullptr;
}

void BcmPoltClient::Disconnected()
{
    // Diosconnected. Delete stale connection
    if (connection_ != nullptr)
    {
        bcmos_task_destroy(&tx_task_);
        delete connection_;
        connection_ = nullptr;
    }
}

bcmos_errno BcmPoltClient::Start()
{
    bcmos_errno err = BCM_ERR_OK;

    if (endpoint_.entry(nullptr) == nullptr)
    {
        BCM_POLT_LOG(INFO, "client %s: no remote entries\n", endpoint_.name());
        return BCM_ERR_PARM;
    }
    // Iterate over endpoint entries until connected
    do
    {
        // Connect with the server and send 'hello'
        const Endpoint *entry = NULL;

        do
        {
            entry = endpoint_.entry(entry);
            if (entry == NULL)
                continue;

            err = Connect(entry);
            // Connected. Now send Hello
            err = err ? err : Hello(entry);
            if (err != BCM_ERR_OK)
            {
                bcmos_usleep(1*1000000);
                continue;
            }
        } while (err != BCM_ERR_OK && !stopping);
        if (stopping)
            break;

        // Create stub interface for message exchange
        message_stub_ = ::tr451_vomci_sbi_service::v1::VomciMessageSbi::NewStub(channel_);

        // Create TX task
        bcmos_errno err;
        bcmos_task_parm tp = {};
        tp.name = endpoint_.name();
        tp.priority = TASK_PRIORITY_TRANSPORT_PROXY;
        tp.handler = _client_tx_task_handler;
        tp.data = (long)this;

        err = bcmos_task_create(&tx_task_, &tp);
        if (err != BCM_ERR_OK)
        {
            BCM_POLT_LOG(ERROR, "client %s: can't create TX task. Terminated.\n",
                endpoint_.name());
            return err;
        }

        // Now send ListenForOmciRx() request. It will block
        ListenForVomciTx();

        Disconnected();

    } while (!stopping);

    return BCM_ERR_OK;
}

// Forward message received from ONU to vOMCI
bcmos_errno BcmPoltClient::OmciTxToVomci(OmciPacket *grpc_omci_packet)
{
    ClientContext context;
    ::google::protobuf::Empty response;
    Status status;
    VomciMessage msg;
    msg.set_allocated_omci_packet_msg(grpc_omci_packet);
    status = message_stub_->VomciTx(&context, msg, &response);
    return status.ok() ? BCM_ERR_OK: BCM_ERR_IO;
}

bcmos_errno bcm_tr451_polt_grpc_client_init(void)
{
    return BCM_ERR_OK;
}

bcmos_errno bcm_tr451_polt_grpc_client_create(const tr451_client_endpoint *endpoint)
{
    GrpcProcessor *old_client = bcm_grpc_processor_get_by_name(endpoint->name,
        GrpcProcessor::processor_type::GRPC_PROCESSOR_TYPE_CLIENT);
    if (old_client != nullptr)
    {
        BCM_POLT_LOG(ERROR, "client %s already exists\n", endpoint->name);
        return BCM_ERR_ALREADY;
    }

    bcmos_errno err = BCM_ERR_OK;

    // Validation
    const tr451_endpoint *entry;
    if (STAILQ_EMPTY(&endpoint->entry_list))
    {
        BCM_POLT_LOG(ERROR, "client %s: no entries\n", endpoint->name);
        return BCM_ERR_PARM;
    }
    STAILQ_FOREACH(entry, &endpoint->entry_list, next)
    {
        if (entry->host_name == nullptr)
        {
            BCM_POLT_LOG(ERROR, "client %s.%s: host_name is required for client connection\n",
                endpoint->name, entry->name);
            return BCM_ERR_PARM;
        }
        if (!entry->port)
        {
            BCM_POLT_LOG(ERROR, "client %s.%s: port is required for client connection\n",
                endpoint->name, entry->name);
            return BCM_ERR_PARM;
        }
        BCM_POLT_LOG(INFO, "Creating client %s: name_for_hello=%s  entry %s %s:%u\n",
            endpoint->name,
            endpoint->local_name ? endpoint->local_name : endpoint->name,
            entry->name,
            entry->host_name ? entry->host_name : "any", entry->port);
    }

    // Create and start client
    BcmPoltClient *client = new BcmPoltClient(endpoint);
    if (bcm_grpc_processor_is_enabled(GrpcProcessor::processor_type::GRPC_PROCESSOR_TYPE_CLIENT))
    {
        err = client->CreateTaskAndStart();
    }

    return err;
}

bcmos_errno bcm_tr451_polt_grpc_client_start(const char *name)
{
    GrpcProcessor *entry = bcm_grpc_processor_get_by_name(name,
        GrpcProcessor::processor_type::GRPC_PROCESSOR_TYPE_CLIENT);
    if (entry == nullptr)
        return BCM_ERR_NOENT;
    return entry->CreateTaskAndStart();
}

bcmos_errno bcm_tr451_polt_grpc_client_stop(const char *name)
{
    GrpcProcessor *entry = bcm_grpc_processor_get_by_name(name,
        GrpcProcessor::processor_type::GRPC_PROCESSOR_TYPE_CLIENT);
    if (entry == nullptr)
        return BCM_ERR_NOENT;
    BcmPoltClient *client = dynamic_cast<BcmPoltClient *>(entry);
    client->Stop();
    return BCM_ERR_OK;
}

bcmos_errno bcm_tr451_polt_grpc_client_delete(const char *name)
{
    GrpcProcessor *entry = bcm_grpc_processor_get_by_name(name,
        GrpcProcessor::processor_type::GRPC_PROCESSOR_TYPE_CLIENT);
    if (entry == nullptr)
        return BCM_ERR_NOENT;
    BcmPoltClient *client = dynamic_cast<BcmPoltClient *>(entry);
    delete client;
    return BCM_ERR_OK;
}

// Get client by name
BcmPoltClient *bcm_polt_client_get_by_name(const char *name)
{
    GrpcProcessor *entry = bcm_grpc_processor_get_by_name(name,
        GrpcProcessor::processor_type::GRPC_PROCESSOR_TYPE_CLIENT);
    return dynamic_cast<BcmPoltClient *>(entry);
}

bcmos_errno bcm_tr451_polt_grpc_client_enable_disable(bcmos_bool enable)
{
    return bcm_grpc_processor_enable_disable((bool)enable,
        GrpcProcessor::processor_type::GRPC_PROCESSOR_TYPE_CLIENT);
}
