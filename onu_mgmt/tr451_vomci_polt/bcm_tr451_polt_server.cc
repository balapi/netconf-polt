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
#include <fstream>
//#include <grpc/grpc_security_constants.h>

// BcmPoltServer constructor
BcmPoltServer::BcmPoltServer(const tr451_server_endpoint *ep):
    GrpcProcessor(GrpcProcessor::processor_type::GRPC_PROCESSOR_TYPE_SERVER, ep->endpoint.name),
    hello_service_(this), message_service_(this), endpoint_(&ep->endpoint, ep->local_name)
{
    p_server_ = nullptr;
}

// Destructor
BcmPoltServer::~BcmPoltServer()
{
    Stop();
}

// Start gRPC server
// This function is called in context of dedicated task
bcmos_errno BcmPoltServer::Start()
{
    std::string server_address =
        string(endpoint_.host_name() ? endpoint_.host_name() : "0.0.0.0") + string(":") +
        std::to_string(endpoint_.port());

    // See if authentication is required
    string my_key, my_cert, peer_cert;
    bool use_auth = false;
    grpc::SslServerCredentialsOptions sslOpts;
    if (bcm_tr451_auth_data(my_key, my_cert, peer_cert))
    {
        sslOpts.pem_root_certs = peer_cert;
        sslOpts.pem_key_cert_pairs.push_back(
            grpc::SslServerCredentialsOptions::PemKeyCertPair{my_key, my_cert});
        sslOpts.client_certificate_request = GRPC_SSL_REQUEST_CLIENT_CERTIFICATE_AND_VERIFY;
        use_auth = true;
        BCM_POLT_LOG(INFO, "%s: Enabling ssl authentication\n", this->name());
    }
    ServerBuilder builder;
    auto creds = grpc::SslServerCredentials(sslOpts);
    builder.AddListeningPort(server_address,
        use_auth ? grpc::SslServerCredentials(sslOpts) : grpc::InsecureServerCredentials());
    builder.RegisterService(&this->hello_service_);
    builder.RegisterService(&this->message_service_);
    std::unique_ptr<Server> server(builder.BuildAndStart());
    if (server == nullptr)
    {
        BCM_POLT_LOG(ERROR, "Failed to create %s on %s\n", this->name(), server_address.c_str());
        return BCM_ERR_PARM;
    }

    BCM_POLT_LOG(INFO, "Server %s is listening on %s\n", this->name(), server_address.c_str());
    p_server_ = &server;
    server->Wait();

    return BCM_ERR_OK;
}

// Stop server
void BcmPoltServer::Stop()
{
    if (!stopping)
    {
        stopping = true;
        VomciConnection *prev = nullptr, *next;
        if (p_server_ != nullptr)
        {
            (*p_server_)->Shutdown();
            p_server_ = nullptr;
        }
        // Pick up the remaining connections if any
        next = vomci_connection_get_next(prev, this);
        while (next != nullptr)
        {
            prev = next;
            next = vomci_connection_get_next(prev, this);
            if (prev != nullptr)
                delete prev;
        }
        GrpcProcessor::Stop();
        BCM_POLT_LOG(INFO, "server %s: Stopped\n", name());
    }
}

// OmciFunctionHello service handler
Status BcmPoltServer::OmciServiceHello::HelloVomci(
    ServerContext* context,
    const HelloVomciRequest* request,
    HelloVomciResponse* response)
{
    const char *vomci_name = request->has_local_endpoint_hello() ?
        request->local_endpoint_hello().endpoint_name().c_str() : nullptr;
    const char *local_name = parent_->endpoint()->name_for_hello();
    if (context->auth_context()->IsPeerAuthenticated() && vomci_name == nullptr)
    {
        std::vector<grpc::string_ref> auth_identity =
            context->auth_context()->FindPropertyValues(context->auth_context()->GetPeerIdentityPropertyName());
        if (auth_identity.size())
            vomci_name = auth_identity[0].data();
    }
    BCM_POLT_LOG(INFO, "Server %s: received HelloRequest from vOMCI %s\n",
        parent_->name(),
        (vomci_name != nullptr) ? vomci_name : "*undefined*");
    if (vomci_name == nullptr || !strlen(vomci_name))
    {
        return tr451_bcm_errno_grpc_status(BCM_ERR_PARM,
            "Can't identify connection. vomci_name is missing in HelloVomci and in Auth identity");
    }

    Hello *olt = new Hello();
    olt->set_endpoint_name(local_name);
    response->set_allocated_remote_endpoint_hello(olt);

    new VomciConnection(parent_, parent_->endpoint()->name(), local_name, vomci_name, context->peer());

    return Status::OK;
}

// OmciFunctionMessage::ListenForOmciRx service handler
Status BcmPoltServer::OmciServiceMessage::ListenForVomciRx(
    ServerContext* context,
    const Empty* request,
    ServerWriter<VomciMessage>* writer)
{
    bcmos_errno err;

    VomciConnection *conn = parent_->connection_by_peer(context->peer());
    if (conn == nullptr)
    {
        return tr451_bcm_errno_grpc_status(BCM_ERR_PARM,
            "%s: vOMCI instance %s is unknown\n", parent_->name(), context->peer().c_str());
    }
    BCM_POLT_LOG(INFO, "%s: Forwarding OMCI messages from pOLT to vOMCI %s@%s enabled\n",
        parent_->name(), conn->name(), conn->peer());
    conn->setConnected(true);
    while (!context->IsCancelled() && !parent_->stopping)
    {
        err = conn->WaitForPacketFromOnu();
        if (err != BCM_ERR_OK && err != BCM_ERR_TIMEOUT)
            break;

        // Got notification that 1 or more OMCI packets are waiting in the queue.
        // Drain the queue and send all packets to vOMCI peer
        OmciPacketEntry *omci_packet;
        while (!context->IsCancelled() && !parent_->stopping &&
            (omci_packet = conn->PopPacketFromOnuFromTxQueue()) != nullptr)
        {
            // Send to vOMCI peer
            VomciMessage tx_msg;
            tx_msg.set_allocated_omci_packet_msg(omci_packet);
            writer->Write(tx_msg);

            ++conn->stats.packets_onu_to_vomci_sent;
        }
    }
    conn->setConnected(false);
    BCM_POLT_LOG(INFO, "%s: Forwarding OMCI messages from pOLT to vOMCI %s disabled\n",
        parent_->name(), conn->name());
    delete conn;

    return Status::OK;
}

Status BcmPoltServer::OmciServiceMessage::VomciTx(
    ServerContext* context,
    const VomciMessage* request,
    Empty* response)
{
    if (!request->has_omci_packet_msg())
    {
        BCM_POLT_LOG(ERROR, "message is not a packet. Ignored\n");
        return grpc::Status(StatusCode::INVALID_ARGUMENT, "message is not a packet");
    }
    return parent()->OmciTxToOnu(request->omci_packet_msg());
}

//
// External interface
//

bcmos_errno bcm_tr451_polt_grpc_server_init(void)
{
    return BCM_ERR_OK;
}

bcmos_errno bcm_tr451_polt_grpc_server_create(const tr451_server_endpoint *endpoint)
{
    bcmos_errno err = BCM_ERR_OK;
    BCM_POLT_LOG(INFO, "Creating server %s: name_for_hello=%s listen=%s:%u\n",
        endpoint->endpoint.name,
        endpoint->local_name ? endpoint->local_name : endpoint->endpoint.name,
        endpoint->endpoint.host_name ? endpoint->endpoint.host_name : "any",
        endpoint->endpoint.port);
    BcmPoltServer *server = new BcmPoltServer(endpoint);
    if (bcm_grpc_processor_is_enabled(GrpcProcessor::processor_type::GRPC_PROCESSOR_TYPE_SERVER))
    {
        err = server->CreateTaskAndStart();
    }
    return err;
}

// Get server by name
BcmPoltServer *bcm_polt_server_get_by_name(const char *name)
{
    GrpcProcessor *entry = bcm_grpc_processor_get_by_name(name,
        GrpcProcessor::processor_type::GRPC_PROCESSOR_TYPE_SERVER);
    return dynamic_cast<BcmPoltServer *>(entry);
}

bcmos_errno bcm_tr451_polt_grpc_server_start(const char *name)
{
    GrpcProcessor *entry = bcm_grpc_processor_get_by_name(name,
        GrpcProcessor::processor_type::GRPC_PROCESSOR_TYPE_SERVER);
    if (entry == nullptr)
        return BCM_ERR_NOENT;
    return entry->CreateTaskAndStart();
}

bcmos_errno bcm_tr451_polt_grpc_server_enable_disable(bcmos_bool enable)
{
    return bcm_grpc_processor_enable_disable((bool)enable,
        GrpcProcessor::processor_type::GRPC_PROCESSOR_TYPE_SERVER);
}

bcmos_errno bcm_tr451_polt_grpc_server_stop(const char *name)
{
    GrpcProcessor *entry = bcm_grpc_processor_get_by_name(name,
        GrpcProcessor::processor_type::GRPC_PROCESSOR_TYPE_SERVER);
    if (entry == nullptr)
        return BCM_ERR_NOENT;
    entry->Stop();
    return BCM_ERR_OK;
}

bcmos_errno bcm_tr451_polt_grpc_server_delete(const char *name)
{
    GrpcProcessor *entry = bcm_grpc_processor_get_by_name(name,
        GrpcProcessor::processor_type::GRPC_PROCESSOR_TYPE_SERVER);
    if (entry == nullptr)
        return BCM_ERR_NOENT;
    BcmPoltServer *server = dynamic_cast<BcmPoltServer *>(entry);
    delete server;
    return BCM_ERR_OK;
}

const char *bcm_tr451_polt_grpc_server_client_get_next(const char *prev)
{
    VomciConnection *conn;
    if (prev != nullptr)
    {
        conn = vomci_connection_get_by_name(prev);
        if (conn != nullptr)
            conn = vomci_connection_get_next(conn);
    }
    else
    {
        conn = vomci_connection_get_next(nullptr);
    }
    while (conn != nullptr && conn->parent()->type() != GrpcProcessor::processor_type::GRPC_PROCESSOR_TYPE_SERVER)
        conn = vomci_connection_get_next(conn);
    return (conn != nullptr) ? conn->name() : nullptr;
}
