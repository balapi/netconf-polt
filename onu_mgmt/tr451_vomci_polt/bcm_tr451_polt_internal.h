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

#ifndef BCM_TR451_POLT_INTERNAL_H_
#define BCM_TR451_POLT_INTERNAL_H_

#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/server_builder.h>
#include <grpcpp/security/server_credentials.h>
#include <grpc/grpc.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>

#include <tr451_vomci_function_sbi_message.pb.h>
#include <tr451_vomci_function_sbi_service.pb.h>
#include <tr451_vomci_function_sbi_service.grpc.pb.h>

#include <bcm_tr451_polt.h>
#include <tr451_polt_vendor.h>
#include <tr451_polt_for_vendor.h>

#define TR451_OMCI_PACKET_POLL_TIMEOUT (100*1000)

using grpc::Server;
using grpc::ServerWriter;
using grpc::ServerBuilder;
using grpc::ServerCompletionQueue;
using grpc::ServerContext;
using grpc::Status;
using grpc::StatusCode;
using grpc::Channel;
using grpc::ClientWriter;
using grpc::ClientReader;
using grpc::ClientContext;
using google::protobuf::Empty;
using std::string;

using tr451_vomci_function_sbi_message::OltHello;
using tr451_vomci_function_sbi_message::HelloVomciRequest;
using tr451_vomci_function_sbi_message::HelloVomciResponse;
using tr451_vomci_function_sbi_message::OmciPacket;

// Endpoint as provisioned over TR-451 YANG
class Endpoint {
    public:
        Endpoint(const tr451_endpoint *ep) :
            name_(ep->name ? ep->name : ""),
            host_name_(ep->host_name ? ep->host_name : ""),
            port_(ep->port) { memset(&next, 0, sizeof(next)); }
        const char *name() const { return name_.length() ? name_.c_str() : nullptr; }
        const char *host_name() const { return host_name_.length() ? host_name_.c_str() : nullptr; }
        uint16_t port() const { return port_; }
        STAILQ_ENTRY(Endpoint) next;
    private:
        string name_;
        string host_name_;
        uint16_t port_;
};

// Client endpoint as provisioned via TR-451 YANG
// It contains a list of 1 or more access points that are tried serially
// until successful completion of vOMCI hello exchangeg
class ClientEndpoint
{
    public:
        ClientEndpoint(const char *name) : name_(name) { STAILQ_INIT(&entry_list_); }
        ~ClientEndpoint() {
            Endpoint *ep;
            while ((ep = STAILQ_FIRST(&entry_list_)) != nullptr) {
                STAILQ_REMOVE_HEAD(&entry_list_, next);
                delete ep;
            }
        }
        void AddEntry(const tr451_endpoint *entry) {
            Endpoint *ep = new Endpoint(entry);
            STAILQ_INSERT_TAIL(&entry_list_, ep, next);
        }
        const Endpoint *entry(const Endpoint *prev) const {
            return prev ? STAILQ_NEXT(prev, next) : STAILQ_FIRST(&entry_list_);
        }
        const char *name() const { return name_.c_str(); }
    private:
        string name_;
        STAILQ_HEAD(, Endpoint) entry_list_;
};

// The base class for both BcmPoltServer and BcmPoltClient
//
class GrpcProcessor {
    public:
        typedef enum
        {
            GRPC_PROCESSOR_TYPE_SERVER,
            GRPC_PROCESSOR_TYPE_CLIENT
        } processor_type;
        GrpcProcessor(processor_type type, const char *ep_name);
        virtual ~GrpcProcessor();
        virtual bcmos_errno Start() = 0;
        Status OmciTxToOnu(const OmciPacket &grpc_omci_packet, const char *peer = nullptr);
        bcmos_errno CreateTaskAndStart();
        virtual void Stop();
        bool isStarted() { return started_; }
        const char *name() { return endpoint_name_.c_str(); }
        processor_type type() { return type_; }
        const char *type_name() {
            static const char *type_name[2] = { "server", "client" };
            return type_name[(int)type_];
        }
        GrpcProcessor *GetNext() { return STAILQ_NEXT(this, next );}
        STAILQ_ENTRY(GrpcProcessor) next;
        bool stopping;
    private:
        processor_type type_;
        string endpoint_name_;
        bool started_;
        bcmos_task task_;
};

// Logical "connection"
// Multiple logical connections can be multiplexed over a single underlying transport connection
class VomciConnection
{
    public:
        VomciConnection(GrpcProcessor *parent,
            const string &endpoint,
            const string &vomci_name,
            const string &vomci_address = string());
        ~VomciConnection();
        GrpcProcessor *parent() { return parent_; }
        const char *name() const { return name_.c_str(); }
        const char *peer() const { return peer_.c_str(); }
        const char *endpoint() const { return endpoint_.c_str(); }
        bool isConnected() { return connected_; };
        void setConnected(bool connected);
        void OmciRxFromOnu(OmciPacketEntry *omci_packet);
        bcmos_errno WaitForPacketFromOnu(uint32_t poll_timeout = TR451_OMCI_PACKET_POLL_TIMEOUT) {
            return bcmos_sem_wait(&omci_ind_sem, poll_timeout);
        }
        OmciPacketEntry *PopPacketFromOnuFromTxQueue(void);
        void conn_lock() { bcmos_mutex_lock(&conn_lock_); }
        void conn_unlock() { bcmos_mutex_unlock(&conn_lock_); }
        void UpdateOnuAssignmentsConnected();
        void UpdateOnuAssignmentsDisconnected();

        // Debug counters
        uint32_t packets_onu_to_vomci_recv;
        uint32_t packets_onu_to_vomci_sent;
        uint32_t packets_onu_to_vomci_disc;
        uint32_t packets_vomci_to_onu_recv;
        uint32_t packets_vomci_to_onu_sent;
        uint32_t packets_vomci_to_onu_disc;

        // List maintenance
        STAILQ_ENTRY(VomciConnection) next;

    private:
        GrpcProcessor *parent_;
        const string name_;
        const string peer_;
        const string endpoint_;
        bool connected_;
        bcmos_mutex conn_lock_;
        STAILQ_HEAD(, OmciPacketEntry) omci_ind_list;
        bcmos_sem omci_ind_sem;
        bcmos_mutex omci_ind_lock;
};

VomciConnection *vomci_connection_get_by_name(const char *name, const GrpcProcessor *owner = nullptr);
VomciConnection *vomci_connection_get_by_peer(const char *peer, const GrpcProcessor *owner = nullptr);
VomciConnection *vomci_connection_get_next(VomciConnection *prev, const GrpcProcessor *owner = nullptr);
void vomci_notify_connect_disconnect(VomciConnection *conn, bool is_connected);

//
// Server class
// There is an instance per server listen-endpoint in bbf-polt-vomci.yang
//
class BcmPoltServer : public GrpcProcessor
{
    public:
        BcmPoltServer(const tr451_server_endpoint *ep);
        virtual ~BcmPoltServer();
        bcmos_errno Start() override;
        void Stop() override;
        const Endpoint *endpoint() { return &endpoint_; }
        VomciConnection *connection_by_name(const string &vomci_name) {
            return vomci_connection_get_by_name(vomci_name.c_str(), this);
        }
        VomciConnection *connection_by_peer(const string &peer) {
            return vomci_connection_get_by_peer(peer.c_str(), this);
        }

    // Find or update remote endpoint

    private:
        class OmciServiceHello final :
            public ::tr451_vomci_function_sbi_service::OmciFunctionHelloSbi::Service
        {
        public:
            OmciServiceHello(BcmPoltServer *parent) : parent_ (parent) {}
            BcmPoltServer *parent() { return parent_; }
        private:
            Status HelloVomci(ServerContext* context,
                const HelloVomciRequest* request,
                HelloVomciResponse* response) override;

            BcmPoltServer *parent_;
        };

        class OmciServiceMessage final :
            public ::tr451_vomci_function_sbi_service::OmciFunctionMessageSbi::Service
        {
        public:
            OmciServiceMessage(BcmPoltServer *parent) : parent_ (parent) {}
            BcmPoltServer *parent() { return parent_; }

        private:
            Status ListenForOmciRx(ServerContext* context,
                const Empty* request,
                ServerWriter<OmciPacket>* writer) override;

            Status OmciTx(ServerContext* context, const OmciPacket* request, Empty* response) override;

            BcmPoltServer *parent_;
        };

        OmciServiceHello hello_service_;
        OmciServiceMessage message_service_;
        Endpoint endpoint_;
        std::unique_ptr<Server> *p_server_;
};

//
// Client class
// There is an instance per client remote-endpoint in bbf-polt-vomci.yang
//
class BcmPoltClient : public GrpcProcessor
{
    public:
        BcmPoltClient(const tr451_client_endpoint *ep);
        virtual ~BcmPoltClient();
        bcmos_errno Start() override;
        void Stop() override;
        bcmos_errno OmciTxToVomci(OmciPacket &grpc_omci_packet);
        const ClientEndpoint *endpoint() { return &endpoint_; }
        void Disconnected();
        VomciConnection *connection() { return connection_; }

    private:
        bcmos_errno Connect(const Endpoint *entry);
        bcmos_errno Hello(const Endpoint *entry);
        void ListenForOmciTx();
        void CancelListenForOmciTx();
        std::unique_ptr<::tr451_vomci_function_sbi_service::OmciFunctionHelloSbi::Stub> hello_stub_;
        std::unique_ptr<::tr451_vomci_function_sbi_service::OmciFunctionMessageSbi::Stub> message_stub_;
        std::shared_ptr<Channel> channel_;
        ClientEndpoint endpoint_;
        bcmos_task tx_task_;
        ClientContext *listen_context_;
        VomciConnection *connection_;
};

// Generic client/server gRPC processor helpers
GrpcProcessor *bcm_grpc_processor_get_by_name(const char *name, GrpcProcessor::processor_type type);
bcmos_errno bcm_grpc_processor_enable_disable(bool enable, GrpcProcessor::processor_type type);
bool bcm_grpc_processor_is_enabled(GrpcProcessor::processor_type type);

// Get server by name
BcmPoltServer *bcm_polt_server_get_by_name(const char *name);

// Get client by name
BcmPoltClient *bcm_polt_client_get_by_name(const char *name);

bool bcm_tr451_auth_data(string &priv_key, string &my_cert, string &peer_cert);

void bcm_tr451_stats_get(const char **endpoint_name, uint32_t *omci_sent,
   uint32_t *omci_recv, uint32_t *send_errors);

extern const char *polt_name;

#endif