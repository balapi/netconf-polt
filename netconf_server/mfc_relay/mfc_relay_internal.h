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
#ifndef MFC_RELAY_INTERNAL__H
#define MFC_RELAY_INTERNAL__H

#include <iostream>
#include <memory>
#include <string>
#include <unistd.h>
#include <stdlib.h>
#include <sstream>
#include <iomanip>
#include <grpc++/grpc++.h>
#include <control_relay_service.grpc.pb.h>
extern "C"
{
#include <bcmos_system.h>
#include <bcm_dev_log.h>
#include <bbf-types.h>
}

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
using namespace std;
using control_relay_service::v1::DeviceHello;
using control_relay_service::v1::HelloRequest;
using control_relay_service::v1::HelloResponse;
using control_relay_service::v1::ControlRelayPacket;
using control_relay_service::v1::ControlRelayHelloService;
using control_relay_service::v1::ControlRelayPacketService;

extern "C" bcmos_errno bbf_xpon_get_vsi_and_rule_by_acl_id(bcmolt_access_control_id,
    const char **p_vsi_name, const char **p_rule_name, const char **p_endpoint_name);
extern "C" bcmos_errno bbf_xpon_get_intf_by_vsi_rule_prty(
    const char *vsi_name, const char *rule_name, uint8_t prty,
    bcmolt_flow_key *flow_key, bcmolt_flow_intf_ref *intf_ref,
    bcmolt_service_port_id *svc_port_id);

class MfcPacketEntry: public ControlRelayPacket {
    public:
        STAILQ_ENTRY(MfcPacketEntry) next;
};

class MfcRelay
{
  public:
    MfcRelay(const char *endpoint_name);
    virtual ~MfcRelay();
    const char *endpoint_name() { return endpoint_name_.c_str(); }
    void rx_from_olt(bcmolt_msg *msg);
    MfcPacketEntry *pop_olt_packet();
    void push_olt_packet(MfcPacketEntry *pkt);
    virtual bcmos_errno tx_to_cp (ControlRelayPacket &pkt) = 0;
    bcmos_errno wait_for_olt_packet() {
        const uint32_t poll_timeout = 10000;
        return bcmos_sem_wait(&mfc_ind_sem_, poll_timeout);
    }
    STAILQ_ENTRY(MfcRelay) next;

  private:
    string endpoint_name_;
    STAILQ_HEAD(, MfcPacketEntry) mfc_ind_list_;
    bcmos_sem mfc_ind_sem_;
    bcmos_mutex mfc_ind_lock_;
    bcmos_task tx_to_cp_task_;
};

/* Debug Trace */
extern dev_log_id log_id_mfc_relay;
#define MFC_LOG_ERR(fmt, args...)   BCM_LOG(ERROR, log_id_mfc_relay, fmt, ##args);
#define MFC_LOG_INFO(fmt, args...)  BCM_LOG(INFO, log_id_mfc_relay, fmt, ##args);
#define MFC_LOG_WARN(fmt, args...)  BCM_LOG(WARNING, log_id_mfc_relay, fmt, ##args);
#define MFC_LOG_DBG(fmt, args...)   BCM_LOG(DEBUG, log_id_mfc_relay, fmt, ##args);

extern bcmolt_mfc_connect_disconnect_cb mfc_conn_discon_cb;
extern void *mfc_conn_discon_cb_data;

bcmos_errno mfc_relay_tx_to_olt(const ControlRelayPacket &grpc_packet);
MfcRelay *mfc_relay_get_by_endpoint_name(const char *endpoint_name);

#endif /* MFC_RELAY_INTERNAL__H */