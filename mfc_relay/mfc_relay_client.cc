#include <iostream>
#include <memory>
#include <string>
#include <unistd.h>
#include <stdlib.h>
#include <sstream>
#include <iomanip>
#include <grpc++/grpc++.h>
#include "control_relay_service.grpc.pb.h"
#include <mfc_relay_client.h>
#include "../netconf_server/modules/bbf-xpon/bbf-types.h"

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
using control_relay_service::DeviceHello;
using control_relay_service::HelloRequest;
using control_relay_service::HelloResponse;
using control_relay_service::ControlRelayPacket;
using control_relay_service::ControlRelayHelloService;
using control_relay_service::ControlRelayPacketService;

extern "C" uint32_t find_flow_id_by_sub_interface (const char *name, const bbf_match_criteria *match);


char ga1Ipaddressandport[25]={0};
char ga1Temp[25]={0};
int golt = 0;

bool stopping;
    static bcm_mfc_grpc_client_connect_disconnect_cb mfc_client_conn_discon_cb;
    static void *mfc_client_conn_discon_cb_data;
tGlobMfcConfig gGlobalMfcConfig;

#define MFC_DEBUG_WANTED 0
void Mfc_tx(bcmolt_access_control_receive_eth_packet *eth_packet);
STAILQ_HEAD(, MfcPacketEntry) mfc_ind_list;
bcmos_sem mfc_ind_sem;
bcmos_mutex mfc_ind_lock;
bcmos_task gListen_task_;
bcmos_task gTx_task_;

class MfcPacketEntry: public ControlRelayPacket {
    public:
        STAILQ_ENTRY(MfcPacketEntry) next;
};

class HelloServiceClient {
    public:
	std::unique_ptr<::control_relay_service::ControlRelayHelloService::Stub> hello_stub_;
	std::unique_ptr<::control_relay_service::ControlRelayPacketService::Stub> message_stub_;
	ClientContext *listen_context_;
	std::shared_ptr<Channel> channel_;

	void ListenForMfcRelayTx();
	bcmos_errno mfc_tx_to_cp (ControlRelayPacket &pkt);
	void task();
	void Disconnected();

	bcmos_errno SayHello()
	{
	    HelloRequest request;
	    HelloResponse response;
	    ClientContext context;
	    
	    DeviceHello *olt = new DeviceHello();
	    olt->set_device_name(gGlobalMfcConfig.DeviceName);
	    request.set_allocated_device(olt);
	    
	    hello_stub_ = ::control_relay_service::ControlRelayHelloService::NewStub(channel_);
	    Status status = hello_stub_->Hello(&context, request, &response);

	    if (!status.ok())
	    {
	         std::cout << status.error_message() << std::endl;
	         std::cout << status.error_code() << std::endl;
	         return BCM_ERR_IO;
	    }
	    return BCM_ERR_OK;
	}	
};

HelloServiceClient *gclient;
static inline bcmos_bool is_vlan_tpid(uint16_t tpid)
{
        return (tpid == 0x8100 || tpid == 0x88A8 || tpid == 0x9100);
}

void parse_packet (uint8_t *packet, uint32_t length, bbf_match_criteria *match, uint16_t *ethtype)
{
    uint16_t p_tpid;
    uint16_t vlan;
    int offset = 12;
    memset(match, 0, sizeof(*match));
    p_tpid = *(const uint16_t *)(packet + offset);
    if (is_vlan_tpid(ntohs(p_tpid)))
    {
        BBF_DOT1Q_TAG_PROP_SET(&match->vlan_tag_match.tags[0], tag_type, ntohs(*(const uint16_t *)(packet + offset)));
        offset += 2;
        vlan = ntohs(*(const uint16_t *)(packet + offset));
        BBF_DOT1Q_TAG_PROP_SET(&match->vlan_tag_match.tags[0], vlan_id, (vlan & 0xfff));
        BBF_DOT1Q_TAG_PROP_SET(&match->vlan_tag_match.tags[0], pbit, (vlan >> 13));
        offset += 2;
        match->vlan_tag_match.num_tags = 1;
        match->vlan_tag_match.tag_match_types[0] = BBF_VLAN_TAG_MATCH_TYPE_VLAN_TAGGED; 
    }
    if (is_vlan_tpid(ntohs(*(const uint16_t *)(packet + offset))))
    {
        BBF_DOT1Q_TAG_PROP_SET(&match->vlan_tag_match.tags[1], tag_type, ntohs(*(const uint16_t *)(packet + offset)));
        offset += 2;
        vlan = ntohs(*(const uint16_t *)(packet + offset));
        BBF_DOT1Q_TAG_PROP_SET(&match->vlan_tag_match.tags[1], vlan_id, (vlan & 0xfff));
        BBF_DOT1Q_TAG_PROP_SET(&match->vlan_tag_match.tags[1], pbit, (vlan >> 13));
        offset += 2;
        match->vlan_tag_match.num_tags = 2;
        match->vlan_tag_match.tag_match_types[1] = BBF_VLAN_TAG_MATCH_TYPE_VLAN_TAGGED; 
    }
    *ethtype = ntohs(*(const uint16_t *)(packet + offset));
}
bcmos_errno bcm_packet_grpc_to_olt(const ControlRelayPacket *grpc_packet, bcmolt_access_control_receive_eth_packet *bcm_packet)
{
     char RxPkt[1500]={0};
     char temp[2];
     char sub_intf_name[100] = {0};
     uint8_t RxPktInHex[1500]={0};
     int u1Byte = 0,pktlen=0,len = 0;
     const uint8_t *ip_hdr;
     const uint8_t *payload = NULL;
     char *endptr = NULL;
     uint16_t flowtype = 0;
     uint16_t ethtype = 0;
     //const  interface_info *iface = NULL;
     bbf_match_criteria match;
     bcmolt_flow_key flow_key = {};
     bcmolt_flow_send_eth_packet packet_out;
     bcmolt_bin_str packet_out_buffer;
     bcmos_errno err;

     len = strlen(grpc_packet->packet().c_str());
     strncpy (RxPkt, grpc_packet->packet().c_str(), len);

     flowtype = atoi(grpc_packet->originating_rule().c_str());
     strcpy (sub_intf_name, grpc_packet->device_interface().c_str());

     for (u1Byte = 0 ; u1Byte <= len-2; u1Byte = u1Byte+2)
     {
         sprintf(temp, "%c%c", RxPkt[u1Byte], RxPkt[u1Byte+1]);
         RxPktInHex[pktlen] = strtol(temp, NULL, 16);
         pktlen++;
     }

     packet_out_buffer.len = pktlen;
     packet_out_buffer.arr = RxPktInHex;

     parse_packet(RxPktInHex,grpc_packet->packet().size(), &match, &ethtype);
     flow_key.flow_id = find_flow_id_by_sub_interface (sub_intf_name, &match);
     if (flow_key.flow_id == 0)
     {
#if MFC_DEBUG_WANTED
         printf("\n === No Matching Flow ID present === \n");
#endif
        return BCM_ERR_PARM;
     }
     if (flowtype == BCMOLT_FLOW_TYPE_DOWNSTREAM)
         flow_key.flow_type = BCMOLT_FLOW_TYPE_DOWNSTREAM;
     else
         flow_key.flow_type = BCMOLT_FLOW_TYPE_UPSTREAM;
#if MFC_DEBUG_WANTED
     printf("\n ====== FLOW_ID %d interface %s Flow_type = %s ======\n",flow_key.flow_id, sub_intf_name, bcmolt_enum_stringval(bcmolt_flow_type_string_table, flow_key.flow_type));
#endif

     BCMOLT_OPER_INIT(&packet_out, flow, send_eth_packet, flow_key);
     BCMOLT_MSG_FIELD_SET(&packet_out, buffer, packet_out_buffer);
     BCMOLT_MSG_FIELD_SET(&packet_out, inject_type, BCMOLT_INJECT_TYPE_INJECT_AT_INGRESS);

     err = bcmolt_oper_submit(golt, &packet_out.hdr);
     if (err != BCM_ERR_OK)
     {
#if MFC_DEBUG_WANTED
         printf("\n Failed to Forward the Packet\n");
#endif
         return err;
     }
     else
     {
#if MFC_DEBUG_WANTED
         printf("\n Packet forwarded: %d bytes\n", pktlen);
#endif
     }
     return BCM_ERR_OK;
}

bcmos_errno Mfc_Relay_Dispatch (const ControlRelayPacket &tx_packet)
{
    bcmolt_access_control_receive_eth_packet bcm_mfc_msg;
    bcmos_errno err;

    err = bcm_packet_grpc_to_olt(&tx_packet, &bcm_mfc_msg);
    if (err != BCM_ERR_OK)
        return err;
    return BCM_ERR_OK;
}

void HelloServiceClient::ListenForMfcRelayTx()
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
	std::unique_ptr<::grpc::ClientReaderInterface< ::control_relay_service::ControlRelayPacket>> reader(
			message_stub_->ListenForPacketRx(listen_context_, request));
	while (reader->Read(&tx_packet))
	{
#if MFC_DEBUG_WANTED
            printf("\n Recieved packet structure \n device %s \n interface %s \n rule %s \n pkt %s\n",tx_packet.device_name().c_str(),tx_packet.device_interface().c_str(),tx_packet.originating_rule().c_str(),tx_packet.mutable_packet()->c_str());
#endif
            err = Mfc_Relay_Dispatch(tx_packet);
            if(err != BCM_ERR_OK)
            {
#if MFC_DEBUG_WANTED
                printf("\n Failed to forward packet. Error %s\n",bcmos_strerror(err));
#endif
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

bcmos_errno HelloServiceClient::mfc_tx_to_cp(ControlRelayPacket &pkt)
{
    ClientContext context;
    ::google::protobuf::Empty response;
    Status status;
    status = message_stub_->PacketTx(&context, pkt, &response);
    return status.ok() ? BCM_ERR_OK: BCM_ERR_IO;
}

MfcPacketEntry* pop()
{
    MfcPacketEntry *mfc_packet;
    bcmos_mutex_lock(&mfc_ind_lock);
    mfc_packet = STAILQ_FIRST(&mfc_ind_list);

    if (mfc_packet != nullptr)
    {
        STAILQ_REMOVE_HEAD(&mfc_ind_list, next);
    }

    bcmos_mutex_unlock(&mfc_ind_lock);
    return mfc_packet;

}

bcmos_errno waitforpacket()
{
	uint32_t poll_timeout = 10000;
	return bcmos_sem_wait(&mfc_ind_sem, poll_timeout);
}

static int _client_tx_task_handler(long data)
{
    bcmos_errno err;
    HelloServiceClient *tx = (HelloServiceClient *)data;
    while (1)
    {
	err = waitforpacket();
	if (err != BCM_ERR_OK && err != BCM_ERR_TIMEOUT)
	{
#if MFC_DEBUG_WANTED
		printf("\r\n ===== Failed or Timeout for waiting the packet  =====\r\n");
#endif
		break;
	}
	MfcPacketEntry *pkt = pop();

        if (pkt == nullptr)
                continue;

        if (gGlobalMfcConfig.bIsStarted == 1)
        {        
            err = tx->mfc_tx_to_cp(*pkt);

            if (err != BCM_ERR_OK)
            {
#if MFC_DEBUG_WANTED
                printf("\r\n==== packet transmission to the BAA failed ====\r\n");
#endif
            }
        }
    }
    return 0;
}

void HelloServiceClient::Disconnected()
{
    if (!stopping)
    {
        stopping = true;
        if (listen_context_ != nullptr)
        {
            listen_context_->TryCancel();
            while (listen_context_ != nullptr)
            {
            }
        }
        bcmos_task_destroy(&gTx_task_);
        if (mfc_client_conn_discon_cb != nullptr)
        {
            mfc_client_conn_discon_cb (mfc_client_conn_discon_cb_data,
                    gGlobalMfcConfig.EndpointName, gGlobalMfcConfig.AccessName, 0);
        }
    }
}

void HelloServiceClient::task()
{
     bcmos_errno err;
     bcmos_task_parm tp = {};
     tp.name = "pkt_tx";
     tp.priority = TASK_PRIORITY_TRANSPORT_PROXY;
     tp.handler = _client_tx_task_handler;
     tp.data = (long)this;

     err = bcmos_task_create(&gTx_task_, &tp);
     if (err != BCM_ERR_OK)
     {
#if MFC_DEBUG_WANTED
         printf("\r\n==== Tast Creation of TX Failed ====\r\n");
#endif
     }
}

static int Listening_task_handler(long data)
{
    bcmos_errno err = BCM_ERR_OK;
    bool ready = false;
    stopping = false;
    gGlobalMfcConfig.bIsStarted = 1;
    HelloServiceClient *client = new HelloServiceClient;
    client->listen_context_ = nullptr;

    gclient = client;
    do
    {
        do
        {
            while(!ready && !stopping)
            {
                memset (ga1Temp, 0, 25);
                sprintf (ga1Temp,"%s:%d",gGlobalMfcConfig.a1Ipaddress, gGlobalMfcConfig.port);
#if MFC_DEBUG_WANTED
                printf ("\r\n IP and port = %s \r\n", ga1Temp);
#endif
                client->channel_ = grpc::CreateChannel(ga1Temp, grpc::InsecureChannelCredentials());
                if (client->channel_ == nullptr || client->channel_->GetState(true) == GRPC_CHANNEL_SHUTDOWN)
                {
                    bcmos_usleep(1*1000000);
                    ready =false;
                }
                else
                {
                    ready = true;
                }
            }
            if (ready == true)
            {
                err = client->SayHello();
                if (err != BCM_ERR_OK)
                {
                    bcmos_usleep(1*1000000);
                }
            }
        } while (err != BCM_ERR_OK && !stopping);
        if (stopping)
            break;

        client->message_stub_ = ::control_relay_service::ControlRelayPacketService::NewStub(client->channel_);
        client->task();
        client->ListenForMfcRelayTx();
        client->Disconnected();

    }while(!stopping);

    gGlobalMfcConfig.bIsStarted = 0;
    delete client;
    return BCM_ERR_OK;
}

void Mfc_tx(bcmolt_access_control_receive_eth_packet *eth_packet)
{
	int u1Byte = 0;
	MfcPacketEntry *pkt = new MfcPacketEntry();
	pkt->set_device_name(gGlobalMfcConfig.DeviceName);
	pkt->set_device_interface(to_string(eth_packet->data.interface_ref.intf_id));
	//pkt->set_originating_rule("rule");
        if (eth_packet->data.interface_ref.intf_type == BCMOLT_INTERFACE_TYPE_PON)
        {
	     pkt->set_originating_rule(to_string(BCMOLT_FLOW_TYPE_UPSTREAM));
        }
        else
        {
	     pkt->set_originating_rule(to_string(BCMOLT_FLOW_TYPE_DOWNSTREAM));
        }
	std::stringstream ss;
	ss << std::hex << std::setfill('0');
	for (u1Byte=0; u1Byte < (eth_packet->data.buffer.len); u1Byte++)
	{
		ss << std::setw(2) << static_cast<unsigned>(eth_packet->data.buffer.arr[u1Byte]);
	}
	std::string StringBuffer = ss.str();
	pkt->set_packet(StringBuffer);
#if MFC_DEBUG_WANTED
            printf("\r\n interface %s \r\n",pkt->mutable_device_interface()->c_str());
            printf("\r\n flow type %s \r\n",pkt->mutable_originating_rule()->c_str());
            printf ("\r\n Packet After copying to GRPC structure = %s len = %d\r\n", pkt->mutable_packet()->c_str(), eth_packet->data.buffer.len);
#endif
        bcmos_mutex_lock(&mfc_ind_lock);

        STAILQ_INSERT_TAIL(&mfc_ind_list, pkt, next);
        // Kick thread that unwinds the queue if the queue was empty
        if (STAILQ_FIRST(&mfc_ind_list) == pkt)
	{
            bcmos_sem_post(&mfc_ind_sem);
	}

        bcmos_mutex_unlock(&mfc_ind_lock);
}

static void bcmolt_Rx_Callback(bcmolt_oltid olt, bcmolt_msg *msg)
{
	bcmolt_access_control_receive_eth_packet *eth_packet = (bcmolt_access_control_receive_eth_packet *)msg;
	/*Transmitting the packet from OLT to BAA*/
	Mfc_tx(eth_packet);
}

bcmos_errno bcm_mfc_relay_init(int olt)
{
    STAILQ_INIT(&mfc_ind_list);
    bcmos_mutex_create(&mfc_ind_lock, 0, "mfc_ind");
    bcmos_sem_create(&mfc_ind_sem, 0, 0, "mfc_ind");
    bcmos_task_parm tp = {};
    bcmos_errno err;
    golt = olt;
    /*registering rx callback*/
    bcmolt_rx_cfg rx_cfg = {};
    rx_cfg.obj_type = BCMOLT_OBJ_ID_ACCESS_CONTROL;
    rx_cfg.rx_cb = bcmolt_Rx_Callback;
    rx_cfg.subgroup = BCMOLT_ACCESS_CONTROL_AUTO_SUBGROUP_RECEIVE_ETH_PACKET;
    err = bcmolt_ind_subscribe(olt, &rx_cfg);
    if (err != BCM_ERR_OK)
    {
#if MFC_DEBUG_WANTED
    	std::cout << "==== Subscription failed  ====\n";
#endif
        return err;
    }

    bcm_mfc_relay_cli_init ();

    return BCM_ERR_OK;
}

bcmos_errno
bcm_mfc_relay_start ()
{
#if MFC_DEBUG_WANTED
        printf("====== bcm_mfc_relay_started ==============\n");
#endif
    bcmos_task_parm tp = {};
    bcmos_errno err;
    tp.name = "polt_client_server";
    tp.priority = TASK_PRIORITY_VOMCI_DOLT_CLIENT;
    tp.handler = Listening_task_handler;
    tp.data = (long)1;
    err = bcmos_task_create(&gListen_task_, &tp);
    if (err == BCM_ERR_OK)
    {
        if (mfc_client_conn_discon_cb != nullptr)
        {
            mfc_client_conn_discon_cb (mfc_client_conn_discon_cb_data,
                    gGlobalMfcConfig.EndpointName, gGlobalMfcConfig.AccessName, 1);
        }
    }
    return err;
}

bcmos_errno
bcm_mfc_relay_stop ()
{
    if (gGlobalMfcConfig.bIsStarted == 1)
    {
        gclient->Disconnected ();
    }
    return BCM_ERR_OK;
}

bcmos_errno 
bcm_mfc_grpc_client_enable_disable(bcmos_bool enable)
{
    bcmos_errno err = BCM_ERR_OK;
    char a1TempIpAddress[50]={0};
    if (enable)
    {
        if ((gGlobalMfcConfig.bIsStarted == 0) &&
            (gGlobalMfcConfig.port != 0) &&
            (strcmp (gGlobalMfcConfig.a1Ipaddress, a1TempIpAddress)))
        {
            /*start the session and update the value in the session start func*/
            err = bcm_mfc_relay_start ();
        }
    }
    else
    {
        /* kill the sesion and dont clear params */
        if (gGlobalMfcConfig.bIsStarted  == 1)
        {
            bcm_mfc_relay_stop ();
        }
    }

    return err;
}
bcmos_errno
bcm_mfc_grpc_client_edit_config (const char * endpoint_name, const char * access_point_name,uint16_t
        port,const char * host_name)
{
    bool b1StartSession = 0;
    char a1TempIpAddress[50]={0};
    bcmos_errno err = BCM_ERR_OK;

    if (gGlobalMfcConfig.bIsStarted ==  1)
    {
        if ((strcmp (endpoint_name, gGlobalMfcConfig.EndpointName)) ||
            (strcmp (access_point_name,  gGlobalMfcConfig.AccessName)))
        {
            return err;
        }
    }
    else
    {
        if (endpoint_name != NULL)
        {
            strcpy (gGlobalMfcConfig.EndpointName, endpoint_name);
        }
        if (access_point_name != NULL)
        {
            strcpy (gGlobalMfcConfig.AccessName, access_point_name);
        }
    }

    if ((port != 0) && (gGlobalMfcConfig.port !=  port))
    {
        gGlobalMfcConfig.port = port;
        b1StartSession = 1;
    }
    else if ((host_name != NULL) &&
            (strcmp(gGlobalMfcConfig.a1Ipaddress, host_name)))
    {
        strcpy (gGlobalMfcConfig.a1Ipaddress, host_name);
        b1StartSession = 1;
    }

    if (b1StartSession == 1)
    {
        if (gGlobalMfcConfig.bIsStarted ==  1)
        {
            /* stop the existing session and reset the start flag*/
            bcm_mfc_relay_stop ();
        }
        /* Trigger the session */
        if ((gGlobalMfcConfig.bIsStarted == 0) &&
            (gGlobalMfcConfig.port != 0) &&
            (strcmp (gGlobalMfcConfig.a1Ipaddress, a1TempIpAddress)))
        {
            err = bcm_mfc_relay_start ();   
        }
    }

    return err;
    /* check if port != 0 and host name != NULL , based on that fill that value and disconnect and connect and before that compar e the endpoing name and access name if different return , if same proceed, if first store. */

}

bcmos_errno
Mfc_disconnect()
{
    if (gGlobalMfcConfig.bIsStarted == 1)
    {
        /* stop the existing session */
        bcm_mfc_relay_stop ();
    }

    return BCM_ERR_OK;
}

bcmos_errno 
bcm_mfc_grpc_client_delete (const char * endpoint_name)
{
    /* clear the access name, endpoint name, and port and ip */
    /* delete the session */
    if (strcmp (endpoint_name, gGlobalMfcConfig.EndpointName))
    {
        return BCM_ERR_OK;
    }

    if (gGlobalMfcConfig.bIsStarted == 1)
    {
        /* stop the existing session */
        bcm_mfc_relay_stop ();
    }
    memset (&gGlobalMfcConfig, 0, sizeof (tGlobMfcConfig));

    return BCM_ERR_OK;
}

bcmos_errno
bcm_mfc_grpc_client_connect_disconnect_cb_register  (bcm_mfc_grpc_client_connect_disconnect_cb cb, void *data)
{
    mfc_client_conn_discon_cb = cb;
    mfc_client_conn_discon_cb_data = data;
    return BCM_ERR_OK;
}

