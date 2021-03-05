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


#ifndef _H_BBF_XPON_CONSTANTS_
#define _H_BBF_XPON_CONSTANTS_

#include <bcmolt_netconf_constants.h>

#define BBF_XPON_MODULE_NAME                        "bbf-xpon"
#define BBF_XPONVANI_MODULE_NAME                    "bbf-xponvani"
#define BBF_XPON_IFTYPE_MODULE_NAME                 "bbf-xpon-if-type"
#define BBF_XPONGEMTCONT_MODULE_NAME                "bbf-xpongemtcont"
#define BBF_L2_FORWARDING_MODULE_NAME               "bbf-l2-forwarding"
#define BBF_HARDWARE_MODULE_NAME                    "bbf-hardware"
#define BBF_HARDWARE_TYPES_MODULE_NAME              "bbf-hardware-types"
#ifdef TR385_ISSUE2
#define BBF_XPON_ONU_STATES_MODULE_NAME             "bbf-xpon-onu-state"
#else
#define BBF_XPON_ONU_STATES_MODULE_NAME             "bbf-xpon-onu-states"
#endif
#define BBF_QOS_CLASSIFIERS_MODULE_NAME             "bbf-qos-classifiers"
#define BBF_QOS_POLICIES_MODULE_NAME                "bbf-qos-policies"
#define BBF_LINK_TABLE_MODULE_NAME                  "bbf-link-table"

#define IETF_INTERFACES_MODULE_NAME                 "ietf-interfaces"
#define IETF_HARDWARE_MODULE_NAME                   "ietf-hardware"
#define BBF_L2_DHCPV4_RELAY_MODULE_NAME             "bbf-l2-dhcpv4-relay"
#define BBF_INTERFACE_PON_REFERENCE                 "bbf-interface-port-reference"

#define BBF_XPON_XPON_PATH_BASE                     "/bbf-xpon:xpon"
#define BBF_XPON_XPON_STATE_PATH_BASE               "/bbf-xpon:xpon-state"
#define BBF_XPON_WAVELEN_PROFILE_PATH_BASE          "/bbf-xpon:xpon/wavelength-profiles/wavelength-profile"
#define BBF_XPON_MULTICAST_GEM_PATH_BASE            "/bbf-xpon:xpon/multicast-gemports/multicast-gemport"
#define BBF_XPON_INTERFACE_PATH_BASE                "/ietf-interfaces:interfaces"
#define BBF_XPON_INTERFACE_STATE_PATH_BASE          "/ietf-interfaces:interfaces-state/interface"
#define BBF_XPON_TD_PROFILE_PATH_BASE               "/bbf-xpongemtcont:xpongemtcont/traffic-descriptor-profiles/traffic-descriptor-profile"
#define BBF_XPON_TCONT_PATH_BASE                    "/bbf-xpongemtcont:xpongemtcont/tconts/tcont"
#define BBF_XPON_TCONT_STATE_PATH_BASE              "/bbf-xpongemtcont:xpongemtcont-state/tconts/tcont"
#define BBF_XPON_GEM_PATH_BASE                      "/bbf-xpongemtcont:xpongemtcont/gemports/gemport"
#define BBF_XPON_GEM_STATE_PATH_BASE                "/bbf-xpongemtcont:xpongemtcont-state/gemports/gemport"
#define BBF_LINK_TABLE_PATH_BASE                    "/bbf-link-table:link-table/link-table"
#define BBQ_QOS_CLASSIFIER_PATH_BASE                "/bbf-qos-classifiers:classifiers/classifier-entry"
#define BBQ_QOS_POLICY_PATH_BASE                    "/bbf-qos-policies:policies/policy"
#define BBQ_QOS_POLICY_PROFILE_PATH_BASE            "/bbf-qos-policies:qos-policy-profiles/policy-profile"
#define BBF_FORWARDING_TABLE_PATH_BASE              "/bbf-l2-forwarding:forwarding/forwarders/forwarder"
#define BBF_FWD_SPLIT_HORIZON_PROFILE_PATH_BASE     "/bbf-l2-forwarding:forwarding/split-horizon-profiles/split-horizon-profile"
#define BBF_FWD_DATABASE_PATH_BASE                  "/bbf-l2-forwarding:forwarding/forwarding-databases/forwarding-database"
#define BBF_HARDWARE_PATH_BASE                      "/ietf-hardware:hardware/component"
#ifdef TR385_ISSUE2
#define BBF_HARDWARE_STATE_PATH_BASE                "/ietf-hardware:hardware/component"
#else
#define BBF_HARDWARE_STATE_PATH_BASE                "/ietf-hardware:hardware-state/component"
#endif
#define BBF_XPON_DHCPR_PROFILE_PATH_BASE            "/bbf-l2-dhcpv4-relay:l2-dhcpv4-relay-profiles/l2-dhcpv4-relay-profile"

#define BBF_XPON_V_ANI_CONFIG_DATA_PREFIX           "bbf-xponvani:v-ani/v-ani-config-data/"

#define BBF_XPON_V_ANI_SERIAL                       "expected-serial-number"
#define BBF_XPON_V_ANI_REGISTRATION_ID              "expected-registration-id"
#define BBF_XPON_V_ANI_PARENT_REF                   "parent-ref"
#define BBF_XPON_V_ANI_SERIAL_PATH                  BBF_XPON_V_ANI_CONFIG_DATA_PREFIX BBF_XPON_V_ANI_SERIAL
#define BBF_XPON_V_ANI_REGISTRATION_ID_PATH         BBF_XPON_V_ANI_CONFIG_DATA_PREFIX BBF_XPON_V_ANI_REGISTRATION_ID
#define BBF_XPON_V_ANI_PARENT_REF_PATH              BBF_XPON_V_ANI_CONFIG_DATA_PREFIX BBF_XPON_V_ANI_PARENT_REF

#define IANA_IFTYPE_PREFIX                          "iana-if-type:"
#define BBF_IFTYPE_PREFIX                           "bbf-if-type:"
#define BBF_XPON_IFTYPE_PREFIX                      "bbf-xpon-if-type:"
#define BBF_XPON_IFTYPE_CHANNEL_GROUP               BBF_XPON_IFTYPE_PREFIX "channel-group"
#define BBF_XPON_IFTYPE_CHANNEL_PARTITION           BBF_XPON_IFTYPE_PREFIX "channel-partition"
#define BBF_XPON_IFTYPE_CHANNEL_PAIR                BBF_XPON_IFTYPE_PREFIX "channel-pair"
#define BBF_XPON_IFTYPE_CHANNEL_TERMINATION         BBF_XPON_IFTYPE_PREFIX "channel-termination"
#define BBF_XPON_IFTYPE_V_ANI                       BBF_XPON_IFTYPE_PREFIX "v-ani"
#define BBF_XPON_IFTYPE_ANI                         BBF_XPON_IFTYPE_PREFIX "ani"
#define BBF_XPON_IFTYPE_OLT_V_ENET                  BBF_XPON_IFTYPE_PREFIX "olt-v-enet"
#define BBF_XPON_IFTYPE_ONU_V_ENET                  BBF_XPON_IFTYPE_PREFIX "onu-v-enet"
#define BBF_IFTYPE_VLAN_SUBIF                       BBF_IFTYPE_PREFIX "vlan-sub-interface"
#define IANA_IFTYPE_ENET                            "iana-if-type:ethernetCsmacd"

#define BBF_GEMTCONT_PREFIX                         "bbf-xpongemtcont:"
#define BBF_TRAFFIC_DESCR_PROFILE_PREFIX            BBF_GEMTCONT_PREFIX "traffic-descriptor-profile"

#endif
