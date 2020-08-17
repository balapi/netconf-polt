# netconf-polt

**Copyright (c) 2016-2020 Broadcom. All Rights Reserved**

TR-383, TR-385, WT-451 NETCONF Server

The project implements a NETCONF server for BCM6862x,BCM6865x-based PON OLT.
It uses a
- NETCONF server https://github.com/CESNET/netopeer2 project
- NETCONF datastore https://github.com/sysrepo
- Broadcom OLT API https://github.com/balapi/bal-api-3.6.3.3

At its netconf-polt project implements the following NBI interfaces:

NETCONF/YANG interface
======================
- A subset of TR-385i2 (XGS PON only)
- A subset of TR-383a3
- WT-451 YANG models (bbf-polt-vomci.yang)
---- client and server endpoints
---- client and server filters

gRPC interface
==============
- Client and Server that can be active simultaneously.
  Multiple client remote-endpoints and server listen-endpoints can be provisioned via
  YANG interface or using CLI commands
- Both pOLT gRPC client and pOLT gRPC server support OmciFunctionHelloSbi and OmciFunctionMessageSbi services
  defined in WT-451 vOMCI Interface Specifications
- Both gRPC client and gRPC server support secured and unsecured connection. By default connections are
  unsecured. In order to create/expect secure connection cerificate file locations must
  be provisioned using CLI command
- new/dropped connactions are reported using NETCONF notifications defined in YMVOMCI-11

ONU Management:
===============
netconf-polt supports the following ONU management options:
- TR-385,TR-385 NETCONF/YANG termination and embedded OMCI stack
- Disagregated ONU management using external WT-451 vOMCI instances

For details see netconf_server/doc/ITU-T PON WT-383,385,451 NETCONF Server PoC.pdf
