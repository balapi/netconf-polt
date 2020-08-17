# bbf-wt451-polt-sim

*Copyright (c) 2016-2020 Broadcom. All Rights Reserved*

pOLT Simulator for Broadband Forum WT-451 vOMCI project

The project implements pOLT interfaces defined
in WT-451 vOMCI Interface Specifications.

At its NBI pOLT implements the following interfaces:

NETCONF/YANG interface
======================
- bbf-polt-vomci.yang
---- client and server endpoints
---- client and server filters
- generates remote-endpoint-connected/disconnected notification as defined in YMVOMCI-11
- generates bbf-xpon-onu-states:onu-state-change notification (simulation mode only)

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

Simulation functions:
=====================
pOLT is provided with simulation vendor sublayer (See "Vendor interface" below).
This sublayer is controlled by CLI commands that allow to
- add/remove ONU. These CLI commands populate the internal data base and also provoke sending
  NETCONF notification bbf-xpon-onu-states:onu-state-change
- set receive-from-vOMCI handling mode. The following modes are supported:
    - discard: OMCI packets received from vOMCI are silently discarded
    - loopback <skip>:
      - OMCI packets that don't require acknowledge (AR bit in OMCI header is not set) are silently discarded
      - For every <skip>+1 packets that require acknowledge
        - discard <skip> packets
        - toggle AR and AK bits in packet <skip>+1 and send it back to vOMCI as if received from ONU
    - onu_sim <remote_IP_address> <remote_port> [local_port]:
        Forward packets to/from ONU simulator via UDP socket. The packets have the following format:
            - char cterm_name[30]
            - uint16_t onu_id; // in network order
            - <omci packet without MIC>

HowTo Build
===========
The build machine must have gcc, g++, make, cmake and wget installed.
Provided that these prerequisites are met, the build is invoked using
"make" command.
It will pull a number of third party packages, such as grpc, openssh,
libssh, netopeer2, etc. from their repositories, build them and then build
pOLT simulator. The 1st build takes a while because of those bit 3rd party
packages.
Once the build is complete, build artifacts are located in build/fs
subdfirectory.

Build artifacts
======================
All build artifacts are created in build/fs directory. The following artifacts are relative to build/fs.

- bcmolt_netconf_server - pOLT executable implementing all the interfaces above
- start_netconf_server.sh - a simple shell script for starting bcmolt_netconf_server
- tr451_polt_daemon - pOLT executable implementing only gRPC and CLI interfaces above (no NETCONF/YANG)
- start_tr451_polt.sh - a simple shell script for starting tr451_polt_daemon
- daemon_attach - a small application allowing to "attach" to a daemon running in the background and use CLI.
        Note that although daemon_attach gives access to daemon's CLI interface, line editing is limited and
        TAB completion is not supported.
- lib/ - third-party packages compiled as shared libraries
- bin/ - executables provided by third-party libraries (such as sysrepoctl, etc.)
- sysrepo/ - sysrepo repository

Starting the application
========================
The following commands are relative to build/fs directory.

1) netopeer2-server must be started first. It can be done using
bin/start_netconf_server.sh script.

> bin/start_netconf_server.sh [netopeer2-server parameters]

By default netopeer2-server is listening on non-standard port 10830
(instead of the standard 830). It allows starting the server from
regular user. Use "-help" to get the list of supported parameters

2) netopeer2-cli can be used for WT-451 NETCONF configuration. Alternatively,
any other compliant netconf client can be used (for example, "Atom" by Nokia)

# bin/sysrepotool.sh bin/netopeer2-cli
A few relevant netopeer2-cli commands are below
- connect --port 10830
- subscribe
- edit-config --target running --defop  merge --test test-then-set --config=../../netconf_server/bbf-vomci-cli-examples/1-set-tr451-server.yc
- edit-config --target running --defop  merge --test test-then-set --config=../../netconf_server/bbf-vomci-cli-examples/2-add-interfaces-olt.yc

3) Start pOLT simulator

./start_netconf_server.sh [parameters]
```
Below is output of "start_netconf_server.sh -help" command.
bcmolt_netconf_server [-d] [-dummy_tr385] [-log level] [-srlog level] [-tr451_polt_log level] [-syslog]
  -d - debug mode. Stay in the foreground
  -dummy_tr385 - Dummy TR-385 management. Register for some TR-385 events
  -syslog - log to syslog
  -tr451_polt_log error|info|debug TR-451 pOLT log level
  -log error|info|debug - netconf server log level
  -srlog error|info|debug - sysrepo log level
Parameters are self-explanatory.
"-d" is recommented because using CLI in foreground mode is much more convenient
```
CLI interface
=============
pOLT simulator supports CLI interface with built-in help, history and TAB completion.
CLI commands are organized hierarchically in directories.
- To change directory type its name or any unique abbreviation
- To execute command without changing current directory type fully qualified command name (ie /dir1/dir2/cmd)
- To return to the main directory use "/"
- To return to the parent directory use ".."
- To print help for a command use "? command"
- Command can be invoked by any unique abbreviation starting from the 1st character, or using a single
  character that is capitalized in command name

Below are commands that are relevant for operating pOLT simulator:
1) Set logging level
/log/name LOG_ID PRINT_LEVEL FILE_LEVEL
whereas the relevant LOG_IDs are: POLT, NETCONF
PRINT_LEVEL and FILE_LEVEL values are: DEBUG, INFO, ERROR.
PRINT_LEVEL controls output on the screen. FILE_LEVEL controls output to a memory file or syslog.

2) /Polt - pOLT debug directory contains the following commands. The parameters are self-explanatory:
```
?
Directory Polt/ - pOLT Debug
Commands:
    Set_state(2 parms): Enable/disable client/server subsystem
    Endpoint_create(4 parms): Create a client/server endpoint
    endpoint_Delete(2 parms): Delete a client/server endpoint
    Filter(7 parms): Create a client/server filter
    Auth(3 parms): Set authentication keys
    sTats(0 parms): Print statistics
    Onu_add(3 parms): Add ONU
    oNu_delete(3 parms): Delete ONU
    Inject(3 parms): Inject OMCI packet received from ONU
    Rx_mode(1 parms): Set Receive handling mode
```
NOTE: if vOMCI instance should communicate with pOLT simulator using
authenticated connection, private key and certificate location
must be set using "/polt/auth" CLI command BEFORE creating the
relevant client and/or server endpoint.

Implementation
======================

Implementation is split in 2 parts. The first part handles NETCONF/YANG interfaces.
It is implemented as a sysrepo2 application.

NETCONF server
======================

1) Of-the-shelf netopeer2-server application handles NETCONF/YANG messages received via ssh or tls.
netopeer2-server uses sysrepo2 APIs to provoke data change events.

2) sysrepo2 generates a series of events that are "forwarded" waiting application(s) via registered callback functions.

3) Application response (OK or failure with error message) is propagated by sysrepo2 back to netopeer2-server,
which in turn generates NETCONF response.

4) "Notifications" are provoked by sysrepo2 applications and forwarded by sysrepo2 engine to netopeer2-server,
similarly to responses.

The NETCONF/YANG part of TR-451 pOLT simulator is located in netconf_server/ directory
```
netconf_server/
├── bcmolt_netconf_server.c
├── CMakeLists.txt
├── modules
│   ├── b64.c
│   ├── b64.h
│   ├── bbf-vomci
│   │   ├── bbf-vomci.c
│   │   ├── bbf-vomci.h
│   │   └── CMakeLists.txt
│   ├── bbf-xpon-dummy
│   │   ├── bbf-xpon.c
│   │   ├── bbf-xpon.h
│   │   └── CMakeLists.txt
│   ├── bcmolt_netconf_constants.h
│   ├── bcmolt_netconf_module_init.c
│   ├── bcmolt_netconf_module_init.h
│   ├── bcmolt_netconf_module_utils.c
│   ├── bcmolt_netconf_module_utils.h
│   ├── bcmolt_netconf_notifications.c
│   ├── bcmolt_netconf_notifications.h
│   └── CMakeLists.txt
└── start_netconf_server.sh
```
File bbf-vomci.c implements WT-451 bbf-polt-vomci.yang YANG model. Other files listed above are
common utilities and the "main" program.

File bbf-xpon-dummy/bbf-xpon.c is a dummy TR-385 implementation that registers for ietf-interfaces changes and
OKs all changes. This module is initialized if bcm_netconf_server is started with command line option "-dummy_tr385".
This dummy module is required if there is no "real" TR-385 netconf server registered with the same sysrepo2.
Otherwise, all ietf-interface changes will remain in "pending" datastore and some bbf-polt-vomci notifications
will fail because of references to "non-existing" interfaces.

gRPC client/server
======================
```
tr451_vomci_polt
├── bcm_tr451_polt_cli.cc                  <--- CLI commands
├── bcm_tr451_polt_client.cc               <--- gRPC client implementation
├── bcm_tr451_polt_common.cc               <--- Common client & server code: filters, ONU add/delete, common connection handling
├── bcm_tr451_polt.h                       <--- External C interface, for NETCONF server integration
├── bcm_tr451_polt_internal.h              <--- Class definitions, internal functions
├── bcm_tr451_polt_server.cc               <--- gRPC server imnplementation
├── CMakeLists.txt
├── grpc_cli_examples
│   └── examples.txt
├── message_definition
... .proto files
│   ├── tr451_vomci_function_sbi_message.proto
│   └── tr451_vomci_function_sbi_service.proto
├── polt_daemon
│   ├── bcm_tr451_polt_main.c              <--- "alternative" main program for gRPC-only application, without NETCONF/YANG part
│   ├── CMakeLists.txt
│   └── start_tr451_polt.sh                <--- startup shell script
├── README
└── tr451_polt_vendor                      <--- vendor sub-layer
    ├── CMakeLists.txt
    ├── sim
    │   ├── CMakeLists.txt
    │   ├── sim_tr451_polt_vendor.cc          <--- simulation "vendor" implementation
    │   ├── sim_tr451_polt_vendor_cli.cc      <--- simulation "vendor" CLI commands
    │   ├── sim_tr451_polt_vendor_internal.h
    │   └── tr451_polt_vendor_specific.h      <--- simulation "vendor"-specific interfaces
    ├── tr451_polt_for_vendor.h            <--- Helper functions that "vendor" implementation is allowed to use
    └── tr451_polt_vendor.h                <--- Functions and interfaces that "vendor" sub-layer must implement
```
Although NETCONF/YANG server is implemented in C, gRPC client/server is implemented


Vendor interface
================
Internally pOLT package has a vendor sub-layer for interacting with ONU via vendor-specific OLT interface.
Vendor interface is defined in the following header files:
- tr451_polt_vendor/tr451_polt_vendor.h - interfaces that vendor sub-layer must implement
- tr451_polt_vendor/tr451_polt_for_vendor.h - common interfaces that vendor sub-layer can use
In addition each vendor can define vendor-specific interfaces in file
tr451_polt_vendor/<vendor>/tr451_polt_vendor_specific.h.

The only vendor interface released as Open Source is "sim" which stands for simulation.

Class hierarchy
======================

See class-diagram.uml, class-diagram.png
