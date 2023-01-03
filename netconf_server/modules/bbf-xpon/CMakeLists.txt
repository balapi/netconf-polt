# Netconf modules
if(NETCONF_SERVER)
    bcm_module_name(netconf_bbf-xpon)
    bcm_module_dependencies(PUBLIC os sysrepo libnetconf2 netconf_modules onu_mgmt api)
    if(TR451_VOMCI_POLT)
        bcm_module_dependencies(PUBLIC tr451_polt)
    endif()
    bcm_module_header_paths(PUBLIC .)
    bcm_module_definitions(PUBLIC -DNETCONF_MODULE_BBF_XPON)
    bcm_module_srcs(
        bbf-xpon.c
        bbf-xpon-utils.c
        bbf-xpon-xpon.c
        bbf-xpon-channel-group.c
        bbf-xpon-channel-pair.c
        bbf-xpon-channel-partition.c
        bbf-xpon-channel-termination.c
        bbf-xpon-v-ani.c
        bbf-xpon-ani.c
        bbf-xpon-v-ani-v-enet.c
        bbf-xpon-ani-v-enet.c
        bbf-xpon-gem.c
        bbf-xpon-tcont.c
        bbf-link-table.c
        bbf-xpon-enet.c
        bbf-xpon-qos.c
        bbf-xpon-vlan-subif.c
        bbf-xpon-forwarder.c
        bbf-hardware.c
        bbf-xpon-apply-flow-config.c
        dhcp-relay-utils.c
        bbf-l2-dhcpv4-relay.c
        bbf-xpon-tm-mgmt.c)
    if(NOT OPEN_SOURCE)
        bcm_module_srcs(bbf-xpon-proprietary.c)
    endif()
    if(MFC_RELAY)
        bcm_module_dependencies(PUBLIC netconf_bbf-polt-mfc)
    endif()
    bcm_create_lib_target()
endif()
