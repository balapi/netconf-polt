# Netconf modules
if(NETCONF_SERVER AND TR451_VOMCI_POLT)
    bcm_module_name(netconf_bbf-polt-vomci)
    bcm_module_dependencies(PUBLIC sysrepo libnetconf2 netconf_modules tr451_polt)
    bcm_module_header_paths(PUBLIC .)
    bcm_module_definitions(PUBLIC -DNETCONF_MODULE_BBF_POLT_VOMCI)
    bcm_module_srcs(
        bbf-vomci.c)
    bcm_create_lib_target()
endif()
