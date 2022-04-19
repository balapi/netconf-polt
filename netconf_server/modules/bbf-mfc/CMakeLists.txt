# Netconf modules
if(MFC_RELAY)
    bcm_module_name(netconf_bbf-polt-mfc)
    bcm_module_dependencies(PUBLIC sysrepo netconf_modules mfc_relay)
    bcm_module_header_paths(PUBLIC .)
    bcm_module_srcs(bbf-mfc.c)
    bcm_create_lib_target()
endif()
