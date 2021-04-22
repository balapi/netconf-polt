# Netconf modules
if(NETCONF_SERVER)
    bcm_module_name(netconf_modules)
    bcm_module_dependencies(PUBLIC os dev_log sysrepo libnetconf2)
    if(TR451_VOMCI_POLT)
        bcm_module_dependencies(PUBLIC netconf_bbf-polt-vomci)
    endif()
    if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/bbf-xpon OR EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/bbf-xpon-dummy)
        bcm_module_dependencies(PUBLIC netconf_bbf-xpon)
    endif()
    if(TR385_ISSUE2)
        bcm_module_definitions(PUBLIC -DTR385_ISSUE2)
    endif()
    if(USE_OBBAA_YANG_MODELS)
        bcm_module_definitions(PUBLIC -DOB_BAA)
    endif()
    bcm_module_header_paths(PUBLIC .)
    bcm_module_srcs(
        b64.c
        bcmolt_netconf_module_utils.c
        bcmolt_netconf_module_init.c
        bcmolt_netconf_notifications.c)
    bcm_create_lib_target()

    if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/bbf-xpon)
        bcm_add_subdirectory(bbf-xpon)
    else()
        bcm_add_subdirectory(bbf-xpon-dummy)
    endif()
    if(TR451_VOMCI_POLT)
        bcm_add_subdirectory(bbf-vomci)
    endif()
endif()
