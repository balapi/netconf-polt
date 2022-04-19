if(${ONU_MGMT})
    bcm_module_name(onu_mgmt)
    bcm_module_header_paths(PUBLIC .)
    bcm_module_dependencies(PUBLIC host_dev_log onu_mgmt_model omci_svc onu_mgmt_test)
    if(NOT OPEN_SOURCE)
        bcm_module_dependencies(PUBLIC dpoe2_svc)
    endif()

    if(${ONU_MGMT_STUB})
        bcm_module_srcs(
            onu_mgmt_stubs.c)
    else()
        bcm_module_srcs(
            onu_mgmt.c)
    endif()

    bcm_create_lib_target()
endif()
