if(${ONU_MGMT})
    bcm_module_name(omci_svc)
    bcm_module_cflags(PRIVATE -Wno-redundant-decls)
    bcm_module_dependencies(PUBLIC system_types dev_log api onu_mgmt_model omci_stack onu_mgmt_test)

#if(${ONU_MGMT_OCS_STACK})
#    bcm_module_definitions(PUBLIC -DUSE_OCS_OMCI_STACK)
#        bcm_add_subdirectory(ocs_adapter)
#    else()
#        bcm_add_subdirectory(bcm_adapter)
#    endif()

    if(${ONU_MGMT_OMCI_STUB})
        bcm_module_header_paths(PUBLIC .)
        bcm_module_srcs(
            omci_svc_stubs.c)
    else()
        bcm_module_header_paths(PUBLIC . bcm_adapter onu_mgmt_migration)
        bcm_module_srcs(
            omci_svc.c
            omci_svc_onu.c
            omci_svc_flow.c
            omci_svc_common.c
            omci_svc_remote_proxy_if.c
            bcm_adapter/omci_svc_adapter_bcm_omci.c)
    endif()

    bcm_create_lib_target()
endif()
