if(${ONU_MGMT})
    bcm_module_name(onu_mgmt_test)
    bcm_module_header_paths(PUBLIC .)
    bcm_module_dependencies(PUBLIC system_types)

    bcm_module_srcs(
            onu_mgmt_test.c)

    bcm_create_lib_target()
endif()
