if(${ONU_MGMT})
    bcm_module_name(onu_mgmt_model)
    bcm_module_dependencies(PUBLIC os utils system_types system_type_funcs dev_log metadata)
    bcm_module_header_paths(PUBLIC .)

    bcm_module_srcs(onu_mgmt_model_funcs.c onu_mgmt_model_metadata.c)

    bcm_create_lib_target()
endif()

