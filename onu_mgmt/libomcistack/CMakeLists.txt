if(${ONU_MGMT})
    bcm_module_name(omci_stack)
    bcm_module_cflags(PRIVATE -Wno-redundant-decls)
    bcm_module_dependencies(PUBLIC os dev_log)
    # When building opensource release, note that only bcmolt_conv.[ch] is used
    # from the utils module
    bcm_module_dependencies(PUBLIC utils)
    bcm_module_header_paths(PUBLIC . transport model)
    file(GLOB _ALL_C_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/*.c
        ${CMAKE_CURRENT_SOURCE_DIR}/transport/*.c
        ${CMAKE_CURRENT_SOURCE_DIR}/model/*.c)
    bcm_module_srcs(${_ALL_C_FILES})
    bcm_create_lib_target()
endif()
