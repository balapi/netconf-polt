# By default, disable CMCC vOMCI ONU Management
bcm_make_normal_option(TR451_VOMCI_POLT    BOOL    "Enable TR-451 vOMCI ONU Management" n)
if(TR451_VOMCI_POLT)
    bcm_module_name(tr451_polt)
    bcm_module_definitions(PUBLIC -DTR451_VOMCI)
    bcm_module_dependencies(PUBLIC os dev_log cli tr451_polt_vendor grpc)
    bcm_module_dependencies(PRIVATE tr451_sbi grpc)
    bcm_module_header_paths(PUBLIC . ${netconf_modules_SRC_DIR})
    bcm_module_srcs(bcm_tr451_polt_common.cc bcm_tr451_polt_client.cc bcm_tr451_polt_server.cc bcm_tr451_polt_cli.cc)
    bcm_create_lib_target()

    bcm_release_install(${CMAKE_INSTALL_PREFIX}/fs/tr451_polt_daemon RELEASE ${BCM_HOST_IMAGES_RELEASE}/netconf_server)
    bcm_release_install(${CMAKE_INSTALL_PREFIX}/fs/start_tr451_polt.sh RELEASE ${BCM_HOST_IMAGES_RELEASE}/netconf_server)
endif()
# Include subdirectories unconditionally to make sure that entire module gets included in ONU_MGMT release
bcm_add_subdirectory(message_definition)
bcm_add_subdirectory(polt_daemon)
bcm_add_subdirectory(tr451_polt_vendor)
