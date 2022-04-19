# By default, enable ONU mgmt
bcm_make_normal_option(ONU_MGMT             BOOL    "Enable ONU Management" y)

if(${ONU_MGMT})
    bcm_module_definitions(PUBLIC -DONU_MGMT)

    # List all the ONU Mgmt subdirectories
    if(CLI)
        bcm_add_subdirectory(libonumgmtcli OPTIONAL)
    endif()
    bcm_add_subdirectory(libonumgmtmodel)
    bcm_add_subdirectory(libonumgmt)
    bcm_add_subdirectory(libomcisvc)
    bcm_add_subdirectory(libomcistack)
    bcm_add_subdirectory(libonumgmttest)

    if(NOT OPEN_SOURCE)
        bcm_add_subdirectory(libonumgmtapiproxy)
        bcm_add_subdirectory(libdpoe2stack)
        bcm_add_subdirectory(libdpoe2svc)
        bcm_add_subdirectory(cmcc_vomci)
    endif()
    bcm_add_subdirectory(tr451_vomci_polt OPTIONAL)

    install(FILES config/onu_mgmt_config.ini DESTINATION fs)
    bcm_release_install(${CMAKE_INSTALL_PREFIX}/fs/onu_mgmt_config.ini RELEASE ${BCM_HOST_IMAGES_RELEASE})
endif()
