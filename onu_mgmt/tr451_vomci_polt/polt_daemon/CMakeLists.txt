# TR-451 ONU Management
# pOLT daemon application
#
if(TR451_VOMCI_POLT)
bcm_module_name(tr451_polt_daemon)
bcm_module_dependencies(PUBLIC tr451_polt daemon)
bcm_module_header_paths(PRIVATE .)
bcm_module_srcs(bcm_tr451_polt_main.c)
bcm_create_app_target(fs)
install(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/start_tr451_polt.sh DESTINATION fs
        PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
endif()
