# Attach to running daemon
bcm_module_name(daemon_attach)
bcm_module_dependencies(PUBLIC os)
bcm_module_header_paths(PUBLIC ${daemon_SRC_DIR})
if(LOG)
    bcm_module_dependencies(PUBLIC dev_log)
endif()
if(CLI_LINENOISE)
    bcm_module_dependencies(PUBLIC linenoise)
endif()
bcm_module_srcs(bcmolt_daemon_attach.c)
bcm_create_app_target(fs RELEASE)
