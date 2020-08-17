# Daemon support
bcm_module_name(daemon)
if("${OS}" STREQUAL "posix")
    bcm_module_srcs(bcmolt_daemon.c)
    bcm_module_dependencies(PUBLIC os)
    bcm_module_header_paths(PUBLIC .)
    bcm_create_lib_target()
    # daemon_attach application
    bcm_add_subdirectory(attach)
endif()
