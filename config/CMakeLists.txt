bcm_module_name(host_config)
bcm_module_header_paths(PUBLIC .)
bcm_create_lib_target()

# Add files to the GitHub part of the release tree.
bcm_github_install(bcm_config.h
                   bcmos_platform.h
                   RELEASE github/include)

