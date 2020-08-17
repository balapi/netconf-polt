# Common API
# This version of CMakeLists.txt pull balapi from github and enables integration
# with an application that uses a BAL SDK build system and need to be integrated
# with BAL API

# BAL API version. Must match of of the versions released in github
bcm_make_normal_option(BAL_API_VERSION STRING "BAL API Version" "3.6.3.3")

include(third_party)

set(_UNPACKED_DIR_NAME bal-api-${BAL_API_VERSION}-master)
bcm_3rdparty_module_name(bal_api_pre_loaded ${BAL_API_VERSION})
bcm_3rdparty_download_wget("https://github.com/balapi/bal-api-${BAL_API_VERSION}/archive" "master.zip" ${_UNPACKED_DIR_NAME})
bcm_3rdparty_build_dummy()
bcm_3rdparty_export()

set(_UNPACKED_DIR_NAME ${CMAKE_CURRENT_BINARY_DIR}/${_UNPACKED_DIR_NAME})
set(_BAL_API_STUBS ${_UNPACKED_DIR_NAME}/stubs/bcmolt_api_stubs.c
                   ${_UNPACKED_DIR_NAME}/stubs/bcm_system_stubs.c)
if(BAL_API_EXTERNAL_OS_ABSTRACTION)
    set(_REMOVE_OS_ABSTRACTION_CMD COMMAND rm -f ${_UNPACKED_DIR_NAME}/include/bcmos_*.h)
endif()
add_custom_target(bal_api_loaded
    ${_REMOVE_OS_ABSTRACTION_CMD}
    DEPENDS bal_api_pre_loaded)
add_custom_command(OUTPUT ${_BAL_API_STUBS}
                   DEPENDS bal_api_loaded)

bcm_module_name(balapi)
bcm_module_header_paths(PUBLIC ${_UNPACKED_DIR_NAME}/include
        ${_UNPACKED_DIR_NAME}/include/object_model)
bcm_module_srcs(${_BAL_API_STUBS})
if(BAL_API_EXTERNAL_OS_ABSTRACTION)
    bcm_module_dependencies(PUBLIC os)
endif()
bcm_create_shared_lib_target()

bcm_module_name(host_api)
bcm_module_dependencies(PUBLIC balapi)
bcm_create_lib_target()

bcm_module_name(metadata)
bcm_module_dependencies(PUBLIC balapi)
bcm_create_lib_target()

bcm_module_name(api)
bcm_module_dependencies(PUBLIC metadata)
bcm_create_lib_target()

bcm_module_name(system_type_funcs)
bcm_module_dependencies(PUBLIC balapi)
bcm_create_lib_target()

bcm_module_name(system_types)
bcm_module_dependencies(PUBLIC system_type_funcs)
bcm_create_lib_target()
