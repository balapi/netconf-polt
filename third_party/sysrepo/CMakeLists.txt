# sysrepo - NETCONF/YANG data base service
#
include(third_party)

if(NETCONF_TOOLS_FROM_DEVEL)
    set(_VERSION "devel")
else()
    set(_VERSION "1.4.66")
endif()
bcm_3rdparty_module_name(sysrepo ${_VERSION})

if("${SYSREPO_VERSION}" STREQUAL "devel")
    bcm_3rdparty_download_wget("https://github.com/sysrepo/sysrepo/archive" "devel.zip" "sysrepo-devel")
else()
    bcm_3rdparty_download_wget("https://github.com/sysrepo/sysrepo/archive" "v${SYSREPO_VERSION}.tar.gz")
endif()

bcm_3rdparty_add_dependencies(libev libredblack libyang protobuf protobuf-c sysrepo-commands)
bcm_3rdparty_add_build_options(-DBUILD_CPP_EXAMPLES=OFF -DBUILD_EXAMPLES=OFF -DGEN_LANGUAGE_BINDINGS=OFF)
bcm_3rdparty_add_build_options(-DENABLE_TESTS=OFF -DGEN_PYTHON_BINDINGS=OFF)
set(_REPO_LOC ${_${_MOD_NAME_UPPER}_INSTALL_TOP}/sysrepo)
# Use native tools when compiling for target other than x86*
if(BCM_CONFIG_HOST MATCHES "x86")
    set(_SYSREPO_TOOLS_PATH ${_${_MOD_NAME_UPPER}_SRC_DIR}/build/src)
else()
    set(_SYSREPO_TOOLS_PATH ${CMAKE_BINARY_DIR}/../host-sim/fs/bin)
endif()
bcm_3rdparty_add_build_options(-DREPO_PATH:PATH=${_REPO_LOC})

bcm_3rdparty_build_cmake(shm_clean install)

bcm_3rdparty_export()

add_custom_target(sysrepo-commands
    COMMAND mkdir -p ${CMAKE_BINARY_DIR}/fs/bin
    COMMAND cp -af ${CMAKE_CURRENT_SOURCE_DIR}/*.sh ${CMAKE_BINARY_DIR}/fs/bin/)

unset(_SYSREPO_TOOLS_PATH)
