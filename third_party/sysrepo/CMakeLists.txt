# sysrepo - NETCONF/YANG data base service
#
include(third_party)

bcm_make_normal_option(SYSREPO_SHM_PREFIX STRING "sysrepo SHM file prefix" "none")

if(NETCONF_TOOLS_FROM_DEVEL)
    set(_VERSION "devel")
elseif(NETOPEER2_VERSION_2X)
    set(_VERSION "2.1.42")
else()
    set(_VERSION "1.4.140")
endif()
bcm_3rdparty_module_name(sysrepo ${_VERSION})

if("${SYSREPO_VERSION}" STREQUAL "devel")
    bcm_3rdparty_download_wget("https://github.com/sysrepo/sysrepo/archive" "devel.zip" "sysrepo-devel")
else()
    bcm_3rdparty_download_wget("https://github.com/sysrepo/sysrepo/archive" "v${SYSREPO_VERSION}.tar.gz")
endif()

bcm_3rdparty_add_dependencies(libev libredblack libyang protobuf protobuf-c sysrepo-commands)
bcm_3rdparty_add_build_options(-DSR_DISABLE_SYSTEMD=ON)
bcm_3rdparty_add_build_options(-DBUILD_CPP_EXAMPLES=OFF -DBUILD_EXAMPLES=ON -DGEN_LANGUAGE_BINDINGS=OFF)
bcm_3rdparty_add_build_options(-DENABLE_TESTS=OFF -DENABLE_VALGRIND_TESTS=OFF -DGEN_PYTHON_BINDINGS=OFF)
if(SYSREPO_SHM_PREFIX AND NOT "${SYSREPO_SHM_PREFIX}" STREQUAL "none")
    bcm_3rdparty_add_env_variables(SYSREPO_SHM_PREFIX=${SYSREPO_SHM_PREFIX})
endif()
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
