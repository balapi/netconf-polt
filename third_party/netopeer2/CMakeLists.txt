# netopeer2 - NETCONF agent
#
include(third_party)

bcm_make_normal_option(NETCONF_ENABLE_NACM BOOL "Enable NETCONF Access Control Management (NACM)" n)
bcm_make_normal_option(NETOPEER_SSH_PORT STRING "Default SSH port netopeer listens on" "10830")

if(NETCONF_TOOLS_FROM_DEVEL)
    set(_VERSION "devel")
elseif(NETOPEER2_VERSION_2X)
    set(_VERSION "2.1.42")
else()
    set(_VERSION "1.1.76")
endif()

# Netopeer2 consists from multiple components
# Umbrella module
bcm_3rdparty_module_name(netopeer2 ${_VERSION})
if("${NETOPEER2_VERSION}" STREQUAL "devel")
    bcm_3rdparty_download_wget("https://github.com/CESNET/netopeer2/archive" "devel.zip" "netopeer2-devel")
else()
    bcm_3rdparty_download_wget("https://github.com/CESNET/netopeer2/archive" "v${NETOPEER2_VERSION}.tar.gz" "netopeer2-${NETOPEER2_VERSION}")
endif()
bcm_3rdparty_add_dependencies(netopeer2-server-configured netopeer2-commands)
bcm_3rdparty_build_dummy()
set(_NETOPEER2_TYPE PACKAGE)
set(NETOPEER2_BASE_DIR ${_${_MOD_NAME_UPPER}_SRC_DIR})
set(NETOPEER2_LOADED ${_${_MOD_NAME_UPPER}_LOADED_FILE})
bcm_3rdparty_export()

if(SYSREPO_SHM_PREFIX AND NOT "${SYSREPO_SHM_PREFIX}" STREQUAL "none")
    set(ENV{SYSREPO_SHM_PREFIX} ${SYSREPO_SHM_PREFIX})
endif()

# Use native tools when cross-compiling
if(BCM_CONFIG_HOST MATCHES "x86")
    set(_SYSREPO_TOOLS_DIR ${CMAKE_BINARY_DIR}/fs/bin)
else()
    set(_SYSREPO_TOOLS_DIR ${BCM_SIM_BUILD_ARTIFACTS}/bin)
endif()
set(_SYSREPOCFG_EXECUTABLE ${CMAKE_BINARY_DIR}/fs/bin/sysrepotool.sh ${_SYSREPO_TOOLS_DIR}/sysrepocfg)

# Server
bcm_3rdparty_module_name(netopeer2-server ${NETOPEER2_VERSION})
bcm_3rdparty_add_dependencies(libyang libnetconf2 libssh sysrepo yang-models)
if(NOT NETOPEER2_DEBUG)
    bcm_3rdparty_add_build_options(-DCMAKE_BUILD_TYPE=Release)
endif()
bcm_3rdparty_add_build_options(-DSYSREPOCTL_EXECUTABLE="${_SYSREPO_TOOLS_DIR}/sysrepoctl")
bcm_3rdparty_add_build_options(-DSYSREPOCFG_EXECUTABLE="${_SYSREPO_TOOLS_DIR}/sysrepocfg")
bcm_3rdparty_add_build_options(-DOPENSSL_EXECUTABLE="${_SYSREPO_TOOLS_DIR}/openssl")
bcm_3rdparty_add_build_options(-DNP2SRV_DISABLE_SYSTEMD:bool=ON)
bcm_3rdparty_add_build_options(-DPIDFILE_PREFIX=/tmp)
bcm_3rdparty_add_build_options(-DBUILD_TESTS:bool=OFF -DVALGRIND_TESTS:bool=OFF)
bcm_3rdparty_add_build_options(-DINSTALL_MODULES=OFF)
#bcm_3rdparty_add_build_options(-DGENERATE_HOSTKEY=OFF)
bcm_3rdparty_add_build_options(-DLIBNETCONF2_ENABLED_SSH:bool=ON)
bcm_3rdparty_add_build_options(-DPOLL_IO_TIMEOUT=100)
bcm_3rdparty_add_build_options(-DBUILD_CLI:bool=ON)
#bcm_3rdparty_add_build_options(-DDATA_CHANGE_TIMEOUT=10)
bcm_3rdparty_add_env_variables(SYSREPO_REPOSITORY_PATH=${CMAKE_BINARY_DIR}/fs/sysrepo)
if(BCM_CONFIG_HOST MATCHES "x86")
   bcm_3rdparty_add_env_variables(PATH=${CMAKE_BINARY_DIR}/fs/bin:$ENV{PATH})
endif()
set(_NETOPEER2-SERVER_SRC_DIR ${NETOPEER2_BASE_DIR})
set(_NETOPEER2-SERVER_TYPE APPLICATION)
add_custom_command(OUTPUT ${_${_MOD_NAME_UPPER}_LOADED_FILE}
    COMMAND mkdir -p build
    COMMAND touch ${_${_MOD_NAME_UPPER}_LOADED_FILE}
    DEPENDS ${NETOPEER2_LOADED}
    WORKING_DIRECTORY ${_${_MOD_NAME_UPPER}_SRC_DIR})
bcm_3rdparty_build_cmake()
bcm_3rdparty_export()

# Server configured
set(_NETOPEER2_CONFIGURED_FILE ${CMAKE_CURRENT_BINARY_DIR}/.netopeer2_configured)
if(NOT NETCONF_ENABLE_NACM)
    set(_DISABLE_NACM_COMMAND COMMAND ${_SYSREPOCFG_EXECUTABLE} -d startup --format xml -m ietf-netconf-acm --edit=${CMAKE_CURRENT_SOURCE_DIR}/disable_nacm.xml)
endif()
add_custom_command(OUTPUT ${_NETOPEER2_CONFIGURED_FILE}
    COMMAND sed -e \'s/@SSH_PORT@/${NETOPEER_SSH_PORT}/\' ${CMAKE_CURRENT_SOURCE_DIR}/set_ssh_port.xml > ./set_ssh_port.xml
    COMMAND ${_SYSREPOCFG_EXECUTABLE} -d startup --format xml -m ietf-netconf-server --edit=set_ssh_port.xml
    ${_DISABLE_NACM_COMMAND}
    COMMAND touch ${_NETOPEER2_CONFIGURED_FILE}
    DEPENDS netopeer2-server
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/fs)

add_custom_target(netopeer2-server-configured
    DEPENDS ${_NETOPEER2_CONFIGURED_FILE})
unset(_DISABLE_NACM_COMMAND)
unset(_NETOPEER2_CONFIGURED_FILE)

add_custom_target(netopeer2-commands
    COMMAND mkdir -p ${CMAKE_BINARY_DIR}/fs/bin
    COMMAND cp -af ${CMAKE_CURRENT_SOURCE_DIR}/*.sh ${CMAKE_BINARY_DIR}/fs/bin/)

