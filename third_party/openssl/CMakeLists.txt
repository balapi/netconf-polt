# openssl
#
include(third_party)

bcm_3rdparty_module_name(openssl "1.1.0j")

bcm_3rdparty_download_wget("https://www.openssl.org/source/old/1.1.0" "openssl-${OPENSSL_VERSION}.tar.gz")

bcm_3rdparty_add_dependencies(zlib)

# openssl uses custom-made configurator. Invoke it directly
set(_CFLAGS_OPTS -I"${BUILD_TOP}"/fs/include ${BCM_ARCHITECTURE_FLAGS} ${_${_MOD_NAME_UPPER}_CFLAGS})
set(_LDFLAGS_OPTS -L"${BUILD_TOP}"/fs/lib ${LINK_FLAGS} ${_${_MOD_NAME_UPPER}_LDFLAGS})
set(_TARGETS ${ARGN})
if(NOT _TARGETS)
    set(_TARGETS install)
endif()
if(NOT DEFINED BCM_CONFIG_HOST)
    message(FATAL_ERROR "Need to add support for board ${BOARD}")
endif()
set(_CONFIG_OPTS no-hw no-sse2 no-asm zlib)
if(BCM_CONFIG_HOST MATCHES ".*aarch64.*")
    set(_CONFIG_HOST linux-aarch64)
elseif(BCM_CONFIG_HOST MATCHES ".*x86_64.*")
    set(_CONFIG_HOST linux-x86_64)
endif()

add_custom_command(OUTPUT ${_${_MOD_NAME_UPPER}_INSTALLED_FILE}
    COMMAND echo "Building ${_MOD_NAME}-${${_MOD_NAME_UPPER}_VERSION}.."
    COMMAND CC=${CMAKE_C_COMPILER}
        ./Configure ${_CONFIG_OPTS} --prefix=${_${_MOD_NAME_UPPER}_INSTALL_TOP}
            ${_CONFIG_HOST} ${_CFLAGS_OPTS} ${_LDFLAGS_OPTS}
    # opennsl doesn't seem to support parallel build
    COMMAND ${CMAKE_MAKE_PROGRAM} -j1 ${_BCM_COMMON_MAKE_FLAGS} ${_TARGETS}
    COMMAND rm -f ${CMAKE_CURRENT_BINARY_DIR}/.${_MOD_NAME}_*_installed
    COMMAND touch ${_${_MOD_NAME_UPPER}_INSTALLED_FILE}
    DEPENDS ${_${_MOD_NAME_UPPER}_DEPS} ${_${_MOD_NAME_UPPER}_LOADED_FILE}
    WORKING_DIRECTORY ${_${_MOD_NAME_UPPER}_SRC_DIR})

unset(_CFLAGS_OPTS)
unset(_LDFLAGS_OPTS)
unset(_CONFIG_OPTS)
unset(_CONFIG_TARGET)
unset(_TARGETS)
unset(_CONFIG_HOST)

bcm_3rdparty_export(ssl)
