# Google protobuf
#
include(third_party)

bcm_3rdparty_module_name(protobuf "3.11.0")

bcm_3rdparty_download_wget("https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOBUF_VERSION}" "protobuf-cpp-${PROTOBUF_VERSION}.tar.gz")

bcm_3rdparty_add_dependencies(zlib)

bcm_3rdparty_add_build_options(--enable-silent-rules --enable-shared --enable-static)
bcm_3rdparty_add_build_options(--with-zlib --with-zlib-include=${_${_MOD_NAME_UPPER}_INSTALL_TOP}/include --with-zlib-lib=${_${_MOD_NAME_UPPER}_INSTALL_TOP}/lib)
if(NOT ("${BOARD}" STREQUAL "sim"))
    bcm_3rdparty_add_build_options(--with-protoc=${PROTOC})
endif()

bcm_3rdparty_build_automake()

bcm_3rdparty_export()
