# protobuf-c library
#
include(third_party)

bcm_3rdparty_module_name(protobuf-c "1.3.2")

bcm_3rdparty_download_wget("https://github.com/protobuf-c/protobuf-c/releases/download/v${PROTOBUF-C_VERSION}"
    "protobuf-c-${PROTOBUF-C_VERSION}.tar.gz")

bcm_3rdparty_add_dependencies(protobuf)

bcm_3rdparty_add_build_options(PKG_CONFIG_PATH=${CMAKE_BINARY_DIR}/fs/lib/pkgconfig)

bcm_3rdparty_build_automake()

bcm_3rdparty_export()
