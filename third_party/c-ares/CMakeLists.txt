# c-ares - A C library for asynchronous DNS requests
#
include(third_party)
bcm_3rdparty_module_name(cares "1_15_0")

#bcm_3rdparty_add_dependencies(protobuf zlib openssl)

bcm_3rdparty_download_wget("https://github.com/c-ares/c-ares/archive" "cares-${CARES_VERSION}.tar.gz" "c-ares-cares-${CARES_VERSION}")

bcm_3rdparty_build_cmake()

bcm_3rdparty_export()
