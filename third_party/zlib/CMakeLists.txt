# zlib
#
include(third_party)

bcm_3rdparty_module_name(zlib "1.2.13")

bcm_3rdparty_download_wget("https://www.zlib.net/fossils" "zlib-${ZLIB_VERSION}.tar.gz")

bcm_3rdparty_add_build_options(-DBUILD_SHARED_LIBS=true)

bcm_3rdparty_build_cmake()

bcm_3rdparty_export(z)
