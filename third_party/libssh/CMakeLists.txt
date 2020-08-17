# libssh - SSH support library
#
include(third_party)

bcm_3rdparty_module_name(libssh "0.9.2")

bcm_3rdparty_download_wget("https://www.libssh.org/files/0.9" "libssh-${LIBSSH_VERSION}.tar.xz")

bcm_3rdparty_add_dependencies(openssl zlib)

bcm_3rdparty_add_build_options(-DWITH_ZLIB=ON -DWITH_GCRYPT=OFF -DWITH_EXAMPLES=OFF -DWITH_GSSAPI=OFF)

bcm_3rdparty_add_cflags(-DHAVE_OPENSSL_CRYPTO_CTR128_ENCRYPT=1)

bcm_3rdparty_build_cmake()

bcm_3rdparty_export()
