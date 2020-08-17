# libgcrypt
#
include(third_party)

bcm_3rdparty_module_name(libgcrypt "1.8.4")

bcm_3rdparty_download_wget("https://gnupg.org/ftp/gcrypt/libgcrypt" "libgcrypt-${LIBGCRYPT_VERSION}.tar.bz2")

bcm_3rdparty_add_dependencies(libgpg-error)

bcm_3rdparty_add_build_options(--disable-pclmul-support --disable-doc --with-libgpg-error-prefix=${_${_MOD_NAME_UPPER}_INSTALL_TOP})

bcm_3rdparty_build_automake()

bcm_3rdparty_export()
