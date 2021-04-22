# libgpg-error
#
include(third_party)

bcm_3rdparty_module_name(libgpg-error "1.42")

bcm_3rdparty_download_wget("https://gnupg.org/ftp/gcrypt/libgpg-error" "libgpg-error-${LIBGPG-ERROR_VERSION}.tar.bz2")

bcm_3rdparty_build_automake()

bcm_3rdparty_export()
